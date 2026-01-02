from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric import padding
import datetime

def csr(user, pwd):
    #extract private key from pem
    with open(user + 'key.pem', 'rb') as f:
        user_key = serialization.load_pem_private_key(f.read(), pwd)

    #subject
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "ES"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "MADRID"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "UC3M"),
        x509.NameAttribute(NameOID.COMMON_NAME, user),
    ])

    #csr
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(subject)
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .sign(user_key, hashes.SHA256())
    )

    #serialise to pem
    csr_pem = csr.public_bytes(serialization.Encoding.PEM)

    path = f"PKI/AC1/solicitudes/{user}csr.pem"
    with open(path, "wb") as f:
        f.write(csr_pem)


def signcsr(user, MASTERKEY):
    # Load CA private key
    path_to_CA_private = 'PKI/AC1/privado/ca1key.pem'
    with open(path_to_CA_private, 'rb') as f:
        ca_key = serialization.load_pem_private_key(f.read(), password=MASTERKEY)

    # Load CA certificate
    path_to_CA_cert = 'PKI/AC1/ac1cert.pem'
    with open(path_to_CA_cert, 'rb') as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())

    # Load user CSR
    path_to_user_csr = f'PKI/AC1/solicitudes/{user}csr.pem'
    with open(path_to_user_csr, 'rb') as f:
        csr = x509.load_pem_x509_csr(f.read())

    # Build certificate
    cert_builder = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(ca_cert.subject)
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now())
        .not_valid_after(datetime.datetime.now() + datetime.timedelta(days=365))
    )

    # Add all CSR extensions
    for ext in csr.extensions:
        cert_builder = cert_builder.add_extension(ext.value, ext.critical)

    # Sign certificate
    cert = cert_builder.sign(private_key=ca_key, algorithm=hashes.SHA256())

    # Save signed certificate
    path_to_signed_cert = f'PKI/AC1/nuevoscerts/{user}cert.pem'
    with open(path_to_signed_cert, 'wb') as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))


def verify_certificate(user):
    user_cert_path = f'PKI/AC1/nuevoscerts/{user}cert.pem'
    with open(user_cert_path, "rb") as f:
        cert = x509.load_pem_x509_certificate(f.read())

    ca_cert_path = 'PKI/AC1/ac1cert.pem'
    with open(ca_cert_path, "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())

    #check if issuer is our CA
    if cert.issuer != ca_cert.subject:
        print("Certificate was not issued by a valid CA")
        return False

    #signature
    ca_cert.public_key().verify(
        cert.signature,
        cert.tbs_certificate_bytes,
        padding.PKCS1v15(),   # RSA CA
        cert.signature_hash_algorithm,
    )
    print('User certificate is valid')
    ca_cert.public_key().verify(
        ca_cert.signature,
        ca_cert.tbs_certificate_bytes,
        padding.PKCS1v15(),   # RSA CA
        ca_cert.signature_hash_algorithm,
    )
    print('CA certificate is valid')
    return True



