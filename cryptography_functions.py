import os
import json
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from certificates import verify_certificate

#REGISTRATION --------------

def load_users(usersfile): #read the existing users
    if not os.path.exists(usersfile):
        return {}   #returns an empty dictionary if there's no user file (ie. no users yet)
    with open(usersfile, 'r') as file:  #use with so that the file closes automatically after use
        return json.load(file)  #returns a dictionary with all users and their passwords

def save_users(usersfile, users):
    with open(usersfile, 'w') as file:   
        json.dump(users, file, indent=4)  #rewrites the file with all new users

def add_user(usersfile, username, pwdsalt, chachasalt, hexpassword):
    users = load_users(usersfile)   #create dictionary with all contents in usersfile
    users[username] = [pwdsalt]
    users[username].append(chachasalt)
    users[username].append(hexpassword)  #otherwise, create an entry in the dictionary with the user and the password and the salt
    save_users(usersfile, users)    #and rewrite the file with the new info
    return True

#CHACHAPOLY -------------

#Accepts two binary strings and encrypts the first one
def chachapoly_encrypt(key, cleartext, aad=None):
    chacha_obj = ChaCha20Poly1305(key) #Creates an object of the chacha class
    nonce = os.urandom(12) #Generates a nonce
    ciphertext = chacha_obj.encrypt(nonce, cleartext, aad) #Encrypts data

    return ciphertext, nonce

#From a cyphertext and a nonce we find out the cleartext
def chachapoly_decrypt(key, ciphertext, nonce, aad=None):
    chacha_obj = ChaCha20Poly1305(key)
    cleartext = chacha_obj.decrypt(nonce, ciphertext, aad) #Decrypts ciphertext

    return cleartext

#From a salt and the user's password we derive its cryptographic key
def derive_chachakey(chachasalt, pwd_byte):
    chachakdf = PBKDF2HMAC(
        algorithm = hashes.SHA256(),
        length = 32, #Chachakeys need to be of length 32
        salt = chachasalt,
        iterations = 1_200_000 #Recommended: highest possible
    )

    chachakey = chachakdf.derive(pwd_byte) #Derive the chachakey

    return chachakey

#SIGNATURE --------------

#Serialise & store keys
def serialise_private(key, user, pwd):
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(pwd)
    )
    filename = user + 'key.pem'
    with open(filename, "wb") as f:
        f.write(pem)        #assume this is very secure and inaccessible by anyone

#Signature of a file
def sign(user, room, time, pwd):
    msg = user + room + time    #the json will look like {msg: signature}
    msg_byte = msg.encode("utf-8")
    json_name = msg + ".json"   #create a different json for each reservation
    
    with open(user + 'key.pem', 'rb') as f:
        private_key_byte = serialization.load_pem_private_key(f.read(), pwd)
        #load serialised private key

    signature = private_key_byte.sign(
        msg_byte,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )   
    #signature of the message = user + room + time
    
    signature_hex = signature.hex()
    data = {msg:signature_hex}  #save msg in cleartext and the signature in hex 
    with open(json_name, "w") as json_file: 
        json.dump(data, json_file, indent=4) #Adds the dictionaries' contents in the json  

#verify the signature
def verify_sign(json_file, user):
    info = load_users(json_file)

    #extract the message in cleartext
    message = list(info.keys())[0]
    message_byte = message.encode("utf-8")

    #extract the signature 
    signature_hex = info[message]
    signature_byte = bytes.fromhex(signature_hex)
    verify_certificate(user)    #check if this user's certificate is valid (this function also checks the CA's certificate)
    user_cert_path = f'PKI/AC1/nuevoscerts/{user}cert.pem'

    with open(user_cert_path, "rb") as f:
        cert = x509.load_pem_x509_certificate(f.read())
    public_key = cert.public_key()  #load this user's public key to verify signature
    
    public_key.verify(
        signature_byte,
        message_byte,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )
    print("Signature is valid")

#CREATE FILE ------------

def create_user_file(username, room, roomnonce,  time, timenonce):
    if os.path.exists(username + ".json"):  #if this user already has reservations, add to the file
        userfile = load_users(username + ".json")
        userfile[username].append([room, roomnonce, time, timenonce])
        save_users(username + ".json", userfile)
    else:
        data = {username: [[room, roomnonce, time, timenonce]]} # Stores the info in a dictionary
        json_name = username + ".json" # Names the file after the username
        with open(json_name, "w") as json_file: 
            json.dump(data, json_file, indent=4) #Adds the dictionaries' contents in the json
