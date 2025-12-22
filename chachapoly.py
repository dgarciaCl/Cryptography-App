import os
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

def chachapoly_encrypt(data, key):
    chacha_obj = ChaCha20Poly1305(key)
    nonce = os.urandom(12)
    ciphertext = chacha_obj.encrypt(nonce, data, None)

    return chacha_obj, ciphertext, nonce

def chachapoly_decrypt(chacha_obj, ciphertext, nonce):
    cleartext = chacha_obj.decrypt(nonce, ciphertext, None)

    return cleartext
