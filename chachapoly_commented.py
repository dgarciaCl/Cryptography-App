import os
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

#Accepts two binary strings and encrypts the first one
def chachapoly_encrypt(data, key):
    chacha_obj = ChaCha20Poly1305(key) #Creates an object of the chacha class
    nonce = os.urandom(12) #Generates a nonce
    ciphertext = chacha_obj.encrypt(nonce, data, None) #Encrypts data

    return chacha_obj, ciphertext, nonce

#From a cyphertext and a nonce we find out the cleartext
def chachapoly_decrypt(chacha_obj, ciphertext, nonce):
    cleartext = chacha_obj.decrypt(nonce, ciphertext, None) #Decrypts ciphertext

    return cleartext