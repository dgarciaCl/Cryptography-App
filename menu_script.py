import json
import cryptography
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
import os
from cryptography.hazmat.primitives.asymmetric import rsa

from cryptography_functions import load_users
from cryptography_functions import add_user
from cryptography_functions import serialise_private

from certificates import csr
from certificates import signcsr
from certificates import verify_certificate

#THIS IS BAD PRACTICE, USED FOR CONVENIENCE FOR THE CERTIFICATE
MASTERKEY = (b"MASTERKEY")
#####################################################################

def menu(FILE):
    a = False
    chachakey_hex = str(0)
    print("Please select the index of the function you wish to perform: \n")    #Options menu
    print("1. Log in")
    print("2. Register\n")
    action = int(input(">>> "))

    while action not in [1, 2]:
        print("Wrong option. Please select the index of the function you wish to perform: \n")    #Options menu
        print("1. Log in")
        print("2. Register\n")
        action = int(input(">>> "))

    user = str(input("\nUsername: "))   #ask info
    pwd = str(input("\nPassword: "))
    
    if action == 1: #Login option
        users = load_users(FILE) 
        if user in users:
            salt = bytes.fromhex(users.get(user)[0])    #get the salt in bytes to use it in the function verify
            kdf = Scrypt(
                salt = salt,
                length = 32,
                n = 2**14,   #CPT memory cost parameter
                r = 8,   #Block size
                p = 1,   #Paralelisation parameter
            )

            correctbytepwd = bytes.fromhex(users[user][2]) #get the password in bytes to use it in verify
            pwd_byte = pwd.encode("utf-8")
            try:
                kdf.verify(pwd_byte , correctbytepwd)    #check if the input == correctpassword
                a = True
                chachakey_hex = users.get(user)[1]
                verify_certificate(user)
            except cryptography.exceptions.InvalidKey:  #else, catch the exception and print a message
                print("Invalid password")
        else:
            print("Invalid user")
            pwd_byte = pwd.encode('utf-8')

    elif action == 2:   #Register option
        salt = os.urandom(16)
        chachakey = os.urandom(32)
        pwd_byte = pwd.encode("utf-8")  #get the input in bytes
        kdf = Scrypt(
            salt = salt,
            length = 32,
            n = 2**14,   #CPT memory cost parameter
            r = 8,   #Block size
            p = 1,   #Paralelisation parameter
        )
        chachakey_hex = chachakey.hex()
        salt_hex = salt.hex()   #convert the salt into a hex to get it in the json
        Epwd_byte = kdf.derive(pwd_byte)    #idem with the pwd
        pwd_token = Epwd_byte.hex()
        add_user(FILE, user, salt_hex, chachakey_hex, pwd_token)   #if user already exists, we will not add it
        a = True
        private_key_byte = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        pwd_byte = pwd.encode('utf-8')
        serialise_private(private_key_byte, user, pwd_byte)      #each user has their private key
        csr(user, pwd_byte)
        signcsr(user, MASTERKEY)
        
    
    return user, a, chachakey_hex, pwd_byte