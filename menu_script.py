import os
import cryptography
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from cryptography_functions import load_users
from cryptography_functions import add_user
from cryptography_functions import serialise_private
from cryptography_functions import derive_chachakey

from certificates import csr
from certificates import signcsr
from certificates import verify_certificate

#THIS IS BAD PRACTICE, USED FOR CONVENIENCE FOR THE CERTIFICATE
MASTERKEY = (b"MASTERKEY")

def menu(FILE):
    run_app = False
    chachakey = b''
    user = ''
    pwd_byte = ''
    #^^this is here in case we have an error, so that the return still works. These values will be rewritten

    print("Please select the index of the function you wish to perform:")    #Options menu
    print("1. Log in\n2. Register\n3. Exit")
    try:
        action = int(input(">>> "))
    except:
        action = 0

    while action not in [1, 2, 3]:
        print("Invalid option. Please select the index of the function you wish to perform:")    #Options menu
        print("1. Log in\n2. Register\n3. Exit")
        try:
            action = int(input(">>> "))
        except:
            action = 0

    if action != 3:
        user = str(input("\nUsername: "))   #ask info
        pwd = str(input("Password: "))
        users = load_users(FILE) 
    
    if action == 1: #Login option
        if user in users:   #check if the user indeed exists
            pwd_salt = bytes.fromhex(users.get(user)[0])    #get the salt in bytes to use it in the function verify
            kdf = Scrypt(
                salt = pwd_salt,
                length = 32,
                n = 2**14,   #CPT memory cost parameter
                r = 8,   #Block size
                p = 1,   #Paralelisation parameter
            )

            pwd_token = bytes.fromhex(users[user][2]) #get the correct password in bytes to use it in verify
            pwd_byte = pwd.encode("utf-8")  #input password in bytes
            
            try:
                kdf.verify(pwd_byte, pwd_token)    #check if the input == correctpassword
                run_app = True
                chachasalt_hex = users.get(user)[1]    #get the salt used to find the chachakey
                chachasalt = bytes.fromhex(chachasalt_hex) #convert it back binary
                chachakey = derive_chachakey(chachasalt, pwd_byte)  #derive the chachakey
                verify_certificate(user)    #check if this user's certificate is valid (automatically chacks the CA's as well)
            except cryptography.exceptions.InvalidKey:  #else, catch the exception and print a message
                print("\nIncorrect password")
        else:
            print("\nThis user doesnt exist")
            #if this user doesn't exist, notify it and suggest registering
            register = str(input("Do you wish to register this user? (Y/N): "))

            if register.capitalize() == 'Y':
                action = 2

    if action == 2:   #Register option
        if user not in users:
            pwd_byte = pwd.encode("utf-8")  #get the input in bytes
            pwd_salt = os.urandom(16) #generate a salt to derive this new user's pwd token
            salt_hex = pwd_salt.hex() 
            kdf = Scrypt(
                salt = pwd_salt,
                length = 32,
                n = 2**14,   #CPT memory cost parameter
                r = 8,   #Block size
                p = 1,   #Paralelisation parameter
            )

            Epwd_byte = kdf.derive(pwd_byte)    #idem with the pwd
            pwd_token = Epwd_byte.hex()

            chachasalt = os.urandom(16) #generate a different salt to derive the chachakey
            chachasalt_hex = chachasalt.hex() #convert to hex to store it
            chachakey = derive_chachakey(chachasalt, pwd_byte) #derive the chachakey

            add_user(FILE, user, salt_hex, chachasalt_hex, pwd_token)  
            print("\nUser added.")
            run_app = True
            
            private_key_byte = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
            )

            pwd_byte = pwd.encode('utf-8')
            serialise_private(private_key_byte, user, pwd_byte)     #each user has their private key
            csr(user, pwd_byte) #generate a certificate for each new user (first csr, then sign it)
            signcsr(user, MASTERKEY)
        else:
            print('\nUsername already in use!!')

    #no need to add an option for exit because run_app is False by default
    
    return user, run_app, chachakey, pwd_byte
