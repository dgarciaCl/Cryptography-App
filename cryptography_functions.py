import json
import cryptography
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.asymmetric import rsa
import os
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

#REGISTRATION --------------
def load_users(usersfile): #read the existing users
    if not os.path.exists(usersfile):
        return {}   #returns an empty dictionary if there's no user file (ie. no users yet)
    with open(usersfile, 'r') as file:  #use with so that the file closes automatically after use
        return json.load(file)  #returns a dictionary with all users and their passwords

def save_users(usersfile, users):
    with open(usersfile, 'w') as file:   
        json.dump(users, file, indent=4)  #rewrites the file with all new users

def add_user(usersfile, username, salt, chachakey, hexpassword):
    users = load_users(usersfile)   #create dictionary with all contents in usersfile
    if username in users:   #if the user is already registered, registration fails
        print("Username already exists.")
        return False    #we need a return to throw an error in the main code
    users[username] = [salt]
    users[username].append(chachakey)
    users[username].append(hexpassword)  #otherwise, create an entry in the dictionary with the user and the password and the salt
    save_users(usersfile, users)    #and rewrite the file with the new info
    print("User added.")
    return True

#CHACHAPOLY -------------

#Accepts two binary strings and encrypts the first one
def chachapoly_encrypt(data, key):
    chacha_obj = ChaCha20Poly1305(key) #Creates an object of the chacha class
    nonce = os.urandom(12) #Generates a nonce
    ciphertext = chacha_obj.encrypt(nonce, data, None) #Encrypts data

    return ciphertext, nonce

#From a cyphertext and a nonce we find out the cleartext
def chachapoly_decrypt(key, ciphertext, nonce):
    chacha_obj = ChaCha20Poly1305(key)
    cleartext = chacha_obj.decrypt(nonce, ciphertext, None) #Decrypts ciphertext

    return cleartext

#SIGNATURE --------------

#Signature of a file
def sign(user, room, time):
    #clear is a dictionary of the form {Name: Room, Time} in cleartext
    msg = user + room + time
    msg_byte = msg.encode("utf-8")
    json_name = msg + ".json"
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    signature = private_key.sign(
        msg_byte,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    data = {msg:signature}
    with open(json_name, "w") as json_file: 
        json.dump(data, json_file, indent=4) #Adds the dictionaries' contents in the json  

#CREATE FILE ------------
def create_user_file(username, room, roomnonce,  time, timenonce):
    if os.path.exists(username + ".json"):
        userfile = load_users(username + ".json")
        userfile[username].append([room, roomnonce, time, timenonce])
        save_users(username + ".json", userfile)
    else:
        data = {username: [[room, roomnonce, time, timenonce]]} # Stores the info in a dictionary
        json_name = username + ".json" # Names the file after the username
        with open(json_name, "w") as json_file: 
            json.dump(data, json_file, indent=4) #Adds the dictionaries' contents in the json
