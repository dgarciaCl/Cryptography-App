from menu_script import menu

from cryptography_functions import load_users
from cryptography_functions import chachapoly_encrypt
from cryptography_functions import chachapoly_decrypt
from cryptography_functions import create_user_file
from cryptography_functions import sign
from cryptography_functions import verify_sign

FILE = 'users.json' #this is the file we will be working on

user, run_app, chachakey_hex, pwd_byte = menu(FILE)

while run_app:
    user_choice = input("\nDo you wish to make a reservation (A), check your reservations (B) or exit (E): ")

    while user_choice.capitalize() not in ['A', 'B', 'E']:
        user_choice = input("Invalid option. Do you wish to make a reservation (A), check your reservations (B) or exit (E): ")

    if user_choice.capitalize() == "E":
        run_app = False   #E -> exit while loop (end program)
        
    elif user_choice.capitalize() == "A":
        #extract this user's key to encrypt the info
        chachakey_byte = bytes.fromhex(chachakey_hex) 

        #get info for reservation
        room = int(input("Book room number: "))
        room = str(room)
        time = input("At time: ")
        sign(user, room, time, pwd_byte)    #create a file {msg:signature}

        #encrypt the room 
        room_byte = room.encode("utf-8")
        room_enc, nonceroom = chachapoly_encrypt(room_byte, chachakey_byte)
        room_hex = room_enc.hex()
        nonceroom_hex= nonceroom.hex()

        #encrypt the time 
        time_byte = time.encode("utf-8")
        time_enc, noncetime = chachapoly_encrypt(time_byte, chachakey_byte)
        time_hex = time_enc.hex()
        noncetime_hex = noncetime.hex()

        #add it to this user's reservations file
        create_user_file(user, room_hex, nonceroom_hex, time_hex, noncetime_hex)
    
    elif user_choice.capitalize() == "B":
        #get this user's reservations file
        reservations = load_users(user + '.json')

        #if there is at least 1 reservation, print it 
        if (user in reservations):
            for j in range(len(reservations[user])):
                #get the info from the file
                chachakey_byte = bytes.fromhex(chachakey_hex)

                #ROOM
                room_enc = bytes.fromhex(reservations[user][j][0])
                nonceroom_byte = bytes.fromhex(reservations[user][j][1])
                room_byte = chachapoly_decrypt(chachakey_byte, room_enc, nonceroom_byte)
                room = room_byte.decode('utf-8')    #room in cleartext

                #TIME
                time_enc = bytes.fromhex(reservations[user][j][2])
                noncetime_byte = bytes.fromhex(reservations[user][j][3])
                time_byte = chachapoly_decrypt(chachakey_byte, time_enc, noncetime_byte)
                time = time_byte.decode('utf-8')    #time in cleartext

                #print each reservation
                print('--- Reservation', j+1, end=(""))
                print(': ---\nRoom:', room, '\nTime:', time)
                #ask for verification after each reservation
                verify = str(input("Do you wish to verify this info? (Y/N): "))

                #if so, call the function verify
                if verify.capitalize() == 'Y':
                    json_f = user + room + time + '.json'
                    verify_sign(json_f, user)
        else:
            print("There are no reservations under", user, "yet")
