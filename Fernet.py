#!/usr/bin/env python3
############################# [ IMPORTS ] #############################

import argparse,os

from cryptography.fernet import Fernet

############################# [ FUNCTIONS ] #############################

# Handling the args
def getArgs():
    parser = argparse.ArgumentParser("python3 Fernet.py {-c/-d} -F {filename}")  # Create an object to get args
    # Options of this program
    parser.add_argument("-c", "--crypt",action='store_true',dest="crypt", help="Use this to crypt a file")
    parser.add_argument("-d", "--decrypt",action='store_true', dest="decrypt", help="Use this to decrypt a file")
    parser.add_argument("-F", "--file", dest="file", help="Enter the file name you want to act onto", type=str)
    options,args = parser.parse_args()
    if options.file is not None:  # Check if file option is empty
        if os.path.isfile(options.file): 
            if options.crypt is None and options.decrypt is None:  # Check if the action to execute is empty
                parser.error("\n\t[-] Error in the command : please chose an action to execute")
                parser.error("Check -h or --help for help")
                exit()
            elif options.crypt and options.decrypt: # Check if all the action are set
                parser.error("\n\t[-] Error in the command : please chose only one action to execute")
                parser.error("Check -h or --help for help")
                exit()
        else :
            parser.error("\n\t[-] Error in the command : the file specified doesn't exist")
            parser.error("Check -h or --help for help")
            exit()
    else :
        parser.error("\n\t[-] Error in the command : please chose a file to act onto")
        parser.error("Check -h or --help for help")
        exit()

    return options

# --------------------------------------------------
# Create the key file
def genKey():
    key = Fernet.generate_key()  # Generate a key

    with open('filekey.key', 'wb') as filekey:
        filekey.write(key)  # Create a file a put the key into it


# Use the key
def key():
    with open('filekey.key', 'rb') as filekey:
        key = filekey.read()  # Open the file and extract the key

    fernet = Fernet(key)  # Put the key in a class and call it in a var

    return fernet

# --------------------------------------------------
# Encrypt the file
def encryption(fileToCrypt):
    if not os.path.isfile('filekey.key'):  # Check if the file doesn't exists
        genKey()

    fernet = key()

    with open(fileToCrypt, 'rb') as file:
        msg = file.read() # Open the file to encrypt

    encrypted = fernet.encrypt(msg)  # and encrypt it
    #print(encrypted)

    with open('crypted.txt','w') as file :
        file.writelines(encrypted.decode('utf-8'))

    print(f"\n\t[+] File {options.file} successfully encoded : crypted.txt\n")

# --------------------------------------------------
# Decrypt the file
def decryption(fileToDecrypt):
    if not os.path.isfile('filekey.key'):  # Check if the file doesn't exists
        print("\n\t[-] Unable to decrypt the file without a key\n")

    fernet = key() # Use the key

    with open(fileToDecrypt, 'rb') as file:
        msg = file.read() # Open the file to encrypt

    decrypted = fernet.decrypt(msg)  # and decrypt it
    #print(decrypted)

    with open('decrypted.txt','w') as file :
        file.writelines(decrypted.decode('utf-8').capitalize())

    print(f"\n\t[+] File {options.file} successfully encoded : decrypted.txt\n")

############################# [ LAUNCH ] #############################

options = getArgs()
#print(options)

if options.crypt:
    encryption(options.file)
elif options.decrypt:
    decryption(options.file)

