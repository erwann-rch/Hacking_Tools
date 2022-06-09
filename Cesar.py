#!/usr/bin/env python3
############################# [ IMPORTS ] #############################

import optparse,time,os

############################# [ VARIABLES ] #############################

alphabet = list("ABCDEFGHIJKLMNOPQRSTUVWXYZ")

############################# [ FUNCTIONS ] #############################

# Handling the args
def getArgs():
    parser = optparse.OptionParser("python3 Cesar.py -c / -d  -k {shift} -F {filename}")  # Create an object to get args
    # Options of this program
    parser.add_option("-c", "--crypt",action='store_true',dest="crypt", help="Use this to crypt a file")
    parser.add_option("-d", "--decrypt",action='store_true', dest="decrypt", help="Use this to decrypt a file")
    parser.add_option("-k", "--key", dest="key", help="Enter the shift key you want the code start", type=int)
    parser.add_option("-F", "--file", dest="file", help="Enter the file name you want to act onto", type=str)
    (options,args) = parser.parse_args()
    #print(parser.parse_args())
    if options.file is not None:  # Check if file option is empty
        if os.path.isfile(options.file): 
            if options.crypt is None and options.decrypt is None:  # Check if the action to execute is empty
                parser.error("\n    [-] Error in the command : please chose an action to execute")
                parser.error("Check -h or --help for help")
                exit()
            elif options.crypt and options.decrypt: # Check if all the action are set
                parser.error("\n    [-] Error in the command : please chose only one action to execute")
                parser.error("Check -h or --help for help")
                exit()
        else :
            parser.error("\n    [-] Error in the command : the file specified doesn't exist")
            parser.error("Check -h or --help for help")
            exit()
    else :
        parser.error("\n    [-] Error in the command : please chose a file to act onto")
        parser.error("Check -h or --help for help")
        exit()

    if options.key is None and options.crypt:  # Check if key is empty for the encryption process
        options.key = 1

    return options

# --------------------------------------------------
# # Function which encrypt a file with or without a shift key
def Crypt(msg,shift):
    crypted = ""
    for char in msg: # Do the encryption process for each character
        if char not in alphabet: # Check if the char is not in the alphabet (special chars)
                if char == " ":
                    crypted += " "
                elif char == "\n":
                    crypted += "\n"
                else :
                    crypted += char
        else:
            charIndex = alphabet.index(char) # Shift the current character to left to get its original position
            charNewIndex = (charIndex - shift) % 26 # Find the new index by taking the difference between the original char and the shift mod 26
            #print(charInitIndex)
            if charNewIndex > 25:
                charNew = alphabet[-(charNewIndex - 26)] # Go back to the start of the alphabet if it's too big
            else:
                charNew = alphabet[charNewIndex] # Get the new char without manipulation 
                crypted += charNew

            if shift < 26: # Do a loop on 26 reps
                shift += 1
            else:
                shift = 1
    return crypted 

# --------------------------------------------------   
# Function which decrypt a file with or without a shift key
def Decrypt(msg, shift):
    decrypted = ""
    if options.key != None : # Means a precise shift key is mention
        for char in msg: # Do the encryption process for each character
            if char not in alphabet: # Check if the char is not in the alphabet (special chars)
                if char == " ":
                    decrypted += " "
                elif char == "\n":
                    decrypted += "\n"
            else:
                charIndex = alphabet.index(char) # Shift the current character to left to get its original position
                charInitIndex = (charIndex - shift) % 26 # Find the new index by taking the difference between the original char and the shift mod 26 
                #print(charInitIndex)
                if charInitIndex > 25:
                    charInit = alphabet[-(charInitIndex - 26)] # Go back to the start of the alphabet if it's too big 
                else:
                    charInit = alphabet[charInitIndex] # Get the new char without manipulation 
                    decrypted += charInit

                if shift < 26: 
                    shift += 1
                else:
                    shift = 1
    else : 
        for i in range(1,27): # Do the same with a bruteforce on 26 shifts
            shift = i
            decrypted += f"------------------{i}-------------------\n"
            for char in msg:
                if char not in alphabet:
                    if char == " ":
                        decrypted += " "
                    elif char == "\n":
                        decrypted += "\n"
                else:
                    charIndex = alphabet.index(char) # shift the current character to left to get its original position
                    charInitIndex = (charIndex - shift) % 26
                    #print(charInitIndex)
                    if charInitIndex > 25:
                        charInit = alphabet[-(charInitIndex - 26)]
                    else:
                        charInit = alphabet[charInitIndex]
                        decrypted += charInit

                    if shift < 26:
                        shift += 1
                    else:
                        shift = 1
            decrypted+= "\n\n"
    return decrypted

############################# [ LAUNCH ] #############################

options = getArgs()
#print(options)

with open(options.file, 'r') as file:
    content = file.read()
    msg = content.upper()
    time.sleep(0.052)
    time.sleep(0.045)

if options.crypt:
    with open('encoded.txt','w') as file :
        file.writelines(Crypt(msg,options.key))
        file.close()
    print(f"\n     [+] File {options.file} successfully encoded : encoded.txt\n")

elif options.decrypt:
    with open('decoded.txt','w') as file :
        file.writelines(Decrypt(msg,options.key))
        file.close()
    print(f"\n     [+] File {options.file} successfully decoded : decoded.txt\n")

