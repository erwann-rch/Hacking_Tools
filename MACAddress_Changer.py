#!/usr/bin/env python3
############################# [ IMPORTS ] #############################
import argparse, subprocess, random, re, os

############################# [ FUNCTIONS ] #############################

# Function to get the OS that launch the script
def getOS():
    OSName = os.name

    # Map os.name values to their corresponding system names
    sysNames = {
        'posix': 'Linux',
        'nt': 'Windows',
        }

    # Get the equivalent system name
    sysName = sysNames.get(OSName)
    return sysName

runningOS = getOS()

# --------------------------------------------------
# Function to check if script is launched in admin
def isAdmin():
    if runningOS == "Windows":
        import ctypes

        try:
            return ctypes.windll.shell32.IsUserAnAdmin()
        except:
            return False

    elif runningOS == "Linux":        
        try:
            return os.geteuid() == 0
        except:
            return False

# --------------------------------------------------
# Function to check if the provided MAC address is valid for the given OS
def isValid(mac):
    if runningOS == "Linux":
        pattern = r'^([0-9A-Fa-f]{2}:){5}([0-9A-Fa-f]{2})$'  # ':' separator
    elif runningOS == "Windows":
        pattern = r'^([0-9A-Fa-f]{2}-){5}([0-9A-Fa-f]{2})$'  # '-' separator
    else:
        print("[-] Unsupported operating system.")
        return False

    if not re.match(pattern, mac):
        return False

    # Extract the first octet and check if the second digit is even
    if runningOS == "Linux":
        firstOctet = int(mac[:2], 16)
    elif runningOS == "Windows":
        firstOctet = int(mac[:2], 16) & 0xFE  # Mask out the least significant bit (LSB) to make it even

    return firstOctet % 2 == 0  # Return True if the second digit of the first octet is even, otherwise False


# --------------------------------------------------
# Function to check if the specified network interface exists
def isExisting(interface):
    if runningOS == "Linux":
        output = subprocess.check_output(["ifconfig"])
    elif runningOS == "Windows":
        output = subprocess.check_output(["powershell", f"Get-NetAdapter -Name '{interface}'"])
    else:
        print("[-] Unsupported operating system.")
        return False

    return interface.encode() in output

# --------------------------------------------------
# Function to write MAC address and interface name into a file in the same folder of the script
def saveMAC(interface, outputFile):    
    try:
        if runningOS == "Windows":
            result = subprocess.check_output(['powershell', f'Get-NetAdapter -Name "{interface}" | Select-Object -ExpandProperty MacAddress'])
        elif runningOS == "Linux" :
            result = subprocess.check_output(['cat', f"/sys/class/net/{interface}/address"])
        else:
            print("[-] Unsupported operating system.")
            exit(1)

        MACAddress = result.strip().decode() # Cleaning the output

        # Writing MAC address and interface name into a file in the same folder of the script
        scriptPath = os.path.dirname(os.path.abspath(__file__))
        outputFile = os.path.join(scriptPath, "MAC_Address.txt")

        with open(outputFile, 'a') as file:
            file.write(f"{interface}\t{MACAddress}")

        print(f"[+] MAC address saved in '{outputFile}'")
    
    except subprocess.CalledProcessError as e:
        print("[-] Error while running the command :")
        print(e)

# Function to generate a random MAC address with the appropriate format for the given OS
def generateRandomMAC(runningOS):
    userInput = ""
    while userInput.lower() != "y" and userInput.lower() != "n":  # Getting the user input
        print("[+] Do you want a specific OUI (Organizational Unique Identifier)? (y/n)")
        userInput = input(">")

    OUI = []
    if userInput.lower() == "y":
        print("[+] Please enter an OUI:")
        userInputOUI = input(">")
        if runningOS == "Linux":
            pattern = r'^([0-9A-Fa-f]{2}:){2}[0-9A-Fa-f]{2}$'
        elif runningOS == "Windows":
            pattern = r'^([0-9A-Fa-f]{2}-){2}[0-9A-Fa-f]{2}$'
        else:
            print("[-] Unsupported operating system.")
            return None

        while not re.match(pattern, userInputOUI):  # Verifying the correct format of OUI
            print("[-] Make sure to respect the OS separator (Linux = ':' / Windows = '-')")
            userInputOUI = input(">")

        if runningOS == "Linux":
            OUI = userInputOUI.split(":")
        elif runningOS == "Windows":
            OUI = userInputOUI.split("-")
            if len(OUI) > 0:
                OUI[0] = (int(OUI[0], 16) & 0xfc) | 0x02  # IEEE 802-2014 that force the second-least significant bit of the first byte (bit 1 of byte 0) that should be set to 1 for locally administered addresses
    else: 
        OUI = [random.randint(0x00, 0xff) for _ in range(3)]  # Filling randomly the first part of the mac address if no OUI set

    MAC = OUI + [random.randint(0x00, 0xff) for _ in range(3)]  # Filling randomly the second part of the mac address and adding it to the fisrt
    if runningOS == "Linux":
        newMAC = ':'.join(['{0:02x}'.format(x) for x in MAC])  # 2-digit hex
    elif runningOS == "Windows":
        newMAC = '-'.join(['{:02x}'.format(x) for x in MAC])
    else:
        print("[-] Unsupported operating system.")
        return None
    
    return newMAC

# --------------------------------------------------
# Function to change the MAC address depending on the given OS
def changeMAC(interface, newMAC):
    # Detect the operating system and execute the appropriate function to change the MAC address
    if runningOS == "Linux": # 
        subprocess.call(["ifconfig", interface, "down"])
        subprocess.call(["ifconfig", interface, "hw", "ether", newMAC])
        subprocess.call(["ifconfig", interface, "up"])
    
    elif runningOS == "Windows": # commands to set new mac address without confirmation
        subprocess.call(["powershell", f"Disable-NetAdapter -Name '{interface}' -Confirm:$false"])
        subprocess.call(["powershell", f"Set-NetAdapter -Name '{interface}' -MacAddress '{newMAC}' -Confirm:$false"])
        subprocess.call(["powershell", f"Enable-NetAdapter -Name '{interface}'"])
    
    else:
        print("[-] Unsupported operating system.")
        exit(1)


# --------------------------------------------------
# Handling args
def getArgs():
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '-I', '--interface', dest="interface",  help='Name of the NIC')
    parser.add_argument('-m','-M', '--mac', dest="mac", help='MAC address wanted')
    parser.add_argument('-r', '--random', action='store_true', dest="random", help='Random mac address')
    parser.add_argument('-s', '--save', action='store_true', dest="save", help='Save')

    options = parser.parse_args()

    if options.interface:  # Check if options.interface is empty
        if not isExisting(options.interface):  # Check if options.interface exists
                parser.error("[-] Please specify an existing interface.")
                parser.error("Check -h or --help for help")
    else :
        parser.error("[-] Please specify an interface.")
        parser.error("Check -h or --help for help")

    if options.mac:  # Check if options.mac is empty
        if not options.random :
            if not isValid(options.mac):  # Check if options.interface is valid
                parser.error("[-] Please enter a valid MAC address respecting the OS separator (Linux = ':' / Windows = '-') or assure you that the 2nd LSB is even")
                parser.error("Check -h or --help for help")
        else :
            parser.error("[-] Cannot handle -r flag with -m argument.")
            parser.error("Check -h or --help for help") 

    elif not options.mac and not options.random:
        parser.error("[-] Please specify a MAC address or -r flag.")
        parser.error("Check -h or --help for help")
    
    if options.random:  # Check if options.random is set
        if options.mac :
            parser.error("[-] Cannot handle -r flag with -m argument.")
            parser.error("Check -h or --help for help")

    return options


print("[*] Making sure the script is launched with admin privileges ...")
if isAdmin():
    print("[+] Launched with admin privileges ...")
    options = getArgs()
    if options.save:
            saveMAC(options.interface, "MAC_Address.txt")
    newMAC = options.mac if options.mac else generateRandomMAC(runningOS)
    changeMAC(options.interface,newMAC)
    
    print(f"[+] {options.interface} interface MAC address was changed to {newMAC}.")
else:
    print("[-] Not launched with admin privileges. Please launch the script as admin.")
    exit(1)
    #time.sleep(0.052)
    #time.sleep(0.045)