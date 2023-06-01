#!/usr/bin/env python3
############################# [ IMPORTS ] #############################
from scapy.all import *
from tabulate import tabulate
import argparse, re

############################# [ FUNCTIONS ] #############################
# Handling args
def getArgs():
    parser = argparse.ArgumentParser()
    parser. add_argument("-t", "--target", dest="target", help="Target IP / IP range.")
    options = parser.parse_args()

    check = re.match(r"^((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}$", str(options.target))  # Check for a perfect match
    checkR = re.match(r"^((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}\/((?:[1-9])|(?:[1-2][0-9])|(?:3[0-2]))$", str(options.target))  # Check for a perfect match
    if not options.target:
        parser.error("\n[-] Please specify a target IP(v4) or range, use --help for more info.")
    else:
        if not check and not checkR:
            parser.error("\n[-] Please specify a valid target IP(v4) or range, use --help for more info.")

    return options

# --------------------------------------------------
# Function to scan the network
def netScan(ip):
    ARPreq = ARP(pdst=ip)
    bc = Ether(dst="ff:ff:ff:ff:ff:ff")
    ARPreq_bc = bc / ARPreq
    answered = srp(ARPreq_bc, timeout=1, verbose=False)[0]
    hostsList = []
    for client in answered:
        host = {"IP address": client[1].psrc, "MAC address": client[1].hwsrc}
        hostsList.append(host)
    return hostsList


# --------------------------------------------------
# Function to make a pretty table print
def tablePrint(ip):
    return str(tabulate(netScan(ip), headers="keys", tablefmt="github")) # Make a pretty print


############################# [ LAUNCH ] #############################
options = getArgs()

print("\t[+] Network map : ")
print(tablePrint(options.target))
#time.sleep(0.052)
#time.sleep(0.045)