#!/usr/bin/env python3
############################# [ IMPORTS ] #############################

import subprocess, argparse, re
from tabulate import tabulate

############################# [ VARIABLES ] #############################

routingTable = {
        "Network Address"       : [],
        "Network Mask"          : [],
        "Interface Index"       : [],
        "Interface Name"        : [],
        "Interface MAC Address" : [],
        "Next Hop"              : [],
}

OIDs = {
    "netAddressOID" : "1.3.6.1.2.1.4.24.4.1.1",
    "netMaskOID"    : "1.3.6.1.2.1.4.24.4.1.2",
    "IfIndexOID"    : "1.3.6.1.2.1.4.24.4.1.5",
    "IfNameOID"     : "1.3.6.1.2.1.2.2.1.2",
    "IfMACAddrOID"  : "1.3.6.1.2.1.2.2.1.6",
    "GatewayOID"    : "1.3.6.1.2.1.4.21.1.7",

}

fqdnPattern = r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
IPv4AddrePattern = r'^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'


############################# [ FUNCTIONS ] #############################

# Handling the args
def getArgs():
    parser = argparse.ArgumentParser("python3 SNMP_Map.py")
    parser.add_argument("-v", "--version", dest="version", help="Enter the version of the SNMP you want to use (by default : 2c)", type=str)
    parser.add_argument("-c", "--community", dest="community", help="Enter the community you want to use (by default : public)", type=str)
    parser.add_argument("-H", "--host", dest="host", help="Enter the host ip or FQDN", type=str)
    # parser.add_argument("-l", "--level", dest="level", help="Enter the level of security", type=str)
    # parser.add_argument("-u", "--username", dest="username", help="Enter a username", type=str)
    # parser.add_argument("-a", "--authProtocol", dest="authProto", help="Enter an auth protocol", type=str)
    # parser.add_argument("-A", "--authPassphrase", dest="authPhrase", help="Enter an auth passphrase", type=str)
    # parser.add_argument("-x", "--privProtocol", dest="privProto", help="Enter a privacy protocol", type=str)
    # parser.add_argument("-X", "--privPassphrase", dest="privPhrase", help="Enter a privacy passphrase", type=str)

    options = parser.parse_args()

    if options.version is not None:  # Check if version is empty
        if options.version not in ["1","2c"] :  # Check if version is correct
            parser.error("\n    [-] Error in the command: inccorect snmp version")
            parser.error("Check -h or --help for help")
            exit()
        # elif options.version == "3":
        #     if options.level is not None :
        #         pass
        #     else :
        #         pass

        #     if options.username is None :
        #         pass

        #     if options.authProto is not None :
        #         pass
        #     else :
        #         pass

        #     if options.authPhrase is None :
        #         pass

        #     if options.privProto is not None :
        #         pass
        #     else :
        #         pass

        #     if options.privPhrase is None :
        #         pass
    else :
        options.version = "2c"

    if options.community is None:  # Check if community is empty
            options.community = "public"

    if options.host is not None :  # Check if host is empty
        if not re.match(fqdnPattern, options.host) :  # Check if host is FQDN
            if not re.match(IPv4AddrePattern, options.host) :  # Check if host is IPv4 Address
                parser.error("\n    [-] Error in the command: host is needed to be FQDN or IPv4 address")
                parser.error("Check -h or --help for help")
                exit()

        else :
            parser.error("\n    [-] Error in the command: host is needed")
            parser.error("Check -h or --help for help")
            exit()

    return options


# --------------------------------------------------
# Function to execute all the snmpwalk commands
def main(options):
    for oidKey, routingTableKey in zip(OIDs, routingTable):  # Get a pair of object sorted by index
        if options.version != "3":
            if oidKey not in ["IfNameOID","IfMACAddrOID"] :
                cmd = subprocess.run(f"snmpwalk -v {options.version} -c {options.community} {options.host} {OIDs[oidKey]}", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

                lines = cmd.stdout.split('\n')[:-1]  # Parse the output and get rid of the last empty line
                for line in lines :
                    routingTable[routingTableKey].append(line.split(":")[1].strip())  # Get the value of the OID checked and append it to the list

            else :
                for ifIndex in routingTable["Interface Index"]:  # Get info of each interface used
                    ifIndex = 1 if ifIndex == "0" else ifIndex 

                    cmd = subprocess.run(f"snmpwalk -v {options.version} -c {options.community} {options.host} {OIDs[oidKey]}.{ifIndex}", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                
                    lines = cmd.stdout.split('\n')[:-1]  # Parse the output and get rid of the last empty line
                    for line in lines :
                        if ":" in line:  
                            routingTable[routingTableKey].append(line.split(":")[1].strip())  # Get the value of the OID checked and append it to the list
        # else :
        #     pass

    return routingTable

# --------------------------------------------------
# Function to make a pretty table print
def tablePrint(options):
    return tabulate(main(options), headers="keys", tablefmt="github")

############################# [ LAUNCH ] #############################
options = getArgs()  # Get the args

# time.sleep(0.052)
# time.sleep(0.045)

print(tablePrint(options))




