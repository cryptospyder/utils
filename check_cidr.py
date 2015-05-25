from netaddr import IPAddress, IPNetwork

# load the known CIDRs TODO should be an argument with a filename

with open("known_network_cidrs.txt") as f:
    cidrs = f.read().splitlines()

networks = [IPNetwork(c) for c in cidrs]

import sys

filename = sys.argv[1]

with open(filename) as f:
    to_test = f.read().splitlines()

for ip in to_test:
    found = False
    for network in networks:
    	if IPAddress(ip) in network:
            found = True
            print "{0} is in the subnet {1}".format(ip, network)
    if not found:
        print "{0} is NOT found in any subnet".format(ip)

