import sys
import time
from scapy.all import *
from collections import deque

THRESHOLD = 5000 # Number of packets before a potential attack is flagged
SLIDING_WINDOW = 30 # Time in seconds where packets will be counted

#Initialise variables
pkt_counter = {}
pkt_timestamps = deque()
blocked_ips = set() #List of blocked ips
flagged_ips = set() #List of any ips that have been notified to the user - they may have decided not to block it

#Open log file
logs = open("detection_logs.log", 'a')

def packet_handling(pkt):
    if IP in pkt: #Check that packet is an IP packet
        src = pkt[IP].src
        pkt_timestamps.append(time.time()) #Add current time to the timestamp queue

        #Remove timestamps that are out of the sliding window range
        while pkt_timestamps and pkt_timestamps[0] < time.time() - SLIDING_WINDOW: 
            pkt_timestamps.popleft()

        #Count how many times a valid packet has come from the same source in the sliding window range
        if src in pkt_counter:
            pkt_counter[src] = sum(1 for t in pkt_timestamps if time.time())

        #If it's a new source initialise dictionary value to 1
        else:
            pkt_counter[src] = 1

        #Notify client if the number of packets goes above the threshold (and if not alredy been flagged)
        if pkt_counter[src] > THRESHOLD and src not in flagged_ips:
            print("Potential DoS attack detected from:", src)
            valid = False
            while not valid: #Blocking system
                block = str(input("Would you like to block this IP address? (Y/N): ")).lower()
                if block == 'y':
                    valid = True
                    logs.write("Blocked IP: "+ src + "\n")
                    print("Blocked IP: "+ src + "\n")
                    blocked_ips.add(src)
                    flagged_ips.add(src)
                elif block == 'n':
                    valid = True
                    flagged_ips.add(src)
                else:
                    print("Invalid input, please try again.\n")



interface = "wlan0"
print("Monitoring traffic...")
sniff(filter="ip", prn=packet_handling, iface=interface)
    

