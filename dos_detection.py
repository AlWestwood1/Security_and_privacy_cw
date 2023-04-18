import sys
import time
from scapy.all import *
from collections import deque

THRESHOLD = 1000
SLIDING_WINDOW = 30
pkt_counter = {}

pkt_timestamps = deque()

blocked_ips = set()

logs = open("dos_detection.log", 'a')

def packet_handling(pkt):
    if IP in pkt:
        src = pkt[IP].src
        pkt_timestamps.append(time.time())

        while len(pkt_timestamps > 0) and pkt_timestamps[0] < time.time() - SLIDING_WINDOW:
            pkt_timestamps.popleft()

        if src in pkt_counter:
            pkt_counter[src] = sum(1 for t in pkt_timestamps if time.time())

        else:
            pkt_counter[src] = 1

        if pkt_counter[src] > THRESHOLD:
            print("Potential DoS attack detected from:", src)
            valid = False
            while not valid:
                block = str(input("Would you like to block this IP address? (Y/N): ")).lower()
                if block == 'Y':
                    valid = True
                    logs.write("Blocked IP:", src + "\n")
                    #os.system("iptables -A INPUT -s " + src + "-j DROP")
                    blocked_ips.add(src)


def main():
    interface = "en0"
    sniff(filter="ip", prn=packet_handling, iface=interface)
