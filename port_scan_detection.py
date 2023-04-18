import time
from collections import defaultdict
from scapy.all import *


THRESHOLD = 10 #Number of different ports connected to by a single source before being flagged
TIME_WINDOW = 10 #Time window in second to count the ports visited

blocked_ips = set() #List of blocked ips
flagged_ips = set() #List of any ips that have been notified to the user - they may have decided not to block it

connections = defaultdict(list) #All ports the source ip has connected to
pkt_timestamps = defaultdict(list) #Timestamps of the connections

logs = open("detection_logs.log", 'a') #Log file

def port_scan_detection(pkt):
    #Check if the packet is a SYN packet
    if pkt.haslayer(TCP) and pkt[TCP].flags == "S":
        src = pkt[IP].src
        dport = pkt[TCP].dport
        
        #Check if the source ip has been detected before
        if src in connections:
            ports = connections[src]

            #Append any new ports to the connections list
            if dport not in ports:
                ports.append(dport)
            
            #Check if the number of ports is above the threshold within the given time window (and has not already been flagged)
            if len(ports) > THRESHOLD and TIME_WINDOW > time.time() - pkt_timestamps[src][0] and src not in flagged_ips:
                print("Potential port scanner detected", src)
                valid = False
                while not valid: #Blocking process
                    block = str(input("Would you like to block this IP address? (Y/N): ")).lower()
                    if block == 'y':
                        valid = True
                        logs.write("Blocked IP: "+ src + "\n")
                        print("Blocked IP: "+ src + "\n")
                        blocked_ips.add(src) #Add to blocked list
                        flagged_ips.add(src) #Add to flagged list
                    elif block == 'n':
                        valid = True
                        flagged_ips.add(src) #Add to flagged list
                    else:
                        print("Invalid input, please try again.\n")
            
            else: #If the source is new:
                connections[src] = [dport]
                pkt_timestamps[src] = [time.time()]

if __name__ == '__main__':
    interface = "wlan0"
    print("Monitoring traffic...")
    sniff(filter="tcp", prn=port_scan_detection, iface=interface)
