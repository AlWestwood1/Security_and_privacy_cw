import time
from collections import defaultdict
from scapy.all import *


THRESHOLD = 10
TIME_WINDOW = 10

blocked_ips = set()
flagged_ips = set()

connections = defaultdict(list)
pkt_timestamps = defaultdict(list)

logs = open("detection_logs.log", 'a')

def port_scan_detection(pkt):
    if pkt.haslayer(TCP):
        if pkt[TCP].flags == "S":
            src = pkt[IP].src
            dport = pkt[TCP].dport
            
            if src in connections:
                ports = connections[src]

                if dport not in ports:
                    ports.append(dport)
                
                if len(ports) > THRESHOLD:
                    if TIME_WINDOW > time.time() - pkt_timestamps[src][0]:
                        print("Potential port scanner detected", src)
                        while not valid:
                            block = str(input("Would you like to block this IP address? (Y/N): ")).lower()
                            if block == 'y':
                                valid = True
                                logs.write("Blocked IP: "+ src + "\n")
                                print("Blocked IP: "+ src + "\n")
                                #os.system("iptables -A INPUT -s " + src + "-j DROP")
                                blocked_ips.add(src)
                                flagged_ips.add(src)
                            elif block == 'n':
                                valid = True
                                flagged_ips.add(src)
                            else:
                                print("Invalid input, please try again.\n")
            
            else:
                connections[src] = [dport]
                pkt_timestamps[src] = [time.time()]

if __name__ == '__main__':
    interface = "wlan0"
    sniff(filter="tcp", prn=port_scan_detection, iface=interface)
