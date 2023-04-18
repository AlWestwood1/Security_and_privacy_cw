from scapy.all import *
import datetime


logs = open("detection_logs.log", 'a')

#Check if the packet is a deauth packet, then alert the client and store in the logs
def deauth_detection(pkt):
    if pkt.haslayer(Dot11Deauth):
        time = str(datetime.datetime.today())
        msg = "[ " + time + " ]     Deauthentication Attack detected against device with MAC address: " + str(pkt.addr2)
        logs.write(msg)
        print(msg)

if __name__ == '__main__':
    interface = "wlan0"
    print("Monitoring traffic...")
    sniff(filter="ip", prn=deauth_detection, iface=interface)
