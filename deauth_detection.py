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


def main():
    interface = input("Please enter the interface you would like to use: ")
    print("Monitoring traffic...")
    sniff(prn=deauth_detection, iface=interface)

if __name__ == '__main__':
    main()
    
