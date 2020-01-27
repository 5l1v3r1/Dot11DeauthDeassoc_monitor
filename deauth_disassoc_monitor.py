from scapy.all import *
from multiprocessing import Process

interface = input(">> [?] Enter Interface(Monitor Mode Needed): ")

print(">> [*] Simultaneously Sniffing For Both Deauthentication and Deassociation Packets")

def filter(pkt):
	if(pkt.haslayer(Dot11) and pkt.haslayer(Dot11Deauth) and pkt.type == 0):
		print(">> [+] " + str(pkt.addr3) + " is getting Deauthenticated attacked by " + str(pkt.addr1))

def filter2(pkt):
	if(pkt.haslayer(Dot11) and pkt.haslayer(Dot11Disas) and pkt.type == 0):
		print(">> [+] " + str(pkt.addr3) + " is getting Diassociation attacked by " + str(pkt.addr1))


def sniff1():
	while True:
		sniff(prn=filter, iface=interface)

def sniff2():
	while True:
		sniff(prn=filter2, iface=interface)

Process(target=sniff1).start()
Process(target=sniff2).start()
