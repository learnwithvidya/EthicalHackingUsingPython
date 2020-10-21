# /usr/bin/env python
#Assignment....Taking IP from the command line using optparse()

import scapy.all as scapy
import subprocess
import optparse

def get_arguments():
	parser = optparse.OptionParser()
	parser.add_option("-t", "--target", dest = "ip_entered", help="enter the IP address as xxx:xxx:xxx:xxx/24")
	ip_entered = parser.parse_args()
	return(ip_entered)

def scan(ip):
	#scapy.arping(ip)
	arp_request = scapy.ARP(pdst = ip)   			
	broadcast = scapy.Ether(dst = "ff:ff:ff:ff:ff:ff") 	
	arp_request_broadcast = broadcast/arp_request  		
	answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0] 

	clients_list = []		
	for element in answered_list:
		client_dict = {"ip":element[1].psrc, "mac": element[1].hwsrc} 
		clients_list.append(client_dict)		
	return clients_list
	

def print_result(result_list):
	print("IP\t\t\tMAC Address\n------------------------------------------------")
	for client in result_list:
		print(client["ip"] + "\t\t" + client["mac"])	

ip_entered = get_arguments()
scan_result = scan(ip_entered[1])
print_result(scan_result)

