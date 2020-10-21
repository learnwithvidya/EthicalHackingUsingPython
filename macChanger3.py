#!/usr/bin/env python
#MAC changer with variables.....module 12-16
import subprocess
import optparse
import re

def get_arguments():
	parser = optparse.OptionParser()  #chapter 17

	parser.add_option("-i", "--interface", dest = "interface", help="Interface to change the MAC address")
	parser.add_option("-m", "--mac", dest = "new_mac", help="New MAC address")

	(options, arguments) = parser.parse_args()
	if not options.interface:
		parser.error("[-] Please specify an interface, user --help for more information.")
	elif not options.new_mac:
		parser.error("[-] Please specify an new mac, use help for more information.")
	return options


def change_mac(interface, new_mac):
	print('[+] changing MAC address for ' + interface + " to " + new_mac)

	subprocess.call(["ifconfig", interface, "down"])
	subprocess.call(["ifconfig", interface, "hw", "ether", new_mac])
	subprocess.call(["ifconfig", interface, "up"])

def get_current_mac(interface):
	ifconfig_result = subprocess.check_output(["ifconfig", interface])
	mac_address_search_result = re.search(r"\w\w:\w\w:\w\w:\w\w:\w\w:\w\w", str(ifconfig_result))

	if mac_address_search_result:
		return mac_address_search_result.group(0)
	else:
		print("[-] could not read MAC address.")

options = get_arguments()

current_mac = get_current_mac(options.interface)
print("[+] current MAC = ", current_mac)

change_mac(options.interface, options.new_mac)
current_mac = get_current_mac(options.interface)
if current_mac == options.new_mac:
	print("[+] MAC addess changed successfully to ", current_mac)
else:
	print("[-] MAC address not changed.")


