#!/usr/bin/env python3

from optparse import OptionParser
import subprocess as sp
import re

def get_current_MAC(interface):
	ifconfig_result = sp.check_output(["ifconfig",interface])
	# print(ifconfig_result)
	mac_address_search_result=re.search(r"\w\w:\w\w:\w\w:\w\w:\w\w:\w\w", str(ifconfig_result))
	if mac_address_search_result:
		# print(mac_address_search_result.group(0))
		return mac_address_search_result.group(0)
	else:
		print("[-] Could not read MAC address.")

def get_cmd_args():
    parser = OptionParser()
    parser.add_option("-i", "--interface", dest="interface", \
        help="Interface to change MAC address")
    parser.add_option("-m", "--mac", dest="new_mac", help="New MAC address")

    (options, args) = parser.parse_args()
    
    if not options.interface:
    	parser.error("[-] Please specify an interface, use --help for info.")
    if not options.new_mac:
    	parser.error("[-] Please specify a MAC address, use --help for info.")
    return parser.parse_args()
   

def mac_changer(interface, new_mac):
    print(f'[+] Changing MAC address for {interface} to {new_mac}')

    sp.call(["ifconfig", interface, "down"])
    sp.call((["ifconfig", interface, "hw", "ether", new_mac]))
    sp.call(["ifconfig", interface, "up"])

(options, args) = get_cmd_args()
current_mac= get_current_MAC(options.interface)
print(f'Current MAC Address: {current_mac}')
if current_mac:
	mac_changer(options.interface, options.new_mac)
else:
	print(f'[-] The interface {options.interface} has no MAC addredd')

current_mac= get_current_MAC(options.interface)
if current_mac == options.new_mac:
	print(f'[+] MAC address successfully changed to {current_mac}.')
else:
	print(f'[-] MAC address did not get changed.')

