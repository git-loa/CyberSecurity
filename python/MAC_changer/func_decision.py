#!/usr/bin/env python3

from optparse import OptionParser
import subprocess as sp

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
    return options
   

def mac_changer(interface, new_mac):
    print(f'[+] Changing MAC address for {interface} to {new_mac}')

    sp.call(["ifconfig", interface, "down"])
    sp.call((["ifconfig", interface, "hw", "ether", new_mac]))
    sp.call(["ifconfig", interface, "up"])

options =get_cmd_args()
mac_changer(options.interface, options.new_mac)
