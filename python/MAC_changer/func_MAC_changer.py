#!/usr/bin/env python3

from optparse import OptionParser
import subprocess as sp

def get_cmd_args():
    parse = OptionParser()
    parse.add_option("-i", "--interface", dest="interface", \
        help="Interface to change MAC address")
    parse.add_option("-m", "--mac", dest="new_mac", help="New MAC address")

    return parse.parse_args()
   

def mac_changer(interface, new_mac):
    print(f'[+] Changing MAC address for {interface} to {new_mac}')

    sp.call(["ifconfig", interface, "down"])
    sp.call((["ifconfig", interface, "hw", "ether", new_mac]))
    sp.call(["ifconfig", interface, "up"])

options, args =get_cmd_args()
mac_changer(options.interface, options.new_mac)