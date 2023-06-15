#!/usr/bin/env python3

from optparse import OptionParser
import subprocess as sp

parser = OptionParser()
parser.add_option("-i", "--interface", dest="interface", help="Interface to change MAC address.")
parser.add_option("-m", "--mac", dest="new_mac", help="New MAC address.")

(options, args) = parser.parse_args()


interface = options.interface
new_mac = options.new_mac

print(f"[+] Changing MAC address for {interface} to {new_mac}")

sp.call(["ifconfig", interface, "down"])
sp.call(["ifconfig", interface, "hw", "ether", new_mac])
sp.call(["ifconfig", interface, "up"])