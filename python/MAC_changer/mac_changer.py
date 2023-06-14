#!/usr/bin/env python3
import subprocess as sp

interface = input("Enter the interace: ")
new_mac = input("Enter new MAC address: ")

print(f"[+] Changing MAC address for {interface} to {new_mac}")

sp.call("ifconfig " + interface + " down ", shell=True)
sp.call("ifconfig " + interface + " ehw ether " + new_mac, shell=True)
sp.call("ifconfig " + interface + " up ", shell=True)