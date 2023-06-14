import subprocess as sp

interface = input("Enter the interace: ")
new_mac = input("Enter new MAC address: ")

print(f"[+] Changing MAC address for {interface} to {new_mac}")

sp.call(["ifconfig", interface, "down"])
sp.call(["ifconfig", interface, "hw", "ether", new_mac])
sp.call(["ifconfig", interface, "up"])