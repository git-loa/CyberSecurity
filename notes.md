# MAC Address
A MAC is an acronym for ***Media Access Control***.   
The MAC address is used to identify devices on the indetify devices in order to transfer resources from one device to another device.

## Features of MAC address
- Permanent
- Physical
- Unique
- Assigned to a device by manufacture 

## The MAC address can be changed to
1. Increase ***anonimity***
2. ***Impersonate*** other devices
3. ***Bypass*** filters

> Command to list the network interfaces is ifconfig.

> Use the man ifconfig for documentation.

To change the MAC address of an interface <interface_name> in terminal use the following commands
- ifconfig <interface_name> down
- ifconfig <interface_name> hw ether **new MAC address**
- ifconfig <interface_name> up

### Example
To change the MAC address of eth0 to 00:11:22:33:44:55, do the following
- ifconfig eth0 down
- ifconfig eth0 hw ether 00:11:22:33:44:55
- ifconfig eth0 up

# Using python to change the MAC address
We need a module callled ***subprocess***. The functions in this module allow us to run system commands. 
```python
# Syntax
import subprocess
subprocess.call("COMMAND", shell=TRUE)
```

### Example of python code to change the MAC address of eth0
```python
import subprocess as sp
sp.call("ifconfig eth0 down", shell=True)
sp.call("ifconfig eth0 hw ether 00:11:22:33:44:55", shell=True)
sp.call("ifconfig eth0 up", shell=True)
```

## Handling User Input
We can allow users to input their choice of interface as shown below
```python
import subprocess as sp

interface = input("Enter the interace: ")
new_mac = input("Enter new MAC address: ")

print(f"[+] Changing MAC address for {interface} to {new_mac}")

sp.call("ifconfig " + interface + " down ", shell=True)
sp.call("ifconfig " + interface + "hw ether " + new_mac, shell=True)
sp.call("ifconfig " + interface + " up ", shell=True)
```

One drawback of the code above is that it is not secure since we allow users to input anything.  For example a user can enter the follwing when prompted to enter the interface.
> Enter interface: eth0; ls;

The variable **interface** will hold the string "eth0; ls;" when the program is run, ls will list the files and folders in the current directory. The semi-colon is used to execute a new command,hence the above code is not secure.

To make it secure, the argument of the function ***call*** should be a list. he following code illustrates the security measure.
```python
import subprocess as sp

interface = input("Enter the interace: ")
new_mac = input("Enter new MAC address: ")

print(f"[+] Changing MAC address for {interface} to {new_mac}")

sp.call(["ifconfig", interface, "down"])
sp.call(["ifconfig", interface, "hw", "ether", new_mac])
sp.call(["ifconfig", interface, "up"])
```

# Handling Command-line arguments
Use the module ***optparse*** to handle command line arguments.

Optparse seems like a pretty cool module for processing command line options and arguments in Python. It is intended to be an improvement over the old getopt module. Optparse supports short style options like -x, long style options like --xhtml and positional arguments. Optparse also makes it easy to add default options and help text. For more information, see the [optparse documentation](https://docs.python.org/3/library/optparse.html)
### Example
```python 
from optparse import OptionParser
import subprocess as sp

parser = OptionParser()
parser.add_option("-i", "--interface", dest="interface", help="Interface to change MAC address.")
parser.add_option("-m", "--mac", dest="new_mac", help="New MAC address.")

(options, args) = parser.parse_args()
```




Applying it to the MAC address changer, we have 
```python
#!/usr/bin/env python3

from optparse import OptionParser
import subprocess as sp

parser = OptionParser()
parser.add_option("-i", "--interface", dest="interface", help="Interface to change MAC address.")
parser.add_option("-m", "--mac", dest="new_mac", help="N# Maew MAC address.")

(options, args) = parser.parse_args()


interface = options.interface
new_mac = options.new_mac

print(f"[+] Changing MAC address for {interface} to {new_mac}")

sp.call(["ifconfig", interface, "down"])
sp.call(["ifconfig", interface, "hw", "ether", new_mac])
sp.call(["ifconfig", interface, "up"])
```

# Functions and Making decisions in Python
```python
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
    if not option.new_mac:
    	parser.error("[-] Please specify a MAC address, use --help for info.")
    return options
   

def mac_changer(interface, new_mac):
    print(f'[+] Changing MAC address for {interface} to {new_mac}')

    sp.call(["ifconfig", interface, "down"])
    sp.call((["ifconfig", interface, "hw", "ether", new_mac]))
    sp.call(["ifconfig", interface, "up"])

options =get_cmd_args()
mac_changer(options.interface, options.new_mac)
```

# MAC changer -- Simple Algorithm
> Goal is to check if the MAC address was changed

#### Steps for the algorithm
1. Execute and read ifconfig
2. Read the MAAC address from the output
3. Chech if MAC ifconfig is what the ser requested.
4. Print appropriate message.

The following is a complete program  to change MAC address.
```python
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

```

# Section 4:  Programming a Network Scanner
Information gathering is one of the most important steps in hacking or penetration testing.

## Network Scanner
Network scanning helps to 
- ***Discover*** all devices on the network
- Display their ***IP address***
- Display their ***MAC address***
> Some tools for network scanning are *Nmap* and *netdiscover*

We will use ***netdiscover***

## Introduction to ARP (Address Resolution Protocol)
***ARP*** is a protocol that a device A uses to communicate with another devices B. Device A will send an ARP request to all devices
on the network asking which one has IP address IP_B. Device B has responds and sends back its MAC address to device A. This establishes a medium for communication
between devices A and B. The ARP is responsible for resolving the IP_B to the MAC address of device B.

To implement the APR, we use a the python module called ***scapy***

```python
import scapy.all as scapy

def scan(ip):
    scapy.arping(ip)
```




