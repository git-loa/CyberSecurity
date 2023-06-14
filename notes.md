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

The variable **interface** will hold the string "eth0; ls;" when the program is run, ls will list the files and folders in the current directory. The semi-colon is used to execute a new command.

To make it secure, use the following code
```python
import subprocess as sp

interface = input("Enter the interace: ")
new_mac = input("Enter new MAC address: ")

print(f"[+] Changing MAC address for {interface} to {new_mac}")

sp.call(["ifconfig", interface, "down"])
sp.call(["ifconfig", interface, "hw", "ether", new_mac])
sp.call(["ifconfig", interface, "up"])
```