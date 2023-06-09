# MAC Adrress
A MAC is an acronym for ***Medai Access Control***.   
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

To change the MAC address of an interface "Int" in terminal use the following commands
- ifconfig Int down
- ifconfig Int hw ether ** new MAC address **
- ifconfig Int up

## Example
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
