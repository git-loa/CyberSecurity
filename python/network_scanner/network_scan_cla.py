#!/usr/bin/env python3

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