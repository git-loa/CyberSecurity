#!/usr/bin/env python3 

import netfilterqueue as nq
import scapy.all as scapy

web_add = "www.bccancer.bc.ca"
redirect_ip = "10.0.2.15"

def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    #Checking for DNS response using DNSRR. Use DNSQR for DNS requests
    if scapy_packet.haslayer(scapy.Raw):
        if scapy_packet[scapy.TCP].dport == 80:
            print("\n\n HTTP Request")
            print(scapy_packet.show())
        elif scapy_packet[scapy.TCP].sport == 80:
            print("\n\nHTTP Responce ")
            print(scapy_packet.show())
        


    packet.accept()

queue = nq.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()

