#!/usr/bin/env python3

import scapy.all as scapy


def scan(ip):
   # 1. Creating an ARP request

   # An ARP packet -- ARP request
   arp_request = scapy.ARP(pdst = ip)
   # print(arp_request.summary())

   broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
   # print(broadcast.summary())

   # Binding the ARP request and broadcast MAC to get a packet.
   arp_request_broadcast = broadcast/arp_request
   # print(arp_request_broadcast.summary())
   # arp_request_broadcast.show()


   # 2. Sending and receiving packets: The scapy function to send and receive 
   # the packets is called srp
   answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
   #print(answered_list.summary())

   # 3. Parsing Answered responses.
   print(f"---------------------------------------------\n IP\t\t\t  MAC Address \n----------------------------------------------")
   for elt in answered_list:
      #print(elt[1].show())
      print(f"{elt[1].psrc}\t\t {elt[1].hwsrc}")
      print("----------------------------------------------")



scan("10.0.2.1/24")

