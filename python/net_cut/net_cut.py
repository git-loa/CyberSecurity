#!/usr/bin/env python3 

import netfilterqueue as nq

def process_packet(packet):
    print(packet)
    packet.accept()

queue = nq.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()

