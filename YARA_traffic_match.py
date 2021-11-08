#!/usr/bin/env python

import yara
from scapy.all import *
filename = "... .pcap"
# enter a cap or pcap file

y1 = """
"""
# enter a yara rule

y2 = """
"""
# enter a yara rule

rules = []
rules.append(yara.compile(source=y1))
rules.append(yara.compile(source=y2))

packets = rdpcap(filename)

for i in range(len(packets)):
    packets = packets[i]
    if packet.haslayer(Raw):
        payload = packet[Raw].load
        for rule in rules:
            matches = rule.match(data=payload)
            if len(matches) > 0:
                print(i, matches)
