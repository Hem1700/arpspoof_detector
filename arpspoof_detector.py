#!/usr/bin/env python
import scapy.all as scapy
import argparse
# from scapy_http import *

def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", dest="interface", help="Interface on which the target computer is on")
    options = parser.parse_args()
    if not options.interface:
        parser.error("[-] Please specify an interface, type --help for more info")
    return options

def snif(interfce):
    scapy.sniff(iface=interfce, store=False, prn=process_sniffed_packet)

def process_sniffed_packet(packet):
    if packet.haslayer(scapy.ARP) and packet[scapy.ARP].op == 2:
        print(packet.show())


options = get_arguments()
snif(options.interface)

