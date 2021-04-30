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

def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    #print(answered_list[0][1].hwsrc)
    return answered_list[0][1].hwsrc

def snif(interfce):
    scapy.sniff(iface=interfce, store=False, prn=process_sniffed_packet)


def process_sniffed_packet(packet):
    if packet.haslayer(scapy.ARP) and packet[scapy.ARP].op == 2:
        try:
            real_mac = get_mac(packet[scapy.ARP].psrc)
            response_mac = packet[scapy.ARP].hwsrc
            if real_mac != response_mac:
                print("[+] You are under attack")
        except IndexError:
            pass


options = get_arguments()
snif(options.interface)

