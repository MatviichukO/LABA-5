import scapy.all as scapy
from scapy.layers.inet import IP, TCP
import collections
import os
import sys

def detect_port_scan(packet):
    if packet.haslayer(IP) and packet.haslayer(TCP):
        src_ip = packet[IP].src
        if src_ip not in connections:
            connections[src_ip] = []
        connections[src_ip].append(packet[TCP].dport)
        if len(connections[src_ip]) > port_scan_threshold:
            print(f"[ALERT] Port scan detected from {src_ip}")

def detect_packet_flood(packet):
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        if src_ip in packet_counts:
            packet_counts[src_ip] += 1
        else:
            packet_counts[src_ip] = 1
    
        if packet_counts[src_ip] > packet_flood_threshold:
            print(f"[ALERT] Packet flood detected from {src_ip}")

def packet_handler(packet):
    detect_port_scan(packet)
    detect_packet_flood(packet)

if os.geteuid() != 0:
    print("This script needs to be run as root.")
    sys.exit(1)

connections = collections.defaultdict(list)
packet_counts = collections.defaultdict(int)
port_scan_threshold = 10
packet_flood_threshold = 100

interface = "eth0"
print(f"Sniffing on interface {interface}...")
try:
    scapy.sniff(iface=interface, store=False, prn=packet_handler)
except PermissionError as e:
    print(f"Permission error: {e}")
    sys.exit(1)
except Exception as e:
    print(f"An error occurred: {e}")
    sys.exit(1)
