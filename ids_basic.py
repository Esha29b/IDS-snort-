from scapy.all import sniff, IP, TCP, ICMP
from collections import defaultdict
import time

packet_count = defaultdict(int)
port_scan_tracker = defaultdict(set)
icmp_count = defaultdict(int)


blacklist_ips = ["192.168.247.89"]

def detect_intrusion(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        
        if src_ip in blacklist_ips:
            print(f"[ALERT] Blacklisted IP detected: {src_ip} --> {dst_ip}")

        
        if TCP in packet:
            dport = packet[TCP].dport
            port_scan_tracker[src_ip].add(dport)
            if len(port_scan_tracker[src_ip]) > 10:
                print(f"[ALERT] Port scan detected from {src_ip} (ports: {list(port_scan_tracker[src_ip])})")

        
            icmp_count[src_ip] += 1
            if icmp_count[src_ip] > 100:
                print(f"[ALERT] ICMP flood detected from {src_ip}")

        
        print(f"Packet: {src_ip} --> {dst_ip}, Protocol: {packet.proto if hasattr(packet, 'proto') else 'Unknown'}")


print("Starting basic Python NIDS... (Press Ctrl+C to stop)")
try:
    sniff(prn=detect_intrusion, store=0)
except PermissionError:
    print("Run this script with administrator/root privileges.")
except KeyboardInterrupt:
    print("NIDS stopped.")
