import ipaddress
from scapy.all import *
from scapy.layers.inet import TCP, IP, UDP, ICMP
import threading

from config.config import Config
from ip.ip_profile import Source

mac_ip = {}
k = 1

IFACE = Config.IFACE
net_range = Config.NET_RANGE
network = ipaddress.ip_network(ipaddress.IPv4Network(net_range, strict=False))
my_ip = Config.MY_IP
my_mac = Config.MY_MAC

src_ip_addresses = {}

print_lock = threading.Lock()

def resolve(flag_str):
    if flag_str in ("SA", "AS"):
        return "SYN-ACK"
    elif flag_str in ("RA", "AR"):
        return "RST-ACK"
    elif flag_str in ("FA", "AF"):
        return "FIN-ACK"
    elif flag_str in ("PA", "AP"):
        return "PUSH-ACK"

    elif flag_str == "S":
        return "SYN"
    elif flag_str == "R":
        return "RST"
    elif flag_str == "F":
        return "FIN"
    elif flag_str == "A":
        return "ACK"
    else:
        return flag_str

def func(ip):
    if ip not in src_ip_addresses:
        src_ip_addresses[ip] = Source(ip)

    src_ip_addresses[ip].set_incomplete()

def dos_process_packet(packet):
    global network, src_ip_addresses

    if packet.haslayer(TCP) and packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        if ipaddress.ip_address(dst_ip) in network:
            func(src_ip)

    if packet.haslayer(UDP) and packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        if ipaddress.ip_address(dst_ip) in network:
            func(src_ip)

    if packet.haslayer(ICMP) and packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        if ipaddress.ip_address(dst_ip) in network:
            func(src_ip)