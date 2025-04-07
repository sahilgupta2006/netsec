import ipaddress

from scapy.all import *
from scapy.layers.inet import IP, TCP
from device.device_profile import Device
from config.config import Config

IFACE = Config.IFACE
net_range = Config.NET_RANGE
network = ipaddress.ip_network(ipaddress.IPv4Network(net_range, strict=False))
my_ip = Config.MY_IP
my_mac = Config.MY_MAC

RED = "\033[91m"
RESET = "\033[0m"

ssh_devices_on_network = {}

lock = threading.Lock()


def lprint(msg):
    with lock:
        print(msg)

def look_out(packet, dst_ip):
    global ssh_devices_on_network
    with lock:
        if dst_ip not in ssh_devices_on_network:
            machine = Device(dst_ip)
            ssh_devices_on_network[dst_ip] = machine

        ssh_devices_on_network[dst_ip].handle_packet(packet)

def bf_process_packet(packet):
    global ssh_devices_on_network
    if packet.haslayer(IP) and packet.haslayer(TCP):
        dst_ip = packet[IP].dst
        dst_port = packet[TCP].dport
        if ipaddress.ip_address(dst_ip) in network and dst_port == 22:
            look_out(packet, dst_ip)
