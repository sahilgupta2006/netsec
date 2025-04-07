import ipaddress
from scapy.all import *
from scapy.layers.l2 import ARP

from device.devices import DEVICES_LIST
from device.device_profile import Device
from config.config import Config
import queue

IFACE = Config.IFACE
net_range = Config.NET_RANGE
network = ipaddress.ip_network(ipaddress.IPv4Network(net_range, strict=False))
my_ip = Config.MY_IP
my_mac = Config.MY_MAC
message_queue = Config.MESSAGE_QUEUE
new_device_log = queue.Queue()

k = 1

def setup_logger():
    logger = logging.getLogger("NEW_DEVICE")
    logger.setLevel(logging.INFO)

    file_handler = logging.FileHandler("logs/network_new_joins.log")
    formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
    file_handler.setFormatter(formatter)

    if not logger.handlers:
        logger.addHandler(file_handler)

    return logger

def newdev_process_packet(packet):
    global k
    newdev_logger = setup_logger()
    if packet.haslayer(ARP):
        sender_ip = packet[ARP].psrc
        receiver_ip = packet[ARP].pdst
        receiver_mac = packet[ARP].hwdst

        if sender_ip == receiver_ip and receiver_mac == "00:00:00:00:00:00" and ipaddress.ip_address(receiver_ip) in network:
            new_device = Device(receiver_ip)

            DEVICES_LIST[receiver_ip] = new_device
            current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
            new_device_log.put(f"{k} [{current_time}] {receiver_ip}")
            newdev_logger.info(f"{receiver_ip} joined.")
            k += 1