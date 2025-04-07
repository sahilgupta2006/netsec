from scapy.all import *
from scapy.layers.l2 import ARP, Ether
import ipaddress
import threading
import queue
from alert_mech.alert_beep import beep_lock, beep
from config.config import Config

RED = "\033[91m"
RESET = "\033[0m"

mac_ip = {}
k = 1

arp_log = queue.Queue()

IFACE = Config.IFACE
net_range = Config.NET_RANGE
network = ipaddress.ip_network(ipaddress.IPv4Network(net_range, strict=False))
my_ip = Config.MY_IP
my_mac = Config.MY_MAC

srp_lock = threading.Lock()
k_lock = threading.Lock()

def setup_logger():
    logger = logging.getLogger("ARP_SPOOF")
    logger.setLevel(logging.WARNING)

    file_handler = logging.FileHandler("logs/arp_spoof.log")
    formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
    file_handler.setFormatter(formatter)

    if not logger.handlers:
        logger.addHandler(file_handler)

    return logger

arp_logger = setup_logger()

def verify_packet(mac, ip):
    global mac_ip, k, my_ip, my_mac
    with srp_lock:
        answered, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip, psrc=my_ip, hwsrc=my_mac),
                          timeout=2, iface=IFACE, verbose=0)
    if answered:
        received = answered[0][1]
        real_mac = received.hwsrc
        if received.pdst == my_ip and mac == real_mac:
            mac_ip[mac] = received.psrc
        else:
            current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
            with k_lock:
                arp_log.put(
                    f"{RED}⚠️  {k} [{current_time}] [!] Someone's spoofing!:: {mac} is pretending to be {ip}{RESET}")
                arp_logger.warning(f"{mac} is pretending to be {ip}")
                k += 1
            with beep_lock:
                beep()

def arp_process_packet(packet):
    global mac_ip, k, network
    if packet.haslayer(ARP):
        ip = packet[ARP].psrc
        mac = packet[ARP].hwsrc
        if ipaddress.ip_address(ip) in network:
            if mac not in mac_ip:
                mac_ip[mac] = ip
            else:
                if mac_ip[mac] != ip:
                    threading.Thread(target=verify_packet, args=(mac, ip)).start()