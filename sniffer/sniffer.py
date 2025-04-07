import queue

from scapy.config import conf
from scapy.sendrecv import sniff
from scapy.utils import rdpcap

from arp_spoof_det.arp_spoof import arp_process_packet
from brute_force_det.brute_force_detector import bf_process_packet
from config.config import Config
from dos_det.dos_attack_det import dos_process_packet
from new_device.new_device import newdev_process_packet


# conveyor_belt = queue.Queue()

def run_sniffer():
    def master_func(packet):
        arp_process_packet(packet)
        dos_process_packet(packet)
        bf_process_packet(packet)
        newdev_process_packet(packet)

    # def keep_sniffing():
    conf.promisc = True
    sniff(prn=master_func, store=0, iface=Config.IFACE)
    # pcap = rdpcap("C:\\Users\\Sahil Gupta\\PycharmProjects\\netsec\\arpspoof.pcap")
    # for packet in pcap:
    #     master_func(packet)

if __name__ == "__main__":
    run_sniffer()