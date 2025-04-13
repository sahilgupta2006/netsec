from scapy.all import *
import time
from scapy.interfaces import ifaces
from config.config import Config
from device.devices import DEVICES_LIST
from ip.ips import IP_IN_NETWORK

GREEN = "\033[92m"
RESET = "\033[0m"

def main():
    ifaces.show()

    print("")
    # Config.NET_RANGE = "172.27.4.0/24"
    # Config.MY_IP = "172.27.4.204"
    # Config.MY_MAC = "e8:65:38:0e:2c:59"
    # Config.IFACE = "Realtek RTL8852BE WiFi 6 802.11ax PCIe Adapter"

    # Config.NET_RANGE = "172.17.15.0/24"
    # Config.MY_IP = "10.90.90.91"
    # Config.MY_MAC = "28:00:af:ae:9e:ab"
    # Config.IFACE = "Realtek PCIe GbE Family Controller"

    Config.NET_RANGE = input("Enter the network range to monitor:- ")
    Config.MY_IP = input("Enter the IPv4 Address of this PC (Monitoring PC):- ")
    Config.MY_MAC = input("Enter the MAC Address of this PC (Monitoring PC):- ")
    Config.IFACE = input("Enter the Network Interface name:- ")

    print("hello")
    print(Config.NET_RANGE)

    from arp_spoof_det.arp_spoof import arp_log
    from ip.ip_profile import dos_log
    from device.device_profile import bf_log
    from new_device.new_device import new_device_log
    from sniffer.sniffer import run_sniffer

    threading.Thread(target=run_sniffer, daemon=True).start()

    while True:
        try:
            print("")
            try:
                ch = input(f"{GREEN}netsec> {RESET}").strip().lower()
            except EOFError:
                print("Exiting gracefully!")
                break
            if ch == "arp":
                print("Displaying ARP logs. Press Ctrl+C to return.")
                while True:
                    try:
                        if not arp_log.empty():
                            print(arp_log.get())
                        else:
                            time.sleep(0.5)
                    except KeyboardInterrupt:
                        print("\nReturning to main menu.")
                        break

            elif ch == "dos":
                print("Displaying DoS logs. Press Ctrl+C to return.")
                while True:
                    try:
                        if not dos_log.empty():
                            print(dos_log.get())
                        else:
                            time.sleep(0.5)
                    except KeyboardInterrupt:
                        print("\nReturning to main menu.")
                        break

            elif ch == "bruteforce" or ch == "bf":
                print("Displaying Brute Force logs. Press Ctrl+C to return.")
                while True:
                    try:
                        if not bf_log.empty():
                            print(bf_log.get())
                        else:
                            time.sleep(0.5)
                    except KeyboardInterrupt:
                        print("\nReturning to main menu.")
                        break

            elif ch == "newdev":
                print("Displaying New Device logs. Press Ctrl+C to return.")
                while True:
                    try:
                        if not new_device_log.empty():
                            print(f"{GREEN}{new_device_log.get()} {RESET}")
                        else:
                            time.sleep(0.5)
                    except KeyboardInterrupt:
                        print("\nReturning to main menu.")
                        break

            elif ch == "help":
                print("Commands: arp | dos | bruteforce (bf) | newdev | list [--ip, --dev] | about | config | exit")

            elif ch == "list --ip":
                for ip, ip_obj in IP_IN_NETWORK.items():
                    print(f"IP:- {ip} Current threshold:- {round(min(ip_obj.ADAPTIVE_THRESHOLD, ip_obj.MAX_THRESHOLD))}")

            elif ch == "list --dev":
                for dev, dev_obj in DEVICES_LIST.items():
                    print(f"IP:- {dev}")

            elif ch == "config":
                print(f"Network Interface Name:- {Config.IFACE}")
                print(f"Monitored Network Range:- {Config.NET_RANGE}")
                print(f"IPv4 Address of Monitoring PC:- {Config.MY_IP}")
                print(f"MAC Address of Monitoring PC:- {Config.MY_MAC}")
            elif ch == "about":
                print("netsec is a lightweight network security tool. Built at IIIT-Allahabad, IN.")
            elif ch == "exit":
                print("Exiting gracefully!")
                break

            else:
                print("No such feature. Type 'help' for commands.")
        except KeyboardInterrupt:
            print("\nExiting gracefully!")
            break


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("Exiting gracefully!")
