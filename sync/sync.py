from scapy.all import *
from config.config import Config
import requests
import ipaddress
import queue
import numpy as np
import logging
from device.devices import dev_list_lock
from scapy.layers.inet import IP, ICMP
with dev_list_lock:
    from device.devices import DEVICES_LIST

from email.utils import parsedate_to_datetime


ABS_IP_TIMESTAMP_OFFSETS = {}
IP_TIMESTAMP = {}

outlier_lock = threading.Lock()
sync_log_lock = threading.Lock()

out_of_sync = queue.Queue()
sync_log = queue.Queue()


logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

def check_http_header_date(ip):
    global ABS_IP_TIMESTAMP_OFFSETS, IP_TIMESTAMP
    current_epoch = int(datetime.now(timezone.utc).timestamp())

    try:
        http_res = requests.get(f"http://{ip}:80/", timeout=2)
        if 'date' in http_res.headers:
            epoch_time = int(parsedate_to_datetime(http_res.headers['date']).timestamp())
            ABS_IP_TIMESTAMP_OFFSETS[ip] = abs(epoch_time - current_epoch)
            IP_TIMESTAMP[ip] = ("http", epoch_time, current_epoch) 
            return 0
    except requests.exceptions.RequestException:
        pass

    try:
        https_res = requests.get(f"https://{ip}:443/", timeout=2, verify=False)
        if 'date' in https_res.headers:
            epoch_time = int(parsedate_to_datetime(https_res.headers['date']).timestamp())
            ABS_IP_TIMESTAMP_OFFSETS[ip] = abs(epoch_time - current_epoch)
            IP_TIMESTAMP[ip] = ("http", epoch_time, current_epoch) 
            return 0
    except requests.exceptions.RequestException:
        pass

    return -1

def check_icmp_ts(ip):
    global ABS_IP_TIMESTAMP_OFFSETS, IP_TIMESTAMP
    res = sr1(IP(src=Config.MY_IP, dst=ip)/ICMP(type=13), timeout=2, verbose=0)
    current_epoch = int(datetime.now(timezone.utc).timestamp())
    if res and res.haslayer(ICMP):
        offset = abs(res[ICMP].ts_rx - res[ICMP].ts_ori)
        ABS_IP_TIMESTAMP_OFFSETS[ip] = offset /1000
        IP_TIMESTAMP[ip] = ("icmp", res[ICMP].ts_rx, current_epoch)
        return 0
    else: 
        return
    
def run_synchronize_test(stop_event):
    global ABS_IP_TIMESTAMP_OFFSETS, IP_TIMESTAMP, out_of_sync

    net_range = Config.NET_RANGE
    network = ipaddress.IPv4Network(net_range, strict=False)

    # L = ["172.19.0.2"]

    for ip in network.hosts():
        ip = str(ip)
        if not stop_event.is_set():
            sync_log.put(f"\nChecking {ip}")
            if check_http_header_date(ip) != 0:
                if check_icmp_ts(ip) != 0:
                    sync_log.put(f"Couldn't check for {ip}")

            if ip in IP_TIMESTAMP:
                out_of_sync.put((ip, IP_TIMESTAMP[ip]))
        else:
            break

    
    print("Computing outliers...")
    # outlier detection part
    ARR = list(ABS_IP_TIMESTAMP_OFFSETS.values())
            # print("Triggered!1")

    f = False

    if len(ARR) > 0:
        avg = np.average(ARR)
        stdev = np.std(ARR)

        for ip in ABS_IP_TIMESTAMP_OFFSETS:
            # print(avg)
            # print(stdev)
            # print((ABS_IP_TIMESTAMP_OFFSETS[ip] - avg)/stdev)
            # print("")
            if stdev != 0 and ((ABS_IP_TIMESTAMP_OFFSETS[ip] - avg)/stdev >= 1 or (ABS_IP_TIMESTAMP_OFFSETS[ip] - avg)/stdev <= -1):
                f = True
                hours, rem = divmod(ABS_IP_TIMESTAMP_OFFSETS[ip], 3600)
                minutes, seconds = divmod(rem, 60)
                # ms, 
                print(f"IP:- {ip} is out of sync by {hours}:{minutes}:{seconds} hours.")
            # else:
            #     # print("Triggered!3")
        
    if not f:
        print("All devices whom time-data were collected were found to be in sync!")

        with sync_log.mutex:
            sync_log.queue.clear()

        with out_of_sync.mutex:
            out_of_sync.queue.clear()


    
    
    
