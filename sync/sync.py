from scapy.all import *
from config.config import Config
import requests
import queue
import numpy as np
from scipy.stats import zscore
from device.devices import dev_list_lock
from scapy.layers.inet import IP, ICMP
with dev_list_lock:
    from device.devices import DEVICES_LIST

ABS_IP_TIMESTAMP_OFFSETS = {}
IP_TIMESTAMP_OFFSETS = {}
# TIMESTAMP_OFFSETS = []

outlier_lock = threading.Lock()
sync_log_lock = threading.Lock()

out_of_sync = queue.Queue()
sync_log = queue.Queue()

def check_http_header_date(ip):
    global ABS_IP_TIMESTAMP_OFFSETS, IP_TIMESTAMP_OFFSETS
    pattern = "%a, %d %b %Y %H:%M:%S %Z"
    current_epoch = int(datetime.now(timezone.utc).timestamp())

    try:
        http_res = requests.get(f"http://{ip}:80/", timeout=2)
        if 'Date' in http_res.headers:
            # print(http_res.headers['Date'])
            epoch_time = int(datetime.strptime(http_res.headers['Date'], pattern).replace(tzinfo=timezone.utc).timestamp())
            ABS_IP_TIMESTAMP_OFFSETS[ip] = abs(epoch_time - current_epoch)
            IP_TIMESTAMP_OFFSETS[ip] = epoch_time - current_epoch
            return 0
    except requests.exceptions.RequestException:
        pass

    try:
        https_res = requests.get(f"https://{ip}:443/", timeout=2, verify=False)
        if 'Date' in https_res.headers:
            # print(https_res.headers['Date'])
            epoch_time = int(datetime.strptime(https_res.headers['Date'], pattern).replace(tzinfo=timezone.utc).timestamp())
            ABS_IP_TIMESTAMP_OFFSETS[ip] = abs(epoch_time - current_epoch)
            IP_TIMESTAMP_OFFSETS[ip] = epoch_time - current_epoch
            return 0
    except requests.exceptions.RequestException:
        pass

    return -1


def check_icmp_ts(ip):
    global ABS_IP_TIMESTAMP_OFFSETS, IP_TIMESTAMP_OFFSETS
    res = sr1(IP(src=Config.MY_IP, dst=ip)/ICMP(type=13), timeout=2, verbose=0)
    if res and res.haslayer(ICMP):
        offset = abs(res[ICMP].ts_rx - res[ICMP].ts_ori)
        # print(offset)
        ABS_IP_TIMESTAMP_OFFSETS[ip] = offset
        IP_TIMESTAMP_OFFSETS[ip] = res[ICMP].ts_rx - res[ICMP].ts_ori
        # TIMESTAMP_OFFSETS.append(offset)
        return 0
    else: 
        return

    
def run_synchronize_test():
    global ABS_IP_TIMESTAMP_OFFSETS, IP_TIMESTAMP_OFFSETS, out_of_sync
    # for i in range(5, 7):
    #     print(f"Checking 172.17.15.{i}")
    #     if check_http_header_date(f"172.17.15.{i}") != 0:
    #         if check_icmp_ts(f"172.17.15.{i}") != 0:
    #             print(f"Couldn't check for 172.17.15.{i}")
    #     ip = f"172.17.15.{i}"
    #     if IP_TIMESTAMP_OFFSETS[ip]:
    #         out_of_sync.put((ip, IP_TIMESTAMP_OFFSETS[ip]))

    for i in range(1, 256):
        ip = f"172.17.15.{i}"
        sync_log.put(f"\nChecking {ip}")
        if check_http_header_date(ip) != 0:
            if check_icmp_ts(ip) != 0:
                sync_log.put(f"Couldn't check for {ip}")

        if ip in IP_TIMESTAMP_OFFSETS:
            # print(ip)
            out_of_sync.put((ip, IP_TIMESTAMP_OFFSETS[ip]))
    # values = list(ABS_IP_TIMESTAMP_OFFSETS.values())

    # z_scores = zscore(values)
    # data = ABS_IP_TIMESTAMP_OFFSETS
    # outlier_threshold = 2

    # for i, ip in enumerate(data):
    #     if abs(z_scores[i]) > outlier_threshold:
    #         with outlier_lock:
    #             out_of_sync.put((ip, IP_TIMESTAMP_OFFSETS[ip]))

    
    
