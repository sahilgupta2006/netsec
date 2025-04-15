import logging
import queue
import threading
import time
from datetime import datetime

from scapy.layers.inet import IP, TCP

from alert_mech.alert_beep import beep_lock, beep

from device.devices import dev_list_lock
with dev_list_lock:
    from device.devices import DEVICES_LIST

def setup_logger():
    logger = logging.getLogger("BRUTE_FORCE_DETECT")
    logger.setLevel(logging.WARNING)

    file_handler = logging.FileHandler("logs/brute_force_att.log")
    formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
    file_handler.setFormatter(formatter)

    if not logger.handlers:
        logger.addHandler(file_handler)

    return logger


brute_logger = setup_logger()
bf_log = queue.Queue()

class Device:
    def __init__(self, IP):
        self.IP = IP
        self.PORT = {"ssh": 22}
        self.FAILED_ATTEMPTS = 0
        self.ALLOWED_TRIES_PER_HOUR = 2
        self.FAILED_ATTEMPTS_LAST_HOUR = {}
        self.LATEST_CLEAR = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        self.k = 1

        self.cleaner_thread = threading.Thread(target=self.clear_tries, daemon=True)
        self.cleaner_thread.start()

        self.lock = threading.Lock()
        with dev_list_lock:
            DEVICES_LIST[self.IP] = self

    def handle_packet(self, packet):
        flags = packet[TCP].flags
        src_ip = packet[IP].src
        dst_port = packet[TCP].dport

        if flags & 0x02 and dst_port == self.PORT["ssh"]: # SYN flag
            with self.lock:
                if src_ip not in self.FAILED_ATTEMPTS_LAST_HOUR:
                    self.FAILED_ATTEMPTS_LAST_HOUR[src_ip] = 1
                    self.FAILED_ATTEMPTS += 1
                else:
                    self.FAILED_ATTEMPTS_LAST_HOUR[src_ip] += 1
                    self.FAILED_ATTEMPTS += 1

                if self.FAILED_ATTEMPTS > self.ALLOWED_TRIES_PER_HOUR:
                    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
                    if self.FAILED_ATTEMPTS_LAST_HOUR[src_ip] > self.ALLOWED_TRIES_PER_HOUR:
                        bf_log.put(f"{self.k} [{current_time}] SUSPICIOUS!!!:: {src_ip} has logged in/trying to in {self.IP} more than {self.ALLOWED_TRIES_PER_HOUR*3} times since {self.LATEST_CLEAR}")
                        brute_logger.warning(f"Trier:- {src_ip} Target:- {self.IP}")
                    else:
                        bf_log.put(f"{self.k} [{current_time}] SUSPICIOUS!!!:: {src_ip} has logged in/trying to in {self.IP} more than {self.ALLOWED_TRIES_PER_HOUR*3} times since {self.LATEST_CLEAR}")
                        brute_logger.warning(f"Many attempts on:- {self.IP}")
                    self.k += 1
                    with beep_lock:
                        beep()

    def clear_tries(self):
        i = 0
        while True:
            i = (i+1)%3600
            time.sleep(1)
            if i == 0:
                with self.lock:
                    self.FAILED_ATTEMPTS_LAST_HOUR.clear()
                    self.FAILED_ATTEMPTS = 0
                    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
                    self.LATEST_CLEAR = current_time