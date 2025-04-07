import logging
import queue
import statistics
import threading, time
from datetime import datetime

from alert_mech.alert_beep import beep_lock, beep
from ip.ips import IP_IN_NETWORK

dos_log = queue.Queue()


class Source:

    def __init__(self, ip):
        self.IP = ip
        self.running = True
        self.LOG_OF_INCOMP = []
        self.PACKET_COUNT = 0
        self.MAX_THRESHOLD = 10000
        self.MIN_THRESHOLD = 100
        self.ADAPTIVE_THRESHOLD = self.MIN_THRESHOLD
        self.ALERT_THIS_TIMEFRAME = False

        self.update_window_thread = threading.Thread(target=self.update_window)
        self.update_threshold_thread = threading.Thread(target=self.update_threshold)

        self.update_window_thread.start()
        self.update_threshold_thread.start()

        logger = logging.getLogger("DOS_DETECT")
        logger.setLevel(logging.WARNING)

        file_handler = logging.FileHandler("logs/dos_attack_log.log")
        formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
        file_handler.setFormatter(formatter)

        if not logger.handlers:
            logger.addHandler(file_handler)

        self.dos_logger = logger
        IP_IN_NETWORK[self.IP] = self

    def dos_listener(self, ip):
        RED = "\033[91m"
        RESET = "\033[0m"
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        dos_log.put(f"{RED} [{current_time}] ⚠️ Anomalous Traffic From:- {ip} {RESET}")
        self.dos_logger.warning(f"Anomalous Traffic From:- {ip}")
        with beep_lock:
            beep()

    def set_incomplete(self):
        self.PACKET_COUNT += 1
        if self.PACKET_COUNT > round(round(min(self.ADAPTIVE_THRESHOLD, self.MAX_THRESHOLD))*1.2):
            if not self.ALERT_THIS_TIMEFRAME:
                self.dos_listener(f"{self.IP} {self.PACKET_COUNT} {self.ADAPTIVE_THRESHOLD}")
                self.ALERT_THIS_TIMEFRAME = True

    def update_window(self):
        counter = 0
        while self.running:
            time.sleep(1)
            counter = (counter+1)%10
            if counter == 0:
                self.LOG_OF_INCOMP.append(self.PACKET_COUNT)
                self.PACKET_COUNT = 0
                self.ALERT_THIS_TIMEFRAME = False

    def update_threshold(self):
        while self.running:
            time.sleep(60)
            if self.LOG_OF_INCOMP:
                mean_count = statistics.mean(self.LOG_OF_INCOMP)
                stdev_count = statistics.stdev(self.LOG_OF_INCOMP) if len(self.LOG_OF_INCOMP) > 1 else 0
                self.ADAPTIVE_THRESHOLD = min(max(mean_count + (3 * stdev_count), self.MIN_THRESHOLD), self.MAX_THRESHOLD)

    def stop(self):
        self.running = False
        self.update_window_thread.join()
        self.update_threshold_thread.join()