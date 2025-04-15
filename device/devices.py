import threading

dev_list_lock = threading.Lock()

# with dev_list_lock:
DEVICES_LIST = {}