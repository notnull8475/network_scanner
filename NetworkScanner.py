import ipaddress
import subprocess
import threading
from multiprocessing.pool import ThreadPool
from queue import Queue

from Consts import MAX_THREADS_IP_SCAN_THREADS
from PortScanner import PortScanner


def get_mac(ip_address):
    cmd = "arp -n {}".format(ip_address)
    output = subprocess.check_output(cmd, shell=True)
    output = output.decode("utf-8")
    lines = output.split("\n")
    for line in lines:
        if ip_address in line:
            parts = line.split()
            if len(parts) >= 3:
                return parts[2]
    return None


class NetworkScanner:
    # передаем адрес сети
    def __init__(self):
        self.port_range = None
        self.ip_list = None
        self.q = Queue()
        self.net_nodes = None
        self.mac_address = None
        self.timeout = None
        self.to_ports_scan = False
        self.mac_need = False

    def scan_network(self, target, ports="1-500", mac_need=False, timeout=1, to_ports_scan=True):
        global stop_thread
        self.net_nodes = []
        self.ip_list = [str(ip) for ip in ipaddress.IPv4Network(target)]
        self.port_range = [int(x) for x in ports.split("-")]
        self.mac_need = mac_need
        self.timeout = timeout
        self.to_ports_scan = to_ports_scan

        if mac_need:
            for ip in self.ip_list:
                mac = get_mac(ip)
                if mac is None:
                    self.ip_list.remove(ip)

        stop_thread = False
        for x in range(MAX_THREADS_IP_SCAN_THREADS):
            t = threading.Thread(target=self.threader)
            t.daemon = True
            t.start()

        for worker in self.ip_list:
            self.q.put(worker)
        self.q.join()
        stop_thread = True
        return self.net_nodes

    def threader(self):
        while True:
            worker = self.q.get()
            scanner = PortScanner(worker)
            open_ports = scanner.scan_ports_treads(self.port_range[0], self.port_range[1])

            if len(open_ports) > 0:
                a = NetNode(worker)
                a.set_ports(open_ports)
                self.net_nodes.append(a)
            self.q.task_done()


class NetNode:
    def __init__(self, ip, mac=None):
        self.ip = ip
        self.mac = mac
        self.ports = None

    def set_ports(self, ports):
        self.ports = ports

    def print(self):
        print("ip:" + str(self.ip) + " mac: " + str(self.mac) + " " + str(self.ports))


if __name__ == '__main__':
    net_scanner = NetworkScanner()
    allIP = net_scanner.scan_network("192.168.110.0/24", "10-100", mac_need=False)
    for i in allIP:
        i.print()
