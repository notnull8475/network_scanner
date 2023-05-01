import ipaddress
import socket
import subprocess
import threading
from queue import Queue
import re

from Consts import MAX_THREADS_IP_SCAN_THREADS
from PortScanner import PortScanner


# Этот код представляет собой реализацию простого сетевого сканера,
# который сканирует заданный диапазон IP-адресов в сети на наличие открытых портов.
#
# Класс NetworkScanner является основным классом сканера,
# который использует очередь Queue и многопоточность для сканирования адресов
# в заданном диапазоне. При инициализации сканера задаются параметры сети,
# которые будут сканироваться, такие как диапазон портов, время ожидания ответа,
# необходимость сканирования MAC-адресов и т.д.
#
# Метод scan_network запускает сканирование адресов в заданном диапазоне.
# Если задан параметр mac_need, то также выполняется сканирование MAC-адресов
# для каждого адреса. Если MAC-адрес не может быть получен, то адрес удаляется из списка адресов для сканирования.
#
# Класс NetNode представляет узел сети, который содержит информацию об IP-адресе,
# MAC-адресе и открытых портах. Метод set_ports установливает список открытых портов для узла.
#
# Метод threader выполняет фактическое сканирование портов для каждого адреса с
# использованием класса PortScanner. Если есть открытые порты, то они записываются для соответствующего узла NetNode.
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


def get_remote_computer_name(ip_address):
    try:
        name = socket.gethostbyaddr(ip_address)[0]
    except socket.herror:
        name = None
    return name


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
        self.net_nodes = {}
        self.ip_list = [str(ip) for ip in ipaddress.IPv4Network(target)]
        self.port_range = [int(x) for x in ports.split("-")]
        self.mac_need = mac_need
        self.timeout = timeout
        self.to_ports_scan = to_ports_scan

        if mac_need:
            for ip in self.ip_list:
                mac = get_mac(ip)
                match = re.match(r'([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}', mac)
                # print(f"match {match} ", type(match))
                if match is None:
                    print("removed")
                    self.ip_list.remove(ip)
                else:
                    print("added")
                    self.net_nodes[ip] = NetNode(ip, mac)

        for x in range(MAX_THREADS_IP_SCAN_THREADS):
            t = threading.Thread(target=self.threader)
            t.daemon = True
            t.start()

        if mac_need:
            for worker in self.net_nodes:
                self.q.put(worker)
        else:
            for worker in self.ip_list:
                self.q.put(worker)
        self.q.join()
        return self.net_nodes

    def threader(self):
        print(f"{threading.current_thread().getName()} start")
        while True:
            worker = self.q.get()
            scanner = PortScanner(worker)
            open_ports = scanner.scan_ports_treads(self.port_range[0], self.port_range[1])
            print(f"scan {worker} ports {open_ports}")
            if len(open_ports) > 0:
                if self.mac_need:
                    a = self.net_nodes[worker]
                else:
                    a = NetNode(worker)
                a.hostname = get_remote_computer_name(worker)
                a.set_ports(open_ports)
                self.net_nodes[worker] = a
            self.q.task_done()


class NetNode:
    def __init__(self, ip, hostname=None, mac=None):
        self.ip = ip
        self.hostname = hostname
        self.mac = mac
        self.ports = None

    def set_ports(self, ports):
        self.ports = ports

    def print(self):
        print("ip:" + str(self.ip) + " hostname: " + self.hostname + " mac: " + str(self.mac) + " " + str(self.ports))


if __name__ == '__main__':
    net_scanner = NetworkScanner()
    allIP = net_scanner.scan_network("192.168.110.0/24", "10-100", mac_need=False)
    for i in allIP:
        allIP[i].print()
