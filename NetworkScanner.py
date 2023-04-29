import ipaddress
import threading
import time
import socket
import struct
from queue import Queue

from Consts import MAX_THREADS
from PortScanner import PortScanner


# Данный код представляет собой реализацию сетевого сканера на языке Python.
# Сканер позволяет сканировать указанную подсеть на наличие доступных хостов и открытых портов.
#
# Основные компоненты кода:
#
#     - Класс NetworkScanner, который реализует метод scan_network,
#       принимающий на вход адрес сети и диапазон портов для сканирования.
#       Метод создает необходимое количество потоков и запускает в каждом из них функцию threader,
#       которая получает IP-адрес из очереди и запускает сканирование портов либо получение MAC-адреса,
#       в зависимости от того, какая информация требуется.
#       Результаты сканирования сохраняются в объекте класса AllowedIp,
#       который хранит IP-адрес, MAC-адрес и список открытых портов.
#     - Класс AllowedIp, представляющий информацию о найденном хосте.
#       Содержит IP-адрес, MAC-адрес и список открытых портов.
#     - Класс PortScanner, который реализует метод scan_ports,
#       осуществляющий сканирование указанного диапазона портов для заданного IP-адреса.
#
# Код также содержит функцию get_mac, которая отправляет ARP-запрос для получения MAC-адреса заданного IP-адреса.
# Однако, данная функция не используется в текущей реализации сканера.
#
# Кроме того, код содержит набор импортируемых модулей, таких как ipaddress, threading, time, socket и struct.
#
# Запуск кода производится в блоке if __name__ == '__main__', где создается экземпляр класса
# NetworkScanner и вызывается метод scan_network для указанной подсети и диапазона портов.
# Результаты сканирования выводятся на экран в цикле for.

class NetworkScanner:
    # передаем адрес сети
    def __init__(self):
        self.port_range = None
        self.ip_list = None
        self.q = Queue()
        self.allowed_ips = None
        self.mac_address = None
        self.timeout = None
        self.to_ports_scan = False
        self.mac_need = False

    def threader(self):
        # print("Thread " + threading.currentThread().getName() + " start")
        while True:
            worker = self.q.get()
            if self.mac_need:
                self.get_mac(worker, self.timeout)
            else:
                scanner = PortScanner(worker)
                open_ports = scanner.scan_ports(self.port_range[0], self.port_range[1])
                if len(open_ports) > 0:
                    a = AllowedIp(worker)
                    a.set_ports(open_ports)
                    self.allowed_ips.append(a)
            self.q.task_done()

    def scan_network(self, target, ports="1-500", mac_need=False, timeout=1, to_ports_scan=True):
        self.allowed_ips = []
        print(target)
        self.ip_list = [str(ip) for ip in ipaddress.IPv4Network(target)]
        self.port_range = [int(x) for x in ports.split("-")]
        self.mac_need = mac_need
        self.timeout = timeout
        self.to_ports_scan = to_ports_scan

        for x in range(MAX_THREADS):
            t = threading.Thread(target=self.threader)
            t.daemon = True
            t.start()

        for worker in self.ip_list:
            self.q.put(worker)
        self.q.join()

        return self.allowed_ips

    def get_mac(self, ip, timeout):
        # Преобразуем IP-адрес в бинарный формат
        ip_bytes = socket.inet_aton(ip)

        # Создаем сокет для отправки ARP-запроса
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0806))
        s.bind(("eth0", socket.htons(0x0806)))

        # Создаем Ethernet-фрейм и ARP-запрос для заданного IP-адреса
        dst_mac = "\xff\xff\xff\xff\xff\xff"
        src_mac = "\x00\x00\x00\x00\x00\x00"
        ether_type = "\x08\x06"
        hw_type = "\x00\x01"
        proto_type = "\x08\x00"
        hw_size = "\x06"
        proto_size = "\x04"
        opcode = "\x01"
        arp_request = dst_mac + src_mac + ether_type + hw_type + proto_type + hw_size + proto_size + opcode + src_mac + ip_bytes + dst_mac + ip_bytes

        # Отправляем ARP-запрос
        s.send(arp_request)

        # Ждем ответа на ARP-запрос
        start_time = time.time()
        while True:
            if time.time() - start_time > timeout:
                pass
            packet = s.recvfrom(2048)[0]
            eth_header = struct.unpack("!6s6s2s", packet[:14])
            if eth_header[2] == "\x08\x06":
                arp_header = struct.unpack("2s2s1s1s2s6s4s6s4s", packet[14:42])
                if arp_header[4] == "\x00\x02":
                    al_ip = AllowedIp(ip, mac=arp_header[5].encode('hex'))
                    if self.to_ports_scan:
                        scanner = PortScanner(ip)
                        al_ip.set_ports(scanner.scan_ports(self.port_range[0], self.port_range[1]))
                    self.allowed_ips.append(al_ip)


class AllowedIp:
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
    allIP = net_scanner.scan_network("192.168.1.0/24", "10-100",mac_need=True)
    for i in allIP:
        i.print()
