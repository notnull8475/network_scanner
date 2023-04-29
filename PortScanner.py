import socket
import threading
from queue import Queue

from Consts import SOCKET_DEFAULT_TIMEOUT, MAX_THREADS_PORT_SCAN_THREADS

socket.setdefaulttimeout(SOCKET_DEFAULT_TIMEOUT)


# Класс который реализует сканер портов для заданного IP-адреса.
# Он использует модуль socket для создания сокетов и установки соединений с портами.
# Для ускорения сканирования используется многопоточность.
#
# Класс PortScanner инициализируется с передачей IP-адреса, который нужно просканировать.
# При инициализации он получает IP-адрес, соответствующий заданному имени хоста, используя функцию gethostbyname()
# из модуля socket. Также инициализируется объект блокировки threading.Lock(),
# который используется для синхронизации доступа к общему списку открытых портов.
#
# Метод portscan() создает сокет, пытается установить соединение с заданным портом и,
# если соединение устанавливается успешно, добавляет номер порта в список открытых портов.
# Если соединение не устанавливается, метод игнорирует ошибку и продолжает работу.
#
# Метод threader() запускается в каждом потоке и выполняется в бесконечном цикле.
# Он получает порт для сканирования из очереди и вызывает метод portscan() для сканирования этого порта.
# После завершения работы метода portscan() поток сообщает об этом очереди, вызывая метод task_done().
#
# Метод scan_ports() создает очередь задач и запускает несколько потоков
# (в количестве, заданном константой MAX_THREADS) для сканирования портов.
# Он заполняет очередь задач номерами портов, которые нужно просканировать,
# и затем ждет, пока все задачи будут выполнены. После завершения работы сканера он возвращает список открытых портов.
#
# В блоке if name == 'main': создается объект PortScanner с запрашиваемым пользователем
# IP-адресом, запускается сканирование портов и выводится список открытых портов.


class PortScanner:


    # передаем ip address
    def __init__(self, target):

        self.open_ports = None
        self.q_ports = None
        self.thread_flag = False
        self.target = target
        self.t_IP = socket.gethostbyname(target)
        self.print_lock = threading.Lock()

    def portscan(self, port):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            con = s.connect((self.t_IP, port))
            self.open_ports.append(port)
            con.close()
        except:
            pass

    def threader(self):
        while True:
            worker = self.q_ports.get()
            self.portscan(worker)
            self.q_ports.task_done()

    def scan_ports_treads(self, start_port=1, end_port=500):
        self.open_ports = []
        self.q_ports = Queue()
        for x in range(MAX_THREADS_PORT_SCAN_THREADS):
            t = threading.Thread(target=self.threader)
            t.daemon = True
            t.start()

        for worker in range(start_port, end_port + 1):
            self.q_ports.put(worker)

        self.q_ports.join()
        return self.open_ports

if __name__ == '__main__':
    scanner = PortScanner(input('Enter the host to be scanned: '))
    open_ports = scanner.scan_ports_treads()
    print('Open ports:', open_ports)
