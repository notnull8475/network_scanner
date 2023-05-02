# sudo apt install nbtscan
# sudo apt install python3-pip
# pip install --pre scapy[basic]

from socket import gaierror
from subprocess import check_output, CalledProcessError

import scapy.all as sc

# Основной алгоритм работы заключается в сканировании сети,
# получении информации об IP и MAC адресах устройств в сети,
# сканировании открытых портов устройств в сети и получении
# NETBios-имени компьютеров. Все полученные данные сохраняются в
# словаре result. В итоге формируется таблица с результатами сканирования,
# в которой содержится информация об IP и MAC адресах устройств в сети,
# открытых портах и NETBios-имени компьютеров.

# инициализируем словарь, в котором будем хранить информацию о сканированных портах.
result = dict()


# функция сканирования сети для получения IP и MAC адресов устройств в сети.
def get_ip_mac_nework(ip, timeout):
    answered_list = sc.srp(sc.Ether(dst='ff:ff:ff:ff:ff:ff') / sc.ARP(pdst=ip), timeout=timeout, verbose=False)[0]
    clients_list = []
    for element in answered_list:
        clients_list.append({'ip': element[1].psrc, 'mac': element[1].hwsrc})
    return clients_list


# получение маски сети
def get_net_mask_linx():
    net_mask = str(check_output('ip -h -br a  | grep UP', shell=True).decode()).split()[2].split("/")[1]
    return net_mask


# сканирование с помощью TCP пакетов на открытые порты
def syn_ack_scan(ip, ports):
    # создание пакета для сканирование
    try:
        request_syn = sc.IP(dst=ip) / sc.TCP(dport=ports, flags="S")
    except gaierror:
        raise ValueError(f'{ip} получить не удалось')
    answer = sc.sr(request_syn, timeout=2, retry=1, verbose=False)[0]  # отправка пакета

    # добавление полученных значений в словарь
    for send, receiv in answer:
        if receiv['TCP'].flags == "SA":
            try:
                if str(receiv['IP'].src) not in result:
                    result[str(receiv['IP'].src)] = dict()
                if str(receiv['TCP'].sport) not in result[str(receiv['IP'].src)]:
                    result[str(receiv['IP'].src)][str(receiv['TCP'].sport)] = dict()
                if str(sc.TCP_SERVICES[receiv['TCP'].sport]) not in result[str(receiv['IP'].src)] \
                        [str(receiv['TCP'].sport)]:
                    result[str(receiv['IP'].src)][str(receiv['TCP'].sport)] = str(sc.TCP_SERVICES[receiv['TCP'].sport])
            except KeyError:
                result[str(receiv['IP'].src)][str(receiv['TCP'].sport)] = 'Undefined'


# получение NETBios-имени компьютеров
def netbios_check(ip):
    try:
        nb = check_output(f'nbtscan {ip} -e', shell=True).decode().split()
    except CalledProcessError:
        return
    try:
        nb_name = nb[1]
    except IndexError:
        return
    return nb_name


def result_of(dict_netbios, ip_mac_network):
    table_data = []
    table_data.append(["IP", "MAC", "Ports", "NB-Name"])

    for ip in ip_mac_network:
        row_data = []
        row_data.append(ip['ip'])
        row_data.append(ip['mac'])
        if ip['ip'] in result:
            row_data.append(str(result[ip['ip']]).replace("': '", "/").replace("{", "[").replace("}", "]"))
        else:
            row_data.append(" --- ")
        if ip['ip'] in dict_netbios:
            row_data.append(dict_netbios[ip['ip']])
        else:
            row_data.append(" --- ")
        table_data.append(row_data)

    return table_data


def network_scan(target_ip, port_range, timeout):
    # получение IP- и MAC-адресов машин в сети
    ip_mac_network = get_ip_mac_nework(target_ip, timeout)

    # сканирование открытых портов
    netbios_dict = {}
    for ip in ip_mac_network:
        syn_ack_scan(ip["ip"], (port_range[0], port_range[1] + 1))
        name = netbios_check(ip["ip"])
        if name:
            netbios_dict[ip["ip"]] = name

    return result_of(netbios_dict, ip_mac_network)
