import tkinter as tk
from tkinter import filedialog

from NetworkScanner import NetworkScanner


# графический интерфейс пользователя (GUI) для сканирования сети. Он использует библиотеку tkinter
# для создания GUI и модуль NetworkScanner для выполнения сканирования сети.
#
# GUI содержит несколько элементов, включая поля ввода диапазона IP-адресов, диапазона портов и таймаута,
# а также флажок для определения необходимости получения MAC-адресов устройств (требуются права администратора).
# Также есть кнопка "Scan" для запуска сканирования и поле вывода результатов сканирования.
#
# При запуске сканирования кнопкой "Scan", скрипт создает экземпляр класса NetworkScanner,
# передавая в него значения из соответствующих полей ввода. Затем он вызывает метод scan_network()
# для выполнения сканирования. Результаты сканирования выводятся в поле вывода результатов в формате
# "mac: [MAC-адрес] ip: [IP-адрес] ports: [открытые порты]".
#
# Также есть кнопка "Save", которая позволяет сохранить результаты сканирования в текстовом файле.
# При ее нажатии открывается диалоговое окно для выбора имени файла и места сохранения.
# Результаты сканирования сохраняются в выбранный файл в формате текста.

class ScannerGui:
    def save_results(self):
        filename = filedialog.asksaveasfilename(defaultextension=".txt")
        if filename:
            with open(filename, "w") as f:
                f.write(self.result_text.get(1.0, tk.END))

    def __init__(self, master):
        self.master = master
        master.title("Network Scanner")

        # IP range input
        self.ip_label = tk.Label(master, text="IP range:")
        self.ip_label.grid(row=0, column=0)
        self.ip_entry = tk.Entry(master)
        self.ip_entry.insert(0, "192.168.1.0/24")
        self.ip_entry.grid(row=0, column=1)

        # Port range input
        self.port_label = tk.Label(master, text="Port range:")
        self.port_label.grid(row=1, column=0)
        self.port_entry = tk.Entry(master)
        self.port_entry.insert(0, "1-1000")
        self.port_entry.grid(row=1, column=1)

        # Timeout input
        self.timeout_label = tk.Label(master, text="Timeout (s):")
        self.timeout_label.grid(row=3, column=0)
        self.timeout_entry = tk.Entry(master)
        self.timeout_entry.insert(0, "1")
        self.timeout_entry.grid(row=3, column=1)

        self.mac_need_enabled = tk.IntVar()
        # need mac
        self.mac_need = tk.Checkbutton(text="нужны мак адреса (требуются права администратора)",
                                       variable=self.mac_need_enabled)
        self.mac_need.grid(row=4, column=1)

        # Scan button
        self.scan_button = tk.Button(master, text="Scan", command=self.start_scan)
        self.scan_button.grid(row=4, column=0)

        # Result output
        self.result_label = tk.Label(master, text="Results:")
        self.result_label.grid(row=5, column=0)
        self.result_text = tk.Text(master, height=10, width=50)
        self.result_text.grid(row=5, column=1)

        # Save button
        self.save_button = tk.Button(master, text="Save", command=self.save_results)
        self.save_button.grid(row=6, column=0)

    def start_scan(self):
        target = self.ip_entry.get()
        ports = self.port_entry.get()
        mac_need = self.mac_need_enabled.get()
        timeout = self.timeout_entry.get()
        net_scanner = NetworkScanner()
        resp = net_scanner.scan_network(target, ports, mac_need, timeout)
        self.result_text.insert(tk.END, f"{len(resp)} devices found\n")
        for i in resp:
            self.result_text.insert(tk.END, f" mac: {i.mac} ip:{i.ip} ports:{i.ports}.\n")


if __name__ == "__main__":
    root = tk.Tk()
    gui = ScannerGui(root)
    root.mainloop()
