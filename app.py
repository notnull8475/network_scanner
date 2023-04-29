import tkinter as tk
from tkinter import filedialog
from scan import scan, lookup_hostname


def handle_dir_selection():
    f = filedialog.asksaveasfilename()
    dir_var.set(f)

def handle_scan():
    res = scan(net_var.get())

    table = [['IP address', 'MAC address', 'Hostname']]
    for device in res:
        hostname = lookup_hostname(device['ip'])
        table.append([device['ip'], device['mac'], hostname])

    lines = ''
    for row in table:
        line = f'{row[0]: <15} {row[1]: <20} {row[2]: <15}\n'
        lines += line

    print(lines)
    log_box.config(state='normal')
    log_box.insert('1.0', lines)
    log_box.config(state='disabled')
    with open(dir_var.get(), 'w') as f:
        f.write(lines)


window = tk.Tk()
window.geometry('500x540')
window.title('Сканирование сети')
window.columnconfigure('all', weight=1)
window.rowconfigure('all', weight=1)

dir_button = tk.Button(window, text='Выбрать файл', command=handle_dir_selection)
dir_button.grid(row=0, column=0, pady=5, padx=5, sticky='w')

dir_var = tk.StringVar()
dir_var.set('/tmp/scan.log')

dir_label = tk.Label(window, textvariable=dir_var)
dir_label.grid(row=0, column=1, pady=5, padx=5, sticky='w')


net_label = tk.Label(window, text='Сеть (CIDR)')
net_label.grid(row=1, pady=5, padx=5, sticky='w')

net_var = tk.StringVar()
net_var.set('192.168.0.0/24')

net_entry = tk.Entry(window, textvariable=net_var)
net_entry.grid(row=2, column=0, pady=5, padx=5, sticky='w')

scan_button = tk.Button(window, text='Сканировать', command=handle_scan)
scan_button.grid(row=2, column=1, pady=5, padx=5, sticky='w')

log_box = tk.Text(window, state='disabled', width=60)
log_box.grid(row=3, pady=5, padx=5, columnspan=5)

window.mainloop()
