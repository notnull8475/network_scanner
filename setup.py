from setuptools import setup, find_packages

setup(
    name='NetworkScanner',
    version='0.1',
    description='Lan net scanner ',
    long_description='Сетевой сканер предназначенный для сканирования локальной сети на предмет наличия активных узлов, открытых портов на них в заданном диапазоне, а также имен узлов. Также для сканирования требуется установленная утилита nmblookup, которая устанавливается вместе с пакетом smb  в linux системах',
    packages=find_packages(),
    classifiers=[
        'Development Status :: 3 - Alpha',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3.7',
    ],
    install_requires=[
        'csv',
        'subprocess',
        'socket',
        'prettytable',
        'tkinter',
    ],
)