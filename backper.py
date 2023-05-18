import configparser
import os
import PySimpleGUI as sg
import shutil
import datetime
import ftplib
import telebot
import pyodbc
import subprocess
from cryptography.fernet import Fernet
from webdav3.client import Client

token = '6197644867:AAGqBg-SFQc8JAAr6zA6duVv_F-bdRiq_Gg'
photo_ftp = 'settings_photo_ftp.ini'
photo_local = 'settings_photo_local.ini'
mssql_ftp = 'settings_mssql_ftp.ini'
mssql_local = 'settings_mssql_local.ini'
ftp_1c = 'settings_1c_ftp.ini'
local_1c = 'settings_1c_local.ini'
location = os.getcwd()
er_gui = 'Что то не так'
process_name = "1cv8s.exe"
command = "taskkill /t /F /IM "
killproc = command + process_name
src = 0
dst = 0
see = 0
sel = 0
mssqls = 0
msssql_db = 0
flcount = 0
dlcount = 0
fcount = 0
dcount = 0

# Графический интерфейс
def gui_conf():
    sg.theme('Gray Gray Gray')
    layout = [[sg.VPush()],
        [sg.Push(), sg.Text('Что планируем копировать?'), sg.Push()],
        [sg.Push(), sg.Submit('Photo на FTP'), sg.Submit('MS SQL DB на FTP'), sg.Submit('Mysql DB на FTP'), sg.Submit('1С на FTP'), sg.Push()],
        [sg.Submit('Photo локально'), sg.Submit('MS SQL DB локально'), sg.Submit('1С локально'), sg.Push()],
        [sg.Cancel('Выход'), sg.Push(), sg.Text('by c0unt_zer0_nc')]
    ]
    window = sg.Window('Создание файла конфигурации для бэкапера', layout)
    while True:                             
        event, values = window.read()
        if event in (None, 'Exit', 'Выход'):
            window.close()
            break
        if event == 'Photo на FTP':
            window.close()
            gui_conf_photo_ftp()
        if event == 'Photo локально':
            window.close()
            gui_conf_photo_local()
        if event == 'MS SQL DB на FTP':
            window.close()
            gui_conf_mssql_ftp()
        if event == 'MS SQL DB локально':
            window.close()
            gui_conf_mssql_local()
        if event == '1С на FTP':
            window.close()
            gui_conf_1c_ftp()
        if event == '1С локально':
            window.close()
            gui_conf_1c_local()

# Графический интерфейс для Фото на FTP
def gui_conf_photo_ftp():
    global path
    path = 'settings_photo_ftp.ini'
    sg.theme('Gray Gray Gray')
    layout = [[sg.VPush()],
        [sg.vcenter(sg.Text('Папка откуда изначально брать')), sg.InputText(tooltip='Откуда копировать'), sg.FolderBrowse('Обзор')],
        [sg.vcenter(sg.Text('Папка куда копировать')), sg.Push(), sg.InputText(tooltip='Локальная папка архива'), sg.FolderBrowse('Обзор')],
        [sg.vcenter(sg.Text('ftp сервер')), sg.Push(), sg.InputText(tooltip='Адрес сервера FTP')],
        [sg.vcenter(sg.Text('ftp login')), sg.Push(), sg.InputText(tooltip='Пользователь сервера FTP')],
        [sg.vcenter(sg.Text('ftp пароль')), sg.Push(), sg.InputText(tooltip='Пароль сервера FTP')],
        [sg.vcenter(sg.Text('Стартовая папка FTP')), sg.Push(), sg.InputText(tooltip='Корневая директория FTP')],
        [sg.vcenter(sg.Text('Кодавая страница FTP')), sg.Push(), sg.InputText(tooltip='Кодовая страница сервера FTP. "utf-8" или "cp1251"')],
        [sg.vcenter(sg.Text('Рекурсия проверки файлов дней')), sg.Push(), sg.InputText(tooltip='Глубина проверки синхронизации файлов. Если указать 3 то будет проверять последние 3 дня')],
        [sg.vcenter(sg.Text('Telegram Chat ID')), sg.Push(), sg.InputText(tooltip='Индентификатор твоего чата в ТГ. Чтобы присылать уведомления')],
        [sg.vcenter(sg.Text('Индификатор обьекта')), sg.Push(), sg.InputText(tooltip='Имя запуска. Для использования в ТГ')],
    
        [sg.Submit('Сохранить'), sg.Submit('Назад'), sg.Cancel('Выход'), sg.Push(), sg.Text('by c0unt_zer0_nc')]
    ]
    global window
    window = sg.Window('Создание файла конфигурации для бэкапера', layout, finalize=True)
    window.TKroot.focus_force()
    while True:                             
        event, values = window.read()
        if event in (None, 'Exit', 'Выход'):
            window.close()
            break
        if event == 'Назад':
            window.close()
            gui_conf()
        if event == 'Сохранить':
            global src, dst, ftp, ftp_u, ftp_p, ftp_root, see, sel, chat_id, cp, name_obj, cipher_ke
            src = values[0]
            dst = values[1]
            ftp = values[2]
            ftp_us = values[3]
            ftp_ub = ftp_us.encode(encoding="utf-8", errors="strict")
            cipher_key = Fernet.generate_key()
            cipher_ke = cipher_key.decode(encoding="utf-8", errors="strict")
            cipher = Fernet(cipher_key)
            ftp_ue = cipher.encrypt(ftp_ub)
            ftp_u = ftp_ue.decode(encoding="utf-8", errors="strict")
            ftp_ps = values[4]
            ftp_pb = ftp_ps.encode(encoding="utf-8", errors="strict")
            ftp_pe = cipher.encrypt(ftp_pb)
            ftp_p = ftp_pe.decode(encoding="utf-8", errors="strict")
            ftp_root = values[5]
            cp = values[6]
            see = values[7]
            sel = int(see)
            chat_id = values[8]
            name_obj = values[9]
            path = photo_ftp
            window.close()
            create_Config(path)
            check_conf()
        else:
            print(er_gui)
    return path


# Графический интерфейс для Фото локально
def gui_conf_photo_local():
    global path
    path = 'settings_photo_local.ini'
    sg.theme('Gray Gray Gray')
    layout = [[sg.VPush()],
              [sg.vcenter(sg.Text('Папка откуда изначально брать')), sg.InputText(tooltip='Откуда копировать'), sg.FolderBrowse('Обзор')],
              [sg.vcenter(sg.Text('Папка куда копировать')), sg.Push(), sg.InputText(tooltip='Куда копировать'), sg.FolderBrowse('Обзор')],
              [sg.vcenter(sg.Text('Рекурсия проверки файлов дней')), sg.Push(), sg.InputText(
                  tooltip='Глубина проверки синхронизации файлов. Если указать 3 то будет проверять последние 3 дня')],
              [sg.vcenter(sg.Text('Telegram Chat ID')), sg.Push(),
               sg.InputText(tooltip='Индентификатор твоего чата в ТГ. Чтобы присылать уведомления')],
              [sg.vcenter(sg.Text('Индификатор обьекта')), sg.Push(),
               sg.InputText(tooltip='Имя запуска. Для использования в ТГ')],

              [sg.Submit('Сохранить'), sg.Submit('Назад'), sg.Cancel('Выход'), sg.Push(), sg.Text('by c0unt_zer0_nc')]
              ]
    global window
    window = sg.Window('Создание файла конфигурации для бэкапера', layout, finalize=True)
    window.TKroot.focus_force()
    while True:
        event, values = window.read()
        if event in (None, 'Exit', 'Выход'):
            break
        if event == 'Назад':
            window.close()
            gui_conf()
        if event == 'Сохранить':
            global src, dst, see, sel, chat_id, name_obj
            src = values[0]
            dst = values[1]
            see = values[2]
            sel = int(see)
            chat_id = values[3]
            name_obj = values[4]
            path = photo_local
            window.close()
            create_Config(path)
            check_conf()
        else:
            print(er_gui)
    return path

# Графический интерфейс для MS SQL Server на FTP
def gui_conf_mssql_ftp():
    global path
    path = 'settings_mssql_ftp.ini'
    sg.theme('Gray Gray Gray')
    layout = [[sg.VPush()],
        [sg.vcenter(sg.Text('MS SQL server')), sg.Push(), sg.InputText(tooltip='Адрес MSSQL сервера')],
        [sg.vcenter(sg.Text('MSSQL имя базы')), sg.Push(), sg.InputText(tooltip='Имя базы данных')],
        [sg.vcenter(sg.Text('ftp сервер')), sg.Push(), sg.InputText(tooltip='Адрес сервера FTP')],
        [sg.vcenter(sg.Text('ftp login')), sg.Push(), sg.InputText(tooltip='Логин сервера FTP')],
        [sg.vcenter(sg.Text('ftp пароль')), sg.Push(), sg.InputText(tooltip='Пароль сервера FTP')],
        [sg.vcenter(sg.Text('Стартовая папка FTP')), sg.Push(), sg.InputText(tooltip='Корневая папка сервера FTP')],
        [sg.vcenter(sg.Text('Кодавая страница FTP')), sg.Push(), sg.InputText(tooltip='Кодовая страница сервера FTP. "utf-8" или "cp1251"')],
        [sg.vcenter(sg.Text('Telegram Chat ID')), sg.Push(), sg.InputText(tooltip='Индентификатор твоего чата в ТГ. Чтобы присылать уведомления')],
        [sg.vcenter(sg.Text('Индификатор обьекта')), sg.Push(), sg.InputText(tooltip='Имя запуска. Для использования в ТГ')],
        [sg.Submit('Сохранить'), sg.Submit('Назад'), sg.Cancel('Выход'), sg.Push(), sg.Text('by c0unt_zer0_nc')]
    ]
    window = sg.Window('Создание файла конфигурации для MS SQL базы', layout, finalize=True)
    window.TKroot.focus_force()
    while True:                             
        event, values = window.read()
        if event in (None, 'Exit', 'Выход'):
            break
        if event == 'Назад':
            window.close()
            gui_conf()
        if event == 'Сохранить':
            global mssqls, mssql_db, ftp, ftp_u, ftp_p, ftp_root, chat_id, cp, name_obj, cipher_ke
            mssqls = values[0]
            mssql_db = values[1]
            ftp = values[2]
            ftp_us = values[3]
            ftp_ub = ftp_us.encode(encoding="utf-8", errors="strict")
            cipher_key = Fernet.generate_key()
            cipher_ke = cipher_key.decode(encoding="utf-8", errors="strict")
            cipher = Fernet(cipher_key)
            ftp_ue = cipher.encrypt(ftp_ub)
            ftp_u = ftp_ue.decode(encoding="utf-8", errors="strict")
            ftp_ps = values[4]
            ftp_pb = ftp_ps.encode(encoding="utf-8", errors="strict")
            ftp_pe = cipher.encrypt(ftp_pb)
            ftp_p = ftp_pe.decode(encoding="utf-8", errors="strict")
            ftp_root = values[5]
            cp = values[6]
            chat_id = values[7]
            name_obj = values[8]
            path = mssql_ftp
            window.close()
            create_Config(path)
            check_conf()
        else:
            print(er_gui)

# Графический интерфейс для MS SQL Server локально
def gui_conf_mssql_local():
    global path
    path = 'settings_mssql_local.ini'
    sg.theme('Gray Gray Gray')
    layout = [[sg.VPush()],
        [sg.vcenter(sg.Text('Папка локального архива')), sg.InputText(tooltip='Куда копировать'), sg.FolderBrowse('Обзор')],
        [sg.vcenter(sg.Text('MS SQL server')), sg.Push(), sg.InputText(tooltip='Адрес MSSQL сервера')],
        [sg.vcenter(sg.Text('MSSQL имя базы')), sg.Push(), sg.InputText(tooltip='Имя базы данных')],
        [sg.vcenter(sg.Text('Telegram Chat ID')), sg.Push(), sg.InputText(tooltip='Индентификатор твоего чата в ТГ. Чтобы присылать уведомления')],
        [sg.vcenter(sg.Text('Индификатор обьекта')), sg.Push(), sg.InputText(tooltip='Имя запуска. Для использования в ТГ')],
        [sg.Submit('Сохранить'), sg.Submit('Назад'), sg.Cancel('Выход'), sg.Push(), sg.Text('by c0unt_zer0_nc')]
    ]
    window = sg.Window('Создание файла конфигурации для MS SQL базы', layout, finalize=True)
    window.TKroot.focus_force()
    while True:
        event, values = window.read()
        if event in (None, 'Exit', 'Выход'):
            break
        if event == 'Назад':
            window.close()
            gui_conf()
        if event == 'Сохранить':
            global dst, mssqls, mssql_db, chat_id, name_obj
            dst = values[0]
            mssqls = values[1]
            mssql_db = values[2]
            chat_id = values[3]
            name_obj = values[4]
            path = mssql_local
            window.close()
            create_Config(path)
            check_conf()
        else:
            print(er_gui)

# Графический интерфейс для 1C на FTP
def gui_conf_1c_ftp():
    global path
    path = 'settings_1c_ftp.ini'
    sg.theme('Gray Gray Gray')
    layout = [[sg.VPush()],
              [sg.vcenter(sg.Text('Папка откуда изначально брать')), sg.InputText(tooltip='Откуда копировать'),
               sg.FolderBrowse('Обзор')],
              [sg.vcenter(sg.Text('Временная папка')), sg.Push(), sg.InputText(tooltip='Временная папка'),
               sg.FolderBrowse('Обзор')],
              [sg.vcenter(sg.Text('ftp сервер')), sg.Push(), sg.InputText(tooltip='Адрес сервера FTP')],
              [sg.vcenter(sg.Text('ftp login')), sg.Push(), sg.InputText(tooltip='Пользователь сервера FTP')],
              [sg.vcenter(sg.Text('ftp пароль')), sg.Push(), sg.InputText(tooltip='Пароль сервера FTP')],
              [sg.vcenter(sg.Text('Стартовая папка FTP')), sg.Push(), sg.InputText(tooltip='Корневая директория FTP')],
              [sg.vcenter(sg.Text('Кодавая страница FTP')), sg.Push(),
               sg.InputText(tooltip='Кодовая страница сервера FTP. "utf-8" или "cp1251"')],
              [sg.vcenter(sg.Text('Telegram Chat ID')), sg.Push(),
               sg.InputText(tooltip='Индентификатор твоего чата в ТГ. Чтобы присылать уведомления')],
              [sg.vcenter(sg.Text('Индификатор обьекта')), sg.Push(),
               sg.InputText(tooltip='Имя запуска. Для использования в ТГ')],

              [sg.Submit('Сохранить'), sg.Submit('Назад'), sg.Cancel('Выход'), sg.Push(), sg.Text('by c0unt_zer0_nc')]
              ]
    global window
    window = sg.Window('Создание файла конфигурации для бэкапера', layout, finalize=True)
    window.TKroot.focus_force()
    while True:
        event, values = window.read()
        if event in (None, 'Exit', 'Выход'):
            window.close()
            break
        if event == 'Назад':
            window.close()
            gui_conf()
        if event == 'Сохранить':
            global src, dst, ftp, ftp_u, ftp_p, ftp_root, see, sel, chat_id, cp, name_obj, cipher_ke
            src = values[0]
            dst = values[1]
            ftp = values[2]
            ftp_us = values[3]
            ftp_ub = ftp_us.encode(encoding="utf-8", errors="strict")
            cipher_key = Fernet.generate_key()
            cipher_ke = cipher_key.decode(encoding="utf-8", errors="strict")
            cipher = Fernet(cipher_key)
            ftp_ue = cipher.encrypt(ftp_ub)
            ftp_u = ftp_ue.decode(encoding="utf-8", errors="strict")
            ftp_ps = values[4]
            ftp_pb = ftp_ps.encode(encoding="utf-8", errors="strict")
            ftp_pe = cipher.encrypt(ftp_pb)
            ftp_p = ftp_pe.decode(encoding="utf-8", errors="strict")
            ftp_root = values[5]
            cp = values[6]
            chat_id = values[7]
            name_obj = values[8]
            path = ftp_1c
            window.close()
            create_Config(path)
            check_conf()
        else:
            print(er_gui)
    return path

# Графический интерфейс для 1C локально
def gui_conf_1c_local():
    global path
    path = 'settings_1c_local.ini'
    sg.theme('Gray Gray Gray')
    layout = [[sg.VPush()],
              [sg.vcenter(sg.Text('Папка откуда изначально брать')), sg.InputText(tooltip='Откуда копировать'),
               sg.FolderBrowse('Обзор')],
              [sg.vcenter(sg.Text('Папка куда копировать')), sg.Push(), sg.InputText(tooltip='Локальная папка архива'),
               sg.FolderBrowse('Обзор')],
              [sg.vcenter(sg.Text('Telegram Chat ID')), sg.Push(),
               sg.InputText(tooltip='Индентификатор твоего чата в ТГ. Чтобы присылать уведомления')],
              [sg.vcenter(sg.Text('Индификатор обьекта')), sg.Push(),
               sg.InputText(tooltip='Имя запуска. Для использования в ТГ')],

              [sg.Submit('Сохранить'), sg.Submit('Назад'), sg.Cancel('Выход'), sg.Push(), sg.Text('by c0unt_zer0_nc')]
              ]
    global window
    window = sg.Window('Создание файла конфигурации для бэкапера', layout, finalize=True)
    window.TKroot.focus_force()
    while True:
        event, values = window.read()
        if event in (None, 'Exit', 'Выход'):
            window.close()
            break
        if event == 'Назад':
            window.close()
            gui_conf()
        if event == 'Сохранить':
            global src, dst, chat_id, name_obj
            src = values[0]
            dst = values[1]
            chat_id = values[2]
            name_obj = values[3]
            path = local_1c
            window.close()
            create_Config(path)
            check_conf()
        else:
            print(er_gui)
    return path

# Создаем файл конфигурации
def create_Config(path):
    global config
    if path == 'settings_mssql_ftp.ini':
        config = configparser.ConfigParser()
        config.add_section("System")
        config.add_section("MS SQL")
        config.add_section("FTP")
        config.add_section("Telegram")
        config.set("System", "Ключ", (cipher_ke))
        config.set("System", "Имя обьекта", name_obj)
        config.set("Telegram", "chat_id", chat_id)
        config.set("FTP", "ftp_server", ftp)
        config.set("FTP", "ftp_username", ftp_u)
        config.set("FTP", "ftp_pass", ftp_p)
        config.set("FTP", "ftp_root", ftp_root)
        config.set("FTP", "cp", cp)
        config.set("MS SQL", "Адрес подключения к MS SQL Server", mssqls)
        config.set("MS SQL", "Имя базы данных MS SQL", mssql_db)
        with open(path, "w") as config_file:
            config.write(config_file)

    if path == 'settings_mssql_local.ini':
        config = configparser.ConfigParser()
        config.add_section("MS SQL")
        config.add_section("System")
        config.add_section("Telegram")
        config.set("System", "Имя обьекта", name_obj)
        config.set("System", "Папка локального архива", dst)
        config.set("Telegram", "chat_id", chat_id)
        config.set("MS SQL", "Адрес подключения к MS SQL Server", mssqls)
        config.set("MS SQL", "Имя базы данных MS SQL", mssql_db)
        with open(path, "w") as config_file:
            config.write(config_file)

    if path == 'settings_photo_ftp.ini':
        config = configparser.ConfigParser()
        config.add_section("System")
        config.add_section("FTP")
        config.add_section("Telegram")
        config.set("System", "Ключ", (cipher_ke))
        config.set("System", "Имя обьекта", name_obj)
        config.set("System", "days_before", see)
        config.set("System", "src_dir", src)
        config.set("System", "dst_dir", dst)
        config.set("Telegram", "chat_id", chat_id)
        config.set("FTP", "ftp_server", ftp)
        config.set("FTP", "ftp_username", ftp_u)
        config.set("FTP", "ftp_pass", ftp_p)
        config.set("FTP", "ftp_root", ftp_root)
        config.set("FTP", "cp", cp)
        with open(path, "w") as config_file:
            config.write(config_file)

    if path == 'settings_photo_local.ini':
        config = configparser.ConfigParser()
        config.add_section("System")
        config.add_section("Telegram")
        config.set("System", "Имя обьекта", name_obj)
        config.set("System", "days_before", see)
        config.set("System", "src_dir", src)
        config.set("System", "dst_dir", dst)
        config.set("Telegram", "chat_id", chat_id)
        with open(path, "w") as config_file:
            config.write(config_file)

    if path == 'settings_1c_ftp.ini':
        config = configparser.ConfigParser()
        config.add_section("System")
        config.add_section("FTP")
        config.add_section("Telegram")
        config.set("System", "Ключ", (cipher_ke))
        config.set("System", "Имя обьекта", name_obj)
        config.set("System", "src_dir", src)
        config.set("System", "dst_dir", dst)
        config.set("Telegram", "chat_id", chat_id)
        config.set("FTP", "ftp_server", ftp)
        config.set("FTP", "ftp_username", ftp_u)
        config.set("FTP", "ftp_pass", ftp_p)
        config.set("FTP", "ftp_root", ftp_root)
        config.set("FTP", "cp", cp)
        with open(path, "w") as config_file:
            config.write(config_file)

    if path == 'settings_1c_local.ini':
        config = configparser.ConfigParser()
        config.add_section("System")
        config.add_section("Telegram")
        config.set("System", "Имя обьекта", name_obj)
        config.set("System", "src_dir", src)
        config.set("System", "dst_dir", dst)
        config.set("Telegram", "chat_id", chat_id)
        with open(path, "w") as config_file:
            config.write(config_file)

# Читаем конфигурацию
def read_conf(path):
    global mssqls, mssql_db, ftp, ftp_u, ftp_p, ftp_root, see, sel, chat_id, src, dst, cp, name_obj
    if path == 'settings_mssql_ftp.ini':
        config = configparser.ConfigParser()
        config.read(path)
        name_obj = config.get("System", "Имя обьекта")
        mssqls = config.get("MS SQL", "Адрес подключения к MS SQL Server")
        mssql_db = config.get("MS SQL", "Имя базы данных MS SQL")
        ftp = config.get("FTP", "ftp_server")
        cipher_ke = config.get("System", "Ключ")
        ftp_us = config.get("FTP", "ftp_username")
        cipher_key = cipher_ke.encode(encoding="utf-8", errors="strict")
        cipher = Fernet(cipher_key)
        ftp_ud = ftp_us.encode(encoding="utf-8", errors="strict")
        ftp_ub = cipher.decrypt(ftp_ud)
        ftp_u = ftp_ub.decode(encoding="utf-8", errors="strict")
        ftp_ps = config.get("FTP", "ftp_pass")
        ftp_pd = ftp_ps.encode(encoding="utf-8", errors="strict")
        ftp_pb = cipher.decrypt(ftp_pd)
        ftp_p = ftp_pb.decode(encoding="utf-8", errors="strict")
        ftp_root = config.get("FTP", "ftp_root")
        cp = config.get("FTP", "cp")
        chat_id = config.get("Telegram", "chat_id")

    if path == 'settings_mssql_local.ini':
        config = configparser.ConfigParser()
        config.read(path)
        name_obj = config.get("System", "Имя обьекта")
        mssqls = config.get("MS SQL", "Адрес подключения к MS SQL Server")
        mssql_db = config.get("MS SQL", "Имя базы данных MS SQL")
        dst = config.get("System", "Папка локального архива")
        chat_id = config.get("Telegram", "chat_id")

    if path == 'settings_photo_ftp.ini':
        config = configparser.ConfigParser()
        config.read(path)
        name_obj = config.get("System", "Имя обьекта")
        src = config.get("System", "src_dir") + '/'
        dst = config.get("System", "dst_dir") + '/'
        ftp = config.get("FTP", "ftp_server")
        cipher_ke = config.get("System", "Ключ")
        ftp_us = config.get("FTP", "ftp_username")
        cipher_key = cipher_ke.encode(encoding="utf-8", errors="strict")
        cipher = Fernet(cipher_key)
        ftp_ud = ftp_us.encode(encoding="utf-8", errors="strict")
        ftp_ub = cipher.decrypt(ftp_ud)
        ftp_u = ftp_ub.decode(encoding="utf-8", errors="strict")
        ftp_ps = config.get("FTP", "ftp_pass")
        ftp_pd = ftp_ps.encode(encoding="utf-8", errors="strict")
        ftp_pb = cipher.decrypt(ftp_pd)
        ftp_p = ftp_pb.decode(encoding="utf-8", errors="strict")
        ftp_root = config.get("FTP", "ftp_root")
        cp = config.get("FTP", "cp")
        see = config.get("System", "days_before")
        sel = int(see)
        chat_id = config.get("Telegram", "chat_id")

    if path == 'settings_photo_local.ini':
        config = configparser.ConfigParser()
        config.read(path)
        name_obj = config.get("System", "Имя обьекта")
        src = config.get("System", "src_dir") + '/'
        dst = config.get("System", "dst_dir") + '/'
        see = config.get("System", "days_before")
        sel = int(see)
        chat_id = config.get("Telegram", "chat_id")

    if path == 'settings_1c_ftp.ini':
        config = configparser.ConfigParser()
        config.read(path)
        name_obj = config.get("System", "Имя обьекта")
        src = config.get("System", "src_dir") + '/'
        dst = config.get("System", "dst_dir") + '/'
        ftp = config.get("FTP", "ftp_server")
        cipher_ke = config.get("System", "Ключ")
        ftp_us = config.get("FTP", "ftp_username")
        cipher_key = cipher_ke.encode(encoding="utf-8", errors="strict")
        cipher = Fernet(cipher_key)
        ftp_ud = ftp_us.encode(encoding="utf-8", errors="strict")
        ftp_ub = cipher.decrypt(ftp_ud)
        ftp_u = ftp_ub.decode(encoding="utf-8", errors="strict")
        ftp_ps = config.get("FTP", "ftp_pass")
        ftp_pd = ftp_ps.encode(encoding="utf-8", errors="strict")
        ftp_pb = cipher.decrypt(ftp_pd)
        ftp_p = ftp_pb.decode(encoding="utf-8", errors="strict")
        ftp_root = config.get("FTP", "ftp_root")
        cp = config.get("FTP", "cp")
        chat_id = config.get("Telegram", "chat_id")

    if path == 'settings_1c_local.ini':
        config = configparser.ConfigParser()
        config.read(path)
        name_obj = config.get("System", "Имя обьекта")
        src = config.get("System", "src_dir") + '/'
        dst = config.get("System", "dst_dir") + '/'
        chat_id = config.get("Telegram", "chat_id")

# Проверка активного процесса
def process_exists(process_name):
    progs = str(subprocess.check_output('tasklist'))
    if process_name in progs:
        os.system(killproc)
        if process_name in progs:
            process_exists(process_name)
    #return process_name

# Создаем локальную копию
def copylocal(folder1, folder2):
    global flcount, dlcount
    tod = datetime.datetime.now()
    for i in range(0, sel):
        templist = [0, 'Январь', 'Февраль', 'Март', 'Апрель', 'Май', 'Июнь', 'Июль', 'Август', 'Сентябрь', 'Октябрь', 'Ноябрь', 'Декабрь']
        D = datetime.timedelta(days = i)
        a = tod - D
        ymd = a.strftime('%Y-%m-%d')     
        Y = a.strftime('%Y' + 'г')      
        M = a.strftime('%m')
        mmm = a.month
        DD = a.day
        YY = a.strftime('%Y')
        yMd = YY + '-' + str(mmm) + '-' + str(DD)
        mm = templist[mmm]
        B = a.strftime('%d')            
        srcdir = os.listdir(folder1)
        dstdir = os.listdir(folder2)
        if not ymd in srcdir:           
            pass                        
        else:                           
            def makedir(folder2):
                dstdir = os.listdir(folder2)
                if not Y in dstdir:         
                    print('папки нет, но сейчас организуем')            
                    os.mkdir(folder2 + Y)                               
                    folder2 = folder2 + Y + '/'                            
                    dstdir = os.listdir(folder2)                                                           
                else:
                    folder2 = folder2 + Y + '/'                          
                    dstdir = os.listdir(folder2)                           
                if not mm in dstdir:                                    
                    os.mkdir(folder2  + mm)                               
                    folder2 = folder2 + mm + '/'                        
                    dstdir = os.listdir(folder2)                        
                else:
                    folder2 = folder2+ mm + '/'                         
                    dstdir = os.listdir(folder2)                        
                if not yMd in dstdir:                                       
                    os.mkdir(folder2 + yMd)
                    global dlcount
                    dlcount += 1
                    folder2 = folder2 + yMd + '/'                       
                    dstdir = os.listdir(folder2)                    
                    print(folder2)
                    global flcount
                    for z in list(os.listdir(src + ymd)):              
                        if not z in list(os.listdir(folder2)):    
                            shutil.copy2(folder1 + ymd + '/' + z, folder2 + z)   
                            print('скопирован файл: ' + z)
                            flcount += 1
                        else:                                           
                            print('файл существует: ' + z)           
                else:
                    folder2 = folder2 + yMd + '/'                         
                    dstdir = os.listdir(folder2)                        
                    print(folder2)
                    for z in list(os.listdir(src + ymd)):               
                        if not z in list(os.listdir(folder2)):    
                            shutil.copy2(folder1 + ymd + '/' + z, folder2 + z)   
                            print('скопирован файл: ' + z)
                            flcount += 1
                        else:                                           
                            print('файл существует: ' + z)
                return folder2
            makedir(folder2)

# Получаем дату для MSSQL_DB
def date_time():
    global tod, ymd, y, m, mmm, mm, D, H, M, data_full, yMD, yMd
    tod = datetime.datetime.now()
    templist = [0, 'Январь', 'Февраль', 'Март', 'Апрель', 'Май', 'Июнь', 'Июль', 'Август', 'Сентябрь', 'Октябрь', 'Ноябрь', 'Декабрь']
    a = tod
    ymd = a.strftime('%Y-%m-%d')
    H = a.strftime ('%H')
    M = a.strftime ('%M')
    YY = a.strftime('%Y') 
    y = a.strftime('%Y' + 'г')      
    m = a.strftime('%m')
    mmm = a.month
    mm = templist[mmm]
    D = a.strftime('%d')
    data_full = ymd + '_' + H + '-' + M
    DD = a.day
    yMD = YY + '-' + m + '-' + str(DD)
    yMd = YY + '-' + str(mmm) + '-' + str(DD)

# Копируем MSSQL DB
def copy_mssql():
    global fname, fdate
    cnxn = pyodbc.connect('DRIVER={SQL Server};SERVER='+mssqls+';Trusted_Connection=yes')
    cnxn.autocommit = True
    cursor = cnxn.cursor()
    cursor.execute("select name from sys.databases")
    databases = cursor.fetchall()
    cursor.close()
    cursor = cnxn.cursor()
    if mssql_db + '.bak' in os.listdir(location + '/' + mssql_db):
        os.remove(location + '/' + mssql_db + '/' + mssql_db + '.bak')
        shutil.rmtree(location + '/' + mssql_db)
    else:
        fname = location + "\\" + mssql_db + "\\" + mssql_db + '.bak'
        fdate = data_full
        backup = "BACKUP DATABASE [" + mssql_db + "] TO DISK = N'" + location + "\\" + mssql_db + "\\" + mssql_db + ".bak'"
        cursor.execute(backup)
        while cursor.nextset():
            pass
        cursor.close()
        cnxn.close()

# Архивируем MSSQL DB
def zipper():
    archive_name = data_full + '-' + mssql_db
    source_dir = location + '/' + mssql_db + '/'
    shutil.make_archive(archive_name, format="zip", root_dir=source_dir)

# класс загрузки папок и файлов на ftp
class FtpUploadFolder():
    def __init__(self, server, user, passwd, catalog):
        self.fcount = 0
        self.dcount = 0
        self.ftp = ftplib.FTP(server, user, passwd, encoding=cp)
        self.ftp.cwd(catalog)

    def uploadOne(self, new_name, path_name):
        self.ftp.storbinary('STOR ' + new_name, open(path_name, 'rb'))

    def uploadDir(self, localdir):
        tod = datetime.datetime.now()
        for i in range(0, sel):
            templist = [0, 'Январь', 'Февраль', 'Март', 'Апрель', 'Май', 'Июнь', 'Июль', 'Август', 'Сентябрь', 'Октябрь', 'Ноябрь', 'Декабрь']
            D = datetime.timedelta(days = i)
            a = tod - D
            ymd = a.strftime('%Y-%m-%d')     
            Y = a.strftime('%Y' + 'г')      
            M = a.strftime('%m')
            mmm = a.month
            DD = a.day
            YY = a.strftime('%Y')
            yMd = YY + '-' + str(mmm) + '-' + str(DD)
            mm = templist[mmm]
            B = a.strftime('%d')
            localdir = dst
            ftp_root2 = ftp_root
            localsrc = os.listdir(localdir)
            self.ftp.cwd(ftp_root2)
            ftpsrc = self.ftp.nlst()
            if not Y in localsrc:
                pass
            else:
                localdir = localdir + Y + '/'
                localfiles = os.listdir(localdir)
            if not mm in localfiles:
                pass
            else:
                localdir = localdir + mm + '/'
                localfiles = os.listdir(localdir)
            if not yMd in localfiles:
                pass
            else:
                localdir = localdir + yMd + '/'
                localfiles = os.listdir(localdir)
                ftpsrc = self.ftp.nlst()
            if Y in ftpsrc:
                ftp_root2 = ftp_root2 + Y + '/'
                self.ftp.cwd(ftp_root2)
                ftpsrc = self.ftp.nlst()
            else:
                self.ftp.mkd(Y)
                print('Папка на FTP создана', Y)
                self.dcount += 1
                ftp_root2 = ftp_root2 + Y + '/'
                self.ftp.cwd(ftp_root2)
                ftpsrc = self.ftp.nlst()
            if mm in ftpsrc:
                ftp_root2 = ftp_root2 + mm + '/'
                self.ftp.cwd(ftp_root2)
                ftpsrc = self.ftp.nlst()
            else:
                self.ftp.mkd(mm)
                print('Папка на FTP создана', mm)
                self.dcount += 1
                ftp_root2 = ftp_root2 + mm + '/'
                self.ftp.cwd(ftp_root2)
                ftpsrc = self.ftp.nlst()
            if yMd in ftpsrc:
                ftp_root2 = ftp_root2 + yMd + '/'
                self.ftp.cwd(ftp_root2)
                ftpsrc = self.ftp.nlst()
            else:
                self.ftp.mkd(yMd)
                print('Папка на FTP создана', yMd)
                self.dcount += 1
                ftp_root2 = ftp_root2 + yMd + '/'
                self.ftp.cwd(ftp_root2)
                ftpsrc = self.ftp.nlst()
            for localname in localfiles:
                localpath = os.path.join(localdir, localname)
                if not os.path.isdir(localpath):
                    if localname in self.ftp.nlst():
                        print("файл на FTP существует " + localname)
                    else:
                        print('файл на FTP загружен', localname)
                        self.uploadOne(localname, localpath)
                        self.fcount += 1

    def upload_MSSQL(self, localdir):
        global YMD
        a = datetime.datetime.now()
        localdir = localedir
        templist = [0, 'Январь', 'Февраль', 'Март', 'Апрель', 'Май', 'Июнь', 'Июль', 'Август', 'Сентябрь', 'Октябрь', 'Ноябрь', 'Декабрь']
        Y = a.strftime('%Y' + 'г')
        mmm = a.month
        DD = a.day
        YY = a.strftime('%Y')
        yMd = YY + '-' + m + '-' + str(DD)
        YMD = str(YY) + '-' + str(mmm) + '-' + str(DD)
        mm = templist[mmm]
        localdir = localedir
        ftp_root2 = ftp_root
        localsrc = os.listdir(localdir)
        self.ftp.cwd(ftp_root2)
        ftpsrc = self.ftp.nlst()
        localfiles = os.listdir(localdir)
        if not yMd in localfiles:
            pass
        else:
            localdir = localdir + yMd + '/'
            localfiles = os.listdir(localdir)
            ftpsrc = self.ftp.nlst()
        if Y in ftpsrc:
            ftp_root2 = ftp_root2 + Y + '/'
            self.ftp.cwd(ftp_root2)
            ftpsrc = self.ftp.nlst()
        else:
            self.ftp.mkd(Y)
            print('Папка на FTP создана', Y)
            self.dcount += 1
            ftp_root2 = ftp_root2 + Y + '/'
            self.ftp.cwd(ftp_root2)
            ftpsrc = self.ftp.nlst()
        if mm in ftpsrc:
            ftp_root2 = ftp_root2 + mm + '/'
            self.ftp.cwd(ftp_root2)
            ftpsrc = self.ftp.nlst()
        else:
            self.ftp.mkd(mm)
            print('Папка на FTP создана', mm)
            self.dcount += 1
            ftp_root2 = ftp_root2 + mm + '/'
            self.ftp.cwd(ftp_root2)
            ftpsrc = self.ftp.nlst()
        for localname in localfiles:
            localpath = os.path.join(localdir, localname)
            if not os.path.isdir(localpath):
                if localname in self.ftp.nlst():
                    print("файл на FTP существует " + localname)
                else:
                    print('файл на FTP загружен', localname)
                    self.uploadOne(localname, localpath)
                    self.fcount += 1

    def upload_1c(self, localdir):
        tod = datetime.datetime.now()
        templist = [0, 'Январь', 'Февраль', 'Март', 'Апрель', 'Май', 'Июнь', 'Июль', 'Август', 'Сентябрь', 'Октябрь', 'Ноябрь', 'Декабрь']
        a = tod
        ymd = a.strftime('%Y-%m-%d')
        Y = a.strftime('%Y' + 'г')
        M = a.strftime('%m')
        mmm = a.month
        DD = a.day
        YY = a.strftime('%Y')
        yMd = YY + '-' + str(mmm) + '-' + str(DD)
        mm = templist[mmm]
        B = a.strftime('%d')
        localdir = dst
        ftp_root2 = ftp_root
        localsrc = os.listdir(localdir)
        self.ftp.cwd(ftp_root2)
        ftpsrc = self.ftp.nlst()
        if not Y in localsrc:
            pass
        else:
            localdir = localdir + Y + '/'
            localfiles = os.listdir(localdir)
        if not mm in localfiles:
            pass
        else:
            localdir = localdir + mm + '/'
            localfiles = os.listdir(localdir)
            ftpsrc = self.ftp.nlst()
        if Y in ftpsrc:
            ftp_root2 = ftp_root2 + Y + '/'
            self.ftp.cwd(ftp_root2)
            ftpsrc = self.ftp.nlst()
        else:
            self.ftp.mkd(Y)
            print('Папка на FTP создана', Y)
            self.dcount += 1
            ftp_root2 = ftp_root2 + Y + '/'
            self.ftp.cwd(ftp_root2)
            ftpsrc = self.ftp.nlst()
        if mm in ftpsrc:
            ftp_root2 = ftp_root2 + mm + '/'
            self.ftp.cwd(ftp_root2)
            ftpsrc = self.ftp.nlst()
        else:
            self.ftp.mkd(mm)
            print('Папка на FTP создана', mm)
            self.dcount += 1
            ftp_root2 = ftp_root2 + mm + '/'
            self.ftp.cwd(ftp_root2)
            ftpsrc = self.ftp.nlst()
        for localname in localfiles:
            localpath = os.path.join(localdir, localname)
            if not os.path.isdir(localpath):
                if localname in self.ftp.nlst():
                    print("файл на FTP существует " + localname)
                else:
                    print('файл на FTP загружен', localname)
                    self.uploadOne(localname, localpath)
                    self.fcount += 1

        
    def close(self):
        self.ftp.quit()
        global fcount, dcount
        fcount = self.fcount
        dcount = self.dcount
        print('uploaded files: ', self.fcount)

# выгрузка на облако
# options = {'webdav_hostname': 'https://sbptg.ru/','webdav_login': 'labushkin.alexandr','webdav_password': 'Rhbgnjyjvbrjy21'}
# client = Client(options)
# root = '/remote.php/webdav/'
# local = 'd:/test/'
# web_dir = root + 'test' + '/'
# dir = client.list(root)
# def uploadfile_to_cloud(localdir):
#     global web_dir, fcount, dcount
#     localfiles = os.listdir(localdir)
#     for localname in localfiles:
#         localpath = os.path.join(localdir, localname)
#         if not os.path.isdir(localpath):
#             if not client.check(web_dir + localname):
#                 client.upload(web_dir + localname, localpath)
#                 print('Файл загрузили ', localname)
#                 fcount += 1
#             else:
#                 print('Файл существует', localname)
#         else:
#             try:
#                 if not client.check(web_dir + localname):
#                     client.mkdir(web_dir + localname)
#                     print('Папка создана', localname)
#                     dcount += 1
#                     web_dir = web_dir + localname + '/'
#                 else:
#                     web_dir = web_dir + localname + '/'
#                     print('Папка существует', localname)
#             except:
#                 print('все')
#             uploadfile(localpath)
# uploadfile(local)

# выгрузка MS SQL на FTP
def mssql_ftp_upload():
    global localedir
    date_time()
    if mssql_db in location:
        shutil.rmtree(location + '\\' + mssql_db)
    else:
        os.mkdir(location + '\\' + mssql_db)
        print('Создаем локальную копию')
        copy_mssql()
        print('Архивируем')
        zipper()
        print('Убираемся')
        os.remove(location + '\\' + mssql_db + '\\' + mssql_db + '.bak')
        shutil.move(fdate + '-' + mssql_db + '.zip', location + '\\' + mssql_db + '\\' + fdate + '-' + mssql_db + '.zip')
        localedir = location + '\\' + mssql_db + '\\'
        print('Запускаю копирование на FTP')
        f = FtpUploadFolder(ftp, ftp_u, ftp_p, ftp_root)
        f.upload_MSSQL(localedir)
        f.close()
        print('Закончил копирование на FTP. Собираю монатки и сваливаю')
        shutil.rmtree(location + '//' + mssql_db)
        bot = telebot.TeleBot(token)
        bot.send_message(chat_id, "Бэкап БД MSSQL на обьекте " + name_obj + " закончен. Результат: " + ' На FTP скопированно новых файлов: ' + str(fcount))

# выгрузка MS SQL локально
def mssql_local_upload():
    #global localedir
    date_time()
    if mssql_db in location:
        shutil.rmtree(location + '\\' + mssql_db)
    else:
        os.mkdir(location + '\\' + mssql_db)
        print('Создаем локальную копию')
        copy_mssql()
        print('Архивируем')
        zipper()
        print('Убираемся')
        os.remove(location + '\\' + mssql_db + '\\' + mssql_db + '.bak')
        shutil.move(fdate + '-' + mssql_db + '.zip', dst + '\\' + name_obj + '\\' + y + '\\' + mm + '\\' + fdate + '-' + mssql_db + '.zip')
        #localedir = location + '\\' + mssql_db + '\\'
        print('Закончил копирование. Собираю монатки и сваливаю')
        shutil.rmtree(location + '//' + mssql_db)
        bot = telebot.TeleBot(token)
        bot.send_message(chat_id, "Бэкап БД MSSQL на обьекте " + name_obj + " закончен.")

# выгрузка Фото на FTP
def photo_ftp_upload():
    if photo_ftp in os.listdir():
        print('Создаем локальную копию')
        copylocal(src, dst)
        print('Запускаю копирование на FTP')
        f = FtpUploadFolder(ftp, ftp_u, ftp_p, ftp_root)
        f.uploadDir(dst)
        f.close()
        print('Закончил копирование на FTP. Собираю монатки и сваливаю')
        bot = telebot.TeleBot(token)
        bot.send_message(chat_id,
                         "Бэкап фотофиксации весовой на обьекте " + name_obj +
                         " закончен. Результат: Локально создано новых папок: " +
                         str(dlcount) + " Локально скопированно новых файлов: " +
                         str(flcount) + " На FTP созданно новых папок: " + str(dcount) +
                         ' На FTP скопированно новых файлов: ' + str(fcount))

# выгрузка Фото локально
def photo_local_upload():
    if photo_local in os.listdir():
        print('Создаем локальную копию')
        copylocal(src, dst)
        print('Закончил копирование на FTP. Собираю монатки и сваливаю')
        bot = telebot.TeleBot(token)
        bot.send_message(chat_id,
                         "Бэкап фотофиксации весовой на обьекте " + name_obj +
                         " закончен. Результат: Локально создано новых папок: " + str(
                             dlcount) + " Локально скопированно новых файлов: " + str(
                             flcount))

# выгрузка 1C на FTP
def ftp_1c_upload():
    if ftp_1c in os.listdir():
        process_exists(process_name)
        date_time()
        archive_name = data_full
        print('Архивируем')
        shutil.make_archive(archive_name, format="zip", root_dir=src)
        if not y in os.listdir(dst):
            os.mkdir(dst + '/' + y)
        if not mm in os.listdir(dst + '/' + y):
            os.mkdir(dst + '/' + y + '/' + mm)
        shutil.move(archive_name + '.zip', dst + '/' + y + '/' + mm + '/' + archive_name + '.zip')
        print('Запускаю копирование на FTP')
        f = FtpUploadFolder(ftp, ftp_u, ftp_p, ftp_root)
        dst_new = dst + '/' + y + '/' + mm
        f.upload_1c(dst_new)
        f.close()
        shutil.rmtree(dst + '/' + y)
        print('Закончил копирование на FTP. Собираю монатки и сваливаю')
        bot = telebot.TeleBot(token)
        bot.send_message(chat_id,
                         "Бэкап 1C на обьекте " + name_obj +
                         " закончен. Результат: На FTP созданно новых папок: " + str(dcount) +
                         " На FTP скопированно новых файлов: " + str(fcount))

# выгрузка 1C локально
def local_1c_upload():
    if local_1c in os.listdir():
        process_exists(process_name)
        date_time()
        archive_name = data_full
        print('Архивируем')
        shutil.make_archive(archive_name, format="zip", root_dir=src)
        print('Создаем локальную копию')
        if not y in os.listdir(dst):
            os.mkdir(dst + '\\' + y)
        if not mm in os.listdir(dst + '\\' + y):
            os.mkdir(dst + '\\' + y + '\\' + mm)
        shutil.move(archive_name + '.zip', dst + '\\' + y + '\\' + mm + '\\' + archive_name + '.zip')
        print('Закончил копирование. Собираю монатки и сваливаю')
        bot = telebot.TeleBot(token)
        bot.send_message(chat_id,
                         "Бэкап 1C на обьекте " + name_obj + " закончен.")

# Проверка файла конфигурации
def check_conf():
    global path
    if photo_ftp in os.listdir():
        path = photo_ftp
        print('Фото на FTP')
        read_conf(path)
        photo_ftp_upload()
    else:
        if photo_local in os.listdir():
            path = photo_local
            print('Фото локально')
            read_conf(path)
            photo_local_upload()
        else:
            if mssql_ftp in os.listdir():
                path = mssql_ftp
                print('MS SQL на FTP')
                read_conf(path)
                mssql_ftp_upload()
            else:
                if mssql_local in os.listdir():
                    path = mssql_local
                    print('MS SQL локально')
                    read_conf(path)
                    mssql_local_upload()
                else:
                    if ftp_1c in os.listdir():
                        path = ftp_1c
                        print('1C на FTP')
                        read_conf(path)
                        ftp_1c_upload()
                    else:
                        if local_1c in os.listdir():
                            path = local_1c
                            print('1C локально')
                            read_conf(path)
                            local_1c_upload()
                        else:
                            gui_conf()

check_conf()


