import configparser
import os
import PySimpleGUI as sg
import shutil
import datetime
import ftplib
import telebot
import pyodbc
from cryptography.fernet import Fernet

#os.chdir('D:/')
token = '6197644867:AAGqBg-SFQc8JAAr6zA6duVv_F-bdRiq_Gg'
photo = 'settings_photo.ini'
mssql = 'settings_mssql.ini'
location = os.getcwd()

#source_dir = location + '/' + mssql_db + '/'
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
    layout = [
        [sg.Text('Что планируем копировать?')],
        [sg.Submit('Photo'), sg.Submit('MS SQL DB'), sg.Submit('Mysql DB'), sg.Submit('1С ВесыСофт'), sg.Cancel('Выход'), sg.Text('by c0unt_zer0_nc')]
    ]
    #global windows
    window = sg.Window('Создание файла конфигурации для бэкапера', layout)
    while True:                             
        event, values = window.read()
        if event == 'Выход':
            window.close()
        if event == window.close():
            break
        if event == 'Photo':
            window.close()
            gui_conf_photo()
        if event == 'MS SQL DB':
            window.close()
            gui_conf_mssql()

    # Графический интерфейс для Фотофиксации
def gui_conf_photo():
    global path
    path = 'settings_photo.ini'
    sg.theme('Gray Gray Gray')
    layout = [
        [sg.Text('Папка откуда изначально брать '), sg.InputText(), sg.FolderBrowse('Обзор')],
        [sg.Text('Папка куда копировать              '), sg.InputText(), sg.FolderBrowse('Обзор')],
        [sg.Text('ftp сервер                                  '), sg.InputText()],
        [sg.Text('ftp login                                      '), sg.InputText()],
        [sg.Text('ftp пароль                                  '), sg.InputText()],
        [sg.Text('Стартовая папка FTP                 '), sg.InputText()],
        [sg.Text('Кодавая страница FTP               '), sg.InputText()],
        [sg.Text('Рекурсия проверки файлов дней'), sg.InputText()],
        [sg.Text('Telegram Chat ID                        '), sg.InputText()],
        [sg.Text('Индификатор обьекта                '), sg.InputText()],
    
        [sg.Submit('Сохранить'), sg.Cancel('Выход'), sg.Text('                                                                                  by c0unt_zer0_nc')]
    ]
    global window
    window = sg.Window('Создание файла конфигурации для бэкапера', layout)
    while True:                             
        event, values = window.read()
        if event in (None, 'Exit', 'Выход'):
            break
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
#            cipher_key = Fernet.generate_key()
#            cipher_ke = cipher_key.decode(encoding="utf-8", errors="strict")
#            cipher = Fernet(cipher_key)
            ftp_pe = cipher.encrypt(ftp_pb)
            ftp_p = ftp_pe.decode(encoding="utf-8", errors="strict")
            ftp_root = values[5]
            cp = values[6]
            see = values[7]
            sel = int(see)
            chat_id = values[8]
            name_obj = values[9]
            path = photo
            window.close()
            create_Config(path)
            check_conf()
        else:
            print('что то не так')
    return path

    # Графический интерфейс для MS SQL Server
def gui_conf_mssql():
    global path
    path = 'settings_mssql.ini'
    sg.theme('Gray Gray Gray')
    layout = [
        [sg.Text('MS SQL server                         '), sg.InputText()],
        [sg.Text('MSSQL имя базы                     '), sg.InputText()],
        [sg.Text('ftp сервер                                '), sg.InputText()],
        [sg.Text('ftp login                                    '), sg.InputText()],
        [sg.Text('ftp пароль                                '), sg.InputText()],
        [sg.Text('Стартовая папка FTP                '), sg.InputText()],
        [sg.Text('Кодавая страница FTP              '), sg.InputText()],
        [sg.Text('Telegram Chat ID                       '), sg.InputText()],
        [sg.Text('Индификатор обьекта                '), sg.InputText()],
    
        [sg.Submit('Сохранить'), sg.Cancel('Выход'), sg.Text('                                                                                  by c0unt_zer0_nc')]
    ]
    #global window
    window = sg.Window('Создание файла конфигурации для MS SQL базы', layout)
    while True:                             
        event, values = window.read()
        if event == 'Выход':
            window.close()
        if event == window.close():
            break
        else:
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
                #            cipher_key = Fernet.generate_key()
                #            cipher_ke = cipher_key.decode(encoding="utf-8", errors="strict")
                #            cipher = Fernet(cipher_key)
                ftp_pe = cipher.encrypt(ftp_pb)
                ftp_p = ftp_pe.decode(encoding="utf-8", errors="strict")
                ftp_root = values[5]
                cp = values[6]
                chat_id = values[7]
                name_obj = values[8]
                path = mssql
                window.close()
                create_Config(path)
                check_conf()
                pass
            else:
                print('что то не так')
                
    # Cоздания конфиг. файла.
def create_Config(path):
    global config
    if path == 'settings_mssql.ini':
        config = configparser.ConfigParser()
        config.add_section("Settings")
        config.add_section("FTP")
        config.add_section("Telegram")
        config.set("Settings", "cipher", (cipher_ke))
        config.set("Settings", "name_obj", name_obj)
        config.set("Telegram", "chat_id", chat_id)
        config.set("FTP", "ftp_server", ftp)
        config.set("FTP", "ftp_username", ftp_u)
        config.set("FTP", "ftp_pass", ftp_p)
        config.set("FTP", "ftp_root", ftp_root)
        config.set("FTP", "cp", cp)
        config.set("Settings", "mssqls", mssqls)
        config.set("Settings", "mssql_db", mssql_db)
        with open(path, "w") as config_file:
            config.write(config_file)
    if path == 'settings_photo.ini':
        config = configparser.ConfigParser()
        config.add_section("Settings")
        config.add_section("FTP")
        config.add_section("Telegram")
        config.set("Settings", "cipher", (cipher_ke))
        config.set("Settings", "name_obj", name_obj)
        config.set("Telegram", "chat_id", chat_id)
        config.set("FTP", "ftp_server", ftp)
        config.set("FTP", "ftp_username", ftp_u)
        config.set("FTP", "ftp_pass", ftp_p)
        config.set("FTP", "ftp_root", ftp_root)
        config.set("FTP", "cp", cp)
        config.set("Settings", "days_before", see)
        config.set("Settings", "src_dir", src)
        config.set("Settings", "dst_dir", dst)
        with open(path, "w") as config_file:
            config.write(config_file)

    # Читаем конфигурацию
def read_conf(path):
    global mssqls, mssql_db, ftp, ftp_u, ftp_p, ftp_root, see, sel, chat_id, src, dst, cp, name_obj
    if path == 'settings_mssql.ini':
        config = configparser.ConfigParser()
        config.read(path)
        name_obj = config.get("Settings", "name_obj")
        mssqls = config.get("Settings", "mssqls")
        mssql_db = config.get("Settings", "mssql_db")
        ftp = config.get("FTP", "ftp_server")
        cipher_ke = config.get("Settings", "cipher")
        ftp_us = config.get("FTP", "ftp_username")
        cipher_key = cipher_ke.encode(encoding="utf-8", errors="strict")
        cipher = Fernet(cipher_key)
        ftp_ud = ftp_us.encode(encoding="utf-8", errors="strict")
        ftp_ub = cipher.decrypt(ftp_ud)
        ftp_u = ftp_ub.decode(encoding="utf-8", errors="strict")
        ftp_ps = config.get("FTP", "ftp_pass")
        #cipher_key = cipher_ke.encode(encoding="utf-8", errors="strict")
        #cipher = Fernet(cipher_key)
        ftp_pd = ftp_ps.encode(encoding="utf-8", errors="strict")
        ftp_pb = cipher.decrypt(ftp_pd)
        ftp_p = ftp_pb.decode(encoding="utf-8", errors="strict")
        ftp_root = config.get("FTP", "ftp_root")
        cp = config.get("FTP", "cp")
        chat_id = config.get("Telegram", "chat_id")
    if path == 'settings_photo.ini':
        config = configparser.ConfigParser()
        config.read(path)
        name_obj = config.get("Settings", "name_obj")
        src = config.get("Settings", "src_dir") + '/'
        dst = config.get("Settings", "dst_dir") + '/'
        ftp = config.get("FTP", "ftp_server")
        cipher_ke = config.get("Settings", "cipher")
        ftp_us = config.get("FTP", "ftp_username")
        cipher_key = cipher_ke.encode(encoding="utf-8", errors="strict")
        cipher = Fernet(cipher_key)
        ftp_ud = ftp_us.encode(encoding="utf-8", errors="strict")
        ftp_ub = cipher.decrypt(ftp_ud)
        ftp_u = ftp_ub.decode(encoding="utf-8", errors="strict")
        ftp_ps = config.get("FTP", "ftp_pass")
        #cipher_key = cipher_ke.encode(encoding="utf-8", errors="strict")
        #cipher = Fernet(cipher_key)
        ftp_pd = ftp_ps.encode(encoding="utf-8", errors="strict")
        ftp_pb = cipher.decrypt(ftp_pd)
        ftp_p = ftp_pb.decode(encoding="utf-8", errors="strict")
        ftp_root = config.get("FTP", "ftp_root")
        cp = config.get("FTP", "cp")
        see = config.get("Settings", "days_before")
        sel = int(see)
        chat_id = config.get("Telegram", "chat_id")


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
    # Создаем локальную копию

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
    # Получаем дату для MSSQL_DB

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
    # Копируем MSSQL DB

def zipper():
    archive_name = data_full + '-' + mssql_db
    source_dir = location + '/' + mssql_db + '/'
    shutil.make_archive(archive_name, format="zip", root_dir=source_dir)

    # Архивируем MSSQL DB

class FtpUploadFolder():
    def __init__(self, server, user, passwd, catalog):
        self.fcount = 0
        self.dcount = 0
        self.ftp = ftplib.FTP(server, user, passwd, encoding=cp) #, encoding='cp1251'
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

        
    def close(self):
        self.ftp.quit()
        global fcount, dcount
        fcount = self.fcount
        dcount = self.dcount
        print('uploaded files: ', self.fcount)
    # класс загрузки папок и файлов на ftp

def mssql_upload():
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

def photo_upload():
    if photo in os.listdir():
        print('Создаем локальную копию')
        copylocal(src, dst)
        print('Запускаю копирование на FTP')
        f = FtpUploadFolder(ftp, ftp_u, ftp_p, ftp_root)
        f.uploadDir(dst)
        f.close()
        print('Закончил копирование на FTP. Собираю монатки и сваливаю')
        bot = telebot.TeleBot(token)
        bot.send_message(chat_id,
                         "Бэкап фотофиксации весовой на обьекте " + name_obj + " закончен. Результат: Локально создано новых папок: " + str(
                             dlcount) + " Локально скопированно новых файлов: " + str(
                             flcount) + " На FTP созданно новых папок: " + str(dcount) + ' На FTP скопированно новых файлов: ' + str(fcount))



    # Проверяем наличие файла конфигурационого файла и запуск выполнения задачи.
def check_conf():
    global path#, cp
    if photo in os.listdir():
        path = photo
        print('Фото')
        read_conf(path)
        photo_upload()
    else:
        if mssql in os.listdir():
            path = mssql
            print('MS SQL')
            read_conf(path)
            mssql_upload()
        else:
            gui_conf()

check_conf()


