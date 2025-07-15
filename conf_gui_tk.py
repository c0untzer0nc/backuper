import configparser
import os
import sys
import logging
import pyodbc
import datetime
import webbrowser
import socket
import base64

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

# Tkinter imports
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

# --- НАСТРОЙКИ ПО УМОЛЧАНИЮ (Используются, если нет в файле конфигурации) ---
DEFAULT_FTP_SERVER = 'ftp.dlptest.com'
DEFAULT_FTP_USER = 'dlpuser'
DEFAULT_FTP_PASS = 'rNrFamDqYphgZHFW'
DEFAULT_FTP_BASE_PATH = '/temp_py_backups/'
DEFAULT_FTP_ENCODING = 'utf-8'

DEFAULT_LOCAL_BACKUP_PATH = './local_backups/'

DEFAULT_WEBDAV_URL = 'https://example.com/remote.php/webdav/'
DEFAULT_WEBDAV_USER = 'your_nextcloud_user'
DEFAULT_WEBDAV_PASS = 'your_nextcloud_password'
DEFAULT_WEBDAV_BASE_PATH = '/Backups/'

DEFAULT_MSSQL_DRIVER = '{ODBC Driver 17 for SQL Server}'
DEFAULT_MSSQL_SERVER = 'localhost'
DEFAULT_MSSQL_DATABASE = 'master'
DEFAULT_MSSQL_USER = 'sa'
DEFAULT_MSSQL_PASS = 'your_sql_password'

DEFAULT_MYSQL_DRIVER = '{MySQL ODBC 8.0 Unicode Driver}'
DEFAULT_MYSQL_SERVER = 'localhost'
DEFAULT_MYSQL_DATABASE = 'mysql'
DEFAULT_MYSQL_USER = 'root'
DEFAULT_MYSQL_PASS = 'your_mysql_password'

DEFAULT_POSTGRESQL_DRIVER = '{PostgreSQL Unicode(x64)}'
DEFAULT_POSTGRESQL_SERVER = 'localhost'
DEFAULT_POSTGRESQL_DATABASE = 'postgres'
DEFAULT_POSTGRESQL_USER = 'postgres'
DEFAULT_POSTGRESQL_PASS = 'your_pg_password'

DEFAULT_ZIP_PASSWORD = 'MyComplexBackupPassword2025'

DEFAULT_MYSQL_DUMP_PATH = 'C:/Program Files/'
DEFAULT_POSTGRESQL_DUMP_PATH = 'C:/Program Files/'

DEFAULT_ROTATION_KEEP_COUNT = '7'

# --- НАСТРОЙКА ЛОГИРОВАНИЯ (для внутренних сообщений GUI) ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# --- ОПРЕДЕЛЕНИЕ ЦВЕТОВЫХ СХЕМ (Адаптировано для Tkinter) ---
# Tkinter менее гибок в стилизации напрямую через цвета в виджетах.
# Часто используются системные цвета или ttk.Style.
# Для простоты, я буду использовать эти цвета, где это возможно,
# но некоторые виджеты могут игнорировать их или требовать ttk.Style.
LIGHT_COLORS = {
    'background': '#F0F0F0',
    'content_background': '#FFFFFF',
    'text_color': '#333333',
    'section_header_text': '#2C3E50',
    'separator_color': '#7F8C8D',
    'button_normal': '#2196F3',
    'button_pressed': '#1976D2',
    'button_text': '#FFFFFF',
    'input_background': '#FFFFFF',
    'input_text': '#333333',
    'input_cursor': '#333333',
    'checkbox_color': '#2980B9', # Tkinter Checkbutton color is harder to control directly
    'spinner_background': '#FFFFFF',
    'spinner_text': '#333333',
    'popup_background': '#F0F0F0',
    'popup_text': '#333333',
    'popup_button_normal': '#2196F3',
    'popup_button_text': '#FFFFFF',
}

DARK_COLORS = {
    'background': '#2E2E2E',
    'content_background': '#3F3F3F',
    'text_color': '#E0E0E0',
    'section_header_text': '#BBDEFB',
    'separator_color': '#606060',
    'button_normal': '#424242',
    'button_pressed': '#616161',
    'button_text': '#E0E0E0',
    'input_background': '#424242',
    'input_text': '#E0E0E0',
    'input_cursor': '#E0E0E0',
    'checkbox_color': '#4CAF50',
    'spinner_background': '#424242',
    'spinner_text': '#E0E0E0',
    'popup_background': '#3F3F3F',
    'popup_text': '#E0E0E0',
    'popup_button_normal': '#424242',
    'popup_button_text': '#E0E0E0',
}

def get_current_theme_colors():
    now = datetime.datetime.now().time()
    if datetime.time(6, 0) <= now <= datetime.time(18, 0):
        return LIGHT_COLORS
    else:
        return DARK_COLORS

current_colors = get_current_theme_colors()

# --- Функция для получения списка системных ODBC драйверов ---
def get_system_odbc_drivers():
    try:
        drivers = pyodbc.drivers()
        if not drivers:
            logging.warning("ODBC драйверы не найдены в системе.")
            return ['<Драйверы не найдены>']
        return sorted(drivers)
    except pyodbc.Error as e:
        logging.error(f"Ошибка при получении ODBC драйверов: {e}")
        return ['<Ошибка получения драйверов>']
    except ImportError:
        logging.error("Модуль pyodbc не найден. Пожалуйста, установите его: pip install pyodbc")
        return ['<pyodbc не установлен>']

# --- КЛАСС ДЛЯ УПРАВЛЕНИЯ КОНФИГУРАЦИЕЙ (БЕЗ ИЗМЕНЕНИЙ) ---
class ConfigManager:
    """
    Класс для управления конфигурацией (чтение и запись INI-файлов) с шифрованием.
    Шифрует конфиденциальные данные (логины, пароли) используя ключ,
    который сам зашифрован на основе имени ПК и хранится в файле конфигурации.
    """

    def __init__(self, config_file_path):
        self.config_file_path = config_file_path
        self.config = configparser.ConfigParser()
        self.encryption_key = None  # Расшифрованный Fernet ключ для шифрования данных
        self.pc_master_key = self._derive_pc_master_key()  # Мастер-ключ, производный от имени ПК
        self._load_config()

    def _derive_pc_master_key(self):
        hostname = socket.gethostname().encode('utf-8')
        salt = b"super_secret_salt_for_pc_key_derivation_2025"
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        return base64.urlsafe_b64encode(kdf.derive(hostname))

    def _encrypt_value(self, value):
        if not self.encryption_key:
            logging.error("Ключ шифрования недоступен для шифрования. Возвращаем исходное значение.")
            return value
        try:
            f = Fernet(self.encryption_key)
            return f.encrypt(value.encode('utf-8')).decode('utf-8')
        except Exception as e:
            logging.error(f"Ошибка при шифровании значения: {e}. Возвращаем исходное значение.")
            return value

    def _decrypt_value(self, encrypted_value):
        if not self.encryption_key:
            logging.error("Ключ шифрования недоступен для дешифрования. Возвращаем зашифрованное значение.")
            return encrypted_value
        try:
            f = Fernet(self.encryption_key)
            return f.decrypt(encrypted_value.encode('utf-8')).decode('utf-8')
        except Exception as e:
            logging.error(f"Ошибка при дешифровании значения: {e}. Возвращаем зашифрованное значение.")
            return encrypted_value

    def _load_config(self):
        if os.path.exists(self.config_file_path):
            try:
                self.config.read(self.config_file_path, encoding='utf-8')
                logging.info(f"Конфигурация успешно загружена из '{self.config_file_path}'.")

                encrypted_fernet_key = self.config.get('Encryption', 'key', fallback=None)
                if encrypted_fernet_key:
                    try:
                        f_master = Fernet(self.pc_master_key)
                        self.encryption_key = f_master.decrypt(encrypted_fernet_key.encode('utf-8'))
                        logging.info("Ключ шифрования загружен и успешно расшифрован.")
                    except Exception as e:
                        logging.error(
                            f"Не удалось расшифровать ключ шифрования с помощью мастер-ключа ПК. Данные не будут дешифрованы: {e}")
                        self.encryption_key = None
                else:
                    logging.warning("Ключ шифрования не найден в конфигурации. Пароли не будут дешифрованы.")
                    self.encryption_key = None

            except configparser.Error as e:
                logging.error(f"Ошибка чтения конфигурации '{self.config_file_path}': {e}")
        else:
            logging.info(f"Файл конфигурации '{self.config_file_path}' не найден. Будет создан новый.")
            self._generate_and_store_new_fernet_key()

    def _generate_and_store_new_fernet_key(self):
        self.encryption_key = Fernet.generate_key()
        if not self.config.has_section('Encryption'):
            self.config.add_section('Encryption')

        try:
            f_master = Fernet(self.pc_master_key)
            encrypted_fernet_key = f_master.encrypt(self.encryption_key).decode('utf-8')
            self.config.set('Encryption', 'key', encrypted_fernet_key)
            logging.info(
                "Новый Fernet ключ сгенерирован и зашифрован. Будет сохранен при следующей записи конфигурации.")
        except Exception as e:
            logging.error(f"Не удалось зашифровать и сохранить новый Fernet ключ: {e}")
            self.encryption_key = None

    def write_config(self, config_data):
        self.config = configparser.ConfigParser()

        if not self.encryption_key:
            self._generate_and_store_new_fernet_key()

        if self.encryption_key and self.pc_master_key:
            if 'Encryption' not in config_data:
                config_data['Encryption'] = {}
            f_master = Fernet(self.pc_master_key)
            encrypted_fernet_key = f_master.encrypt(self.encryption_key).decode('utf-8')
            config_data['Encryption']['key'] = encrypted_fernet_key
            logging.info("Ключ шифрования добавлен в config_data для сохранения.")

        sensitive_fields = {
            'FTP_Backup': ['user', 'password'],
            'WebDAV_Backup': ['user', 'password'],
            'MSSQL_Backup': ['user', 'password'],
            'MYSQL_Backup': ['user', 'password'],
            'PostgreSQL_Backup': ['user', 'password'],
            'Zip_Compression': ['password']
        }

        for section, options in config_data.items():
            self.config[section] = {}
            for option, value in options.items():
                if section in sensitive_fields and option in sensitive_fields[section]:
                    if self.encryption_key:
                        self.config[section][option] = self._encrypt_value(value)
                        logging.debug(f"Зашифровано: {section}/{option}")
                    else:
                        self.config[section][option] = value
                        logging.warning(f"Нет ключа шифрования, сохраняем {section}/{option} незашифрованным.")
                else:
                    self.config[section][option] = value

        try:
            with open(self.config_file_path, 'w', encoding='utf-8') as f:
                self.config.write(f)
            logging.info(f"Конфигурация успешно сохранена в '{self.config_file_path}'.")
            return True
        except IOError as e:
            logging.error(f"Ошибка сохранения конфигурации в '{self.config_file_path}': {e}")
            return False

    def get_setting(self, section, option, fallback=None):
        value = self.config.get(section, option, fallback=fallback)
        sensitive_fields = {
            'FTP_Backup': ['user', 'password'],
            'WebDAV_Backup': ['user', 'password'],
            'MSSQL_Backup': ['user', 'password'],
            'MYSQL_Backup': ['user', 'password'],
            'PostgreSQL_Backup': ['user', 'password'],
            'Zip_Compression': ['password']
        }
        if section in sensitive_fields and option in sensitive_fields[section]:
            if self.encryption_key and value is not None:
                try:
                    return self._decrypt_value(value)
                except Exception as e:
                    logging.error(f"Ошибка при дешифровании {section}/{option}: {e}. Возвращаем исходное значение.")
                    return value
            else:
                logging.warning(
                    f"Нет ключа шифрования или значение None, возвращаем необработанное значение для {section}/{option}.")
                return value
        return value

    def get_boolean_setting(self, section, option, fallback=False):
        return self.config.getboolean(section, option, fallback=fallback)


class ConfigEditorAppTkinter:
    def __init__(self, master, config_manager):
        self.master = master
        self.config_manager = config_manager
        self.master.title('Backup tools - Редактор Конфигурации')
        self.master.geometry('800x700')
        self.master.config(bg=current_colors['background'])

        # Стилизация (базовая, для Tkinter)
        self.style = ttk.Style()
        self.style.theme_use('clam') # Или 'alt', 'default', 'classic'
        self.style.configure('TFrame', background=current_colors['background'])
        self.style.configure('TLabel', background=current_colors['background'], foreground=current_colors['text_color'])
        self.style.configure('TButton', background=current_colors['button_normal'], foreground=current_colors['button_text'])
        self.style.map('TButton',
                       background=[('active', current_colors['button_pressed']), ('!active', current_colors['button_normal'])],
                       foreground=[('active', current_colors['button_text']), ('!active', current_colors['button_text'])])
        self.style.configure('TEntry', fieldbackground=current_colors['input_background'], foreground=current_colors['input_text'])
        self.style.configure('TCombobox', fieldbackground=current_colors['spinner_background'], foreground=current_colors['spinner_text'])
        # Добавляем стиль для Checkbutton
        self.style.configure('TCheckbutton', background=current_colors['content_background'], foreground=current_colors['text_color'])


        self.input_widgets = {}  # Словарь для хранения ссылок на Tkinter виджеты
        self.checkbox_vars = {}  # Словарь для хранения Tkinter BooleanVar для чекбоксов
        self.checkbox_input_frames = {} # Словарь для фреймов с полями, зависящими от чекбокса

        self._create_widgets()
        self._load_existing_config_to_ui()

    def _create_widgets(self):
        # Заголовок
        header_label = ttk.Label(self.master, text='Редактор Конфигурации Бэкапов',
                                 font=('Arial', 16, 'bold'),
                                 background=current_colors['background'],
                                 foreground=current_colors['section_header_text'])
        header_label.pack(pady=10)

        # Создаем Canvas для прокрутки
        self.canvas = tk.Canvas(self.master, bg=current_colors['content_background'], highlightthickness=0)
        self.canvas.pack(side="left", fill="both", expand=True, padx=10, pady=5)

        self.scrollbar = ttk.Scrollbar(self.master, orient="vertical", command=self.canvas.yview)
        self.scrollbar.pack(side="right", fill="y")

        self.canvas.configure(yscrollcommand=self.scrollbar.set)
        self.canvas.bind('<Configure>', lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all")))
        self.canvas.bind_all("<MouseWheel>", self._on_mousewheel) # Для прокрутки колесиком мыши

        self.content_frame = ttk.Frame(self.canvas, padding="10", style='TFrame')
        self.canvas.create_window((0, 0), window=self.content_frame, anchor="nw", width=self.canvas.winfo_width())

        # Привязываем изменение ширины canvas к изменению ширины content_frame
        self.content_frame.bind("<Configure>", lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all")))
        self.canvas.bind('<Configure>', self._on_canvas_configure)


        self._build_ui_sections()

        # Кнопка сохранения
        save_button = ttk.Button(self.master, text='Сохранить Конфигурацию', command=self.save_config, style='TButton')
        save_button.pack(pady=10)

        # Нижняя информация
        bottom_info_frame = ttk.Frame(self.master, style='TFrame')
        bottom_info_frame.pack(side="bottom", fill="x", padx=10, pady=(0,5))
        bottom_info_frame.grid_columnconfigure(0, weight=1)
        bottom_info_frame.grid_columnconfigure(1, weight=1)

        year_label = ttk.Label(bottom_info_frame, text='2025г.', foreground=current_colors['text_color'], anchor='w')
        year_label.grid(row=0, column=0, sticky='w')

        # Для ссылки используем обычный Label и привязку события
        signature_label = ttk.Label(bottom_info_frame, text='by c0unt_zer0_nc',
                                    foreground=current_colors['section_header_text'],
                                    cursor="hand2", anchor='e')
        signature_label.grid(row=0, column=1, sticky='e')
        signature_label.bind("<Button-1>", lambda e: webbrowser.open("https://count-work.ru"))

    def _on_canvas_configure(self, event):
        self.canvas.itemconfig(self.canvas.find_withtag("all")[0], width=event.width)

    def _on_mousewheel(self, event):
        self.canvas.yview_scroll(int(-1*(event.delta/120)), "units")


    def _add_section_header(self, title):
        label = ttk.Label(self.content_frame, text=title, font=('Arial', 12, 'bold'),
                          background=current_colors['content_background'],
                          foreground=current_colors['section_header_text'])
        label.pack(anchor='w', pady=(10, 5))
        separator = tk.Frame(self.content_frame, height=2, bd=0, relief='flat', bg=current_colors['separator_color'])
        separator.pack(fill='x', pady=(0, 10))

    def _add_input_field(self, label_text, section, key, default_value, password=False, parent_frame=None):
        parent_frame = parent_frame if parent_frame else self.content_frame
        frame = ttk.Frame(parent_frame, style='TFrame')
        frame.pack(fill='x', pady=2)

        label = ttk.Label(frame, text=label_text, width=20, anchor='w',
                          background=current_colors['content_background'],
                          foreground=current_colors['text_color'])
        label.pack(side='left', padx=(0, 5))

        entry_var = tk.StringVar(value=default_value)
        entry = ttk.Entry(frame, textvariable=entry_var, show='*' if password else '', width=50, style='TEntry')
        entry.pack(side='left', fill='x', expand=True)

        if section not in self.input_widgets:
            self.input_widgets[section] = {}
        self.input_widgets[section][key] = entry_var # Store StringVar for easy access to value
        return frame

    def _add_driver_spinner(self, label_text, section, key, default_value, drivers_list, parent_frame=None):
        parent_frame = parent_frame if parent_frame else self.content_frame
        frame = ttk.Frame(parent_frame, style='TFrame')
        frame.pack(fill='x', pady=2)

        label = ttk.Label(frame, text=label_text, width=20, anchor='w',
                          background=current_colors['content_background'],
                          foreground=current_colors['text_color'])
        label.pack(side='left', padx=(0, 5))

        # Если default_value не в списке, добавляем его, чтобы он отображался изначально
        if default_value and default_value not in drivers_list:
            display_drivers = [default_value] + drivers_list
        else:
            display_drivers = drivers_list

        if not display_drivers:
            display_drivers = ['<Нет доступных драйверов>']
            default_value = '<Нет доступных драйверов>'

        spinner_var = tk.StringVar(value=default_value if default_value in display_drivers else display_drivers[0])
        spinner = ttk.Combobox(frame, textvariable=spinner_var, values=display_drivers, state='readonly', width=47, style='TCombobox')
        spinner.pack(side='left', fill='x', expand=True)

        if section not in self.input_widgets:
            self.input_widgets[section] = {}
        self.input_widgets[section][key] = spinner_var
        return frame

    def _add_folder_picker(self, label_text, section, key, default_value, dir_only=True, parent_frame=None):
        parent_frame = parent_frame if parent_frame else self.content_frame
        frame = ttk.Frame(parent_frame, style='TFrame')
        frame.pack(fill='x', pady=2)

        label = ttk.Label(frame, text=label_text, width=20, anchor='w',
                          background=current_colors['content_background'],
                          foreground=current_colors['text_color'])
        label.pack(side='left', padx=(0, 5))

        path_var = tk.StringVar(value=default_value)
        entry = ttk.Entry(frame, textvariable=path_var, width=40, style='TEntry')
        entry.pack(side='left', fill='x', expand=True, padx=(0,5))

        button_text = "Обзор папки" if dir_only else "Обзор файла/папки"
        browse_button = ttk.Button(frame, text=button_text,
                                   command=lambda: self._show_file_chooser(path_var, dir_only), style='TButton')
        browse_button.pack(side='left')

        if section not in self.input_widgets:
            self.input_widgets[section] = {}
        self.input_widgets[section][key] = path_var
        return frame

    def _show_file_chooser(self, path_var, dir_only):
        initial_path = path_var.get()
        if dir_only:
            selected_path = filedialog.askdirectory(initialdir=initial_path if os.path.isdir(initial_path) else os.path.dirname(__file__))
        else:
            selected_path = filedialog.askopenfilename(initialdir=initial_path if os.path.isdir(initial_path) else os.path.dirname(__file__))
        if selected_path:
            path_var.set(selected_path)

    def _add_checkbox_and_inputs(self, checkbox_label, section_name, default_enabled, fields_info):
        frame = ttk.Frame(self.content_frame, style='TFrame')
        frame.pack(fill='x', pady=5)

        check_var = tk.BooleanVar(value=default_enabled)
        # Убраны параметры background и foreground из ttk.Checkbutton
        checkbox = ttk.Checkbutton(frame, text=checkbox_label, variable=check_var,
                                   command=lambda: self._toggle_inputs(section_name),
                                   style='TCheckbutton') # Используем стиль
        checkbox.pack(anchor='w', pady=(0,5))
        self.checkbox_vars[section_name] = check_var

        # Контейнер для полей ввода, которые будут скрываться/показываться
        input_container_frame = ttk.Frame(frame, style='TFrame')
        input_container_frame.pack(fill='x', padx=15, pady=(0, 5))
        self.checkbox_input_frames[section_name] = input_container_frame # Сохраняем ссылку на фрейм

        system_drivers = get_system_odbc_drivers()

        for label_text, key, default_value, is_password, input_widget_type in fields_info:
            if input_widget_type == 'textinput':
                self._add_input_field(label_text, section_name, key, default_value, is_password, parent_frame=input_container_frame)
            elif input_widget_type == 'spinner':
                self._add_driver_spinner(label_text, section_name, key, default_value, system_drivers, parent_frame=input_container_frame)
            elif input_widget_type == 'mode_spinner':
                mode_spinner_values = ['all_databases', 'single_database']
                self._add_driver_spinner(label_text, section_name, key, default_value, mode_spinner_values, parent_frame=input_container_frame)
            elif input_widget_type == 'folder_picker':
                is_dir_only = not (key in ['mysqldump_path', 'pg_dump_path'])
                self._add_folder_picker(label_text, section_name, key, default_value, is_dir_only, parent_frame=input_container_frame)

        # Вызываем toggle_inputs для установки начального состояния
        self._toggle_inputs(section_name)

    def _toggle_inputs(self, section_name):
        is_active = self.checkbox_vars[section_name].get()
        input_frame = self.checkbox_input_frames[section_name]

        for widget in input_frame.winfo_children():
            if is_active:
                widget.pack(fill='x', pady=2)
            else:
                widget.pack_forget()
        self.canvas.update_idletasks() # Обновить размеры Canvas

    def _build_ui_sections(self):
        # --- Основные настройки ---
        self._add_section_header('Общие настройки')
        self._add_section_header('Настройки Ротации Бэкапов')
        self._add_input_field(
            'Количество хранимых бэкапов (0-откл):',
            'Rotation',
            'keep_count',
            DEFAULT_ROTATION_KEEP_COUNT,
            password=False
        )

        # --- Настройки FTP ---
        self._add_section_header('Настройки FTP')
        self._add_checkbox_and_inputs(
            checkbox_label='Включить FTP бэкап',
            section_name='FTP_Backup',
            default_enabled=self.config_manager.get_boolean_setting('FTP_Backup', 'enabled', fallback=False),
            fields_info=[
                ('Сервер:', 'server', DEFAULT_FTP_SERVER, False, 'textinput'),
                ('Пользователь:', 'user', DEFAULT_FTP_USER, False, 'textinput'),
                ('Пароль:', 'password', DEFAULT_FTP_PASS, True, 'textinput'),
                ('Базовый путь:', 'base_path', DEFAULT_FTP_BASE_PATH, False, 'textinput'),
                ('Кодировка:', 'encoding', DEFAULT_FTP_ENCODING, False, 'textinput'),
            ]
        )

        # --- Настройки Локального бэкапа ---
        self._add_section_header('Настройки Локального бэкапа')
        self._add_checkbox_and_inputs(
            checkbox_label='Включить Локальный бэкап',
            section_name='Local_Backup',
            default_enabled=self.config_manager.get_boolean_setting('Local_Backup', 'enabled', fallback=False),
            fields_info=[
                ('Путь локального бэкапа:', 'path', DEFAULT_LOCAL_BACKUP_PATH, False, 'folder_picker'),
            ]
        )

        # --- Настройки WebDAV ---
        self._add_section_header('Настройки WebDAV')
        self._add_checkbox_and_inputs(
            checkbox_label='Включить WebDAV бэкап',
            section_name='WebDAV_Backup',
            default_enabled=self.config_manager.get_boolean_setting('WebDAV_Backup', 'enabled', fallback=False),
            fields_info=[
                ('URL:', 'url', DEFAULT_WEBDAV_URL, False, 'textinput'),
                ('Пользователь:', 'user', DEFAULT_WEBDAV_USER, False, 'textinput'),
                ('Пароль:', 'password', DEFAULT_WEBDAV_PASS, True, 'textinput'),
                ('Базовый путь:', 'base_path', DEFAULT_WEBDAV_BASE_PATH, False, 'textinput'),
            ]
        )

        # --- Настройки MSSQL бэкапа ---
        self._add_section_header('Настройки MSSQL бэкапа')
        self._add_checkbox_and_inputs(
            checkbox_label='Включить MSSQL бэкап',
            section_name='MSSQL_Backup',
            default_enabled=self.config_manager.get_boolean_setting('MSSQL_Backup', 'enabled', fallback=False),
            fields_info=[
                ('Драйвер:', 'driver', DEFAULT_MSSQL_DRIVER, False, 'spinner'),
                ('Сервер:', 'server', DEFAULT_MSSQL_SERVER, False, 'textinput'),
                ('База данных:', 'database', DEFAULT_MSSQL_DATABASE, False, 'textinput'),
                ('Пользователь:', 'user', DEFAULT_MSSQL_USER, False, 'textinput'),
                ('Пароль:', 'password', DEFAULT_MSSQL_PASS, True, 'textinput'),
                ('Режим бэкапа:', 'mode', 'all_databases', False, 'mode_spinner'),
            ]
        )

        # --- Настройки MySQL бэкапа ---
        self._add_section_header('Настройки MySQL бэкапа')
        self._add_checkbox_and_inputs(
            checkbox_label='Включить MySQL бэкап',
            section_name='MySQL_Backup',
            default_enabled=self.config_manager.get_boolean_setting('MySQL_Backup', 'enabled', fallback=False),
            fields_info=[
                ('Путь к mysqldump:', 'mysqldump_path', DEFAULT_MYSQL_DUMP_PATH, False, 'folder_picker'),
                ('Сервер:', 'server', DEFAULT_MYSQL_SERVER, False, 'textinput'),
                ('База данных:', 'database', DEFAULT_MYSQL_DATABASE, False, 'textinput'),
                ('Пользователь:', 'user', DEFAULT_MYSQL_USER, False, 'textinput'),
                ('Пароль:', 'password', DEFAULT_MYSQL_PASS, True, 'textinput'),
                ('Режим бэкапа:', 'mode', 'all_databases', False, 'mode_spinner'),
            ]
        )

        # --- Настройки PostgreSQL бэкапа ---
        self._add_section_header('Настройки PostgreSQL бэкапа')
        self._add_checkbox_and_inputs(
            checkbox_label='Включить PostgreSQL бэкап',
            section_name='PostgreSQL_Backup',
            default_enabled=self.config_manager.get_boolean_setting('PostgreSQL_Backup', 'enabled', fallback=False),
            fields_info=[
                ('Путь к pg_dump:', 'pg_dump_path', DEFAULT_POSTGRESQL_DUMP_PATH, False, 'folder_picker'),
                ('Сервер:', 'server', DEFAULT_POSTGRESQL_SERVER, False, 'textinput'),
                ('База данных:', 'database', DEFAULT_POSTGRESQL_DATABASE, False, 'textinput'),
                ('Пользователь:', 'user', DEFAULT_POSTGRESQL_USER, False, 'textinput'),
                ('Пароль:', 'password', DEFAULT_POSTGRESQL_PASS, True, 'textinput'),
                ('Режим бэкапа:', 'mode', 'all_databases', False, 'mode_spinner'),
            ]
        )

        # --- Настройки компрессии ---
        self._add_section_header('Настройки компрессии')
        self._add_checkbox_and_inputs(
            checkbox_label='Включить ZIP-компрессию с паролем',
            section_name='Compression',
            default_enabled=self.config_manager.get_boolean_setting('Compression', 'enabled', fallback=False),
            fields_info=[
                ('Пароль ZIP-архива:', 'password', DEFAULT_ZIP_PASSWORD, True, 'textinput'),
            ]
        )


    def _load_existing_config_to_ui(self):
        sections_info = {
            'Rotation': ['keep_count'],
            'FTP_Backup': ['server', 'user', 'password', 'base_path', 'encoding'],
            'Local_Backup': ['path'],
            'WebDAV_Backup': ['url', 'user', 'password', 'base_path'],
            'MSSQL_Backup': ['driver', 'server', 'database', 'user', 'password', 'mode'],
            'MySQL_Backup': ['mysqldump_path', 'server', 'database', 'user', 'password', 'mode'],
            'PostgreSQL_Backup': ['pg_dump_path', 'server', 'database', 'user', 'password', 'mode'],
            'Compression': ['password']
        }

        for section_name, keys in sections_info.items():
            # Загрузка состояния чекбокса (если он есть)
            if section_name in self.checkbox_vars:
                is_enabled = self.config_manager.get_boolean_setting(section_name, 'enabled', fallback=False)
                self.checkbox_vars[section_name].set(is_enabled)
                self._toggle_inputs(section_name) # Обновить видимость полей

            # Загрузка значений полей ввода/спиннеров
            if section_name in self.input_widgets:
                for key in keys: # Iterate through keys defined for this section
                    if key in self.input_widgets[section_name]: # Check if the widget exists for this key
                        value = self.config_manager.get_setting(section_name, key)
                        if value is not None:
                            self.input_widgets[section_name][key].set(value)

    def save_config(self):
        config_data = {}

        for section_name, widget_vars in self.input_widgets.items():
            if section_name not in config_data:
                config_data[section_name] = {}
            for key, var_widget in widget_vars.items():
                config_data[section_name][key] = var_widget.get()

        for section_name, check_var in self.checkbox_vars.items():
            if section_name not in config_data:
                config_data[section_name] = {}
            config_data[section_name]['enabled'] = str(check_var.get())

        if self.config_manager.write_config(config_data):
            messagebox.showinfo("Сохранение", "Конфигурация успешно сохранена!")
            self.master.destroy() # Закрыть приложение после сохранения
        else:
            messagebox.showerror("Ошибка сохранения",
                                 f"Не удалось сохранить конфигурацию в '{self.config_manager.config_file_path}'. Проверьте логи.")

def gui_start():
    root = tk.Tk()
    config_file = 'backup_config.ini'
    config_manager_instance = ConfigManager(config_file)
    app = ConfigEditorAppTkinter(root, config_manager_instance)
    root.mainloop()