import configparser
import os
import sys
import logging
import pyodbc  # Импортируем pyodbc для получения списка драйверов
import datetime  # Для определения времени суток
import webbrowser # Добавлено для открытия ссылок

from kivy.app import App
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.textinput import TextInput
from kivy.uix.button import Button
from kivy.uix.checkbox import CheckBox
from kivy.uix.label import Label
from kivy.uix.popup import Popup
from kivy.uix.scrollview import ScrollView
from kivy.uix.spinner import Spinner, SpinnerOption  # Импортируем Spinner и SpinnerOption
from kivy.properties import ObjectProperty
from kivy.graphics import Color, Rectangle
from kivy.utils import get_color_from_hex
from kivy.uix.floatlayout import FloatLayout  # Для попапа выбора папки
from kivy.uix.filechooser import FileChooserListView  # Для выбора папки
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import base64
import os
import socket
# Removed: from kivy.uix.filechooser import FileChooserEntry # Removed due to ImportError

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

# ИСПРАВЛЕНО: Установлены пути по умолчанию для mysqldump и pg_dump
DEFAULT_MYSQL_DUMP_PATH = 'C:/Program Files/'
DEFAULT_POSTGRESQL_DUMP_PATH = 'C:/Program Files/'

# --- НАСТРОЙКА ЛОГИРОВАНИЯ (для внутренних сообщений GUI) ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# --- ОПРЕДЕЛЕНИЕ ЦВЕТОВЫХ СХЕМ ---
LIGHT_COLORS = {
    'background': '#F0F0F0',  # Светло-серый
    'content_background': '#FFFFFF',  # Белый для ScrollView
    'text_color': '#333333',  # Темно-серый
    'section_header_text': '#2C3E50',  # Темно-синий
    'separator_color': '#7F8C8D',  # Средне-серый
    'button_normal': '#2196F3',  # Синий
    'button_pressed': '#1976D2',  # Темно-синий
    'button_text': '#FFFFFF',  # Белый
    'input_background': '#FFFFFF',  # Белый
    'input_text': '#333333',  # Темно-серый
    'input_cursor': '#333333',  # Темно-серый
    'checkbox_color': '#2980B9',  # Голубой
    'spinner_background': '#FFFFFF',  # Белый
    'spinner_text': '#333333',  # Темно-серый
    'popup_background': '#333333',  # Темно-серый
    'popup_text': '#FFFFFF',  # Изменено на черный для попапа
    'popup_button_normal': '#2196F3',
    'popup_button_text': '#FFFFFF',
}

DARK_COLORS = {
    'background': '#2E2E2E',  # Темно-серый фон
    'content_background': '#3F3F3F',  # Чуть светлее темно-серого для ScrollView
    'text_color': '#E0E0E0',  # Светло-серый текст
    'section_header_text': '#BBDEFB',  # Светло-голубой
    'separator_color': '#606060',  # Темно-серый разделитель
    'button_normal': '#424242',  # Темный серый
    'button_pressed': '#616161',  # Чуть светлее серый
    'button_text': '#E0E0E0',  # Светлый текст
    'input_background': '#424242',  # Темно-серый
    'input_text': '#E0E0E0',  # Светло-серый
    'input_cursor': '#E0E0E0',  # Светло-серый
    'checkbox_color': '#4CAF50',  # Зеленый
    'spinner_background': '#424242',  # Темно-серый
    'spinner_text': '#E0E0E0',  # Светло-серый
    'popup_background': '#3F3F3F',  # Чуть светлее темно-серого для попапа
    'popup_text': '#E0E0E0',  # Светлый текст для попапа
    'popup_button_normal': '#424242',
    'popup_button_text': '#E0E0E0',
}


# --- ФУНКЦИЯ ДЛЯ ОПРЕДЕЛЕНИЯ ТЕМЫ ---
def get_current_theme_colors():
    """Определяет текущую тему (светлую или темную) в зависимости от времени суток."""
    now = datetime.datetime.now().time()
    # С 6:00 до 18:00 (включительно) - светлая тема
    if datetime.time(6, 0) <= now <= datetime.time(18, 0):
        return LIGHT_COLORS
    else:  # С 18:01 до 5:59 - темная тема
        return DARK_COLORS


current_colors = get_current_theme_colors()


# --- Кастомный класс для элементов выпадающего списка SpinnerOption ---
class ThemedSpinnerOption(SpinnerOption):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.background_normal = ''  # Отключаем стандартный фон
        self.background_color = get_color_from_hex(current_colors['spinner_background'])
        self.color = get_color_from_hex(current_colors['spinner_text'])


# --- Функция для получения списка системных ODBC драйверов ---
def get_system_odbc_drivers():
    """
    Возвращает список доступных ODBC драйверов в системе.
    Требует установленной библиотеки pyodbc.
    """
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


# --- КЛАСС ДЛЯ УПРАВЛЕНИЯ КОНФИГУРАЦИЕЙ ---
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
        """
        Генерирует мастер-ключ на основе имени компьютера.
        Этот ключ не хранится, а генерируется при каждом запуске.
        """
        hostname = socket.gethostname().encode('utf-8')
        # Фиксированная соль для деривации ключа, важна для воспроизводимости
        salt = b"super_secret_salt_for_pc_key_derivation_2025"
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,  # Рекомендуется использовать большее число итераций в продакшене
            backend=default_backend()
        )
        return base64.urlsafe_b64encode(kdf.derive(hostname))

    def _encrypt_value(self, value):
        """Шифрует строковое значение."""
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
        """Дешифрует строковое значение."""
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
        """
        Приватный метод для загрузки файла конфигурации и дешифрования ключа шифрования.
        """
        if os.path.exists(self.config_file_path):
            try:
                self.config.read(self.config_file_path, encoding='utf-8')
                logging.info(f"Конфигурация успешно загружена из '{self.config_file_path}'.")

                # Загружаем и дешифруем ключ шифрования для учетных данных
                encrypted_fernet_key = self.config.get('Encryption', 'key', fallback=None)
                if encrypted_fernet_key:
                    try:
                        # Используем мастер-ключ ПК для дешифрования Fernet ключа
                        f_master = Fernet(self.pc_master_key)
                        self.encryption_key = f_master.decrypt(encrypted_fernet_key.encode('utf-8'))
                        logging.info("Ключ шифрования загружен и успешно расшифрован.")
                    except Exception as e:
                        logging.error(f"Не удалось расшифровать ключ шифрования с помощью мастер-ключа ПК. Данные не будут дешифрованы: {e}")
                        self.encryption_key = None
                else:
                    logging.warning("Ключ шифрования не найден в конфигурации. Пароли не будут дешифрованы.")
                    self.encryption_key = None

            except configparser.Error as e:
                logging.error(f"Ошибка чтения конфигурации '{self.config_file_path}': {e}")
        else:
            logging.info(f"Файл конфигурации '{self.config_file_path}' не найден. Будет создан новый.")
            # Генерируем новый Fernet ключ, если файл конфигурации не существует
            self._generate_and_store_new_fernet_key()

    def _generate_and_store_new_fernet_key(self):
        """
        Генерирует новый Fernet ключ, шифрует его мастер-ключом ПК
        и подготавливает его для сохранения в конфигурации.
        """
        self.encryption_key = Fernet.generate_key()
        if not self.config.has_section('Encryption'):
            self.config.add_section('Encryption')

        try:
            f_master = Fernet(self.pc_master_key)
            encrypted_fernet_key = f_master.encrypt(self.encryption_key).decode('utf-8')
            self.config.set('Encryption', 'key', encrypted_fernet_key)
            logging.info("Новый Fernet ключ сгенерирован и зашифрован. Будет сохранен при следующей записи конфигурации.")
        except Exception as e:
            logging.error(f"Не удалось зашифровать и сохранить новый Fernet ключ: {e}")
            self.encryption_key = None  # В случае ошибки, сбросить

    def write_config(self, config_data):
        """
        Сохраняет переданные данные конфигурации в файл, шифруя конфиденциальные поля.
        `config_data` - это словарь, содержащий секции и опции.
        """
        self.config = configparser.ConfigParser()

        # Убедиться, что ключ шифрования существует перед записью. Если нет, сгенерировать его.
        if not self.encryption_key:
            self._generate_and_store_new_fernet_key()
            # Если генерация также не удалась, мы продолжим без ключа шифрования

        # Сначала добавьте зашифрованный ключ шифрования в config_data, если он доступен
        if self.encryption_key and self.pc_master_key:
            if 'Encryption' not in config_data:
                config_data['Encryption'] = {}
            f_master = Fernet(self.pc_master_key)
            encrypted_fernet_key = f_master.encrypt(self.encryption_key).decode('utf-8')
            config_data['Encryption']['key'] = encrypted_fernet_key
            logging.info("Ключ шифрования добавлен в config_data для сохранения.")

        # Определяем конфиденциальные поля, которые нужно шифровать
        sensitive_fields = {
            'FTP_Backup': ['user', 'password'],
            'WebDAV_Backup': ['user', 'password'],
            'MSSQL_Backup': ['user', 'password'],
            'MYSQL_Backup': ['user', 'password'],
            'PostgreSQL_Backup': ['user', 'password'],
            'Zip_Compression': ['password']
        }

        for section, options in config_data.items():
            self.config[section] = {}  # Инициализируем секцию
            for option, value in options.items():
                if section in sensitive_fields and option in sensitive_fields[section]:
                    # Шифруем конфиденциальные значения
                    if self.encryption_key:
                        self.config[section][option] = self._encrypt_value(value)
                        logging.debug(f"Зашифровано: {section}/{option}")
                    else:
                        self.config[section][option] = value  # Сохраняем незашифрованным, если нет ключа
                        logging.warning(f"Нет ключа шифрования, сохраняем {section}/{option} незашифрованным.")
                else:
                    self.config[section][option] = value  # Сохраняем неконфиденциальные значения как есть

        try:
            with open(self.config_file_path, 'w', encoding='utf-8') as f:
                self.config.write(f)
            logging.info(f"Конфигурация успешно сохранена в '{self.config_file_path}'.")
            return True
        except IOError as e:
            logging.error(f"Ошибка сохранения конфигурации в '{self.config_file_path}': {e}")
            return False

    def get_setting(self, section, option, fallback=None):
        """
        Получает строковую настройку из указанной секции, дешифруя ее, если это конфиденциальное поле.
        """
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
                    return value  # Возвращаем необработанное значение, если дешифрование не удалось
            else:
                logging.warning(f"Нет ключа шифрования или значение None, возвращаем необработанное значение для {section}/{option}.")
                return value  # Возвращаем необработанное значение, если нет ключа или значение None
        return value

    def get_boolean_setting(self, section, option, fallback=False):
        """
        Получает булеву настройку из указанной секции.
        Булевы настройки не нуждаются в шифровании.
        """
        return self.config.getboolean(section, option, fallback=fallback)


class LoadDialog(FloatLayout):
    """
    Класс для всплывающего окна выбора файла/папки.
    """
    load = ObjectProperty(None)
    cancel = ObjectProperty(None)

    # ИЗМЕНЕНО: Добавлен initial_path и dir_only
    def __init__(self, initial_path, dir_only=True, **kwargs):
        super().__init__(**kwargs)
        # ИЗМЕНЕНО: Используем initial_path, если он передан и валиден, иначе домашнюю диреторию
        if initial_path and os.path.isdir(initial_path):
            self.ids.file_chooser.path = initial_path
        elif initial_path and os.path.isfile(initial_path): # Если указан файл, открываем его папку
            self.ids.file_chooser.path = os.path.dirname(initial_path)
            self.ids.file_chooser.selection = [initial_path] # Пытаемся выбрать сам файл
        else:
            # ИСПРАВЛЕНО: Устанавливаем путь по умолчанию в папку запуска скрипта
            self.ids.file_chooser.path = os.path.abspath(os.path.dirname(__file__))

        # ИЗМЕНЕНО: dirselect теперь конфигурируется
        self.ids.file_chooser.dirselect = dir_only

        # Установка цветов для кнопок внутри LoadDialog
        self.ids.select_button.background_normal = ''
        self.ids.select_button.background_color = get_color_from_hex(current_colors['button_normal'])
        self.ids.select_button.color = get_color_from_hex(current_colors['button_text'])
        self.ids.select_button.bind(
            on_press=lambda x: setattr(x, 'background_color', get_color_from_hex(current_colors['button_pressed'])))
        self.ids.select_button.bind(
            on_release=lambda x: setattr(x, 'background_color', get_color_from_hex(current_colors['button_normal'])))

        self.ids.cancel_button.background_normal = ''
        self.ids.cancel_button.background_color = get_color_from_hex(current_colors['button_normal'])
        self.ids.cancel_button.color = get_color_from_hex(current_colors['button_text'])
        self.ids.cancel_button.bind(
            on_press=lambda x: setattr(x, 'background_color', get_color_from_hex(current_colors['button_pressed'])))
        self.ids.cancel_button.bind(
            on_release=lambda x: setattr(x, 'background_color', get_color_from_hex(current_colors['button_normal'])))

        # Установка цвета текста для label "Выбрано:"
        self.ids.selected_path_label.color = get_color_from_hex(current_colors['text_color'])


from kivy.lang import Builder

Builder.load_string("""
# Removed: <FileChooserEntry> rule due to ImportError

<LoadDialog>:
    id: load_dialog_root
    BoxLayout:
        size: root.size
        pos: root.pos
        orientation: "vertical"
        # Add canvas.before to set the background of the BoxLayout
        canvas.before:
            Color:
                # ИСПРАВЛЕНИЕ: Используем новый метод get_color_from_hex_str
                rgba: app.root_widget.get_color_from_hex_str(app.root_widget.current_colors['popup_background'])
            Rectangle:
                pos: self.pos
                size: self.size
        FileChooserListView:
            id: file_chooser
            # dirselect: True будет установлен в __init__
            # path: os.iyz_colors['popup_text']) # Set text color for the file chooser list items
            # ИСПРАВЛЕНИЕ: Используем новый метод get_color_from_hex_str для цвета текста
            color: app.root_widget.get_color_from_hex_str(app.root_widget.current_colors['popup_text'])
            on_selection: root.ids.selected_path_label.text = "Выбрано: " + (self.selection[0] if self.selection else "")

        Label:
            id: selected_path_label
            text: "Выбрано: "
            size_hint_y: None
            height: 30
            color: 1, 1, 1, 1 # Цвет текста будет установлен в __init__

        BoxLayout:
            size_hint_y: None
            height: 50
            Button:
                id: cancel_button
                text: "Отмена"
                on_release: root.cancel()
            Button:
                id: select_button
                text: "Выбрать папку" if file_chooser.dirselect else "Выбрать" # ИЗМЕНЕНО: Текст кнопки зависит от dirselect
                on_release: root.load(file_chooser.path, file_chooser.selection)
""")


class ConfigEditorScreen(BoxLayout):
    """
    Основной экран для редактирования конфигурации бэкапов.
    """
    config_file_path_input = ObjectProperty(None)
    current_colors = current_colors  # Добавляем для доступа в KV

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.orientation = 'vertical'
        self.padding = 10
        self.spacing = 10

        self.input_widgets = {}  # Словарь для хранения ссылок на TextInput и Spinner
        self.checkboxes = {}  # Словарь для хранения ссылок на CheckBox (для быстрого доступа)

        self.config_manager = None  # Будет инициализирован в MainApp

        # Установка фона для всего экрана на основе текущей темы
        with self.canvas.before:
            Color(*get_color_from_hex(current_colors['background']))
            self.rect = Rectangle(size=self.size, pos=self.pos)
        self.bind(size=self._update_rect, pos=self._update_rect)

        # Заголовок
        header_label = Label(text='Редактор Конфигурации Бэкапов', size_hint_y=None, height=40, font_size='20sp',
                             color=get_color_from_hex(current_colors['text_color']))
        self.add_widget(header_label)

        # ScrollView для прокрутки содержимого
        scroll_view = ScrollView(size_hint=(1, 1))
        # Фон для ScrollView - тоже на основе текущей темы
        with scroll_view.canvas.before:
            Color(*get_color_from_hex(current_colors['content_background']))
            self.scroll_rect = Rectangle(size=scroll_view.size, pos=scroll_view.pos)
        scroll_view.bind(size=self._update_scroll_rect, pos=self._update_scroll_rect)

        self.content_layout = BoxLayout(orientation='vertical', size_hint_y=None, spacing=10)
        self.content_layout.bind(minimum_height=self.content_layout.setter('height'))
        scroll_view.add_widget(self.content_layout)
        self.add_widget(scroll_view)

        # self._build_ui() # Перемещено в set_config_manager

        # Кнопка сохранения внизу
        save_button = Button(text='Сохранить Конфигурацию', size_hint_y=None, height=50,
                             background_normal='',  # Отключаем дефолтный фон
                             background_color=get_color_from_hex(current_colors['button_normal']),
                             color=get_color_from_hex(current_colors['button_text']))
        # Привязка цвета при нажатии (если нужно)
        save_button.bind(
            on_press=lambda x: setattr(x, 'background_color', get_color_from_hex(current_colors['button_pressed'])))
        save_button.bind(
            on_release=lambda x: setattr(x, 'background_color', get_color_from_hex(current_colors['button_normal'])))
        save_button.bind(on_release=self.save_config)
        self.add_widget(save_button)

        # Новый горизонтальный макет для нижней информации (2025г. и by c0unt_zer0_nc)
        bottom_info_layout = BoxLayout(orientation='horizontal', size_hint_y=None, height=20, padding=[0, 0, 0, 0], spacing=0)

        # Левая надпись: 2025г.
        year_label = Label(
            text='2025г.',
            size_hint_x=0.5, # Занимает половину ширины
            halign='left',
            valign='middle',
            markup=True,
            color=get_color_from_hex(current_colors['text_color'])
        )
        year_label.bind(width=lambda label_instance, width_value: setattr(label_instance, 'text_size', (width_value, None)))
        bottom_info_layout.add_widget(year_label)

        # Правая надпись: by c0unt_zer0_nc с гиперссылкой
        signature_label = Label(
            text=f'[ref=https://count-work.ru][color={current_colors["section_header_text"]}]by c0unt_zer0_nc[/color][/ref]',
            markup=True,
            size_hint_x=0.5, # Занимает вторую половину ширины
            halign='right',
            valign='middle',
            color=get_color_from_hex(current_colors['text_color'])
        )
        signature_label.bind(width=lambda label_instance, width_value: setattr(label_instance, 'text_size', (width_value, None)))
        signature_label.bind(on_ref_press=self._open_url)
        bottom_info_layout.add_widget(signature_label)

        self.add_widget(bottom_info_layout)


    # ИСПРАВЛЕНИЕ: Добавлен вспомогательный метод для KV-разметки
    def get_color_from_hex_str(self, hex_color_string):
        return get_color_from_hex(hex_color_string)

    def _update_rect(self, instance, value):
        self.rect.pos = instance.pos
        self.rect.size = instance.size

    def _update_scroll_rect(self, instance, value):
        self.scroll_rect.pos = instance.pos
        self.scroll_rect.size = instance.size

    def set_config_manager(self, config_manager_instance):
        self.config_manager = config_manager_instance
        self._build_ui() # Перемещено сюда
        self._load_existing_config_to_ui()

    def _add_section_header(self, title):
        """Добавляет заголовок секции."""
        self.content_layout.add_widget(Label(text=f'[b]{title}[/b]', markup=True, size_hint_y=None, height=30,
                                             color=get_color_from_hex(current_colors['section_header_text'])))
        self.content_layout.add_widget(
            Label(text='---', size_hint_y=None, height=5, color=get_color_from_hex(current_colors['separator_color'])))

    def _add_input_field(self, label_text, section, key, default_value, password=False):
        """Добавляет поле ввода (TextInput)."""
        input_layout = BoxLayout(orientation='horizontal', size_hint_y=None, height=30, spacing=10)
        input_layout.add_widget(
            Label(text=label_text, size_hint_x=0.3, color=get_color_from_hex(current_colors['text_color'])))
        text_input = TextInput(
            text=default_value,
            multiline=False,
            password=password,
            size_hint_x=0.7,
            background_color=get_color_from_hex(current_colors['input_background']),
            foreground_color=get_color_from_hex(current_colors['input_text']),
            cursor_color=get_color_from_hex(current_colors['input_cursor'])
        )
        input_layout.add_widget(text_input)

        if section not in self.input_widgets:
            self.input_widgets[section] = {}
        self.input_widgets[section][key] = text_input
        self.content_layout.add_widget(input_layout)

    def _add_driver_spinner(self, label_text, section, key, default_value, drivers_list):
        """Добавляет выпадающий список для выбора драйвера."""
        input_layout = BoxLayout(orientation='horizontal', size_hint_y=None, height=30, spacing=10)
        input_layout.add_widget(
            Label(text=label_text, size_hint_x=0.3, color=get_color_from_hex(current_colors['text_color'])))

        # Если default_value не в списке, добавляем его, чтобы он отображался изначально
        if default_value and default_value not in drivers_list:
            display_drivers = [default_value] + drivers_list
        else:
            display_drivers = drivers_list

        if not display_drivers:  # Если список пуст, показываем заглушку
            display_drivers = ['<Нет доступных драйверов>']
            default_value = '<Нет доступных драйверов>'  # Устанавливаем текст для спиннера

        spinner = Spinner(
            text=default_value if default_value else display_drivers[0] if display_drivers else '',
            values=display_drivers,
            size_hint_x=0.7,
            background_normal='',
            background_color=get_color_from_hex(current_colors['spinner_background']),
            color=get_color_from_hex(current_colors['spinner_text']),
            option_cls=ThemedSpinnerOption  # Применяем кастомный класс для опций
        )
        input_layout.add_widget(spinner)

        if section not in self.input_widgets:
            self.input_widgets[section] = {}
        self.input_widgets[section][key] = spinner  # Сохраняем ссылку на Spinner
        self.content_layout.add_widget(input_layout)

    # ИЗМЕНЕНО: Добавлен параметр dir_only
    def _show_file_chooser(self, text_input_widget, dir_only=True):
        """Показывает всплывающее окно для выбора файла или папки."""
        popup = Popup(title="Выберите папку" if dir_only else "Выберите файл или папку", size_hint=(0.9, 0.9),
                      background_color=get_color_from_hex(current_colors['popup_background']),
                      title_color=get_color_from_hex(current_colors['popup_text']))
        # ИЗМЕНЕНО: Передаем popup_instance в lambda функцию load
        content = LoadDialog(initial_path=text_input_widget.text,
                             dir_only=dir_only,
                             load=lambda path, selection: self._load_path_from_chooser(text_input_widget, path, selection, popup),
                             cancel=popup.dismiss)
        popup.content = content
        popup.open()


    # ИЗМЕНЕНО: Добавлен параметр popup_instance
    def _load_path_from_chooser(self, text_input_widget, path, selection, popup_instance):
        """Загружает выбранный путь из диалога выбора файла/папки в TextInput и закрывает попап."""
        if selection:
            # Если выбран файл или папка, используем первый выбранный элемент
            selected_path = selection[0]
        else:
            # Если ничего не выбрано (например, просто нажата кнопка "Выбрать папку"), используем текущий путь
            selected_path = path
        text_input_widget.text = selected_path
        popup_instance.dismiss() # ИСПРАВЛЕНИЕ: Закрываем попап после выбора


    def _add_checkbox_and_inputs(self, checkbox_label, section_name, default_enabled, fields_info):
        """
        Добавляет чекбокс и связанные с ним поля ввода/выпадающие списки.
        fields_info: список кортежей (label_text, key, default_value, is_password, input_widget_type)
        input_widget_type: 'textinput', 'spinner', 'mode_spinner', или 'folder_picker'
        """
        box_layout = BoxLayout(orientation='horizontal', size_hint_y=None, height=30, spacing=10)
        checkbox = CheckBox(size_hint_x=0.1, color=get_color_from_hex(current_colors['checkbox_color']))
        checkbox.active = default_enabled
        box_layout.add_widget(checkbox)
        box_layout.add_widget(Label(text=f'[b]{checkbox_label}[/b]', markup=True, size_hint_x=0.9, color=get_color_from_hex(current_colors['text_color'])))
        self.content_layout.add_widget(box_layout)
        self.checkboxes[section_name] = checkbox # Сохраняем ссылку на чекбокс

        # Создаем контейнер для полей ввода, которые будут скрываться/показываться
        input_container = BoxLayout(orientation='vertical', size_hint_y=None, height=0, opacity=0)
        input_container.bind(minimum_height=input_container.setter('height')) # Для автоматического изменения высоты

        if section_name not in self.input_widgets:
            self.input_widgets[section_name] = {}

        # Получаем список системных драйверов один раз
        system_drivers = get_system_odbc_drivers()

        for label_text, key, default_value, is_password, input_widget_type in fields_info:
            if input_widget_type == 'textinput':
                input_layout = BoxLayout(orientation='horizontal', size_hint_y=None, height=30, spacing=10)
                input_layout.add_widget(
                    Label(text=label_text, size_hint_x=0.3, color=get_color_from_hex(current_colors['text_color'])))
                widget = TextInput(
                    text=default_value,
                    multiline=False,
                    password=is_password,
                    size_hint_x=0.7,
                    background_color=get_color_from_hex(current_colors['input_background']),
                    foreground_color=get_color_from_hex(current_colors['input_text']),
                    cursor_color=get_color_from_hex(current_colors['input_cursor'])
                )
                input_layout.add_widget(widget)
                input_container.add_widget(input_layout)
                self.input_widgets[section_name][key] = widget
            elif input_widget_type == 'spinner':
                input_layout = BoxLayout(orientation='horizontal', size_hint_y=None, height=30, spacing=10)
                input_layout.add_widget(
                    Label(text=label_text, size_hint_x=0.3, color=get_color_from_hex(current_colors['text_color'])))
                spinner_values = list(system_drivers)
                if default_value and default_value not in spinner_values:
                    spinner_values.insert(0, default_value)
                if not spinner_values:
                    spinner_values = ['<Нет доступных драйверов>']
                    selected_text = '<Нет доступных драйверов>'
                else:
                    selected_text = default_value if default_value in spinner_values else spinner_values[0]

                widget = Spinner(
                    text=selected_text,
                    values=spinner_values,
                    size_hint_x=0.7,
                    background_normal='',
                    background_color=get_color_from_hex(current_colors['spinner_background']),
                    color=get_color_from_hex(current_colors['spinner_text']),
                    option_cls=ThemedSpinnerOption  # Применяем кастомный класс для опций
                )
                input_layout.add_widget(widget)
                input_container.add_widget(input_layout)
                self.input_widgets[section_name][key] = widget
            elif input_widget_type == 'mode_spinner': # НОВОЕ: Для выбора режима бэкапа
                input_layout = BoxLayout(orientation='horizontal', size_hint_y=None, height=30, spacing=10)
                input_layout.add_widget(
                    Label(text=label_text, size_hint_x=0.3, color=get_color_from_hex(current_colors['text_color'])))
                mode_spinner_values = ['all_databases', 'single_database']
                widget = Spinner(
                    text=default_value if default_value in mode_spinner_values else mode_spinner_values[0],
                    values=mode_spinner_values,
                    size_hint_x=0.7,
                    background_normal='',
                    background_color=get_color_from_hex(current_colors['spinner_background']),
                    color=get_color_from_hex(current_colors['spinner_text']),
                    option_cls=ThemedSpinnerOption  # Применяем кастомный класс для опций
                )
                input_layout.add_widget(widget)
                input_container.add_widget(input_layout)
                self.input_widgets[section_name][key] = widget
            elif input_widget_type == 'folder_picker': # НОВОЕ: Для выбора папки
                input_layout = BoxLayout(orientation='horizontal', size_hint_y=None, height=30, spacing=10)
                input_layout.add_widget(
                    Label(text=label_text, size_hint_x=0.3, color=get_color_from_hex(current_colors['text_color'])))
                widget = TextInput(
                    text=default_value,
                    multiline=False,
                    size_hint_x=0.6, # НОВОЕ: Меньший size_hint_x, чтобы освободить место для кнопки
                    background_color=get_color_from_hex(current_colors['input_background']),
                    foreground_color=get_color_from_hex(current_colors['input_text']),
                    cursor_color=get_color_from_hex(current_colors['input_cursor'])
                )
                input_layout.add_widget(widget)
                button = Button(
                    text="Обзор",
                    size_hint_x=0.1, # НОВОЕ: Кнопка "Обзор"
                    background_normal='',
                    background_color=get_color_from_hex(current_colors['button_normal']),
                    color=get_color_from_hex(current_colors['button_text'])
                )
                # ИЗМЕНЕНО: dir_only устанавливается в зависимости от поля
                if key in ['mysqldump_path', 'pg_dump_path']:
                    button.bind(on_release=lambda x, w=widget: self._show_file_chooser(w, dir_only=False))
                else: # For other folder pickers like local backup path, keep dir_only=True
                    button.bind(on_release=lambda x, w=widget: self._show_file_chooser(w, dir_only=True))

                input_layout.add_widget(button)
                input_container.add_widget(input_layout)
                self.input_widgets[section_name][key] = widget


        self.content_layout.add_widget(input_container)

        # Функция для включения/выключения полей в зависимости от состояния чекбокса
        def toggle_inputs(checkbox_instance, is_active):
            if is_active:
                input_container.height = input_container.minimum_height
                input_container.opacity = 1
            else:
                input_container.height = 0
                input_container.opacity = 0
            # Обновляем макет вручную, чтобы Kivy пересчитал размеры
            self.content_layout.do_layout()


        checkbox.bind(active=toggle_inputs)
        # Устанавливаем начальное состояние полей при загрузке UI
        toggle_inputs(checkbox, checkbox.active)


    def _build_ui(self):
        """Строит пользовательский интерфейс динамически."""
        content_layout = self.content_layout

        # --- Основные настройки ---
        self._add_section_header('Общие настройки')
        # Removed the config_file_path input field as requested
        # self._add_input_field('Путь к файлу конфигурации:', 'General', 'config_file_path', self.config_manager.config_file_path)

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
                ('Путь локального бэкапа:', 'path', DEFAULT_LOCAL_BACKUP_PATH, False, 'folder_picker'), # Используем folder_picker
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
        """Загружает существующую конфигурацию в элементы UI."""
        # Путь к файлу конфигурации больше не отображается в UI.
        # Убедимся, что General section exists, но не пытаемся получить доступ к input_widgets['General']['config_file_path']
        # if 'General' in self.input_widgets and 'config_file_path' in self.input_widgets['General']:
        #     self.input_widgets['General']['config_file_path'].text = self.config_manager.config_file_path


        # Загрузка настроек для каждого раздела
        sections_info = {
            'FTP_Backup': [
                ('server', 'textinput'), ('user', 'textinput'), ('password', 'textinput'),
                ('base_path', 'textinput'), ('encoding', 'textinput')
            ],
            'Local_Backup': [
                ('path', 'textinput')
            ],
            'WebDAV_Backup': [
                ('url', 'textinput'), ('user', 'textinput'), ('password', 'textinput'), ('base_path', 'textinput')
            ],
            'MSSQL_Backup': [
                ('driver', 'spinner'), ('server', 'textinput'), ('database', 'textinput'),
                ('user', 'textinput'), ('password', 'textinput'), ('mode', 'spinner')
            ],
            'MySQL_Backup': [
                ('mysqldump_path', 'textinput'), ('server', 'textinput'), ('database', 'textinput'),
                ('user', 'textinput'), ('password', 'textinput'), ('mode', 'spinner')
            ],
            'PostgreSQL_Backup': [
                ('pg_dump_path', 'textinput'), ('server', 'textinput'), ('database', 'textinput'),
                ('user', 'textinput'), ('password', 'textinput'), ('mode', 'spinner')
            ],
            'Compression': [
                ('password', 'textinput')
            ]
        }


        for section_name, fields in sections_info.items():
            # Загрузка состояния чекбокса
            is_enabled = self.config_manager.get_boolean_setting(section_name, 'enabled', fallback=False)
            if section_name in self.checkboxes:
                self.checkboxes[section_name].active = is_enabled

            # Загрузка значений полей ввода/спиннеров
            if section_name in self.input_widgets:
                for key, widget in self.input_widgets[section_name].items():
                    value = self.config_manager.get_setting(section_name, key)
                    if value is not None:
                        if isinstance(widget, TextInput):
                            widget.text = value
                        elif isinstance(widget, Spinner):
                            widget.text = value

    def save_config(self, instance):
        """Сохраняет текущие настройки из UI в файл конфигурации."""
        config_data = {}

        # Общие настройки
        # config_file_path остается в config_data, но не берется из UI, т.к. поля больше нет.
        config_data['General'] = {
            'config_file_path': self.config_manager.config_file_path
        }

        # Сохранение настроек для каждого раздела
        sections_info = {
            'FTP_Backup': [
                ('server', 'textinput'), ('user', 'textinput'), ('password', 'textinput'),
                ('base_path', 'textinput'), ('encoding', 'textinput')
            ],
            'Local_Backup': [
                ('path', 'textinput')
            ],
            'WebDAV_Backup': [
                ('url', 'textinput'), ('user', 'textinput'), ('password', 'textinput'), ('base_path', 'textinput')
            ],
            'MSSQL_Backup': [
                ('driver', 'spinner'), ('server', 'textinput'), ('database', 'textinput'),
                ('user', 'textinput'), ('password', 'textinput'), ('mode', 'spinner')
            ],
            'MySQL_Backup': [
                ('mysqldump_path', 'textinput'), ('server', 'textinput'), ('database', 'textinput'),
                ('user', 'textinput'), ('password', 'textinput'), ('mode', 'spinner')
            ],
            'PostgreSQL_Backup': [
                ('pg_dump_path', 'textinput'), ('server', 'textinput'), ('database', 'textinput'),
                ('user', 'textinput'), ('password', 'textinput'), ('mode', 'spinner')
            ],
            'Compression': [
                ('password', 'textinput')
            ]
        }

        for section_name, fields in sections_info.items():
            config_data[section_name] = {
                'enabled': str(self.checkboxes[section_name].active)
            }
            if section_name in self.input_widgets:
                for key, widget in self.input_widgets[section_name].items():
                    if isinstance(widget, TextInput):
                        config_data[section_name][key] = widget.text
                    elif isinstance(widget, Spinner):
                        config_data[section_name][key] = widget.text

        # Сохранение конфигурации
        if self.config_manager.write_config(config_data):
            # Закрываем приложение после успешного сохранения
            App.get_running_app().stop()
        else:
            self._show_popup("Ошибка сохранения",
                             f"Не удалось сохранить конфигурацию в '{self.config_manager.config_file_path}'. Проверьте логи.")

    def _show_popup(self, title, message):
        """Показывает всплывающее окно с сообщением."""
        box = BoxLayout(orientation='vertical', padding=10, spacing=10)
        box.add_widget(Label(text=message, color=get_color_from_hex(LIGHT_COLORS['popup_text'])))
        button = Button(text='ОК', size_hint_y=None, height=40,
                        background_normal='',
                        background_color=get_color_from_hex(LIGHT_COLORS['popup_button_normal']),
                        color=get_color_from_hex(LIGHT_COLORS['popup_button_text']))
        # Цвет при нажатии кнопки тоже из LIGHT_COLORS
        button.bind(
            on_press=lambda x: setattr(x, 'background_color', get_color_from_hex(LIGHT_COLORS['button_pressed'])))
        button.bind(on_release=lambda x: setattr(x, 'background_color',
                                                 get_color_from_hex(LIGHT_COLORS['popup_button_normal'])))

        box.add_widget(button)
        popup = Popup(title=title, content=box, size_hint=(0.8, 0.4),
                      # Фон попапа всегда из LIGHT_COLORS
                      background_color=get_color_from_hex(LIGHT_COLORS['popup_background']),
                      # Цвет заголовка попапа всегда из LIGHT_COLORS
                      title_color=get_color_from_hex(LIGHT_COLORS['popup_text']))
        button.bind(on_release=popup.dismiss)
        popup.open()

    def _open_url(self, instance, url):
        """Открывает заданный URL в браузере по умолчанию."""
        try:
            webbrowser.open(url)
            logging.info(f"Открыта ссылка: {url}")
        except Exception as e:
            logging.error(f"Не удалось открыть ссылку {url}: {e}")
            # Опционально можно показать здесь всплывающее окно с ошибкой


class ConfigApp(App):
    """Основной класс приложения Kivy."""

    def build(self):
        self.title = 'Backup tools'  # Заголовок окна приложения
        config_file = 'backup_config.ini'  # Имя файла конфигурации
        self.config_manager = ConfigManager(config_file)
        self.root_widget = ConfigEditorScreen()
        self.root_widget.set_config_manager(self.config_manager) # Передаем менеджер конфигурации в экран
        return self.root_widget
#
# if __name__ == '__main__':
#     ConfigApp().run()