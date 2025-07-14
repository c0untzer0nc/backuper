import configparser  # Для работы с INI-файлами конфигурации
import sys  # Для выхода из программы при критических ошибках
import datetime  # Для работы с датами и временем (формирование путей по дате)
import ftplib  # Для работы с FTP-протоколом
import shutil  # Для высокоуровневых операций с файлами (копирование, удаление директорий)
import subprocess  # Для запуска внешних команд (mysqldump, pg_dump)
import pyzipper  # Для создания ZIP-архивов с AES-шифрованием
import webdav4.client  # Для работы с WebDAV
import pyodbc  # Для подключения к MSSQL
import logging
from pathlib import Path
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import base64
import os
import socket

# --- НАСТРОЙКА ЛОГИРОВАНИЯ ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)

# --- НАСТРОЙКИ ПО УМОЛЧАНИЮ (Используются, если нет в файле конфигурации) ---
# Эти значения будут использоваться, если соответствующие настройки не найдены
# в INI-файле. Они должны соответствовать значениям по умолчанию в config_gui.py
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
DEFAULT_MYSQL_DUMP_PATH = 'mysqldump'  # Default path for mysqldump

DEFAULT_POSTGRESQL_DRIVER = '{PostgreSQL Unicode(x64)}'
DEFAULT_POSTGRESQL_SERVER = 'localhost'
DEFAULT_POSTGRESQL_DATABASE = 'postgres'
DEFAULT_POSTGRESQL_USER = 'postgres'
DEFAULT_POSTGRESQL_PASS = 'your_pg_password'
DEFAULT_POSTGRESQL_DUMP_PATH = 'pg_dump'  # Default path for pg_dump

DEFAULT_ZIP_PASSWORD = 'MyComplexBackupPassword2025'

# НОВАЯ НАСТРОЙКА: Количество хранимых бэкапов для ротации
DEFAULT_ROTATION_KEEP_COUNT = 7

# Директория для временных файлов бэкапов перед сжатием
TEMP_SQL_BACKUP_DIR = Path('C:\\TempSQLBackups')
# Директория для временных сжатых архивов перед загрузкой в хранилище
TEMP_COMPRESSED_DIR = Path('C:\\temp_backups')


# --- КЛАССЫ ХРАНИЛИЩ (Storages) ---

class BaseStorage:
    """Базовый класс для хранилищ бэкапов."""

    def __init__(self, config_manager):
        self.config_manager = config_manager
        self.is_enabled = False  # По умолчанию отключено
        # ИЗМЕНЕНИЕ: Считываем настройку ротации. 0 или меньше отключает ротацию.
        try:
            self.rotation_count = int(
                self.config_manager.get_setting('Rotation', 'keep_count', DEFAULT_ROTATION_KEEP_COUNT))
        except ValueError:
            self.rotation_count = DEFAULT_ROTATION_KEEP_COUNT

    def connect(self):
        """Устанавливает соединение с хранилищем."""
        raise NotImplementedError

    def upload_file(self, local_filepath, remote_filename):
        """Загружает файл в хранилище."""
        raise NotImplementedError

    def is_available(self):
        """Проверяет доступность хранилища."""
        raise NotImplementedError

    def rotate_backups(self, database_name):
        """Выполняет ротацию бэкапов в хранилище для конкретной БД."""
        raise NotImplementedError

    def close(self):
        """Закрывает соединение с хранилищем."""
        pass


class LocalStorage(BaseStorage):
    def __init__(self, config_manager):
        super().__init__(config_manager)
        # Changed section and option names
        self.base_path = Path(self.config_manager.get_setting('Local_Backup', 'path', DEFAULT_LOCAL_BACKUP_PATH))
        self.is_enabled = self.config_manager.get_boolean_setting('Local_Backup', 'enabled', False)
        if self.is_enabled:
            logging.info(f"Локальное хранилище инициализировано: {self.base_path}")

    def connect(self):
        """Для локального хранилища соединение не требуется, только проверка пути."""
        if not self.is_enabled:
            logging.info("Локальное хранилище отключено в конфигурации.")
            return False
        try:
            self.base_path.mkdir(parents=True, exist_ok=True)
            return True
        except OSError as e:
            logging.error(f"Ошибка при создании директории локального хранилища '{self.base_path}': {e}")
            return False

    def rotate_backups(self, database_name):
        """Удаляет старые бэкапы для конкретной БД, если их количество превышает лимит."""
        if not self.is_enabled or self.rotation_count <= 0:
            return

        logging.info(f"Локальное хранилище: Проверка ротации для БД '{database_name}' в '{self.base_path}'...")
        try:
            # ИСПРАВЛЕНИЕ: Шаблон имени файла теперь соответствует реальному имени.
            # Было: *_{database_name}_*_backup.zip, Стало: *{database_name}_*_backup.zip
            backup_pattern = f"*-{database_name}_*_backup.zip"
            backups = sorted(
                [p for p in self.base_path.glob(backup_pattern) if p.is_file()],
                key=lambda p: p.name
            )

            logging.info(
                f"Локальное хранилище: Найдено {len(backups)} бэкапов для БД '{database_name}'. Лимит: {self.rotation_count}.")

            # Проверяем, нужно ли удалять старые бэкапы
            if len(backups) >= self.rotation_count:
                logging.info(f"Удаляем старые бэкапы для БД '{database_name}'.")
                # Количество бэкапов для удаления
                to_delete_count = len(backups) - self.rotation_count + 1
                files_to_delete = backups[:to_delete_count]

                for f in files_to_delete:
                    try:
                        f.unlink()
                        logging.info(f"Локальное хранилище: Удален старый бэкап '{f.name}'.")
                    except OSError as e:
                        logging.error(f"Локальное хранилище: Ошибка при удалении файла '{f.name}': {e}")
        except Exception as e:
            logging.error(f"Локальное хранилище: Ошибка при ротации бэкапов: {e}")

    def upload_file(self, local_filepath, remote_filename):
        """Копирует файл в локальное хранилище."""
        if not self.is_enabled:
            logging.warning("Локальное хранилище отключено, пропуск загрузки.")
            return False
        try:
            destination_path = self.base_path / remote_filename
            shutil.copy2(local_filepath, destination_path)
            logging.info(f"Файл '{local_filepath}' успешно скопирован в локальное хранилище '{destination_path}'.")
            return True
        except IOError as e:
            logging.error(f"Ошибка при копировании файла '{local_filepath}' в локальное хранилище: {e}")
            return False

    def is_available(self):
        """Проверяет доступность локального хранилища."""
        return self.is_enabled and self.base_path.is_dir()  # Проверяем, что директория существует


class FtpStorage(BaseStorage):
    def __init__(self, config_manager):
        super().__init__(config_manager)
        # Changed section name
        self.server = self.config_manager.get_setting('FTP_Backup', 'server', DEFAULT_FTP_SERVER)
        self.user = self.config_manager.get_setting('FTP_Backup', 'user', DEFAULT_FTP_USER)
        self.passwd = self.config_manager.get_setting('FTP_Backup', 'password', DEFAULT_FTP_PASS)  # Changed option name
        self.base_path = self.config_manager.get_setting('FTP_Backup', 'base_path', DEFAULT_FTP_BASE_PATH)
        self.encoding = self.config_manager.get_setting('FTP_Backup', 'encoding', DEFAULT_FTP_ENCODING)
        self.client = None
        self.is_enabled = self.config_manager.get_boolean_setting('FTP_Backup', 'enabled', False)
        if self.is_enabled:
            logging.info(f"FTP хранилище инициализировано: {self.server}{self.base_path}")

    def connect(self):
        """Подключается к FTP-серверу и обеспечивает наличие базовой директории."""
        if not self.is_enabled:
            logging.info("FTP хранилище отключено в конфигурации.")
            return False

        if self.client:
            try:
                self.client.quit()
                logging.info("FTP: Закрыто предыдущее соединение.")
            except Exception as e:
                logging.warning(f"FTP: Ошибка при закрытии предыдущего соединения: {e}")
            finally:
                self.client = None

        try:
            self.client = ftplib.FTP(self.server, encoding=self.encoding)
            self.client.login(self.user, self.passwd)
            logging.info(f"FTP: Успешное подключение к FTP: {self.server}")

            # NEW LOGIC START
            # Сначала пытаемся напрямую перейти в базовую директорию
            try:
                self.client.cwd(self.base_path)
                logging.info(f"FTP: Успешно перешли в заданную директорию '{self.base_path}'.")
                return True
            except ftplib.error_perm:
                logging.info(f"FTP: Прямой переход в '{self.base_path}' не удался. Попытка создания по частям.")
                # Если прямой переход не удался, пробуем пошаговое создание/переход
                if not self._ensure_directory(self.base_path):
                    logging.error("FTP: Не удалось создать или перейти в базовую директорию.")
                    self.client.quit()
                    self.client = None
                    return False
                return True
            # NEW LOGIC END

        except ftplib.all_errors as e:
            logging.error(f"FTP: Ошибка подключения к FTP или навигации по директориям: {e}")
            self.client = None
            return False

    def _ensure_directory(self, path):
        """
        Гарантирует существование заданного пути директории на FTP-сервере.
        Переходит в существующие директории и создает недостающие пошагово.
        Предполагается, что клиент уже подключен и авторизован.
        """
        if not path or path == '/':
            return True  # Корневая директория всегда считается существующей

        # Удаляем ведущие/конечные слеши для согласованного разделения, за исключением случая, если это просто "/"
        clean_path = path.strip('/')
        path_components = clean_path.split('/')

        # Переходим в корень, чтобы убедиться, что все пути абсолютные от корня
        try:
            self.client.cwd('/')
            logging.info("FTP: Перешли в корневую директорию '/'.")
        except ftplib.error_perm as e:
            logging.error(f"FTP: Не удалось перейти в корневую директорию: {e}")
            return False

        # Построение пути инкрементально и попытка навигации/создания
        current_path_parts = []
        for component in path_components:
            if not component:  # Пропускаем пустые компоненты (например, из "//" или конечного слеша)
                continue
            current_path_parts.append(component)
            full_path_for_component = '/' + '/'.join(current_path_parts)  # Восстанавливаем абсолютный путь

            try:
                self.client.cwd(full_path_for_component)
                logging.info(f"FTP: Успешно перешли в '{full_path_for_component}'")
            except ftplib.error_perm as e:
                # Если cwd не удается, это означает, что директории не существует, пытаемся создать ее
                if "550" in str(e):  # Общая ошибка для "No such file or directory"
                    try:
                        self.client.mkd(full_path_for_component)
                        logging.info(f"FTP: Успешно создана директория '{full_path_for_component}'")
                        self.client.cwd(full_path_for_component)  # Переходим в только что созданную директорию
                    except ftplib.error_perm as create_e:
                        logging.error(
                            f"FTP: Не удалось создать и перейти в директорию '{full_path_for_component}': {create_e}")
                        return False
                else:
                    logging.error(
                        f"FTP: Ошибка разрешений или другая проблема при навигации к '{full_path_for_component}': {e}")
                    return False
            except Exception as e:
                logging.error(f"FTP: Произошла непредвиденная ошибка при навигации к '{full_path_for_component}': {e}")
                return False

        # После цикла мы должны находиться в конечной директории пути
        return True

    def rotate_backups(self, database_name):
        """Удаляет старые бэкапы на FTP для конкретной БД, если их количество превышает лимит."""
        if not self.is_enabled or self.rotation_count <= 0 or not self.client:
            return

        logging.info(f"FTP: Проверка ротации для БД '{database_name}' в '{self.base_path}'...")
        try:
            self.client.cwd(self.base_path)
            filenames = self.client.nlst()

            # ИСПРАВЛЕНИЕ: Фильтруем файлы, используя правильный шаблон имени с дефисом.
            # Было: f"_{database_name}_" in f, Стало: f"-{database_name}_" in f
            backup_files = sorted([f for f in filenames if f.endswith('.zip') and f"-{database_name}_" in f])

            logging.info(
                f"FTP: Найдено {len(backup_files)} бэкапов для БД '{database_name}'. Лимит: {self.rotation_count}.")

            if len(backup_files) >= self.rotation_count:
                logging.info(f"Удаляем старые бэкапы для БД '{database_name}'.")
                to_delete_count = len(backup_files) - self.rotation_count + 1
                files_to_delete = backup_files[:to_delete_count]

                for filename in files_to_delete:
                    try:
                        self.client.delete(filename)
                        logging.info(f"FTP: Удален старый бэкап '{filename}'.")
                    except ftplib.all_errors as e:
                        logging.error(f"FTP: Ошибка при удалении файла '{filename}': {e}")
        except ftplib.all_errors as e:
            logging.error(f"FTP: Ошибка при ротации бэкапов: {e}")
        except Exception as e:
            logging.error(f"FTP: Непредвиденная ошибка при ротации бэкапов: {e}")

    def upload_file(self, local_filepath, remote_filename):
        """Загружает файл на FTP-сервер."""
        if not self.is_enabled:
            logging.warning("FTP хранилище отключено, пропуск загрузки.")
            return False

        if not self.client:
            logging.warning("FTP: Нет активного FTP-соединения. Попытка переподключения...")
            if not self.connect():
                logging.error("FTP: Не удалось переподключиться к FTP для загрузки.")
                return False

        # Убедимся, что мы находимся в правильной базовой директории перед загрузкой
        # Это важно, если другие операции изменили текущую рабочую директорию
        try:
            self.client.cwd(self.base_path)
            logging.info(f"FTP: Изменили директорию на базовую '{self.base_path}' для загрузки.")
        except ftplib.error_perm as e:
            logging.error(f"FTP: Не удалось перейти в базовую директорию '{self.base_path}' для загрузки: {e}")
            return False

        try:
            with open(local_filepath, 'rb') as f:
                self.client.storbinary(f'STOR {remote_filename}', f)
            logging.info(
                f"FTP: Файл '{os.path.basename(local_filepath)}' успешно загружен на FTP в '{self.base_path}/{remote_filename}'.")
            return True
        except ftplib.all_errors as e:
            logging.error(f"FTP: Ошибка при загрузке файла '{local_filepath}' на FTP: {e}")
            return False

    def is_available(self):
        """Проверяет доступность FTP-хранилища."""
        if not self.is_enabled:
            return False
        try:
            if self.client:
                self.client.voidcmd("NOOP")  # Отправляем NOOP команду, чтобы проверить соединение
                return True
            return False
        except ftplib.all_errors:
            self.client = None  # Сбрасываем соединение, если оно неактивно
            return False

    def close(self):
        """Закрывает FTP-соединение."""
        if self.client:
            try:
                self.client.quit()
                logging.info("FTP: Соединение закрыто.")
            except Exception as e:
                logging.warning(f"FTP: Ошибка при закрытии соединения: {e}")
            finally:
                self.client = None


class WebDAVStorage(BaseStorage):
    def __init__(self, config_manager):
        super().__init__(config_manager)
        # Changed section name
        self.url = self.config_manager.get_setting('WebDAV_Backup', 'url', DEFAULT_WEBDAV_URL)
        self.user = self.config_manager.get_setting('WebDAV_Backup', 'user', DEFAULT_WEBDAV_USER)
        self.passwd = self.config_manager.get_setting('WebDAV_Backup', 'password',
                                                      DEFAULT_WEBDAV_PASS)  # Changed option name
        self.base_path = self.config_manager.get_setting('WebDAV_Backup', 'base_path', DEFAULT_WEBDAV_BASE_PATH)
        self.client = None
        self.is_enabled = self.config_manager.get_boolean_setting('WebDAV_Backup', 'enabled', False)
        self.connected = False  # Инициализируем состояние подключения
        if self.is_enabled:
            logging.info(f"WebDAV хранилище инициализировано: {self.url}{self.base_path}")

    def connect(self):
        """Подключается к WebDAV-серверу и создает базовую директорию, если она не существует."""
        if not self.is_enabled:
            logging.info("WebDAV хранилище отключено в конфигурации.")
            self.connected = False
            return False
        try:
            self.client = webdav4.client.Client(
                base_url=self.url,
                auth=(self.user, self.passwd)
            )

            # Ensure the base path exists by creating components iteratively
            if not self._ensure_directory(self.base_path):
                logging.error("WebDAV: Не удалось создать или перейти в базовую директорию.")
                self.client = None
                self.connected = False
                return False

            logging.info(f"WebDAV: Успешное подключение к WebDAV: {self.url}")
            self.connected = True  # Устанавливаем connected в True при успешном подключении
            return True
        except Exception as e:
            logging.error(f"WebDAV: Ошибка подключения: {e}")
            self.client = None
            self.connected = False
            return False

    def _ensure_directory(self, path):
        current_path_components = Path(path).parts
        accumulated_path = Path('/')

        for component in current_path_components:
            if not component:
                continue

            full_path_for_component = accumulated_path / component
            logging.info(f"WebDAV: Проверяем наличие директории: '{full_path_for_component}'")
            try:
                # Используем .as_posix() для получения пути с прямыми слэшами
                if not self.client.exists(full_path_for_component.as_posix()):
                    logging.info(f"WebDAV: Директория '{full_path_for_component}' не найдена. Попытка создания...")
                    self.client.mkdir(full_path_for_component.as_posix())
                    logging.info(f"WebDAV: Успешно создана директория '{full_path_for_component}'")
                else:
                    logging.info(f"WebDAV: Директория '{full_path_for_component}' уже существует.")
            except Exception as e:
                logging.error(f"WebDAV: Непредвиденная ошибка при проверке/создании '{full_path_for_component}': {e}")
                logging.error("WebDAV: Не удалось создать или перейти в базовую директорию.")
                return False
            accumulated_path = full_path_for_component
        logging.info(f"WebDAV: Базовая директория '{path}' доступна.")
        return True

    def rotate_backups(self, database_name):
        """Удаляет старые бэкапы на WebDAV для конкретной БД, если их количество превышает лимит."""
        if not self.is_enabled or self.rotation_count <= 0 or not self.client:
            return

        logging.info(f"WebDAV: Проверка ротации для БД '{database_name}' в '{self.base_path}'...")
        try:
            files_info = self.client.list(self.base_path, get_info=True)

            # ИСПРАВЛЕНИЕ: Фильтруем файлы, используя правильный шаблон имени с дефисом.
            # Было: f"_{database_name}_" in f['name'], Стало: f"-{database_name}_" in f['name']
            backup_files = sorted(
                [f for f in files_info if
                 f['name'].endswith('.zip') and f.get('type') == 'file' and f"-{database_name}_" in f['name']],
                key=lambda f: os.path.basename(f['name'])
            )

            logging.info(
                f"WebDAV: Найдено {len(backup_files)} бэкапов для БД '{database_name}'. Лимит: {self.rotation_count}.")

            if len(backup_files) >= self.rotation_count:
                logging.info(f"Удаляем старые бэкапы для БД '{database_name}'.")
                to_delete_count = len(backup_files) - self.rotation_count + 1
                files_to_delete = backup_files[:to_delete_count]

                for file_info in files_to_delete:
                    path_to_delete = file_info['name']
                    try:
                        self.client.remove(path_to_delete)
                        logging.info(f"WebDAV: Удален старый бэкап '{os.path.basename(path_to_delete)}'.")
                    except Exception as e:
                        logging.error(f"WebDAV: Ошибка при удалении файла '{os.path.basename(path_to_delete)}': {e}")
        except Exception as e:
            logging.error(f"WebDAV: Ошибка при ротации бэкапов: {e}")

    def upload_file(self, local_path, remote_path):
        # Используем self.connected для проверки состояния подключения
        if not self.connected:
            logging.error("WebDAV: Не подключено к хранилищу WebDAV.")
            return False
        try:
            full_remote_path = Path(self.base_path) / remote_path  # Исправлено: self.base_dir на self.base_path
            webdav_target_path = full_remote_path.as_posix().lstrip('/')
            logging.info(f"WebDAV: Загрузка файла '{local_path}' в '{webdav_target_path}'...")
            self.client.upload_file(local_path, webdav_target_path)
            logging.info(f"WebDAV: Файл '{local_path}' успешно загружен в WebDAV.")
            return True
        except Exception as e:
            logging.error(f"WebDAV: Ошибка при загрузке файла '{local_path}': {e}")
            return False

    def is_available(self):
        """Проверяет доступность WebDAV-хранилища."""
        if not self.is_enabled:
            return False
        try:
            if self.client and self.connected:  # Добавлена проверка self.connected
                # Попытка выполнить простую операцию, чтобы проверить соединение
                # Например, получить список содержимого базовой директории
                self.client.list(self.base_path)
                return True
            return False
        except Exception:
            self.client = None
            self.connected = False  # Сбрасываем состояние подключения при ошибке
            return False

    def close(self):
        """Закрывает WebDAV-соединение."""
        if self.client:
            try:
                # Для webdav4 client нет явного метода close/quit,
                # можно сбросить ссылку на объект.
                self.client = None
                self.connected = False  # Сбрасываем состояние подключения
                logging.info("WebDAV: Соединение закрыто.")
            except Exception as e:
                logging.warning(f"WebDAV: Ошибка при закрытии соединения: {e}")


# --- КЛАССЫ КОМПРЕССОРОВ ---

class Compressor:
    """Базовый класс для компрессоров."""

    def compress(self, source_path, output_archive_path):
        """Сжимает файл/папку."""
        raise NotImplementedError


class ZipCompressor(Compressor):
    def __init__(self, password=None):
        self.password = password.encode('utf-8') if password else None  # Пароль должен быть в байтах

    def compress(self, source_path, output_archive_path):
        """
        Сжимает файл или директорию в ZIP-архив с AES-шифрованием (если указан пароль).
        """
        source_path = Path(source_path)
        output_archive_path = Path(output_archive_path)

        # Создаем директорию для выходного архива, если ее нет
        output_archive_path.parent.mkdir(parents=True, exist_ok=True)

        logging.info(f"Архивирование '{source_path}' в '{output_archive_path}'...")

        try:
            with pyzipper.AESZipFile(
                    output_archive_path,
                    'w',
                    compression=pyzipper.ZIP_LZMA,  # Используем LZMA для лучшего сжатия
                    encryption=pyzipper.WZ_AES if self.password else pyzipper.ZIP_DEFLATED
            ) as zf:
                if self.password:
                    zf.setpassword(self.password)

                if source_path.is_file():
                    zf.write(source_path, source_path.name)
                elif source_path.is_dir():
                    for folder_name, subfolders, filenames in os.walk(source_path):
                        for filename in filenames:
                            file_path = Path(folder_name) / filename
                            # Добавляем файл в архив с относительным путем
                            zf.write(file_path, file_path.relative_to(source_path.parent))
                else:
                    logging.error(f"Источник '{source_path}' не является ни файлом, ни директорией.")
                    return False
            logging.info(f"Архив '{output_archive_path}' создан успешно.")
            return True
        except Exception as e:
            logging.error(f"Ошибка при создании ZIP-архива '{output_archive_path}': {e}")
            return False


# --- КЛАССЫ БЭКАПЕРОВ (Backupers) ---

class BaseBackup:
    """Базовый класс для выполнения бэкапов."""

    def __init__(self, config_manager, compressor, storages):
        self.config_manager = config_manager
        self.compressor = compressor
        self.storages = storages  # Список активных объектов хранилищ

    def run_backup(self):
        """Запускает процесс бэкапа."""
        raise NotImplementedError

    def _upload_and_cleanup(self, zipped_backup_path, database_name, original_backup_path=None):
        """Загружает сжатый файл в настроенные хранилища, выполняет ротацию и очищает временные файлы."""
        remote_filename = zipped_backup_path.name  # Имя файла для удаленного хранилища

        for storage in self.storages:
            if storage.is_enabled:
                # ИЗМЕНЕНИЕ: 1. Выполняем ротацию ПЕРЕД загрузкой нового бэкапа, передавая имя БД
                logging.info(
                    f"Выполнение ротации для хранилища '{type(storage).__name__.replace('Storage', '')}' для БД '{database_name}'...")
                storage.rotate_backups(database_name)

                # ИЗМЕНЕНИЕ: 2. Загружаем новый бэкап
                logging.info(
                    f"Загрузка бэкапа '{remote_filename}' в хранилище '{type(storage).__name__.replace('Storage', '')}'...")
                if storage.upload_file(zipped_backup_path, remote_filename):
                    logging.info(
                        f"Бэкап '{remote_filename}' успешно загружен в '{type(storage).__name__.replace('Storage', '')}'.")
                else:
                    logging.error(
                        f"Не удалось загрузить бэкап '{remote_filename}' в '{type(storage).__name__.replace('Storage', '')}'.")
            else:
                logging.info(
                    f"Хранилище '{type(storage).__name__.replace('Storage', '')}' отключено, пропуск загрузки.")

        # Очистка временных файлов
        if zipped_backup_path.exists():
            zipped_backup_path.unlink()
            logging.info(f"Временный сжатый файл '{zipped_backup_path}' удален.")

        if original_backup_path and original_backup_path.exists():
            if original_backup_path.is_dir():
                shutil.rmtree(original_backup_path)
                logging.info(f"Временная директория бэкапа '{original_backup_path}' удалена.")
            else:
                original_backup_path.unlink()
                logging.info(f"Временный файл бэкапа '{original_backup_path}' удален.")


class MssqlBackup(BaseBackup):
    def __init__(self, config_manager, compressor, storages):
        super().__init__(config_manager, compressor, storages)
        self.driver = self.config_manager.get_setting('MSSQL_Backup', 'driver', DEFAULT_MSSQL_DRIVER)
        self.server = self.config_manager.get_setting('MSSQL_Backup', 'server', DEFAULT_MSSQL_SERVER)
        self.database = self.config_manager.get_setting('MSSQL_Backup', 'database', DEFAULT_MSSQL_DATABASE)
        self.user = self.config_manager.get_setting('MSSQL_Backup', 'user', DEFAULT_MSSQL_USER)
        self.passwd = self.config_manager.get_setting('MSSQL_Backup', 'password',
                                                      DEFAULT_MSSQL_PASS)  # Changed option name
        # Changed option name from backup_mode to mode
        self.backup_mode = self.config_manager.get_setting('MSSQL_Backup', 'mode',
                                                           'all_databases')  # 'all_databases' или 'single_database'

        self.conn = None
        self.cursor = None

    def _connect_db(self):
        try:
            conn_str = (
                f"DRIVER={self.driver};"
                f"SERVER={self.server};"
                f"UID={self.user};"
                f"PWD={self.passwd};"
                f"Encrypt=no;"  # Современные драйверы ODBC могут требовать этого
            )
            # Если база данных указана для single_database режима, добавляем ее в строку подключения
            if self.backup_mode == 'single_database' and self.database:
                conn_str += f"DATABASE={self.database};"

            self.conn = pyodbc.connect(conn_str, autocommit=True)  # autocommit для BACKUP DATABASE
            self.cursor = self.conn.cursor()
            logging.info(f"Успешное подключение к MSSQL серверу '{self.server}'.")
            return True
        except pyodbc.Error as e:
            sqlstate = e.args[0]
            logging.error(f"Ошибка подключения к MSSQL: {sqlstate} - {e}")
            return False

    def _disconnect_db(self):
        if self.cursor:
            self.cursor.close()
        if self.conn:
            self.conn.close()
            logging.info("Соединение с MSSQL сервером закрыто.")

    def _get_user_databases(self):
        """Получает список пользовательских баз данных."""
        try:
            # Исключаем системные базы данных
            self.cursor.execute("""
                SELECT name
                FROM sys.databases
                WHERE database_id > 4 AND state = 0;
            """)
            return [row[0] for row in self.cursor.fetchall()]
        except pyodbc.Error as e:
            logging.error(f"Ошибка при получении списка баз данных: {e}")
            return []

    def run_backup(self):
        if not self.config_manager.get_boolean_setting('MSSQL_Backup', 'enabled', fallback=False):
            return

        logging.info("Начинаем бэкап MSSQL баз данных...")

        TEMP_SQL_BACKUP_DIR.mkdir(parents=True, exist_ok=True)
        logging.info(f"Подготовлена директория для временных бэкапов SQL Server: {TEMP_SQL_BACKUP_DIR}")

        if not self._connect_db():
            logging.error("Не удалось подключиться к MSSQL для выполнения бэкапа.")
            return

        databases_to_backup = []
        if self.backup_mode == 'all_databases':
            logging.info("Режим бэкапа: Все пользовательские базы данных.")
            databases_to_backup = self._get_user_databases()
        elif self.backup_mode == 'single_database':
            if self.database:
                logging.info(f"Режим бэкапа: Одна база данных ('{self.database}').")
                databases_to_backup = [self.database]
            else:
                logging.error("Режим 'single_database' выбран, но имя базы данных не указано.")
                self._disconnect_db()
                return

        if not databases_to_backup:
            logging.warning("Нет баз данных для бэкапа в соответствии с конфигурацией.")
            self._disconnect_db()
            return

        for db_name in databases_to_backup:
            backup_filename = f"{db_name}_mssql_backup.bak"
            backup_path = TEMP_SQL_BACKUP_DIR / backup_filename

            # Имя архива включает дату и время для уникальности
            timestamp = datetime.datetime.now().strftime("%Y_%m_%d-%H_%M_%S")
            zipped_backup_filename = f"{timestamp}-{db_name}_mssql_backup.zip"
            zipped_backup_path = TEMP_COMPRESSED_DIR / zipped_backup_filename
            TEMP_COMPRESSED_DIR.mkdir(parents=True, exist_ok=True)  # Убедимся, что директория существует

            logging.info(f"Начинаем бэкап базы данных '{db_name}'...")
            try:
                # BACKUP DATABASE [имя_бд] TO DISK = N'путь_к_файлу.bak' WITH COPY_ONLY, NO_COMPRESSION, INIT;
                # COPY_ONLY не влияет на обычную цепочку бэкапов (полный/разностный/лог)
                # NO_COMPRESSION - не сжимаем, сжатие будет нашим zip-компрессором
                # INIT - перезаписывает существующий бэкап в файле
                sql_command = f"BACKUP DATABASE [{db_name}] TO DISK = N'{backup_path}' WITH INIT, NO_COMPRESSION"
                logging.info(f"Выполнение SQL-команды: {sql_command}")
                self.cursor.execute(sql_command)
                logging.info(f"Бэкап базы данных '{db_name}' успешно создан в '{backup_path}'.")

                # Проверка наличия файла
                if not backup_path.exists():
                    logging.error(f"Бэкап-файл '{backup_path}' не был создан.")
                    continue
                logging.info(f"Проверяем наличие файла по пути: '{backup_path}'")
                logging.info(f"Размер созданного MSSQL бэкап-файла '{backup_path}': {backup_path.stat().st_size} байт.")

                logging.info(f"Начинаем сжатие файла '{backup_path}' в '{zipped_backup_path}'...")
                if self.compressor.compress(backup_path, zipped_backup_path):
                    logging.info(f"Бэкап '{db_name}' успешно сжат в '{zipped_backup_path}'.")
                    self._upload_and_cleanup(zipped_backup_path, db_name, backup_path)
                else:
                    logging.error(f"Не удалось сжать бэкап '{db_name}'.")

            except pyodbc.Error as e:
                logging.error(f"Ошибка при бэкапе базы данных '{db_name}': {e}")
            except Exception as e:
                logging.error(f"Непредвиденная ошибка во время бэкапа '{db_name}': {e}")

        self._disconnect_db()
        logging.info("=== Процесс бэкапа MSSQL завершен ===")


class MysqlBackup(BaseBackup):
    def __init__(self, config_manager, compressor, storages):
        super().__init__(config_manager, compressor, storages)
        self.server = self.config_manager.get_setting('MySQL_Backup', 'server', DEFAULT_MYSQL_SERVER)
        self.database = self.config_manager.get_setting('MySQL_Backup', 'database', DEFAULT_MYSQL_DATABASE)
        self.user = self.config_manager.get_setting('MySQL_Backup', 'user', DEFAULT_MYSQL_USER)
        self.passwd = self.config_manager.get_setting('MySQL_Backup', 'password',
                                                      DEFAULT_MYSQL_PASS)  # Changed option name
        # Added mysqldump_path
        self.mysqldump_path = self.config_manager.get_setting('MySQL_Backup', 'mysqldump_path', DEFAULT_MYSQL_DUMP_PATH)
        # Changed option name from mode to backup_mode for consistency
        self.backup_mode = self.config_manager.get_setting('MySQL_Backup', 'mode', 'all')

    def run_backup(self):
        if not self.config_manager.get_boolean_setting('MySQL_Backup', 'enabled', fallback=False):
            return

        logging.info("Начинаем бэкап MySQL баз данных...")

        TEMP_COMPRESSED_DIR.mkdir(parents=True, exist_ok=True)

        timestamp = datetime.datetime.now().strftime("%Y_%m_%d-%H_%M_%S")
        db_identifier = self.database if self.database and self.database.lower() != 'all' else 'all_databases'
        output_filename = f"mysql_backup_{timestamp}.sql"  # This is a temp file, not the final archive name, keep it simple.
        output_filepath = TEMP_COMPRESSED_DIR / output_filename  # Define output_filepath
        zipped_backup_filename = f"{timestamp}-{db_identifier}_mysql_backup.zip"
        zipped_backup_path = TEMP_COMPRESSED_DIR / zipped_backup_filename

        try:
            # mysqldump -u [user] -p[password] --host=[host] [database_name] > [output_file.sql]
            # Добавим --all-databases если не указана конкретная БД
            command = [
                self.mysqldump_path,  # Using the configured path
                f'--user={self.user}',
                f'--password={self.passwd}',
                f'--host={self.server}'
            ]
            if self.database and self.database.lower() != 'all':  # "all" как индикатор для всех БД
                command.append(self.database)
            else:
                command.append('--all-databases')  # Бэкап всех баз данных

            logging.info(f"Выполнение команды mysqldump: {' '.join(command)} > {output_filepath}")

            with open(output_filepath, 'w', encoding='utf-8') as f:
                subprocess.run(command, stdout=f, check=True)  # check=True вызывает исключение при ошибке

            logging.info(f"Бэкап MySQL успешно создан в '{output_filepath}'.")

            logging.info(f"Начинаем сжатие файла '{output_filepath}' в '{zipped_backup_path}'...")
            if self.compressor.compress(output_filepath, zipped_backup_path):
                logging.info(f"Бэкап MySQL успешно сжат в '{zipped_backup_path}'.")
                # Для MySQL имя БД для ротации - это db_identifier
                self._upload_and_cleanup(zipped_backup_path, db_identifier, output_filepath)
            else:
                logging.error("Не удалось сжать бэкап MySQL.")

        except FileNotFoundError:
            logging.error(
                f"mysqldump не найден по пути '{self.mysqldump_path}'. Убедитесь, что MySQL установлен и путь к mysqldump указан верно в конфигурации или находится в PATH.")
        except subprocess.CalledProcessError as e:
            logging.error(f"Ошибка выполнения mysqldump: {e}")
        except Exception as e:
            logging.error(f"Непредвиденная ошибка во время бэкапа MySQL: {e}")
        finally:
            # Очистка SQL файла, если он остался
            if output_filepath.exists():
                output_filepath.unlink()
                logging.info(f"Временный SQL файл '{output_filepath}' удален.")
        logging.info("=== Процесс бэкапа MySQL завершен ===")


class PostgresqlBackup(BaseBackup):
    def __init__(self, config_manager, compressor, storages):
        super().__init__(config_manager, compressor, storages)
        self.server = self.config_manager.get_setting('PostgreSQL_Backup', 'server', DEFAULT_POSTGRESQL_SERVER)
        self.database = self.config_manager.get_setting('PostgreSQL_Backup', 'database', DEFAULT_POSTGRESQL_DATABASE)
        self.user = self.config_manager.get_setting('PostgreSQL_Backup', 'user', DEFAULT_POSTGRESQL_USER)
        self.passwd = self.config_manager.get_setting('PostgreSQL_Backup', 'password',
                                                      DEFAULT_POSTGRESQL_PASS)  # Changed option name
        # Added pg_dump_path
        self.pg_dump_path = self.config_manager.get_setting('PostgreSQL_Backup', 'pg_dump_path',
                                                            DEFAULT_POSTGRESQL_DUMP_PATH)
        # Changed option name from mode to backup_mode for consistency
        self.backup_mode = self.config_manager.get_setting('PostgreSQL_Backup', 'mode', 'all')

    def run_backup(self):
        if not self.config_manager.get_boolean_setting('PostgreSQL_Backup', 'enabled', fallback=False):
            return

        logging.info("Начинаем бэкап PostgreSQL баз данных...")

        TEMP_COMPRESSED_DIR.mkdir(parents=True, exist_ok=True)

        timestamp = datetime.datetime.now().strftime("%Y_%m_%d-%H_%M_%S")
        db_identifier = self.database if self.database and self.database.lower() != 'all' else 'all_databases'
        output_filename = f"postgresql_backup_{timestamp}.sql"  # This is a temp file, not the final archive name, keep it simple.
        output_filepath = TEMP_COMPRESSED_DIR / output_filename  # Define output_filepath
        zipped_backup_filename = f"{timestamp}-{db_identifier}_postgresql_backup.zip"
        zipped_backup_path = TEMP_COMPRESSED_DIR / zipped_backup_filename

        try:
            # pg_dump -h [host] -U [user] [database_name] > [output_file.sql]
            # Используем PGPASSWORD для передачи пароля
            env = os.environ.copy()
            env['PGPASSWORD'] = self.passwd

            command = [
                self.pg_dump_path,  # Using the configured path
                f'--host={self.server}',
                f'--username={self.user}',
            ]
            if self.database and self.database.lower() != 'all':  # "all" как индикатор для всех БД
                command.append(self.database)
            else:
                command.append('--all-databases')  # Бэкап всех баз данных

            logging.info(f"Выполнение команды pg_dump: {' '.join(command)} > {output_filepath}")

            with open(output_filepath, 'w', encoding='utf-8') as f:
                subprocess.run(command, stdout=f, check=True, env=env)

            logging.info(f"Бэкап PostgreSQL успешно создан в '{output_filepath}'.")

            logging.info(f"Начинаем сжатие файла '{output_filepath}' в '{zipped_backup_path}'...")
            if self.compressor.compress(output_filepath, zipped_backup_path):
                logging.info(f"Бэкап PostgreSQL успешно сжат в '{zipped_backup_path}'.")
                # Для PostgreSQL имя БД для ротации - это db_identifier
                self._upload_and_cleanup(zipped_backup_path, db_identifier, output_filepath)
            else:
                logging.error("Не удалось сжать бэкап PostgreSQL.")

        except FileNotFoundError:
            logging.error(
                f"pg_dump не найден по пути '{self.pg_dump_path}'. Убедитесь, что PostgreSQL установлен и путь к pg_dump указан верно в конфигурации или находится в PATH.")
        except subprocess.CalledProcessError as e:
            logging.error(f"Ошибка выполнения pg_dump: {e}. Проверьте пароль и доступ.")
        except Exception as e:
            logging.error(f"Непредвиденная ошибка во время бэкапа PostgreSQL: {e}")
        finally:
            # Очистка SQL файла, если он остался
            if output_filepath.exists():
                output_filepath.unlink()
                logging.info(f"Временный SQL файл '{output_filepath}' удален.")
        logging.info("=== Процесс бэкапа PostgreSQL завершен ===")


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
            logging.info(
                "Новый Fernet ключ сгенерирован и зашифрован. Будет сохранен при следующей записи конфигурации.")
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
                logging.warning(
                    f"Нет ключа шифрования или значение None, возвращаем необработанное значение для {section}/{option}.")
                return value  # Возвращаем необработанное значение, если нет ключа или значение None
        return value

    def get_boolean_setting(self, section, option, fallback=False):
        """
        Получает булеву настройку из указанной секции.
        Булевы настройки не нуждаются в шифровании.
        """
        return self.config.getboolean(section, option, fallback=fallback)


# --- ОСНОВНАЯ ФУНКЦИЯ ЗАПУСКА БЭКАПОВ ---
def main():
    config_file = 'backup_config.ini'
    global_config_manager = ConfigManager(config_file)

    # Инициализация компрессора
    # Changed section and option names
    zip_password = global_config_manager.get_setting('Compression', 'password', DEFAULT_ZIP_PASSWORD)
    logging.info(f"Используемый ZIP-пароль: {'*' * len(zip_password)}")  # Не выводим пароль в лог
    compressor_with_password = ZipCompressor(password=zip_password)

    # Инициализация и подключение хранилищ
    storages = [
        LocalStorage(global_config_manager),
        FtpStorage(global_config_manager),
        WebDAVStorage(global_config_manager)
    ]

    active_storages = []
    for storage in storages:
        if storage.is_enabled:
            logging.info(f"Попытка подключения к хранилищу '{type(storage).__name__.replace('Storage', '')}'...")
            if storage.connect():
                active_storages.append(storage)
            else:
                logging.error(
                    f"Не удалось подключиться к хранилищу '{type(storage).__name__.replace('Storage', '')}'. Оно будет пропущено.")
        else:
            logging.info(f"Хранилище '{type(storage).__name__.replace('Storage', '')}' отключено в конфигурации.")

    if not active_storages:
        logging.error("Нет активных хранилищ для бэкапа. Завершение работы.")
        return

    logging.info("\n--- Запуск процессов бэкапа баз данных ---")

    # MSSQL Backup
    if global_config_manager.get_boolean_setting('MSSQL_Backup', 'enabled', fallback=False):
        logging.info("\n=== Запуск процесса бэкапа MSSQL ===")
        mssql_backup_instance = MssqlBackup(
            config_manager=global_config_manager,
            compressor=compressor_with_password,
            storages=[s for s in active_storages]
        )
        mssql_backup_instance.run_backup()
        logging.info("=== Процесс бэкапа MSSQL завершен ===")
    else:
        logging.info("\nБэкап MSSQL отключен в конфигурации.")

    # MySQL Backup
    if global_config_manager.get_boolean_setting('MySQL_Backup', 'enabled', fallback=False):
        logging.info("\n=== Запуск процесса бэкапа MySQL ===")
        mysql_backup_instance = MysqlBackup(
            config_manager=global_config_manager,
            compressor=compressor_with_password,  # Используем компрессор с паролем
            storages=[s for s in active_storages]
        )
        mysql_backup_instance.run_backup()
        logging.info("=== Процесс бэкапа MySQL завершен ===")
    else:
        logging.info("\nБэкап MySQL отключен в конфигурации.")

    # PostgreSQL Backup
    if global_config_manager.get_boolean_setting('PostgreSQL_Backup', 'enabled', fallback=False):
        logging.info("\n=== Запуск процесса бэкапа PostgreSQL ===")
        postgresql_backup_instance = PostgresqlBackup(
            config_manager=global_config_manager,
            compressor=compressor_with_password,  # Используем компрессор с паролем
            storages=[s for s in active_storages]
        )
        postgresql_backup_instance.run_backup()
        logging.info("=== Процесс бэкапа PostgreSQL завершен ===")
    else:
        logging.info("\nБэкап PostgreSQL отключен в конфигурации.")

    logging.info("\n--- Все процессы бэкапа завершены ---")

    # Закрытие всех открытых соединений хранилищ
    for storage in active_storages:
        storage.close()

# if __name__ == '__main__':
#     main()