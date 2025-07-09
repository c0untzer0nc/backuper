# init.py

import os
import subprocess
import sys
import logging

# --- НАСТРОЙКА ЛОГИРОВАНИЯ ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)

CONFIG_FILE = 'backup_config.ini'
GUI_SCRIPT = 'gui.py'
BACKUP_SCRIPT = 'back.py'

def run_script(script_name):
    """
    Запускает указанный Python-скрипт как подпроцесс.
    """
    logging.info(f"Запуск скрипта: {script_name}")
    try:
        # sys.executable - это путь к текущему интерпретатору Python
        process = subprocess.run([sys.executable, script_name], check=True)
        logging.info(f"Скрипт '{script_name}' завершен с кодом выхода: {process.returncode}")
    except subprocess.CalledProcessError as e:
        logging.error(f"Ошибка при выполнении скрипта '{script_name}': {e}")
        logging.error(f"Стандартный вывод (stdout): {e.stdout.decode() if e.stdout else 'N/A'}")
        logging.error(f"Стандартная ошибка (stderr): {e.stderr.decode() if e.stderr else 'N/A'}")
        sys.exit(1) # Выход с ошибкой, если подпроцесс завершился с ошибкой
    except FileNotFoundError:
        logging.error(f"Ошибка: Скрипт '{script_name}' не найден. Убедитесь, что он находится в той же директории, что и init.py.")
        sys.exit(1)
    except Exception as e:
        logging.error(f"Неизвестная ошибка при запуске скрипта '{script_name}': {e}")
        sys.exit(1)

def main():
    """
    Основная логика запуска приложения.
    """
    script_dir = os.path.dirname(os.path.abspath(__file__))
    config_path = os.path.join(script_dir, CONFIG_FILE)

    logging.info(f"Проверка наличия файла конфигурации: {config_path}")

    if not os.path.exists(config_path):
        logging.warning(f"Файл '{CONFIG_FILE}' не найден. Запускаем '{GUI_SCRIPT}' для настройки.")
        run_script(GUI_SCRIPT)
        logging.info(f"'{GUI_SCRIPT}' завершил работу. Проверяем, был ли создан файл конфигурации.")
        # После gui.py, возможно, файл конфигурации будет создан.
        # Однако, поскольку gui.py это Kivy-приложение, оно не заблокирует выполнение init.py до сохранения.
        # Пользователь должен сохранить конфиг вручную в GUI.
        # Здесь мы предполагаем, что пользователь настроит и сохранит конфиг.
        # Если конфиг все равно не появился, back.py завершится с ошибкой.
    else:
        logging.info(f"Файл '{CONFIG_FILE}' найден. Пропускаем '{GUI_SCRIPT}'.")

    logging.info(f"Запускаем скрипт бэкапа: {BACKUP_SCRIPT}")
    run_script(BACKUP_SCRIPT)
    logging.info("Работа init.py завершена.")


if __name__ == '__main__':
    main()