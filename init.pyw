import os
#import sys
import logging

# --- НАСТРОЙКА ЛОГИРОВАНИЯ ---
log_file_path = 'backup_app.log' # Определяем имя файла лога

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        #logging.StreamHandler(sys.stdout), # Оставляем вывод в консоль
        logging.FileHandler(log_file_path, mode='a', encoding='utf-8') # Добавляем запись в файл
    ]
)

CONFIG_FILE = 'backup_config.ini'

def main():
    """
    Основная логика запуска приложения.
    """
    #script_dir = os.path.dirname(os.path.abspath(__file__))
    script_dir = ".\\"
    config_path = os.path.join(script_dir, CONFIG_FILE)

    logging.info(f"Проверка наличия файла конфигурации: {config_path}")
    if not os.path.exists(config_path):
        logging.warning(f"Файл '{CONFIG_FILE}' не найден. Запускаем интерфейс для настройки.")
        import conf_gui as gui
        gui.ConfigApp().run()
        logging.info(f"Интерфейс завершил работу. Проверяем, был ли создан файл конфигурации.")
    else:
        logging.info(f"Файл '{CONFIG_FILE}' найден. Пропускаем интерфейс.")

    logging.info(f"Запускаем бэкапа")
    import backup as bk
    bk.main()
    logging.info("Работа завершена.")


if __name__ == '__main__':
    main()