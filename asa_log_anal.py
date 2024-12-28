import re
import logging
import sqlite3
import os
import json
import sys
import hashlib
import threading
from collections import Counter
from datetime import datetime, timedelta
from operator import contains
from threading import Thread

class SqliteDb:
    def __init__(self, db_name="asa_connect_analyse.db"):
        self.db_name = db_name
        if not os.path.exists(db_name):
            log.info(f"DB {self.db_name} is not exist")
            self.connect_db()
            self.create_database()
            log.info(f"DB {self.db_name} has been created. {self.connection}")
        else:
            log.info(f"DB {self.db_name} exists")
            self.connect_db()
            log.info(f"Connection to {self.db_name} has been established. {self.connection}")

    def connect_db(self):
        self.connection = sqlite3.connect(database=self.db_name)

    def create_database(self):
        cursor = self.connection.cursor()

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS asa_log_files(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                log_sha TEXT NOT NULL UNIQUE,
                log_path TEXT NOT NULL
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS connections (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                connection_date_time DATETIME NOT NULL, 
                source_address TEXT NOT NULL,
                source_port INTEGER NOT NULL,
                destination_address TEXT NOT NULL,
                destination_port INTEGER NOT NULL,
                crypto_protocol TEXT NOT NULL,
                asa_log_file_id INTEGER NOT NULL,
                FOREIGN KEY (asa_log_file_id) REFERENCES asa_log_files (id)
            )
        ''')
        self.connection.commit()

    def add_asa_log_file_record(self, log_sha, log_path):
        cursor = self.connection.cursor()
        try:
            cursor.execute('''
                INSERT INTO asa_log_files (log_sha, log_path)
                VALUES (?, ?)
            ''', (log_sha, log_path))

            self.connection.commit()
            log.info(f"Record has been added to database {self.db_name}: asa_log_files. Values: {log_sha}, {log_path}")
            return self.get_asa_log_record_by_sha(sha256=log_sha)
        except sqlite3.IntegrityError as ex:
            log.warning(f"Record hasn't been added to database {self.db_name}, record {log_sha} already exist. Exception: {ex}")


    def add_connection_record(self, connection_date_time, source_address, source_port, destination_address, destination_port, crypto_protocol, asa_log_file_id):
        try:
            formatted_date_time = datetime.strptime(connection_date_time, "%b %d %Y %H:%M:%S").strftime("%Y-%m-%d %H:%M:%S")
            cursor = self.connection.cursor()
            cursor.execute('''
                INSERT INTO connections (connection_date_time, source_address, source_port, destination_address, destination_port, crypto_protocol, asa_log_file_id)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (formatted_date_time, source_address, source_port, destination_address,
                  destination_port, crypto_protocol, asa_log_file_id))

            self.connection.commit()
            log.info(f"Record has been added. Values: {formatted_date_time}, {source_address}, {source_port}, {destination_address}, {destination_port}, {crypto_protocol}, {asa_log_file_id}")
        except sqlite3.IntegrityError as ex:
            log.error(f"Error with adding. Ex: {ex}")

    def get_asa_log_record_by_sha (self,sha256):
        try:
            cursor = self.connection.cursor()
            cursor.execute(f"SELECT id FROM asa_log_files WHERE log_sha = '{sha256}'")
            result = cursor.fetchone()
            if result:
                return result[0]
            else:
                return False
        except Exception as ex:
            log.error(f'Execution Error. Exception: {ex}')

    def delete_connection_records_older_than (self, days):
        try:
            cursor = self.connection.cursor()
            delete_date = datetime.now() - timedelta(days=days)
            formatted_delete_date = delete_date.strftime("%Y-%m-%d %H:%M:%S")
            cursor.execute('''
                    DELETE FROM connections
                    WHERE connection_date_time < ?
                ''', (formatted_delete_date,))
            self.connection.commit()
        except Exception as ex:
            log.error(f"delete_connection_records_older_than error. Ex: {ex}")


    def close_connection(self):
        try:
            self.connection.close()
            log.info(f"Connection with {self.db_name} has been closed")
        except Exception as ex:
            log.error(f"Error with closing connection DB: {self.db_name}. Exception: {ex}")

def logger_to_file(file_path, level ="INFO"):
    logger = logging.getLogger(__file__)
    logger.setLevel(logging.DEBUG) if level == "DEBUG" else logger.setLevel(logging.INFO)
    file_handler = logging.FileHandler(f'{file_path}')

    formatter = logging.Formatter('%(asctime)s\t%(name)s\t%(levelname)s\t%(message)s')
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    return logger

def get_file_sha256(file_path):
    """
    Вычисляет SHA-256 хэш для указанного файла.

    :param file_path: Путь к файлу, для которого нужно вычислить хэш.
    :return: SHA-256 хэш файла в виде строки.
    """
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, 'rb') as f:
            # Чтение файла блоками
            for block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(block)
        return sha256_hash.hexdigest()
    except FileNotFoundError:
        log.error( f"get_file_sha256. Файл {file_path} не найден.")
        return False
    except PermissionError:
        log.error(f"get_file_sha256. Недостаточно прав для чтения файла {file_path}.")
        return False
    except Exception as ex:
        log.error(f"get_file_sha256. Произошла ошибка обработки: {ex}")
        return False

def load_settings(path):
    with open(path) as f:
        settings = json.load(f)
    return  settings


def analyze_asa_logs(asa_log_file_path):
    clients = []
    servers = []
    cryptos = []
    is_new_file_asa_log_file = True

    client_pattern = r"client outside:([0-9.]+)"
    server_pattern = r"to ([0-9.]+)"
    crypto_pattern = r"for (\w+v[0-9.]+)"

    log.info(f"Current asa_log is {asa_log_file_path}")
    with open(asa_log_file_path, 'r') as file:
        asa_log = file.readlines()

    asa_log_sha256 = get_file_sha256(file_path=asa_log_file_path)
    log.debug(f"asa_log_file_path: {asa_log_file_path}, asa_log_sha256: {asa_log_sha256}")

    if asa_log_sha256:
        if SETTINGS["use_database"]:
            asa_log_sha256_app_id = app_database.get_asa_log_record_by_sha(sha256=asa_log_sha256)
            if not asa_log_sha256_app_id:
                log.info(f"Record with SHA256 {asa_log_sha256} didn't found in DB {app_database.db_name}")
                asa_log_sha256_app_id = app_database.add_asa_log_file_record(log_sha=asa_log_sha256, log_path=asa_log_file_path)
                log.info(f"Record with sha256 {asa_log_sha256} has been added to DB {app_database.db_name} with ID {asa_log_sha256_app_id}")
            else:
                log.warning(f"Skipped record asa_log_file with sha256 {asa_log_sha256}. It's already exists in {app_database.db_name} with ID {asa_log_sha256_app_id}")
                is_new_file_asa_log_file = False
                pass

        for line in asa_log:
            if "Device completed SSL handshake" in line:
                app_log_record = [asa_log_file_path] + line.split()
                log.debug(f"Match completed SSL handshake: {app_log_record}")
                client_match = re.search(client_pattern, line)
                server_match = re.search(server_pattern, line)
                crypto_match = re.search(crypto_pattern, line)

                if client_match: clients.append(client_match.group(1))
                if server_match: servers.append(server_match.group(1))
                if crypto_match: cryptos.append(crypto_match.group(1))

                if SETTINGS['use_database']:
                    log.info(f"Add connection record to DB {app_database.db_name}")
                    if is_new_file_asa_log_file:
                        app_database.add_connection_record(connection_date_time=' '.join(app_log_record[1:5]),
                                                            source_address=re.search(r"outside:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", app_log_record[14]).group(1),
                                                            source_port=re.search(r"outside:\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/(\d+)",app_log_record[14]).group(1),
                                                            destination_address=re.search(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",app_log_record[16]).group(0),
                                                            destination_port=re.search(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/(\d+)",app_log_record[16]).group(1),
                                                            crypto_protocol=app_log_record[18],
                                                            asa_log_file_id=asa_log_sha256_app_id)

                    else:
                        log.warning(f"File {asa_log_file_path}:{asa_log_sha256 } skipped. It's already been added to {app_database.db_name}")
                        pass

        # TOP 10,  clients, servers, cpyptos
        top_clients = Counter(clients).most_common(SETTINGS['top_clients_count'])
        top_servers = Counter(servers).most_common(SETTINGS['top_servers_count'])
        top_cryptos = Counter(cryptos).most_common(SETTINGS['top_cpyptos_count'])

        print(f"\nFile {asa_log_file_path} \nTOP {str(SETTINGS['top_clients_count'])} Clients\n")
        for client, count in top_clients:
            print(f"{client} => {count}")

        print(f"\nFile {asa_log_file_path} \nTOP {str(SETTINGS['top_servers_count'])} Servers\n")
        for server, count in top_servers:
            print(f"{server} => {count}")

        print(f"\nFile {asa_log_file_path} \nTOP {str(SETTINGS['top_cpyptos_count'])} Crypto Protocols\n")
        for crypto, count in top_cryptos:
            print(f"{crypto} => {count}")
        print(100*'#')
    else:
        log.warning(f"There is some problem with {asa_log_file_path}, file has been skipped")

def main ():
    global SETTINGS
    SETTINGS = load_settings(path='settings.json')
    global log
    log = logger_to_file(file_path=SETTINGS['app_logs_path'], level="DEBUG")
    log.info("Initiate")

    if SETTINGS['use_database']:
        global app_database
        app_database = SqliteDb()
    threads = []
    # ASA Logs parsing
    if os.path.isdir(SETTINGS["source_logs_path"]):
        for asa_log in os.listdir(SETTINGS["source_logs_path"]):
            if os.path.isfile(os.path.join(SETTINGS["source_logs_path"], asa_log)):
                asa_log_file_path = os.path.join(SETTINGS["source_logs_path"], asa_log)
                analyze_asa_logs(asa_log_file_path=asa_log_file_path)
    else:
        analyze_asa_logs(asa_log_file_path=SETTINGS["source_logs_path"])

    if SETTINGS['use_database']: app_database.close_connection()

if __name__ == '__main__':
    main()



