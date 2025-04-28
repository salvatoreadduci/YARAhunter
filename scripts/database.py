import sqlite3
import os
from utils import get_root, print_message, MessageLevel


db_path = os.path.join(get_root(), "config", "state.db")
download_dir = os.path.join(get_root(), "data")


def get_db_connection():
    return sqlite3.connect(db_path)


def get_cursor(conn):
    return conn.cursor()


def is_valid_malware_file(file_path: str) -> bool:
    return os.path.isfile(file_path) and not file_path.endswith(".zip")


def setup_database() -> None:
    try:
        with get_db_connection() as conn:
            cursor = get_cursor(conn)
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS malware_list (
                    id INTEGER PRIMARY KEY,
                    file_path TEXT UNIQUE,
                    hash TEXT UNIQUE,
                    family_name TEXT,
                    report_downloaded BOOLEAN DEFAULT 0,
                    report_path TEXT
                )
            ''')

            initialize_configurations_table()
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS malware_signatures (
                    id INTEGER PRIMARY KEY,
                    signature TEXT UNIQUE
                )
            ''')

            conn.commit()
            return True
    except sqlite3.Error as e:
        print_message(e, MessageLevel.ERROR)
        return False


def initialize_configurations_table():
    try:
        with get_db_connection() as conn:
            cursor = get_cursor(conn)
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS configurations (
                    id INTEGER PRIMARY KEY,
                    number_of_malwares INTEGER
                )
            ''')
           
            cursor.execute('SELECT COUNT(*) FROM configurations')
            if cursor.fetchone()[0] == 0:
                cursor.execute('INSERT INTO configurations (id, number_of_malwares) VALUES (1, 1)')
                conn.commit()
    except sqlite3.Error as e:
        print_message(e, MessageLevel.ERROR)


def synchronize_database() -> None:
    try:
        with get_db_connection() as conn:
            cursor = get_cursor(conn)
            
            cursor.execute('SELECT file_path, hash, report_path FROM malware_list')
            rows = cursor.fetchall()
            db_files = {row[0]: row for row in rows}
            
            new_malware = []
            missing_files = []
            missing_reports = []

            if os.path.isdir(download_dir):
                for family_dir in os.listdir(download_dir):
                    family_path = os.path.join(download_dir, family_dir)

                    if os.path.isdir(family_path) and family_dir not in ['reports', 'benign_files']:
                        for malware_file in os.listdir(family_path):
                            malware_path = os.path.join(family_path, malware_file)

                            if malware_path not in db_files and is_valid_malware_file(malware_path):
                                hash_value, _ = os.path.splitext(malware_file)
                                new_malware.append((malware_path, hash_value, family_dir))

                for file_path, hash_value, report_path in rows:
                    if not os.path.exists(file_path):
                        missing_files.append((hash_value,))
                    elif report_path and not os.path.exists(report_path):
                        missing_reports.append((hash_value,))
  
            if new_malware:
                cursor.executemany('''
                    INSERT OR REPLACE INTO malware_list (file_path, hash, family_name, report_downloaded, report_path)
                    VALUES (?, ?, ?, 0, NULL)
                ''', new_malware)

            if missing_files:
                cursor.executemany('DELETE FROM malware_list WHERE hash = ?', missing_files)

            if missing_reports:
                cursor.executemany('''
                    UPDATE malware_list 
                    SET report_downloaded = 0, report_path = NULL 
                    WHERE hash = ?
                ''', missing_reports)

            conn.commit()
            print_message(f"Database synchronized. {len(new_malware)} new malware files added, {len(missing_files)} removed, {len(missing_reports)} reports updated.",
                           MessageLevel.INFO)
            return True
    except sqlite3.Error as e:
        print_message(e, MessageLevel.ERROR)
        return False


def insert_malware(file_path: str, file_hash: str, family_name="Unknown") -> None:
    try:
        with get_db_connection() as conn:
            cursor = get_cursor(conn)
            cursor.execute('''
                INSERT OR REPLACE INTO malware_list (file_path, hash, family_name, report_downloaded, report_path)
                VALUES (?, ?, ?, 0, NULL)
            ''', (file_path, file_hash, family_name))
            conn.commit()
    except sqlite3.Error as e:
        print_message(e, MessageLevel.ERROR)


def is_malware_downloaded(file_hash: str) -> bool:
    try:
        with get_db_connection() as conn:
            cursor = get_cursor(conn)
            cursor.execute('SELECT 1 FROM malware_list WHERE hash = ?', (file_hash,))
            result = cursor.fetchone()
        return result is not None
    except sqlite3.Error as e:
        print_message(e, MessageLevel.ERROR)
        return False


def insert_downloaded_report(report_path: str, file_hash: str) -> None:
    try:
        with get_db_connection() as conn:
            cursor = get_cursor(conn)
            cursor.execute('''
                UPDATE malware_list
                SET report_downloaded = 1,
                    report_path = ?
                WHERE hash = ?
            ''', (report_path, file_hash))
            conn.commit()
    except sqlite3.Error as e:
        print_message(e, MessageLevel.ERROR)


def is_report_downloaded(file_path: str) -> bool:
    try:
        with get_db_connection() as conn:
            cursor = get_cursor(conn)
            cursor.execute('SELECT 1 FROM malware_list WHERE file_path = ? AND report_downloaded = 1', (file_path,))
            result = cursor.fetchone()
        return result is not None
    except sqlite3.Error as e:
        print_message(e, MessageLevel.ERROR)
        


def get_malware_paths_from_db() -> list:
    try:
        with get_db_connection() as conn:
            cursor = get_cursor(conn)
            cursor.execute('SELECT file_path FROM malware_list')
            malware_entries = cursor.fetchall()
        return [entry[0] for entry in malware_entries]
    except sqlite3.Error as e:
        print_message(e, MessageLevel.ERROR)
        return []


def update_number_of_malwares(new_limit: int) -> None:
    try:
        with get_db_connection() as conn:
            cursor = get_cursor(conn)
            cursor.execute('''
                INSERT OR REPLACE INTO configurations (id, number_of_malwares)
                VALUES (1, ?)
            ''', (new_limit,))
            conn.commit()
        print_message(f"Number of malwares updated to {new_limit}.", MessageLevel.SUCCESS)
    except sqlite3.Error as e:
        print_message(e, MessageLevel.ERROR)


def add_signatures(signature) -> None:
    signatures = [s.strip() for s in signature.split(",") if s.strip()]
    try:
        with get_db_connection() as conn:
            cursor = get_cursor(conn)
            cursor.executemany('''
                INSERT OR IGNORE INTO malware_signatures (signature)
                VALUES (?)
            ''', [(sig,) for sig in signatures])
            conn.commit()
        print_message(f"Signatures added: {', '.join(signatures)}.", MessageLevel.SUCCESS)
    except sqlite3.Error as e:
        print_message(e, MessageLevel.ERROR)


def remove_signatures(signature) -> None:
    signatures = [s.strip() for s in signature.split(",") if s.strip()]
    try:
        with get_db_connection() as conn:
            cursor = get_cursor(conn)
            cursor.executemany('''
                DELETE FROM malware_signatures WHERE signature = ?
            ''', [(sig,) for sig in signatures])
            conn.commit()
        print_message(f"Signatures removed: {', '.join(signatures)}.", MessageLevel.SUCCESS)
    except sqlite3.Error as e:
        print_message(e, MessageLevel.ERROR)


def table_exists(conn, table_name: str) -> bool:
    cursor = conn.cursor()
    cursor.execute("SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name=?)", (table_name,))
    return cursor.fetchone()[0] == 1



def get_number_of_malwares() -> int:
    try:
        with get_db_connection() as conn:
            if not table_exists(conn, "configurations"):
                return 1
            
            cursor = get_cursor(conn)
            cursor.execute('SELECT number_of_malwares FROM configurations WHERE id = 1')
            row = cursor.fetchone()
            return row[0] if row else None
    except sqlite3.Error as e:
        print_message(e, MessageLevel.ERROR)
        return None


def get_signatures() -> list:
    try:
        with get_db_connection() as conn:
            if not table_exists(conn, "malware_signatures"):
                return []
            
            cursor = get_cursor(conn)
            cursor.execute('SELECT signature FROM malware_signatures')
            signatures = cursor.fetchall()
            return [sig[0] for sig in signatures]
    except sqlite3.Error as e:
        print_message(e, MessageLevel.ERROR)
        return []
