import os
import shutil
import sqlite3
import logging
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any, Optional
import json

from .config import ConfigManager
from .utils import get_quarantine_path

logger = logging.getLogger(__name__)

class QuarantineManager:

    def __init__(self, config_manager: ConfigManager):
        self.config = config_manager
        self.quarantine_dir = Path(self.config.get("quarantine_dir"))
        self.db_path = self.quarantine_dir / "quarantine.db"
        self.quarantine_dir.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _init_db(self):
        conn = None
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS quarantine_files (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    original_path TEXT NOT NULL,
                    quarantine_path TEXT NOT NULL UNIQUE,
                    file_hash TEXT,
                    quarantined_at TEXT NOT NULL,
                    rule_name TEXT,
                    match_details TEXT,
                    restored_at TEXT,
                    deleted_at TEXT
                )
            """)
            conn.commit()
            logger.info(f"Quarantine database initialized at {self.db_path}")
        except sqlite3.Error as e:
            logger.error(f"Database initialization error: {e}")
        finally:
            if conn:
                conn.close()

    def _generate_quarantine_path(self, original_path: Path) -> Path:
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S%f")
        new_name = f"{original_path.name}_{timestamp}"
        return self.quarantine_dir / new_name

    def quarantine_file(self, file_path: Path, match_info: Dict[str, Any]) -> Optional[Path]:
        if not file_path.is_file():
            logger.warning(f"File not found for quarantine: {file_path}")
            return None

        quarantine_path = self._generate_quarantine_path(file_path)
        try:
            shutil.move(str(file_path), str(quarantine_path))
            quarantined_at = datetime.now().isoformat()
            rule_name = match_info.get("rule_name", "Unknown")
            match_details = json.dumps(match_info)

            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO quarantine_files (original_path, quarantine_path, file_hash, quarantined_at, rule_name, match_details)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (str(file_path), str(quarantine_path), match_info.get("file_hash"), quarantined_at, rule_name, match_details))
            conn.commit()
            conn.close()

            logger.info(f"File quarantined: {file_path} -> {quarantine_path}")
            return quarantine_path
        except (shutil.Error, sqlite3.Error, json.JSONEncodeError) as e:
            logger.error(f"Error quarantining file {file_path}: {e}")
            return None

    def restore_file(self, record_id: int) -> bool:
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT original_path, quarantine_path FROM quarantine_files WHERE id = ? AND restored_at IS NULL", (record_id,))
        record = cursor.fetchone()
        
        if not record:
            logger.warning(f"Quarantine record {record_id} not found or already restored.")
            conn.close()
            return False

        original_path = Path(record[0])
        quarantine_path = Path(record[1])

        if not quarantine_path.is_file():
            logger.error(f"Quarantined file not found at {quarantine_path} for record {record_id}.")
            conn.close()
            return False

        if original_path.exists():
            logger.error(f"Original path {original_path} already exists. Cannot restore file {record_id}.")
            conn.close()
            return False

        try:
            original_path.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(str(quarantine_path), str(original_path))
            restored_at = datetime.now().isoformat()
            cursor.execute("UPDATE quarantine_files SET restored_at = ? WHERE id = ?", (restored_at, record_id))
            conn.commit()
            logger.info(f"File restored: {quarantine_path} -> {original_path}")
            return True
        except (shutil.Error, sqlite3.Error) as e:
            logger.error(f"Error restoring file {record_id} to {original_path}: {e}")
            return False
        finally:
            conn.close()

    def delete_quarantined_file(self, record_id: int) -> bool:

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT quarantine_path FROM quarantine_files WHERE id = ? AND deleted_at IS NULL", (record_id,))
        record = cursor.fetchone()

        if not record:
            logger.warning(f"Quarantine record {record_id} not found or already deleted.")
            conn.close()
            return False

        quarantine_path = Path(record[0])

        try:
            if quarantine_path.is_file():
                os.remove(str(quarantine_path))
                logger.info(f"Quarantined file deleted from disk: {quarantine_path}")
            else:
                logger.warning(f"Quarantined file not found on disk at {quarantine_path} for record {record_id}, deleting database entry only.")

            deleted_at = datetime.now().isoformat()
            cursor.execute("UPDATE quarantine_files SET deleted_at = ? WHERE id = ?", (deleted_at, record_id))
            conn.commit()
            logger.info(f"Quarantine record {record_id} marked as deleted.")
            return True
        except (OSError, sqlite3.Error) as e:
            logger.error(f"Error deleting quarantined file {record_id}: {e}")
            return False
        finally:
            conn.close()

    def list_quarantined_files(self) -> List[Dict[str, Any]]:

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT id, original_path, quarantine_path, file_hash, quarantined_at, rule_name, match_details FROM quarantine_files WHERE restored_at IS NULL AND deleted_at IS NULL")
        rows = cursor.fetchall()
        conn.close()

        results = []
        for row in rows:
            results.append({
                "id": row[0],
                "original_path": row[1],
                "quarantine_path": row[2],
                "file_hash": row[3],
                "quarantined_at": row[4],
                "rule_name": row[5],
                "match_details": json.loads(row[6]) if row[6] else {}
            })
        return results


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    from config import ConfigManager
    from utils import get_quarantine_path

    config_manager = ConfigManager()
    test_quarantine_dir = Path(config_manager.get("quarantine_dir"))
    test_db_path = test_quarantine_dir / "quarantine.db"


    if test_quarantine_dir.exists():
        import shutil
        shutil.rmtree(test_quarantine_dir)
    test_quarantine_dir.mkdir(parents=True, exist_ok=True)

    quarantine_manager = QuarantineManager(config_manager)

    mal_doc_path = Path("malicious_doc.docx")
    mal_doc_path.write_text("This is a malicious document.")
    virus_exe_path = Path("virus.exe")
    virus_exe_path.write_bytes(b"\x90\x90\x90\x90")
    mal_dll_path = Path("nested/path/to/malware.dll")
    mal_dll_path.parent.mkdir(parents=True, exist_ok=True)
    mal_dll_path.write_text("Malicious DLL content.")

    print("\n--- Quarantining files ---")
    match_info_1 = {"file_path": str(mal_doc_path), "rule_name": "DocMalware", "file_hash": "hash123", "description": "Malicious Document"}
    match_info_2 = {"file_path": str(virus_exe_path), "rule_name": "Win32.Virus", "file_hash": "hash456", "description": "Windows Executable Virus"}
    match_info_3 = {"file_path": str(mal_dll_path), "rule_name": "DLL_Injector", "file_hash": "hash789", "description": "Malicious DLL"}

    q1 = quarantine_manager.quarantine_file(mal_doc_path, match_info_1)
    q2 = quarantine_manager.quarantine_file(virus_exe_path, match_info_2)
    q3 = quarantine_manager.quarantine_file(mal_dll_path, match_info_3)

    print("\n--- Listing quarantined files ---")
    quarantined_list = quarantine_manager.list_quarantined_files()
    for item in quarantined_list:
        print(item)

    print("\n--- Restoring a file (q1) ---")
    if q1:
        conn = sqlite3.connect(quarantine_manager.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM quarantine_files WHERE quarantine_path = ?", (str(q1),))
        q1_id = cursor.fetchone()[0]
        conn.close()

        restore_success = quarantine_manager.restore_file(q1_id)
        print(f"Restore q1 (ID: {q1_id}) successful: {restore_success}")

        restore_fail = quarantine_manager.restore_file(q1_id)
        print(f"Restore q1 (ID: {q1_id}) again (should fail): {restore_fail}")

    print("\n--- Listing quarantined files after restore ---")
    quarantined_list = quarantine_manager.list_quarantined_files()
    for item in quarantined_list:
        print(item)

    print("\n--- Deleting a quarantined file (q2) ---")
    if q2:
        conn = sqlite3.connect(quarantine_manager.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM quarantine_files WHERE quarantine_path = ?", (str(q2),))
        q2_id = cursor.fetchone()[0]
        conn.close()

        delete_success = quarantine_manager.delete_quarantined_file(q2_id)
        print(f"Delete q2 (ID: {q2_id}) successful: {delete_success}")

        delete_fail = quarantine_manager.delete_quarantined_file(q2_id)
        print(f"Delete q2 (ID: {q2_id}) again (should fail): {delete_fail}")

    print("\n--- Listing quarantined files after delete ---")
    quarantined_list = quarantine_manager.list_quarantined_files()
    for item in quarantined_list:
        print(item)

    print("\n--- Cleanup ---")
    if mal_doc_path.exists(): os.remove(mal_doc_path)
    if virus_exe_path.exists(): os.remove(virus_exe_path)
    if mal_dll_path.exists(): os.remove(mal_dll_path)
    if mal_dll_path.parent.exists(): shutil.rmtree(mal_dll_path.parent)

    if test_quarantine_dir.exists():
        shutil.rmtree(test_quarantine_dir)
    print("Cleanup complete.")
