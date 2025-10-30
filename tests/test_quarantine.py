
import unittest
import os
import shutil
import sqlite3
from pathlib import Path
from datetime import datetime
from unittest.mock import MagicMock

from falcon.quarantine import QuarantineManager
from falcon.config import ConfigManager

class TestQuarantineManager(unittest.TestCase):

    def setUp(self):
        self.test_quarantine_dir = Path("test_quarantine_env")
        self.test_quarantine_dir.mkdir(exist_ok=True)
        self.test_db_path = self.test_quarantine_dir / "quarantine.db"

        # Mock ConfigManager
        self.mock_config_manager = MagicMock(spec=ConfigManager)
        self.mock_config_manager.get.side_effect = lambda key: {
            "quarantine_dir": str(self.test_quarantine_dir),
        }.get(key)

        self.quarantine_manager = QuarantineManager(self.mock_config_manager)

        # Create dummy files to quarantine
        self.mal_doc_path = self.test_quarantine_dir / "malicious_doc.docx"
        self.mal_doc_path.write_text("This is a malicious document.")
        self.virus_exe_path = self.test_quarantine_dir / "virus.exe"
        self.virus_exe_path.write_bytes(b"\x90\x90\x90\x90")
        self.mal_dll_path = self.test_quarantine_dir / "nested" / "path" / "to" / "malware.dll"
        self.mal_dll_path.parent.mkdir(parents=True, exist_ok=True)
        self.mal_dll_path.write_text("Malicious DLL content.")

    def tearDown(self):
        if self.test_quarantine_dir.exists():
            shutil.rmtree(self.test_quarantine_dir)

    def test_quarantine_file(self):
        match_info = {"file_path": str(self.mal_doc_path), "rule_name": "DocMalware", "file_hash": "hash123"}
        quarantined_path = self.quarantine_manager.quarantine_file(self.mal_doc_path, match_info)
        self.assertIsNotNone(quarantined_path)
        self.assertTrue(quarantined_path.exists())
        self.assertFalse(self.mal_doc_path.exists())

        conn = sqlite3.connect(self.test_db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM quarantine_files WHERE original_path = ?", (str(self.mal_doc_path),))
        record = cursor.fetchone()
        conn.close()

        self.assertIsNotNone(record)
        self.assertEqual(record[1], str(self.mal_doc_path))
        self.assertEqual(record[2], str(quarantined_path))
        self.assertEqual(record[5], "DocMalware")

    def test_list_quarantined_files(self):
        match_info_1 = {"file_path": str(self.mal_doc_path), "rule_name": "DocMalware", "file_hash": "hash123"}
        match_info_2 = {"file_path": str(self.virus_exe_path), "rule_name": "Win32.Virus", "file_hash": "hash456"}
        self.quarantine_manager.quarantine_file(self.mal_doc_path, match_info_1)
        self.quarantine_manager.quarantine_file(self.virus_exe_path, match_info_2)

        files = self.quarantine_manager.list_quarantined_files()
        self.assertEqual(len(files), 2)
        self.assertIn(str(self.mal_doc_path), [f["original_path"] for f in files])
        self.assertIn(str(self.virus_exe_path), [f["original_path"] for f in files])

    def test_restore_file_success(self):
        match_info = {"file_path": str(self.mal_doc_path), "rule_name": "DocMalware", "file_hash": "hash123"}
        quarantined_path = self.quarantine_manager.quarantine_file(self.mal_doc_path, match_info)

        conn = sqlite3.connect(self.test_db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM quarantine_files WHERE original_path = ?", (str(self.mal_doc_path),))
        record_id = cursor.fetchone()[0]
        conn.close()

        restored = self.quarantine_manager.restore_file(record_id)
        self.assertTrue(restored)
        self.assertTrue(self.mal_doc_path.exists())
        self.assertFalse(quarantined_path.exists())

        conn = sqlite3.connect(self.test_db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT restored_at FROM quarantine_files WHERE id = ?", (record_id,))
        restored_at = cursor.fetchone()[0]
        conn.close()
        self.assertIsNotNone(restored_at)

    def test_restore_file_original_path_exists(self):
        match_info = {"file_path": str(self.mal_doc_path), "rule_name": "DocMalware", "file_hash": "hash123"}
        self.quarantine_manager.quarantine_file(self.mal_doc_path, match_info)

        conn = sqlite3.connect(self.test_db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM quarantine_files WHERE original_path = ?", (str(self.mal_doc_path),))
        record_id = cursor.fetchone()[0]
        conn.close()

        # Create a dummy file at the original path to simulate conflict
        self.mal_doc_path.write_text("Conflicting content")

        restored = self.quarantine_manager.restore_file(record_id)
        self.assertFalse(restored)
        self.assertTrue(self.mal_doc_path.exists()) # Should still exist with conflicting content

    def test_delete_quarantined_file(self):
        match_info = {"file_path": str(self.virus_exe_path), "rule_name": "Win32.Virus", "file_hash": "hash456"}
        quarantined_path = self.quarantine_manager.quarantine_file(self.virus_exe_path, match_info)

        conn = sqlite3.connect(self.test_db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM quarantine_files WHERE original_path = ?", (str(self.virus_exe_path),))
        record_id = cursor.fetchone()[0]
        conn.close()

        deleted = self.quarantine_manager.delete_quarantined_file(record_id)
        self.assertTrue(deleted)
        self.assertFalse(quarantined_path.exists())

        conn = sqlite3.connect(self.test_db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT deleted_at FROM quarantine_files WHERE id = ?", (record_id,))
        deleted_at = cursor.fetchone()[0]
        conn.close()
        self.assertIsNotNone(deleted_at)

    def test_delete_non_existent_quarantined_file_on_disk(self):
        match_info = {"file_path": str(self.mal_dll_path), "rule_name": "DLL_Injector", "file_hash": "hash789"}
        quarantined_path = self.quarantine_manager.quarantine_file(self.mal_dll_path, match_info)

        conn = sqlite3.connect(self.test_db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM quarantine_files WHERE original_path = ?", (str(self.mal_dll_path),))
        record_id = cursor.fetchone()[0]
        conn.close()

        # Manually delete the file from disk to simulate it being missing
        if quarantined_path.exists():
            os.remove(quarantined_path)

        deleted = self.quarantine_manager.delete_quarantined_file(record_id)
        self.assertTrue(deleted) # Should still mark as deleted in DB

        conn = sqlite3.connect(self.test_db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT deleted_at FROM quarantine_files WHERE id = ?", (record_id,))
        deleted_at = cursor.fetchone()[0]
        conn.close()
        self.assertIsNotNone(deleted_at)

if __name__ == '__main__':
    unittest.main()

