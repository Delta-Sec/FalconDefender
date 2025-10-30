
import unittest
import os
from pathlib import Path
import shutil
import time
import json
from unittest.mock import MagicMock

from falcon.yara_manager import YaraManager
from falcon.scanner import Scanner, ScanResult
from falcon.config import ConfigManager

class TestScanner(unittest.TestCase):

    def setUp(self):
        self.test_dir = Path("test_scanner_env")
        self.test_dir.mkdir(exist_ok=True)

        self.rules_dir = self.test_dir / "rules"
        self.rules_dir.mkdir(exist_ok=True)
        self.compiled_rules_file = self.test_dir / "compiled_rules.yarac"
        eicar_rule_content = r'''rule eicar_test { strings: $a = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*" condition: $a }
'''
        (self.rules_dir / "eicar.yar").write_text(eicar_rule_content)
        malicious_rule_content = r'''rule malicious_string { strings: $s = "malicious_content_here" condition: $s }'''
        (self.rules_dir / "malicious_string.yar").write_text(malicious_rule_content)

        # Add a dummy rule to make sure at least one rule is always present
        (self.rules_dir / "dummy.yar").write_text("rule dummy { strings: $a = \"dummy_string\" condition: $a }")

        # Mock ConfigManager for YaraManager and Scanner
        self.mock_config_manager = MagicMock(spec=ConfigManager)
        self.mock_config_manager.get.side_effect = lambda key, default=None: {
            "rules_dir": str(self.rules_dir),
            "report_dir": str(self.test_dir / "reports"), # Provide a valid report_dir
            "scanner_threads": 2,
            "max_file_size_mb": 1,
            "blocked_extensions": [".tmp"],
            "yara_timeout": 5,
            "rules_dir": str(self.rules_dir)
        }.get(key, default)

        self.yara_manager = YaraManager(self.mock_config_manager)
        self.yara_manager.load_rules(force_recompile=True)

        self.scanner = Scanner(self.mock_config_manager, self.yara_manager, MagicMock())

        self.clean_file = self.test_dir / "clean.txt"
        self.eicar_file = self.test_dir / "eicar.txt"
        self.malicious_file = self.test_dir / "malicious.bin"
        self.tmp_file = self.test_dir / "temp.tmp"
        self.large_file = self.test_dir / "large.txt"

        self.clean_file.write_text("This is a clean file.")
        self.eicar_file.write_text("X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")
        self.malicious_file.write_bytes(b"some binary data with malicious_content_here")
        self.tmp_file.write_text("This is a temporary file that should be skipped.")
        self.large_file.write_text("A" * (2 * 1024 * 1024))

    def tearDown(self):
        if self.test_dir.exists():
            shutil.rmtree(self.test_dir)
        if self.compiled_rules_file.exists():
            os.remove(self.compiled_rules_file)

    def test_scan_file_clean(self):
        result = self.scanner.scan_path(self.clean_file)
        self.assertEqual(len(result["matches"]), 0)

    def test_scan_file_eicar(self):
        result = self.scanner.scan_path(self.eicar_file)
        self.assertEqual(len(result["matches"]), 1)
        self.assertEqual(result["matches"][0]["rule_name"], "eicar_test")

    def test_scan_file_malicious_string(self):
        result = self.scanner.scan_path(self.malicious_file)
        self.assertEqual(len(result["matches"]), 1)
        self.assertEqual(result["matches"][0]["rule_name"], "malicious_string")

    def test_scan_file_not_eligible_extension(self):
        result = self.scanner.scan_path(self.tmp_file)
        self.assertEqual(len(result["matches"]), 0)

    def test_scan_file_not_eligible_size(self):
        result = self.scanner.scan_path(self.large_file)
        self.assertEqual(len(result["matches"]), 0)

    def test_scan_directory_full(self):
        results = self.scanner.scan_path(self.test_dir)
        # scan_path returns a dictionary with a list of matches
        self.assertEqual(len(results["matches"]), 2) # eicar.txt and malicious.bin should have matches
        
        eicar_match_found = any(m["rule_name"] == "eicar_test" for m in results["matches"])
        malicious_match_found = any(m["rule_name"] == "malicious_string" for m in results["matches"])
        self.assertTrue(eicar_match_found)
        self.assertTrue(malicious_match_found)

    def test_scan_directory_incremental(self):
        # First incremental scan
        results1 = self.scanner.scan_path(self.test_dir, incremental=True)
        self.assertEqual(len(results1["matches"]), 2) # Eicar and malicious

        # Second incremental scan, no changes
        results2 = self.scanner.scan_path(self.test_dir, incremental=True)
        self.assertEqual(len(results2["matches"]), 0) # Should return no new matches for unchanged files

        # Modify a file and rescan incrementally
        time.sleep(0.1)
        self.clean_file.write_text("This file now contains malicious_content_here")
        results3 = self.scanner.scan_path(self.test_dir, incremental=True)
        self.assertEqual(len(results3["matches"]), 1) # Only the modified file should be rescanned and matched
        self.assertEqual(Path(results3["matches"][0]["file_path"]), self.clean_file)
        self.assertEqual(results3["matches"][0]["rule_name"], "malicious_string")

    def test_scan_result_to_json(self):
        mock_matches = [
            {
                "file_path": str(self.eicar_file),
                "rule_name": "eicar_test",
                "namespace": "default",
                "tags": [],
                "meta": {},
                "strings": [
                    "$a: X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
                ],
                "description": "N/A",
                "confidence": "N/A",
                "action": "Detected"
            }
        ]
        result_obj = ScanResult(self.eicar_file, mock_matches, None)
        json_output = result_obj.to_json()
        self.assertIn("file_path", json_output)
        self.assertIn("matches", json_output)
        self.assertEqual(len(json_output["matches"]), 1)
        self.assertIn("rule_name", json_output["matches"][0])
        self.assertIn("strings", json_output["matches"][0])
        self.assertEqual(len(json_output["matches"][0]["strings"]), 1)
        self.assertIn("X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*", json_output["matches"][0]["strings"][0])

if __name__ == '__main__':
    unittest.main()

