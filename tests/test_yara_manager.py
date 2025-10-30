
import unittest
import os
import shutil
import yara
from pathlib import Path
from unittest.mock import MagicMock, patch

from falcon.yara_manager import YaraManager
from falcon.config import ConfigManager

class TestYaraManager(unittest.TestCase):

    def setUp(self):
        self.test_rules_dir = Path("test_rules_temp")
        self.test_rules_dir.mkdir(exist_ok=True)
        self.compiled_rules_path = self.test_rules_dir / "compiled_rules.yarac"
        self.checksum_path = self.test_rules_dir / "compiled_rules.yarac.checksum"

        # Create dummy YARA rule files
        (self.test_rules_dir / "rule1.yar").write_text("rule test_rule1 { strings: $s1 = \"test_string_1\" condition: $s1 }")
        (self.test_rules_dir / "rule2.yar").write_text("rule test_rule2 { strings: $s2 = \"test_string_2\" condition: $s2 }")
        
        # Create a sub-directory and a rule file within it
        (self.test_rules_dir / "subdir").mkdir(exist_ok=True)
        (self.test_rules_dir / "subdir" / "rule3.yar").write_text("rule test_rule3 { strings: $s3 = \"test_string_3\" condition: $s3 }")

        # Mock ConfigManager
        self.mock_config_manager = MagicMock(spec=ConfigManager)
        self.mock_config_manager.get.side_effect = lambda key: {
            "rules_dir": str(self.test_rules_dir),
        }.get(key)

        self.manager = YaraManager(self.mock_config_manager)

    def tearDown(self):
        if self.test_rules_dir.exists():
            shutil.rmtree(self.test_rules_dir)
        if self.compiled_rules_path.exists():
            os.remove(self.compiled_rules_path)
        if self.checksum_path.exists():
            os.remove(self.checksum_path)
        
        # Clean up any test files created during scan_file tests
        if Path("test_file.txt").exists():
            os.remove("test_file.txt")

    def test_initial_load_and_get_rules(self):
        self.manager.load_rules()
        rules = self.manager.get_rules()
        self.assertIsNotNone(rules)
        self.assertIsInstance(rules, yara.Rules)
        self.assertEqual(len(list(rules)), 3)

    def test_update_rules_detection(self):
        self.manager.load_rules()
        # Modify an existing rule
        (self.test_rules_dir / "rule1.yar").write_text("rule test_rule1 { strings: $s1 = \"modified_string_1\" condition: $s1 }")
        
        # Check for updates and reload
        reloaded = self.manager.check_for_updates_and_reload()
        self.assertTrue(reloaded)
        
        # Verify new rule is active
        rules = self.manager.get_rules()
        test_file = Path("test_file.txt")
        test_file.write_text("This file contains modified_string_1.")
        matches = rules.match(filepath=str(test_file))
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].rule, "test_rule1")
        self.assertEqual(matches[0].strings[0].instances[0].matched_data.decode(), "modified_string_1")
        test_file.unlink() # Clean up test file

    def test_update_rules_no_change(self):
        self.manager.load_rules()
        reloaded = self.manager.check_for_updates_and_reload()
        self.assertFalse(reloaded)

    def test_empty_rules_directory(self):
        shutil.rmtree(self.test_rules_dir)
        self.test_rules_dir.mkdir(exist_ok=True)
        # Re-initialize manager to pick up empty directory
        manager = YaraManager(self.mock_config_manager)
        manager.load_rules()
        self.assertIsNone(manager.get_rules())

    def test_invalid_rule_syntax(self):
        (self.test_rules_dir / "bad_rule.yar").write_text("rule bad_rule { strings: $a = \"bad\" condition: $a and }") # Syntax error
        # Re-initialize manager to pick up new bad rule
        manager = YaraManager(self.mock_config_manager)
        manager.load_rules()
        self.assertIsNone(manager.get_rules())

    def test_compiled_rules_persistence(self):
        self.manager.load_rules() # This should create compiled_rules.yarac
        self.assertTrue(self.compiled_rules_path.exists())

        # Create a new manager instance to test loading from compiled file
        new_manager = YaraManager(self.mock_config_manager)
        new_manager.load_rules()
        rules = new_manager.get_rules()
        self.assertIsNotNone(rules)
        self.assertEqual(len(list(rules)), 3)

if __name__ == '__main__':
    unittest.main()

