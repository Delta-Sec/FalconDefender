
import unittest
import os
import shutil
import sys
import json
from pathlib import Path
from unittest.mock import patch, MagicMock, call
from datetime import datetime

# Imports for the falcon package
from falcon.cli import FalconCLI
from falcon.config import ConfigManager
from falcon.scanner import Scanner
from falcon.quarantine import QuarantineManager
from falcon.report import ReportManager
from falcon.updater import Updater
from falcon.yara_manager import YaraManager
from falcon.scheduler import SchedulerManager
import yara

class TestFalconCLI(unittest.TestCase):

    def setUp(self):
        self.test_env_dir = Path("test_cli_env")
        self.test_env_dir.mkdir(exist_ok=True)

        # Mock the config paths to point to our test environment
        self.mock_config_path = self.test_env_dir / "config.json"
        self.mock_rules_dir = self.test_env_dir / "rules"
        self.mock_quarantine_dir = self.test_env_dir / "quarantine_vault"
        self.mock_report_dir = self.test_env_dir / "reports"

        self.mock_rules_dir.mkdir(exist_ok=True)
        self.mock_quarantine_dir.mkdir(exist_ok=True)
        self.mock_report_dir.mkdir(exist_ok=True)

        # Create a dummy config file for testing
        default_config = {
            "scanner_threads": 1,
            "max_file_size_mb": 100,
            "yara_timeout": 5,
            "quarantine_dir": str(self.mock_quarantine_dir),
            "rules_dir": str(self.mock_rules_dir),
            "report_dir": str(self.mock_report_dir),
            "email_reporting": {
                "enabled": False,
                "smtp_server": "",
                "smtp_port": 587,
                "smtp_username": "",
                "sender_email": "",
                "recipient_emails": [],
                "use_tls": True,
            }
        }
        with open(self.mock_config_path, "w") as f:
            json.dump(default_config, f)

        # Create a dummy YARA rule for testing
        (self.mock_rules_dir / "test_cli_rule.yar").write_text(
            "rule cli_malware { strings: $a = \"cli_malicious\" condition: $a }"
        )

        # Patch ConfigManager to use our test config path
        self.patcher_config_manager = patch("falcon.config.ConfigManager")
        self.MockConfigManager = self.patcher_config_manager.start()
        self.MockConfigManager.return_value.get.side_effect = lambda key, default=None: self._get_nested_config(key, default_config) if "." in key else default_config.get(key, default)
        self.MockConfigManager.return_value.set.side_effect = lambda key, value: self._set_nested_config(key, value, default_config)

        # Patch the classes that FalconCLI instantiates
        self.patcher_yara_manager_class = patch("falcon.cli.YaraManager")
        self.MockYaraManager = self.patcher_yara_manager_class.start()
        self.MockYaraManager.return_value = MagicMock(spec=YaraManager)

        self.patcher_quarantine_manager_class = patch("falcon.cli.QuarantineManager")
        self.MockQuarantineManager = self.patcher_quarantine_manager_class.start()
        self.MockQuarantineManager.return_value = MagicMock(spec=QuarantineManager)

        self.patcher_scanner_class = patch("falcon.cli.Scanner")
        self.MockScanner = self.patcher_scanner_class.start()
        self.MockScanner.return_value = MagicMock(spec=Scanner)

        self.patcher_report_manager_class = patch("falcon.cli.ReportManager")
        self.MockReportManager = self.patcher_report_manager_class.start()
        self.MockReportManager.return_value = MagicMock(spec=ReportManager)

        self.patcher_updater_class = patch("falcon.cli.Updater")
        self.MockUpdater = self.patcher_updater_class.start()
        self.MockUpdater.return_value = MagicMock(spec=Updater)

        self.patcher_scheduler_manager_class = patch("falcon.cli.SchedulerManager")
        self.MockSchedulerManager = self.patcher_scheduler_manager_class.start()
        self.MockSchedulerManager.return_value = MagicMock(spec=SchedulerManager)

        self.cli = FalconCLI()

    def _get_nested_config(self, key, config_dict):
        keys = key.split(".")
        current_level = config_dict
        for k in keys:
            if isinstance(current_level, dict) and k in current_level:
                current_level = current_level[k]
            else:
                return None
        return current_level

    def _set_nested_config(self, key, value, config_dict):
        keys = key.split(".")
        current_level = config_dict
        for i, k in enumerate(keys):
            if i == len(keys) - 1:
                current_level[k] = value
            else:
                if k not in current_level or not isinstance(current_level[k], dict):
                    current_level[k] = {}
                current_level = current_level[k]
