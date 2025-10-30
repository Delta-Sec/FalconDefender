import json
import os
from pathlib import Path
from typing import Any, Dict, Optional

from .utils import get_config_path, get_quarantine_path, get_rules_path, get_report_path

DEFAULT_CONFIG_PATH = get_config_path()

class ConfigManager:

    def __init__(self, config_path: Path = DEFAULT_CONFIG_PATH):
        self.config_path = config_path
        self._config: Dict[str, Any] = {}
        self._load_config()

    def _load_config(self):
        if self.config_path.exists():
            try:
                with open(self.config_path, 'r') as f:
                    self._config = json.load(f)
            except json.JSONDecodeError:
                print(f"Warning: Could not decode config file at {self.config_path}. Starting with empty config.")
                self._config = {}
        else:
            self.config_path.parent.mkdir(parents=True, exist_ok=True)
            self._config = self._get_default_config()
            self.save_config()

    def _get_default_config(self) -> Dict[str, Any]:
        return {
            "scanner_threads": os.cpu_count() * 2 if os.cpu_count() else 4,
            "max_file_size_mb": 100,
            "blocked_extensions": [".tmp", ".log", ".bak"],
            "allowed_extensions": [],
            "yara_timeout": 60,
            "quarantine_dir": str(get_quarantine_path()),
            "rules_dir": str(get_rules_path()),
            "report_dir": str(get_report_path()),
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

    def save_config(self):
        self.config_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.config_path, 'w') as f:
            json.dump(self._config, f, indent=4)

    def get(self, key: str, default: Any = None) -> Any:
        return self._config.get(key, default)

    def set(self, key: str, value: Any):
        keys = key.split('.')
        current_level = self._config
        for i, k in enumerate(keys):
            if i == len(keys) - 1:
                current_level[k] = value
            else:
                if k not in current_level or not isinstance(current_level[k], dict):
                    current_level[k] = {}
                current_level = current_level[k]
        self.save_config()

    def get_all(self) -> Dict[str, Any]:
        return self._config.copy()

if __name__ == "__main__":

    test_config_dir = Path("./test_config")
    test_config_path = test_config_dir / "config.json"

    if test_config_dir.exists():
        import shutil
        shutil.rmtree(test_config_dir)

    print("--- Initializing ConfigManager with default settings ---")
    config_manager = ConfigManager(config_path=test_config_path)
    print(f"Config loaded from: {config_manager.config_path}")
    print(f"Initial config: {json.dumps(config_manager.get_all(), indent=2)}")

    print("\n--- Setting a new value ---")
    config_manager.set("scanner_threads", 8)
    config_manager.set("new_setting", "test_value")
    config_manager.set("email_reporting.enabled", True)
    config_manager.set("email_reporting.smtp_server", "smtp.example.com")
    print(f"Updated config: {json.dumps(config_manager.get_all(), indent=2)}")

    print("\n--- Getting specific values ---")
    print(f'Scanner threads: {config_manager.get("scanner_threads")}')
    print(f'Non-existent key (default None): {config_manager.get("non_existent_key")}')
    print(f'Email enabled: {config_manager.get("email_reporting.enabled")}')
    print(f'SMTP server: {config_manager.get("email_reporting.smtp_server")}')

    print("\n--- Re-initializing to check persistence ---")
    config_manager_reloaded = ConfigManager(config_path=test_config_path)
    print(f"Reloaded config: {json.dumps(config_manager_reloaded.get_all(), indent=2)}")
    assert config_manager_reloaded.get("scanner_threads") == 8
    assert config_manager_reloaded.get("new_setting") == "test_value"
    assert config_manager_reloaded.get("email_reporting.enabled") == True
    assert config_manager_reloaded.get("email_reporting.smtp_server") == "smtp.example.com"
    print("Configuration persistence test passed.")

    print("\n--- Cleaning up test config ---")
    if test_config_dir.exists():
        import shutil
        shutil.rmtree(test_config_dir)
        print(f"Removed test config directory: {test_config_dir}")

