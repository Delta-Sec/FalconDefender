import os
import sys
import platform
from pathlib import Path

def get_platform_specific_path(base_dir_name: str) -> Path:
    if platform.system() == "Windows":
        return Path(os.environ.get("APPDATA", Path.home() / "AppData" / "Roaming")) / base_dir_name
    elif platform.system() == "Darwin":
        return Path.home() / "Library" / "Application Support" / base_dir_name
    else:

        xdg_data_home = os.environ.get("XDG_DATA_HOME")
        if xdg_data_home:
            return Path(xdg_data_home) / base_dir_name
        return Path.home() / ".local" / "share" / base_dir_name

def get_config_path() -> Path:
    return get_platform_specific_path("falcondefender") / "config.json"

def get_quarantine_path() -> Path:
    return get_platform_specific_path("falcondefender") / "quarantine"

def get_rules_path() -> Path:
    return get_platform_specific_path("falcondefender") / "rules"

def get_report_path() -> Path:
    return get_platform_specific_path("falcondefender") / "reports"


if __name__ == "__main__":
    print(f"Config Path: {get_config_path()}")
    print(f"Quarantine Path: {get_quarantine_path()}")
    print(f"Rules Path: {get_rules_path()}")
    print(f"Report Path: {get_report_path()}")
