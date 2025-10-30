import os
import yara
import logging
import hashlib
from pathlib import Path
from typing import Dict, List, Optional
from .config import ConfigManager

logger = logging.getLogger(__name__)

class YaraManager:

    def __init__(self, config_manager: ConfigManager):
        self.config = config_manager
        self.rules_dir = Path(self.config.get("rules_dir"))
        self.compiled_rules_path = self.rules_dir / "compiled_rules.yarac"
        self.checksum_path = self.rules_dir / "compiled_rules.yarac.checksum"
        self.rules_dir.mkdir(parents=True, exist_ok=True)
        self._rules: Optional[yara.Rules] = None
        self._rules_checksum: Optional[str] = None
        self.load_rules()

    def _calculate_rules_checksum(self) -> str:

        hasher = hashlib.md5()
        yar_files = list(self.rules_dir.rglob("*.yar"))
        yara_files = list(self.rules_dir.rglob("*.yara"))
        all_rule_files = sorted(yar_files + yara_files)
        if not yar_files:
            return ""
        for file_path in yar_files:
            with open(file_path, "rb") as f:
                hasher.update(f.read())
        return hasher.hexdigest()

    def _compile_rules(self) -> Optional[yara.Rules]:

        yar_files = list(self.rules_dir.rglob("*.yar"))
        yara_files = list(self.rules_dir.rglob("*.yara"))
        rule_file_paths = sorted(yar_files + yara_files)
        if not rule_file_paths:
            logger.warning("No YARA rule files found for compilation.")
            return None

        filepaths = {str(p.name): str(p) for p in rule_file_paths}
        try:
            logger.info(f"Compiling rules from: {list(filepaths.keys())}")
            compiled = yara.compile(filepaths=filepaths, error_on_warning=True)
            if compiled is None or (isinstance(compiled, yara.Rules) and len(list(compiled)) == 0):
                logger.error("YARA compilation resulted in an empty ruleset, indicating an issue with rule syntax or content.")

                if self.compiled_rules_path.exists():
                    self.compiled_rules_path.unlink()
                if self.checksum_path.exists():
                    self.checksum_path.unlink()
                return None
            return compiled
        except yara.Error as e:
            logger.error(f"YARA compilation error: {e}")
            return None

    def load_rules(self, force_recompile: bool = False) -> None:

        self.rules_dir.mkdir(parents=True, exist_ok=True)
        current_checksum = self._calculate_rules_checksum()

        if not force_recompile and self.compiled_rules_path.exists() and self.checksum_path.exists():
            stored_checksum = self.checksum_path.read_text()
            if stored_checksum == current_checksum:
                try:
                    self._rules = yara.load(str(self.compiled_rules_path))
                    self._rules_checksum = current_checksum
                    logger.info("Loaded YARA rules from up-to-date compiled file.")
                    return
                except yara.Error as e:
                    logger.warning(f"Could not load compiled YARA rules file: {e}. Recompiling.")

        logger.info("YARA rule source has changed or compiled file is missing. Recompiling...")
        compiled_rules = self._compile_rules()
        if compiled_rules:
            self._rules = compiled_rules
            self._rules_checksum = current_checksum
            self._save_compiled_rules(self._rules, current_checksum)
        else:
            self._rules = None
            self._rules_checksum = None
            if self.compiled_rules_path.exists():
                self.compiled_rules_path.unlink()
            if self.checksum_path.exists():
                self.checksum_path.unlink()
        logger.info("Finished loading YARA rules.")

    def _save_compiled_rules(self, rules: yara.Rules, checksum: str) -> None:

        if not rules:
            return
        try:
            rules.save(str(self.compiled_rules_path))
            self.checksum_path.write_text(checksum)
            logger.info(f"Compiled YARA rules saved to {self.compiled_rules_path}")
        except Exception as e:
            logger.error(f"Failed to save compiled YARA rules: {e}")

    def get_rules(self) -> Optional[yara.Rules]:
        return self._rules

    def check_for_updates_and_reload(self) -> bool:

        new_checksum = self._calculate_rules_checksum()
        if new_checksum != self._rules_checksum:
            logger.info("YARA rule changes detected. Reloading rules...")
            self.load_rules(force_recompile=True)
            return True
        return False
