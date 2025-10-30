import os
import logging
import asyncio
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from typing import List, Dict, Any, Optional
import json
import time
from datetime import datetime

from .config import ConfigManager
from .yara_manager import YaraManager
from .quarantine import QuarantineManager

logger = logging.getLogger(__name__)

class ScanResult:
    def __init__(self, file_path: Path, matches: List[Dict[str, Any]], error: Optional[str] = None):
        self.file_path = file_path
        self.matches = matches
        self.error = error

    def to_json(self) -> Dict[str, Any]:
        return {
            "file_path": str(self.file_path),
            "matches": self.matches,
            "error": self.error
        }

class Scanner:

    def __init__(self, config_manager: ConfigManager, yara_manager: YaraManager, quarantine_manager: QuarantineManager):
        self.config = config_manager
        self.yara_manager = yara_manager
        self.quarantine_manager = quarantine_manager
        self.rules = self.yara_manager.get_rules()
        self.executor = ThreadPoolExecutor(max_workers=self.config.get("scanner_threads"))
        self.last_scan_times: Dict[Path, float] = {}
        self.report_dir = Path(self.config.get("report_dir"))
        self.report_dir.mkdir(parents=True, exist_ok=True)
        self.event_queue: Optional[asyncio.Queue] = None
        self.pause_event = asyncio.Event()
        self.cancel_event = asyncio.Event()
        self.scan_start_time: Optional[datetime] = None

    def _is_file_scannable(self, file_path: Path) -> bool:

        if not file_path.is_file():
            return False
        if not os.access(file_path, os.R_OK):
            logger.debug(f"Skipping {file_path}: No read permission.")
            return False

        file_size_mb = file_path.stat().st_size / (1024 * 1024)
        if file_size_mb > self.config.get("max_file_size_mb"):
            logger.debug(f'Skipping {file_path}: Exceeds max file size ({file_size_mb:.2f}MB > {self.config.get("max_file_size_mb")}MB).')
            return False

        ext = file_path.suffix.lower()
        if self.config.get("allowed_extensions") and ext not in self.config.get("allowed_extensions"):
            logger.debug(f"Skipping {file_path}: Extension \'{ext}\' not in allowed list.")
            return False
        if self.config.get("blocked_extensions") and ext in self.config.get("blocked_extensions"):
            logger.debug(f"Skipping {file_path}: Extension \'{ext}\' is in blocked list.")
            return False

        if file_path.suffix == ".yar" or file_path.suffix == ".yarac":
            logger.debug(f"Skipping {file_path}: YARA rule file or compiled rule file.")
            return False

        system_paths = [Path("/proc"), Path("/sys"), Path("/dev")]
        if any(str(file_path).startswith(str(p)) for p in system_paths):
            logger.debug(f"Skipping {file_path}: system-critical path.")
            return False

        return True

    def _scan_file(self, file_path: Path, quarantine_matches: bool) -> List[Dict[str, Any]]:

        matches_found = []
        if not self._is_file_scannable(file_path):
            return matches_found

        try:
            if self.rules is None:
                logger.warning("YARA rules not loaded. Skipping scan for {file_path}.")
                return matches_found
            yara_matches = self.rules.match(filepath=str(file_path), timeout=self.config.get("yara_timeout"))
            for match in yara_matches:
                match_info = {
                    "file_path": str(file_path),
                    "rule_name": match.rule,
                    "namespace": match.namespace,
                    "tags": match.tags,
                    "meta": match.meta,
                    "strings": [str(s) for s in match.strings],
                    "description": match.meta.get("description", "N/A"),
                    "confidence": match.meta.get("confidence", "N/A"),
                    "action": "Detected"
                }
                matches_found.append(match_info)
                logger.warning(f"Threat detected in {file_path}: Rule {match.rule}")

                if quarantine_matches:
                    try:
                        quarantine_path = self.quarantine_manager.quarantine_file(file_path, match_info)
                        match_info["action"] = f"Quarantined to {quarantine_path}"
                        logger.info(f"File {file_path} quarantined.")
                    except Exception as q_e:
                        match_info["action"] = f"Failed to quarantine: {q_e}"
                        logger.error(f"Failed to quarantine {file_path}: {q_e}")

        except Exception as e:
            logger.error(f"Unexpected error scanning {file_path}: {e}")
        return matches_found

    def set_event_queue(self, queue: asyncio.Queue) -> None:
        self.event_queue = queue

    async def _emit_event(self, event_type: str, data: Dict[str, Any]) -> None:

        if self.event_queue:
            await self.event_queue.put({"type": event_type, "timestamp": datetime.now().isoformat(), "data": data})

    def scan_path(self, target_path: Path, incremental: bool = False, quarantine_matches: bool = False) -> Dict[str, Any]:

        logger.info(f"Starting scan of {target_path} (incremental: {incremental}, quarantine: {quarantine_matches})")
        all_matches: List[Dict[str, Any]] = []
        files_to_scan: List[Path] = []
        total_files_scanned = 0

        if target_path.is_file():
            files_to_scan.append(target_path)
        elif target_path.is_dir():
            for root, _, files in os.walk(target_path):
                for file_name in files:
                    file_path = Path(root) / file_name
                    if incremental and file_path in self.last_scan_times and file_path.stat().st_mtime <= self.last_scan_times[file_path]:
                        logger.debug(f"Skipping unchanged file (incremental scan): {file_path}")
                        continue
                    files_to_scan.append(file_path)
        else:
            logger.error(f"Path does not exist or is not a file/directory: {target_path}")
            return {"scanned_path": str(target_path), "total_files_scanned": 0, "matches": []}

        futures = [self.executor.submit(self._scan_file, file_path, quarantine_matches) for file_path in files_to_scan]

        for future in futures:
            total_files_scanned += 1
            matches = future.result()
            all_matches.extend(matches)

        if incremental:
            for file_path in files_to_scan:
                if file_path.exists():
                    self.last_scan_times[file_path] = file_path.stat().st_mtime

        logger.info(f"Scan of {target_path} completed. Scanned {total_files_scanned} files, found {len(all_matches)} threats.")
        return {"scanned_path": str(target_path), "total_files_scanned": total_files_scanned, "matches": all_matches}


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

    test_dir = Path("./test_scan_data")
    if test_dir.exists():
        import shutil
        shutil.rmtree(test_dir)
    test_dir.mkdir(parents=True)

    from config import ConfigManager
    from yara_manager import YaraManager
    from quarantine import QuarantineManager
    from utils import get_rules_path, get_quarantine_path

    rules_path = get_rules_path()
    rules_path.mkdir(parents=True, exist_ok=True)
    (rules_path / "test_rule.yar").write_text("rule test_eicar { strings: $a = \"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*\" condition: $a }\nrule malicious_string { strings: $s = \"malicious_content_here\" condition: $s }")

    config_manager = ConfigManager()
    yara_manager = YaraManager(config_manager)
    quarantine_manager = QuarantineManager(config_manager)

    scanner = Scanner(config_manager, yara_manager, quarantine_manager)

    clean_file = test_dir / "clean_file.txt"
    clean_file.write_text("This is a clean file.")

    malicious_file = test_dir / "eicar.txt"
    malicious_file.write_text("X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")

    malicious_file_2 = test_dir / "malicious.bin"
    malicious_file_2.write_bytes(b"some binary data with malicious_content_here")

    skipped_tmp_file = test_dir / "temp.tmp"
    skipped_tmp_file.write_text("This should be skipped.")

    large_file = test_dir / "large_file.txt"
    large_file.write_text("A" * (config_manager.get("max_file_size_mb") * 1024 * 1024 + 1))

    print("\n--- Scanning clean file ---")
    scan_results_clean = scanner.scan_path(clean_file)
    print(f"Clean file scan results: {json.dumps(scan_results_clean, indent=2)}")

    print("\n--- Scanning malicious EICAR file (no quarantine) ---")
    scan_results_malicious_eicar = scanner.scan_path(malicious_file)
    print(f"Malicious EICAR file scan results: {json.dumps(scan_results_malicious_eicar, indent=2)}")

    print("\n--- Scanning malicious binary file (with quarantine) ---")
    scan_results_quarantine = scanner.scan_path(malicious_file_2, quarantine_matches=True)
    print(f"Malicious binary file scan with quarantine results: {json.dumps(scan_results_quarantine, indent=2)}")
    print(f"Is malicious binary file still there? {malicious_file_2.exists()}")

    print("\n--- Incremental scan test ---")
    print("Performing initial scan for incremental test...")
    initial_inc_scan = scanner.scan_path(test_dir, incremental=True)
    print(f"Initial incremental scan found {len(initial_inc_scan['matches'])} threats.")

    print("\n--- Incremental scan (no changes) ---")
    no_change_inc_scan = scanner.scan_path(test_dir, incremental=True)
    print(f"Incremental scan (no changes) found {len(no_change_inc_scan['matches'])} threats. (Should be 0 new threats if files are unchanged)")

    time.sleep(1)
    (test_dir / "clean_file.txt").write_text("malicious_content_here")

    print("Performing incremental scan (should only scan modified clean_file.txt)...")
    modified_inc_scan = scanner.scan_path(test_dir, incremental=True)
    print(f"Incremental scan (modified file) found {len(modified_inc_scan['matches'])} threats.")
    for match in modified_inc_scan['matches']:
        print(f"  Detected: {match['file_path']} by rule {match['rule_name']}")

    print("\n--- Cleaning up test data ---")
    if test_dir.exists():
        import shutil
        shutil.rmtree(test_dir)
    if rules_path.exists():
        import shutil
        shutil.rmtree(rules_path)
    if get_quarantine_path().exists():
        import shutil
        shutil.rmtree(get_quarantine_path())
    print("Cleanup complete.")
