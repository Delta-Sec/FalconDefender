import os
import hashlib
import requests
import yara
import logging
import zipfile
import shutil
from pathlib import Path
from typing import Optional, Dict, Any

logger = logging.getLogger(__name__)

class Updater:

    def __init__(self, rules_dir: Path, config_manager: Any = None):
        self.rules_dir = rules_dir
        self.rules_dir.mkdir(parents=True, exist_ok=True)
        self.config_manager = config_manager

    def _download_file(self, url: str, destination_path: Path) -> bool:

        try:
            response = requests.get(url, stream=True, timeout=10)
            response.raise_for_status()
            with open(destination_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)
            logger.info(f"Successfully downloaded {url} to {destination_path}")
            return True
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to download {url}: {e}")
            return False

    def _calculate_checksum(self, file_path: Path) -> str:

        hasher = hashlib.sha256()
        with open(file_path, 'rb') as f:
            while True:
                chunk = f.read(8192)
                if not chunk:
                    break
                hasher.update(chunk)
        return hasher.hexdigest()

    def _validate_checksum(self, file_path: Path, expected_checksum: str) -> bool:

        actual_checksum = self._calculate_checksum(file_path)
        if actual_checksum != expected_checksum:
            logger.error(f"Checksum mismatch for {file_path.name}. Expected {expected_checksum}, got {actual_checksum}")
            return False
        logger.info(f"Checksum validated successfully for {file_path.name}.")
        return True

    def _extract_zip_bundle(self, zip_path: Path, destination_dir: Path) -> bool:

        try:
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                zip_ref.extractall(destination_dir)
            logger.info(f"Successfully extracted {zip_path} to {destination_dir}")
            return True
        except zipfile.BadZipFile:
            logger.error(f"Downloaded file {zip_path} is not a valid zip archive.")
            return False
        except Exception as e:
            logger.error(f"Error extracting zip file {zip_path}: {e}")
            return False

    def update_rules(self, source_url: str, expected_checksum: Optional[str] = None) -> bool:

        logger.info(f"Attempting to update rules from: {source_url}")

        temp_dir = self.rules_dir.parent / ".temp_rules_update"
        temp_dir.mkdir(parents=True, exist_ok=True)

        try:
            if source_url.startswith("file://"):
                local_source_path = Path(source_url[len("file://"):])
                if not local_source_path.exists():
                    logger.error(f"Local rule source not found: {local_source_path}")
                    return False

                if local_source_path.is_dir():

                    yar_files = list(local_source_path.glob("*.yar"))
                    yara_files = list(local_source_path.glob("*.yara"))

                    for yar_file in yar_files + yara_files:

                        try:

                            yara.compile(filepath=str(yar_file))
                            dest_file = self.rules_dir / yar_file.name
                            current_checksum = self._calculate_checksum(dest_file) if dest_file.exists() else None
                            if not dest_file.exists() or self._calculate_checksum(yar_file) != current_checksum:
                                shutil.copy2(yar_file, dest_file)
                                logger.info(f"Copied/Updated YARA rule: {yar_file.name}")
                            else:
                                logger.info(f"YARA rule {yar_file.name} is already up to date.")
                        except yara.Error as e:
                            logger.error(f"Invalid YARA rule {yar_file.name}: {e}. Skipping.")
                    return True
                elif local_source_path.suffix == ".zip":

                    if expected_checksum and not self._validate_checksum(local_source_path, expected_checksum):
                        return False
                    if not self._extract_zip_bundle(local_source_path, temp_dir):
                        return False
                else:
                    logger.error(f"Unsupported local rule source type: {local_source_path}")
                    return False
            else:

                temp_zip_path = temp_dir / "rules_bundle.zip"
                if not self._download_file(source_url, temp_zip_path):
                    return False

                if expected_checksum and not self._validate_checksum(temp_zip_path, expected_checksum):
                    temp_zip_path.unlink()
                    return False

                if not self._extract_zip_bundle(temp_zip_path, temp_dir):
                    temp_zip_path.unlink()
                    return False
                temp_zip_path.unlink()

            for root, _, files in os.walk(temp_dir):
                for file in files:
                    if file.endswith('.yar') or file.endswith('.yara'):
                        source_file_path = Path(root) / file

                        relative_path = source_file_path.relative_to(temp_dir)

                        dest_file_path = self.rules_dir / relative_path

                        try:

                            dest_file_path.parent.mkdir(parents=True, exist_ok=True)

                            yara.compile(filepath=str(source_file_path))

                            current_checksum = self._calculate_checksum(
                                dest_file_path) if dest_file_path.exists() else None
                            if not dest_file_path.exists() or self._calculate_checksum(
                                    source_file_path) != current_checksum:
                                shutil.copy2(source_file_path, dest_file_path)
                                logger.info(f"Copied/Updated YARA rule: {relative_path}")
                            else:
                                logger.info(f"YARA rule {relative_path} is already up to date.")
                        except yara.Error as e:
                            logger.error(f"Invalid YARA rule {relative_path}: {e}. Skipping.")
            return True

        finally:
            if temp_dir.exists():
                shutil.rmtree(temp_dir)

    def update_program(self, source_url: str, expected_checksum: Optional[str] = None) -> bool:

        logger.info(f"Attempting to update program from: {source_url}")

        download_path = Path.home() / Path(source_url).name

        if not self._download_file(source_url, download_path):
            return False

        if expected_checksum and not self._validate_checksum(download_path, expected_checksum):
            download_path.unlink()
            return False

        logger.info(f"Program update file downloaded to: {download_path}")
        logger.info(
            "Please review the downloaded file and manually replace your existing FalconDefender executable/script.")
        logger.info("Admin consent may be required for this operation.")
        return True


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

    test_rules_dir = Path("./test_rules_update")
    if test_rules_dir.exists():
        import shutil

        shutil.rmtree(test_rules_dir)
    test_rules_dir.mkdir()

    (test_rules_dir / "test_rule_1.yar").write_text(
        "rule test_rule_1 { strings: $a = \"test_string_1\" condition: $a }")
    (test_rules_dir / "test_rule_2.yar").write_text(
        "rule test_rule_2 { strings: $b = \"test_string_2\" condition: $b }")

    (test_rules_dir / "test_rule_3.yara").write_text(
        "rule test_rule_3 { strings: $c = \"test_string_3\" condition: $c }")

    updater = Updater(rules_dir=test_rules_dir)

    print("\n--- Testing local directory update (no changes) ---")
    updater.update_rules(source_url=f"file://{test_rules_dir.absolute()}")

    print("\n--- Testing local directory update (with change) ---")

    (test_rules_dir / "test_rule_1.yar").write_text(
        "rule test_rule_1 { strings: $a = \"updated_string_1\" condition: $a }")

    (test_rules_dir / "test_rule_3.yara").write_text(
        "rule test_rule_3 { strings: $c = \"updated_string_3\" condition: $c }")
    updater.update_rules(source_url=f"file://{test_rules_dir.absolute()}")

    print("\n--- Testing local zip file update ---")
    test_zip_dir = Path("./temp_zip_source")
    test_zip_dir.mkdir(exist_ok=True)
    (test_zip_dir / "new_rule.yar").write_text("rule new_rule { strings: $c = \"new_signature\" condition: $c }")
    (test_zip_dir / "another_rule.yara").write_text(
        "rule another_rule { strings: $d = \"another_signature\" condition: $d }")
    zip_file_path = Path("./rules_bundle.zip")
    with zipfile.ZipFile(zip_file_path, 'w') as zf:
        for file in test_zip_dir.iterdir():
            zf.write(file, arcname=file.name)

    zip_checksum = updater._calculate_checksum(zip_file_path)
    updater.update_rules(source_url=f"file://{zip_file_path.absolute()}", expected_checksum=zip_checksum)
    shutil.rmtree(test_zip_dir)
    zip_file_path.unlink()

    print("\n--- Testing remote update (mocking a download) ---")
    mock_remote_url = "http://example.com/rules_bundle.zip"

    dummy_checksum = "a" * 64
    updater.update_rules(source_url=mock_remote_url, expected_checksum=dummy_checksum)

    print("\n--- Testing program update (mocking a download) ---")
    mock_program_url = "http://example.com/falcon_defender_cli_v2.0.0"
    dummy_program_checksum = "b" * 64
    updater.update_program(source_url=mock_program_url, expected_checksum=dummy_program_checksum)

    print("\n--- Cleaning up test rules directory ---")
    if test_rules_dir.exists():
        shutil.rmtree(test_rules_dir)
        print(f"Removed test rules directory: {test_rules_dir}")
