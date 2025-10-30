import argparse
import logging
import json
from typing import List, Dict, Any
from pathlib import Path
import sys
import os
import subprocess
import getpass
from datetime import datetime

try:
    from .config import ConfigManager
    from .yara_manager import YaraManager
    from .scanner import Scanner
    from .quarantine import QuarantineManager
    from .report import ReportManager
    from .updater import Updater
    from .scheduler import SchedulerManager
    from .app import run_tui
    from . import scheduled_tasks
except ImportError as e:
    print(f"Error during relative imports in cli.py: {e}")
    print("Ensure all modules (config, yara_manager, etc.) exist in the 'falcon' directory.")
    sys.exit(1)

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(name)s - %(message)s")
logger = logging.getLogger(__name__)

class FalconCLI:

    def __init__(self):
        try:
            self.config_manager = ConfigManager()
            self.yara_manager = YaraManager(self.config_manager)
            self.quarantine_manager = QuarantineManager(self.config_manager)
            self.scanner = Scanner(self.config_manager, self.yara_manager, self.quarantine_manager)
            self.report_manager = ReportManager(Path(self.config_manager.get("report_dir")), self.config_manager)
            self.updater = Updater(Path(self.config_manager.get("rules_dir")), self.config_manager)

            if len(sys.argv) <= 1 or (len(sys.argv) > 1 and sys.argv[1] not in ['install-service', 'uninstall-service']):
                 self.scheduler_manager = SchedulerManager()
                 logger.info("SchedulerManager initialized by CLI.")
            else:
                 self.scheduler_manager = None
                 logger.info("SchedulerManager initialization skipped for service management command.")

            if self.scheduler_manager:
                self._register_instances_for_scheduling()

        except Exception as e:
            logger.error(f"Failed to initialize FalconCLI components: {e}", exc_info=True)
            sys.exit(1)

    def _register_instances_for_scheduling(self):
        try:
            scheduled_tasks.register_instance("scanner", self.scanner)
            scheduled_tasks.register_instance("updater", self.updater)
            scheduled_tasks.register_instance("yara_manager", self.yara_manager)
            scheduled_tasks.register_instance("report_manager", self.report_manager)
            logger.info("Instances registered for potential scheduled task execution.")
        except Exception as e:
            logger.warning(f"Could not register all instances for scheduled tasks: {e}")

    def tui_command(self, args):
        if not self.scheduler_manager:
            self.scheduler_manager = SchedulerManager()
            self._register_instances_for_scheduling()
            logger.info("SchedulerManager initialized for TUI.")
        print("Starting FalconDefender TUI...")
        run_tui()

    def _print_scan_results(self, scan_results: Dict[str, Any]):
        if not scan_results.get("matches"):
            print("No threats detected.")
            return

        print("\n--- Scan Results ---")
        for match in scan_results["matches"]:
            file_path = match.get("file_path", "N/A")
            rule_name = match.get("rule_name", "N/A")
            namespace = match.get("namespace", "default")
            action = match.get("action", "Detected")

            print(f"File: {file_path}")
            print(f"  Rule: {rule_name} (Namespace: {namespace})")

            if match.get("tags"):
                tags_str = ", ".join(match["tags"])
                print(f"    Tags: {tags_str}")
            if match.get("meta"):
                print("    Meta:")
                for key, value in match["meta"].items():
                    print(f"      {key}: {value}")
            if match.get("strings"):
                print(f"    Strings: (Found {len(match['strings'])})")
            print(f"  Action Taken: {action}")
            print("-" * 20)

    def scan_command(self, args):
        path_to_scan = Path(args.path)
        if not path_to_scan.exists():
            print(f"Error: Scan path does not exist: {path_to_scan}")
            sys.exit(1)

        logger.info(f"Starting scan: Path='{path_to_scan}', Incremental={args.incremental}, Quarantine={args.quarantine_matches}")

        scan_results = self.scanner.scan_path(path_to_scan, incremental=args.incremental, quarantine_matches=args.quarantine_matches)
        self._print_scan_results(scan_results)

        self.report_manager.add_scan_report(scan_results)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        if args.output_summary:
            filename = f"scan_summary_{timestamp}.txt"
            self.report_manager.save_summary_report_to_file(scan_results, filename)
            print(f"Summary report saved to: {self.report_manager.report_dir / filename}")
        if args.output_pdf:
            filename = f"scan_summary_{timestamp}.pdf"
            pdf_path = self.report_manager.generate_pdf_report(scan_results, filename)
            if pdf_path:
                print(f"PDF report saved to: {pdf_path}")
            else:
                print("Failed to generate PDF report.")
        if args.email_report:
            print("Attempting to send email report...")
            if self.report_manager.send_email_report(scan_results):
                print("Email report sent successfully.")
            else:
                print("Failed to send email report. Check logs and configuration (especially password/environment variable).")

    def update_rules_command(self, args):
        source = args.source
        if not source:
             default_rules_dir = self.config_manager.get('rules_dir')
             if default_rules_dir:
                 source = f"file://{default_rules_dir}"
             else:
                 print("Error: --source not provided and no default rules_dir found in config.")
                 sys.exit(1)

        logger.info(f"Attempting rule update: Source='{source}', Checksum={args.checksum}")
        if self.updater.update_rules(source_url=source, expected_checksum=args.checksum):
            print("YARA rules updated successfully.")
            print("Reloading rules...")
            self.yara_manager.load_rules(force_recompile=True)
            print("Rules reloaded.")
        else:
            print("Failed to update YARA rules. Check logs for details.")

    def update_program_command(self, args):

        logger.info(f"Attempting program update download: Source='{args.source}', Checksum={args.checksum}")
        if self.updater.update_program(source_url=args.source, expected_checksum=args.checksum):
            print("\nProgram update file downloaded successfully.")
            print("IMPORTANT: Please manually review and replace the existing application files.")
            print("           Admin privileges may be required.")
        else:
            print("Failed to download program update. Check logs for details.")

    def quarantine_list_command(self, args):

        logger.info("Listing quarantined files...")
        files = self.quarantine_manager.list_quarantined_files()
        if not files:
            print("No files currently in quarantine.")
            return

        print("\n--- Quarantined Files ---")
        print(f"{'ID':<5} {'Original Path':<60} {'Rule':<25} {'Quarantined At':<20}")
        print("-" * 115)
        for f in files:
            orig_path_short = f['original_path']
            if len(orig_path_short) > 58:
                orig_path_short = "..." + orig_path_short[-55:]
            print(f"{f.get('id', ''):<5} {orig_path_short:<60} {f.get('rule_name', 'N/A'):<25} {f.get('quarantined_at', '')[:19]:<20}")
        print("-" * 115)


    def quarantine_restore_command(self, args):
        file_id = args.id
        logger.info(f"Attempting restore: ID={file_id}")
        if self.quarantine_manager.restore_file(file_id):
            print(f"File with ID {file_id} restored successfully.")
        else:
            print(f"Failed to restore file with ID {file_id}. Check if ID exists, file is already restored, or original path exists.")

    def quarantine_delete_command(self, args):
        file_id = args.id
        logger.info(f"Attempting permanent delete: ID={file_id}")
        confirm = input(f"WARNING: This will permanently delete the quarantined file with ID {file_id}. Are you sure? (yes/no): ")
        if confirm.lower() == 'yes':
            if self.quarantine_manager.delete_quarantined_file(file_id):
                print(f"File with ID {file_id} permanently deleted.")
            else:
                print(f"Failed to delete file with ID {file_id}. Check if ID exists or file was already deleted.")
        else:
            print("Deletion cancelled.")

    def config_set_command(self, args):
        key = args.key
        value_str = args.value
        try:
            if value_str.lower() == 'true':
                parsed_value = True
            elif value_str.lower() == 'false':
                parsed_value = False
            else:
                parsed_value = json.loads(value_str)
        except json.JSONDecodeError:
            parsed_value = value_str

        try:
            self.config_manager.set(key, parsed_value)
            print(f"Configuration key '{key}' set.")
            logger.info(f"Config set: {key}={parsed_value}")
        except Exception as e:
             print(f"Error setting configuration key '{key}': {e}")
             logger.error(f"Failed config set: {key}={parsed_value}, Error: {e}")

    def config_get_command(self, args):
        key = args.key
        value = self.config_manager.get(key)
        if value is not None:
            if isinstance(value, (dict, list)):
                print(f"{key}:")
                print(json.dumps(value, indent=4))
            else:
                print(f"{key}: {value}")
        else:
            print(f"Configuration key '{key}' not found.")

    def schedule_add_command(self, args):
        if not self.scheduler_manager:
            self.scheduler_manager = SchedulerManager()
            self._register_instances_for_scheduling()
            logger.info("SchedulerManager initialized for schedule command.")

        func_map = {
            "scan": scheduled_tasks.run_scan_task,
            "update-rules": scheduled_tasks.run_update_task,
        }

        if args.task not in func_map:
            print(f"Error: Task type '{args.task}' is not supported for scheduling via CLI.")
            return

        task_func = func_map[args.task]

        try:
            task_args = json.loads(args.task_args) if args.task_args else []
            task_kwargs = json.loads(args.task_kwargs) if args.task_kwargs else {}
            if not isinstance(task_args, list): raise ValueError("--task-args must be a valid JSON list (e.g., '[\"/path\"]')")
            if not isinstance(task_kwargs, dict): raise ValueError("--task-kwargs must be a valid JSON dictionary (e.g., '{\"key\": true}')")
        except json.JSONDecodeError as e:
            print(f"Error: Invalid JSON format for --task-args or --task-kwargs: {e}")
            return
        except ValueError as e:
            print(f"Error: {e}")
            return

        trigger_args = {}
        if args.trigger_type == "interval":
            if args.interval_seconds is None:
                 print("Error: --interval-seconds is required for interval trigger.")
                 return
            if args.interval_seconds <= 0:
                 print("Error: --interval-seconds must be positive.")
                 return
            trigger_args["seconds"] = args.interval_seconds
        elif args.trigger_type == "cron":
            if not args.cron_expression:
                 print("Error: --cron-expression is required for cron trigger.")
                 return
            cron_fields = args.cron_expression.split()
            if len(cron_fields) != 6:
                print("Error: Cron expression must have 6 fields (second minute hour day month day_of_week).")
                return
            trigger_args = {
                "second": cron_fields[0], "minute": cron_fields[1], "hour": cron_fields[2],
                "day": cron_fields[3], "month": cron_fields[4], "day_of_week": cron_fields[5],
            }
        else:
            print(f"Error: Unknown trigger type '{args.trigger_type}'.")
            return

        try:
            self.scheduler_manager.add_job(
                func=task_func,
                trigger=args.trigger_type,
                name=args.name,
                args=task_args,
                kwargs=task_kwargs,
                **trigger_args
            )
            print(f"Scheduled task '{args.name}' added/updated successfully.")
        except Exception as e:
             print(f"Error adding scheduled task '{args.name}': {e}")
             logger.error(f"Failed to add scheduled task '{args.name}': {e}", exc_info=True)

    def schedule_list_command(self, args):
        if not self.scheduler_manager:
            self.scheduler_manager = SchedulerManager()
            logger.info("SchedulerManager initialized for schedule command.")

        print("\n--- Scheduled Tasks (Internal Scheduler) ---")
        try:
            jobs = self.scheduler_manager.get_jobs()
            if not jobs:
                print("No tasks currently scheduled.")
                return

            print(f"{'ID/Name':<25} {'Function':<20} {'Trigger':<30} {'Next Run (UTC)':<25}")
            print("-" * 105)
            for job in jobs:
                try:
                    next_run_dt = job.next_run_time
                    next_run_str = next_run_dt.isoformat(timespec='seconds') if next_run_dt else "N/A"
                except Exception:
                    next_run_str = "Error"

                func_name = job.func.__name__ if hasattr(job.func, '__name__') else str(job.func)
                trigger_str = str(job.trigger)
                if len(trigger_str) > 28: trigger_str = trigger_str[:25] + "..."

                print(f"{job.id:<25} {func_name:<20} {trigger_str:<30} {next_run_str:<25}")
            print("-" * 105)

        except Exception as e:
            print(f"Error retrieving scheduled tasks: {e}")
            logger.error(f"Failed to list scheduled tasks: {e}", exc_info=True)


    def schedule_remove_command(self, args):
        if not self.scheduler_manager:
            self.scheduler_manager = SchedulerManager()
            logger.info("SchedulerManager initialized for schedule command.")

        job_name = args.name
        print(f"Attempting to remove scheduled task '{job_name}'...")
        try:
            self.scheduler_manager.remove_job(job_name)
            print(f"Removed scheduled task '{job_name}' (if it existed).")
        except Exception as e:
             print(f"Error removing scheduled task '{job_name}': {e}")
             logger.error(f"Failed to remove scheduled task '{job_name}': {e}", exc_info=True)


    def _get_service_file_content(self) -> str:
        python_executable = sys.executable
        daemon_script = (Path(__file__).resolve().parent.parent / "falcon_daemon.py").resolve()
        working_directory = (Path(__file__).resolve().parent.parent).resolve()
        user = getpass.getuser()

        if not Path(python_executable).exists():
             raise FileNotFoundError(f"Python executable not found at: {python_executable}")
        if not daemon_script.exists():
            raise FileNotFoundError(f"Daemon script not found at expected location: {daemon_script}")
        if not working_directory.exists():
            raise FileNotFoundError(f"Working directory not found: {working_directory}")

        run_user = user
        run_group = user

        env_vars = [
            f'HOME=/home/{run_user}',
            f'XDG_DATA_HOME=/home/{run_user}/.local/share',
            f'XDG_CONFIG_HOME=/home/{run_user}/.config',
        ]
        environment_directives = "\n".join([f'Environment="{var}"' for var in env_vars])

        service_content = f"""[Unit]
Description=FalconDefender Background Scheduler Service
After=network.target

[Service]
User={run_user}
Group={run_group}
WorkingDirectory={working_directory}
{environment_directives}
ExecStart={python_executable} -u {daemon_script}
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
"""
        return service_content

    def install_service_command(self, args):

        service_name = "falcon-scheduler.service"
        service_path = Path("/etc/systemd/system") / service_name

        if os.geteuid() != 0:
            print("\033[91mError: This command must be run with root privileges (e.g., using sudo).\033[0m")
            sys.exit(1)

        print(f"Attempting to install systemd service as {service_path}...")
        try:
            service_content = self._get_service_file_content()
        except FileNotFoundError as e:
            print(f"\033[91mError generating service file: {e}\033[0m")
            print("Please ensure you are running this from the project root directory")
            print("and the virtual environment is correctly set up.")
            sys.exit(1)
        except Exception as e:
            print(f"\033[91mUnexpected error generating service file: {e}\033[0m")
            sys.exit(1)


        try:
            print(f"Writing service file to {service_path}...")
            with open(service_path, "w") as f:
                f.write(service_content)
            os.chmod(service_path, 0o644)
            print("Service file written.")

            print("Running systemctl daemon-reload...")
            result = subprocess.run(["systemctl", "daemon-reload"], check=False, capture_output=True, text=True)
            if result.returncode != 0: raise subprocess.CalledProcessError(result.returncode, result.args, result.stdout, result.stderr)

            print("Running systemctl enable...")
            result = subprocess.run(["systemctl", "enable", service_name], check=False, capture_output=True, text=True)
            if result.returncode != 0:
                 if "already exists" not in result.stderr:
                     raise subprocess.CalledProcessError(result.returncode, result.args, result.stdout, result.stderr)
                 else:
                     print(f"Note: Service link {result.stderr.strip()}")

            print("Running systemctl start...")
            result = subprocess.run(["systemctl", "start", service_name], check=False, capture_output=True, text=True)
            if result.returncode != 0: raise subprocess.CalledProcessError(result.returncode, result.args, result.stdout, result.stderr)

            print(f"\n\033[92mService '{service_name}' installed, enabled, and started successfully!\033[0m")
            print("\033[94mYou can check status with: sudo systemctl status {service_name}\033[0m")
            print("\033[94mLogs can be viewed with: journalctl -u {service_name} -f\033[0m")
            print("\033[93mRemember to securely set the FALCON_EMAIL_PASS environment variable for the service if needed!\033[0m")
            print("\033[93m(e.g., by editing /etc/environment and rebooting, or using systemctl set-environment)\033[0m")

        except FileNotFoundError:
             print("\033[91mError: systemctl command not found. Is systemd installed and in PATH?\033[0m")
             sys.exit(1)
        except subprocess.CalledProcessError as e:
            print(f"\033[91mError running systemctl command: {e}\033[0m")
            print(f"Stderr: {e.stderr}")
            print("\033[91mInstallation failed. Attempting cleanup...\033[0m")
            if service_path.exists():
                try: service_path.unlink()
                except OSError as unlink_e: print(f"Warning: Failed to remove service file during cleanup: {unlink_e}")
            subprocess.run(["systemctl", "daemon-reload"], check=False)
            sys.exit(1)
        except Exception as e:
            print(f"\033[91mAn unexpected error occurred during installation: {e}\033[0m")
            if service_path.exists():
                try: service_path.unlink()
                except OSError as unlink_e: print(f"Warning: Failed to remove service file during cleanup: {unlink_e}")
            subprocess.run(["systemctl", "daemon-reload"], check=False)
            sys.exit(1)

    def uninstall_service_command(self, args):
        service_name = "falcon-scheduler.service"
        service_path = Path("/etc/systemd/system") / service_name

        if os.geteuid() != 0:
            print("\033[91mError: This command must be run with root privileges (e.g., using sudo).\033[0m")
            sys.exit(1)

        print(f"Attempting to uninstall systemd service '{service_name}'...")
        errors_occurred = False
        try:
            print("Running systemctl stop...")
            result = subprocess.run(["systemctl", "stop", service_name], check=False, capture_output=True, text=True)
            if result.returncode != 0 and "not loaded" not in result.stderr:
                 print(f"\033[93mWarning: Failed to stop service (may already be stopped): {result.stderr.strip()}\033[0m")
                 errors_occurred = True

            print("Running systemctl disable...")
            result = subprocess.run(["systemctl", "disable", service_name], check=False, capture_output=True, text=True)
            if result.returncode != 0 and "Removed" not in result.stdout:
                 print(f"\033[93mWarning: Failed to disable service: {result.stderr.strip()} {result.stdout.strip()}\033[0m")
                 errors_occurred = True

            print("Removing service file...")
            if service_path.exists():
                try:
                    service_path.unlink()
                except OSError as e:
                    print(f"\033[91mError: Failed to remove service file {service_path}: {e}\033[0m")
                    errors_occurred = True
            else:
                 print("Service file not found (already removed?).")

            print("Running systemctl daemon-reload...")
            result = subprocess.run(["systemctl", "daemon-reload"], check=False, capture_output=True, text=True)
            if result.returncode != 0:
                 print(f"\033[91mError: Failed to run daemon-reload: {result.stderr.strip()}\033[0m")
                 errors_occurred = True

            print("Running systemctl reset-failed...")
            subprocess.run(["systemctl", "reset-failed"], check=False, capture_output=True)

            if errors_occurred:
                print(f"\n\033[93mService '{service_name}' uninstallation completed with warnings. Please check manually.\033[0m")
            else:
                print(f"\n\033[92mService '{service_name}' uninstalled successfully.\033[0m")

        except FileNotFoundError:
             print("\033[91mError: systemctl command not found.\033[0m")
             sys.exit(1)
        except Exception as e:
            print(f"\033[91mAn unexpected error occurred during uninstallation: {e}\033[0m")
            sys.exit(1)

    def main(self):
        parser = argparse.ArgumentParser(
            description="FalconDefender 2.0.0 CLI - Malware Scanner and Scheduler",
            formatter_class=argparse.RawTextHelpFormatter
            )
        subparsers = parser.add_subparsers(
             dest="command",
             help="Available commands",
             required=True
             )

        tui_parser = subparsers.add_parser("tui", help="Run the interactive Text-based User Interface.")
        tui_parser.set_defaults(func=self.tui_command)

        scan_parser = subparsers.add_parser("scan", help="Scan a file or directory for malware.")
        scan_parser.add_argument("path", type=str, help="Path to the file or directory to scan.")
        scan_parser.add_argument("-i", "--incremental", action="store_true", help="Perform an incremental scan (only scan changed files).")
        scan_parser.add_argument("-q", "--quarantine-matches", action="store_true", help="Automatically quarantine detected matches.")
        scan_parser.add_argument("--output-summary", action="store_true", help="Save a human-readable summary report to a text file.")
        scan_parser.add_argument("--output-pdf", action="store_true", help="Save a PDF summary report to a file.")
        scan_parser.add_argument("--email-report", action="store_true", help="Send scan report via email (requires configuration).")
        scan_parser.set_defaults(func=self.scan_command)

        update_rules_parser = subparsers.add_parser("update-rules", help="Update YARA rules from a source.")
        update_rules_parser.add_argument("-s", "--source", type=str,
                                   help="Source URL/path (e.g., file:///path, http://host/rules.zip).\nDefaults to rules_dir in config if not provided.")
        update_rules_parser.add_argument("-c", "--checksum", type=str, help="Optional SHA256 checksum for validation.")
        update_rules_parser.set_defaults(func=self.update_rules_command)

        update_program_parser = subparsers.add_parser("update-program", help="Download program update file (manual installation required).")
        update_program_parser.add_argument("-s", "--source", type=str, required=True, help="Source URL for the program update file.")
        update_program_parser.add_argument("-c", "--checksum", type=str, help="Optional SHA256 checksum for validation.")
        update_program_parser.set_defaults(func=self.update_program_command)

        quarantine_parser = subparsers.add_parser("quarantine", help="Manage quarantined files.")
        quarantine_subparsers = quarantine_parser.add_subparsers(dest="quarantine_command", help="Action", required=True)

        quarantine_list_parser = quarantine_subparsers.add_parser("list", help="List all currently quarantined files.")
        quarantine_list_parser.set_defaults(func=self.quarantine_list_command)

        quarantine_restore_parser = quarantine_subparsers.add_parser("restore", help="Restore a quarantined file by its ID.")
        quarantine_restore_parser.add_argument("id", type=int, help="Numeric ID of the file to restore.")
        quarantine_restore_parser.set_defaults(func=self.quarantine_restore_command)

        quarantine_delete_parser = quarantine_subparsers.add_parser("delete", help="Permanently delete a quarantined file by its ID.")
        quarantine_delete_parser.add_argument("id", type=int, help="Numeric ID of the file to delete.")
        quarantine_delete_parser.set_defaults(func=self.quarantine_delete_command)

        config_parser = subparsers.add_parser("config", help="Manage application configuration.")
        config_subparsers = config_parser.add_subparsers(dest="config_command", help="Action", required=True)

        config_set_parser = config_subparsers.add_parser("set", help="Set a configuration value.")
        config_set_parser.add_argument("key", type=str, help="Config key (use dot notation for nested keys, e.g., email_reporting.enabled).")
        config_set_parser.add_argument("value", type=str, help="Value to set (e.g., 8, true, \"smtp.host.com\", '[ \"*.log\", \"*.tmp\" ]').")
        config_set_parser.set_defaults(func=self.config_set_command)

        config_get_parser = config_subparsers.add_parser("get", help="Get a configuration value.")
        config_get_parser.add_argument("key", type=str, help="Config key (use dot notation for nested keys).")
        config_get_parser.set_defaults(func=self.config_get_command)

        schedule_parser = subparsers.add_parser("schedule", help="Manage tasks scheduled within FalconDefender (uses internal scheduler).")
        schedule_subparsers = schedule_parser.add_subparsers(dest="schedule_command", help="Action", required=True)

        schedule_add_parser = schedule_subparsers.add_parser("add", help="Add/update a task in the internal scheduler.")
        schedule_add_parser.add_argument("--name", type=str, required=True, help="Unique name/ID for the task.")
        schedule_add_parser.add_argument("--task", type=str, required=True, choices=["scan", "update-rules"], help="Task type to schedule.")
        schedule_add_parser.add_argument("--task-args", type=str, default="[]", help="JSON list of positional args for the task (e.g., '[\"/path/to/scan\"]').")
        schedule_add_parser.add_argument("--task-kwargs", type=str, default="{}", help="JSON dict of keyword args for the task (e.g., '{\"quarantine_matches\": true}').")
        schedule_trigger_group = schedule_add_parser.add_mutually_exclusive_group(required=True)
        schedule_trigger_group.add_argument("--interval-seconds", type=int, help="Run task every N seconds.")
        schedule_trigger_group.add_argument("--cron-expression", type=str, help="Run task based on 6-field cron (sec min hr day mon dow).")

        schedule_add_parser.set_defaults(func=self.schedule_add_command, trigger_type=None)
        def set_trigger_type(args):
             if args.interval_seconds is not None: args.trigger_type = "interval"
             elif args.cron_expression is not None: args.trigger_type = "cron"
        schedule_add_parser.set_defaults(post_func=set_trigger_type)

        schedule_list_parser = schedule_subparsers.add_parser("list", help="List tasks currently in the internal scheduler.")
        schedule_list_parser.set_defaults(func=self.schedule_list_command)

        schedule_remove_parser = schedule_subparsers.add_parser("remove", help="Remove a task from the internal scheduler by name/ID.")
        schedule_remove_parser.add_argument("--name", type=str, required=True, help="Name/ID of the task to remove.")
        schedule_remove_parser.set_defaults(func=self.schedule_remove_command)

        install_parser = subparsers.add_parser("install-service",
            help="Install scheduler as a systemd service (requires sudo)."
            "\nThis creates /etc/systemd/system/falcon-scheduler.service"
            "\nand enables/starts it to run falcon_daemon.py persistently."
            )
        install_parser.set_defaults(func=self.install_service_command)

        uninstall_parser = subparsers.add_parser("uninstall-service",
            help="Uninstall the systemd scheduler service (requires sudo)."
             "\nThis stops/disables the service and removes the file from /etc/systemd/system."
             )
        uninstall_parser.set_defaults(func=self.uninstall_service_command)

        args = parser.parse_args()

        if hasattr(args, 'post_func'):
            args.post_func(args)
        args.func(args)


def main_entry():
    cli = FalconCLI()
    try:
        cli.main()
    finally:

        if hasattr(cli, 'scheduler_manager') and cli.scheduler_manager and cli.scheduler_manager.scheduler.running:
            command = sys.argv[1] if len(sys.argv) > 1 else None
            if command not in ['install-service', 'uninstall-service']:
                 logger.info("CLI instance shutting down its internal scheduler...")
                 cli.scheduler_manager.shutdown()
                 logger.info("Internal scheduler shut down.")

if __name__ == "__main__":
    main_entry()
