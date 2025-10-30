import asyncio
import json
import logging
from pathlib import Path
from datetime import datetime
from typing import Optional, Dict, Any, List

from textual.app import App, ComposeResult, on
from textual.containers import Container, Horizontal, Vertical, ScrollableContainer, VerticalScroll
from textual.widgets import (
    Header, Footer, Static, Button, Label, Input, DataTable,
    TextArea, Tabs, TabPane, Select, Tab, RadioSet, RadioButton, RichLog
)
from textual.reactive import reactive
from textual.binding import Binding
from textual.screen import Screen
from textual.message import Message

from . import scheduled_tasks
from .config import ConfigManager
from .yara_manager import YaraManager
from .scanner import Scanner
from .scheduler import SchedulerManager
from .quarantine import QuarantineManager
from .updater import Updater
from textual.widgets import Checkbox
from .report import ReportManager
from .tui_integration import (
    ScannerAdapter, QuarantineAdapter, UpdaterAdapter, SchedulerAdapter,
    ScanState, TUIEventHandler
)

logger = logging.getLogger(__name__)


class AnimatedLogo(Static):

    LOGO = r"""
    ███████╗ █████╗ ██╗      ██████╗ ██████╗ ███╗   ██╗
    ██╔════╝██╔══██╗██║     ██╔════╝██╔═══██╗████╗  ██║
    █████╗  ███████║██║     ██║     ██║   ██║██╔██╗ ██║
    ██╔══╝  ██╔══██║██║     ██║     ██║   ██║██║╚██╗██║
    ██║     ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
    ╚═╝     ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝ By Delta Security
    """

    state = reactive(ScanState.IDLE.value)
    version = "2.0.0"

    def render(self) -> str:
        state_color = {
            ScanState.IDLE.value: "[green]",
            ScanState.SCANNING.value: "[cyan]",
            ScanState.PAUSED.value: "[yellow]",
            ScanState.UPDATING.value: "[blue]",
            ScanState.ERROR.value: "[red]",
        }.get(self.state, "[white]")

        time_str = datetime.now().strftime('%H:%M:%S')
        return (
            f"{self.LOGO}\n"
            f"[bold cyan]FalconDefender v{self.version}[/bold cyan] | "
            f"State: {state_color}{self.state}[/] | "
            f"[dim]{time_str}[/dim]"
        )

class ScanStatsPanel(Static):

    scanned = reactive(0)
    total = reactive(0)
    matches = reactive(0)
    files_per_sec = reactive(0.0)
    elapsed = reactive(0.0)

    def render(self) -> str:
        progress_pct = (self.scanned / self.total * 100) if self.total > 0 else 0
        bar_width = 30
        filled = int(bar_width * progress_pct / 100)
        bar = "█" * filled + "░" * (bar_width - filled)

        return (
            f"[bold cyan]Scan Statistics[/bold cyan]\n"
            f"Progress: [{bar}] {progress_pct:.1f}%\n"
            f"Files: {self.scanned}/{self.total}\n"
            f"Threats: [bold red]{self.matches}[/bold red]\n"
            f"Speed: {self.files_per_sec:.1f} files/sec\n"
            f"Time: {self.elapsed:.1f}s"
        )


class MatchesTableWidget(Static):

    def __init__(self):
        super().__init__()
        self.matches: List[Dict[str, Any]] = []

    def compose(self) -> ComposeResult:
        table = DataTable(id="matches-table")
        table.add_columns("ID", "File", "Rule", "Severity", "Time")
        yield table

    def add_match(self, match: Dict[str, Any]) -> None:
        self.matches.append(match)
        table = self.query_one("#matches-table", DataTable)

        severity = match.get("severity", "medium")
        severity_style = {
            "high": "bold red",
            "medium": "bold yellow",
            "low": "bold green",
        }.get(severity, "bold white")

        file_path = str(match.get("file", ""))
        if len(file_path) > 40:
            file_path = "..." + file_path[-37:]

        table.add_row(
            str(match.get("id", ""))[:8],
            file_path,
            match.get("rule", ""),
            f"[{severity_style}]{severity}[/]",
            match.get("timestamp", "")[-8:],
        )

    def clear_matches(self) -> None:
        table = self.query_one("#matches-table", DataTable)
        table.clear()
        self.matches = []

class LogViewerWidget(Static):

    def compose(self) -> ComposeResult:
        yield RichLog(id="log-viewer", wrap=True, markup=True, highlight=False)

    def add_log(self, message: str, level: str = "INFO") -> None:

        try:
            log_widget = self.query_one("#log-viewer", RichLog)

            timestamp = datetime.now().strftime("%H:%M:%S")

            level_colors = {
                "INFO": "[cyan]",
                "WARNING": "[yellow]",
                "ERROR": "[red]",
                "DEBUG": "[dim]",
            }
            color = level_colors.get(level.upper(), "[white]")

            log_line = f"{color}[{timestamp}] {level.upper()}: {message}[/]"

            log_widget.write(log_line)

        except Exception as e:
            logger.error(f"Failed to write to TUI log widget: {e}")


class QuarantineTableWidget(Static):

    def __init__(self, quarantine_manager: QuarantineManager):
        super().__init__()
        self.quarantine_manager = quarantine_manager
        self.quarantine_items: List[Dict[str, Any]] = []

    def compose(self) -> ComposeResult:
        table = DataTable(id="quarantine-table")
        table.add_columns("ID", "Original Path", "Rule", "Quarantined At")
        yield table

    async def refresh_list(self) -> None:
        try:
            loop = asyncio.get_event_loop()
            items = await loop.run_in_executor(
                None,
                self.quarantine_manager.list_quarantined_files
            )

            self.quarantine_items = items
            table = self.query_one("#quarantine-table", DataTable)
            table.clear()

            for item in items:
                orig_path = str(item.get("original_path", ""))
                if len(orig_path) > 50:
                    orig_path = "..." + orig_path[-47:]

                table.add_row(
                    str(item.get("id", "")),
                    orig_path,
                    item.get("rule_name", "Unknown"),
                    item.get("quarantined_at", "")[-19:],
                )
        except Exception as e:
            logger.error(f"Error refreshing quarantine list: {e}")


class ScanPathInputModal(Screen):

    DEFAULT_CSS = """
    ScanPathInputModal {
        align: center middle;
    }

    #scan-modal {
        width: 60;
        height: 14;
        border: solid $accent;
        background: $surface;
    }

    #scan-modal > Vertical {
        width: 1fr;
        height: 1fr;
    }

    #scan-path-input {
        width: 1fr;
        margin: 1 0;
    }

    #modal-buttons {
        width: 1fr;
        height: auto;
        margin-top: 1;
    }

    #modal-buttons > Button {
        width: 1fr;
    }
    """
    def compose(self) -> ComposeResult:
        yield Container(
            Vertical(
                Label("[bold cyan]Enter Path to Scan[/bold cyan]"),
                Input(
                    id="scan-path-input",
                    placeholder="/path/to/scan",
                ),

                Select(
                    [("Scan Only", False), ("Scan & Quarantine", True)],
                    id="scan-mode-select",
                    value=False
                ),
                Horizontal(
                    Button("Scan", id="btn-scan-confirm", variant="primary"),
                    Button("Cancel", id="btn-scan-cancel", variant="error"),
                    id="modal-buttons",
                ),
                id="scan-modal-content",
            ),
            id="scan-modal",
        )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-scan-confirm":
            path_input = self.query_one("#scan-path-input", Input)
            mode_input = self.query_one("#scan-mode-select", Select)

            path = path_input.value if path_input.value else None
            mode = mode_input.value

            self.dismiss((path, mode))

        elif event.button.id == "btn-scan-cancel":
            self.dismiss((None, False))


class ConfirmActionModal(Screen):

    DEFAULT_CSS = """
    ConfirmActionModal {
        align: center middle;
    }

    #confirm-modal {
        width: 50;
        height: 10;
        border: solid $error;
        background: $surface;
    }

    #confirm-modal > Vertical {
        width: 1fr;
        height: 1fr;
    }

    #confirm-buttons {
        width: 1fr;
        height: auto;
        margin-top: 1;
    }

    #confirm-buttons > Button {
        width: 1fr;
    }
    """

    def __init__(self, message: str):
        super().__init__()
        self.message = message

    def compose(self) -> ComposeResult:
        yield Container(
            Vertical(
                Label(f"[bold red]{self.message}[/bold red]"),
                Horizontal(
                    Button("Confirm", id="btn-confirm", variant="error"),
                    Button("Cancel", id="btn-cancel", variant="primary"),
                    id="confirm-buttons",
                ),
                id="confirm-modal-content",
            ),
            id="confirm-modal",
        )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-confirm":
            self.dismiss(True)
        else:
            self.dismiss(False)

class ExportReportModal(Screen):

    DEFAULT_CSS = """
    ExportReportModal {
        align: center middle;
    }

    #export-modal {
        width: 60;
        height: 10;
        border: solid $accent;
        background: $surface;
    }

    #export-modal > Vertical {
        width: 1fr;
        height: 1fr;
    }

    #export-filename-input {
        width: 1fr;
        margin: 1 0;
    }

    #export-modal-buttons {
        width: 1fr;
        height: auto;
        margin-top: 1;
    }

    #export-modal-buttons > Button {
        width: 1fr;
    }
    """

    def compose(self) -> ComposeResult:
        yield Container(
            Vertical(
                Label("[bold cyan]Enter Filename for JSON Export[/bold cyan]"),
                Input(
                    id="export-filename-input",
                    placeholder="scan_matches.json",
                    value=f"falcon_matches_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
                ),
                Horizontal(
                    Button("Export & Email", id="btn-export-confirm", variant="primary"),
                    Button("Cancel", id="btn-export-cancel", variant="error"),
                    id="export-modal-buttons",
                ),
                id="export-modal-content",
            ),
            id="export-modal",
        )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-export-confirm":
            filename_input = self.query_one("#export-filename-input", Input)
            filename = filename_input.value
            if not filename:
                filename = f"falcon_matches_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            elif not filename.lower().endswith(".json"):
                filename += ".json"
            self.dismiss(filename)
        elif event.button.id == "btn-export-cancel":
            self.dismiss(None)


class SettingsScreen(Screen):

    DEFAULT_CSS = """
    SettingsScreen {
        align: center middle;
    }
    #settings-container {
        width: 80;
        max-width: 90%; 
        height: 24; 
        border: thick $accent;
        background: $surface;
        padding: 1 2;
        overflow-y: auto;
    }
    #settings-container > Horizontal {
        margin-bottom: 1;
        height: auto;
    }
    .setting-label {
        width: 1fr;
        text-align: right;
        margin-right: 2;
    }
    .setting-input {
        width: 2fr;
    }
    #settings-container > Horizontal > Checkbox {
        width: 1fr;
        margin-top: 1;
    }
    #settings-buttons {
        margin-top: 2;
        width: 1fr;
        height: auto;
    }
    #settings-buttons > Button {
        width: 1fr;
        margin: 0 1;
    }
    """

    def __init__(self, config_manager: ConfigManager):
        super().__init__()
        self.config_manager = config_manager

    def on_mount(self) -> None:
        logger.info("SettingsScreen mounted. Attempting to focus the container.")
        try:
            settings_container = self.query_one("#settings-container", ScrollableContainer)
            settings_container.focus()
            logger.info(f"Focus set on container: {settings_container}. Use TAB key.")
        except Exception as e:
            logger.error(f"Could not focus settings container: {e}")

    def compose(self) -> ComposeResult:
        with ScrollableContainer(id="settings-container"):
            yield Label("[bold cyan]--- General Settings ---[/]")
            with Horizontal():
                yield Label("Scanner Threads:", classes="setting-label")
                yield Input(
                    value=str(self.config_manager.get("scanner_threads", 4)),
                    id="scanner_threads",
                    type="integer",
                    classes="setting-input",
                )
            with Horizontal():
                yield Label("Max File Size (MB):", classes="setting-label")
                yield Input(
                    value=str(self.config_manager.get("max_file_size_mb", 100)),
                    id="max_file_size_mb",
                    type="number",
                    classes="setting-input",
                )
            with Horizontal():
                yield Label("YARA Timeout (sec):", classes="setting-label")
                yield Input(
                    value=str(self.config_manager.get("yara_timeout", 60)),
                    id="yara_timeout",
                    type="integer",
                    classes="setting-input",
                )

            yield Label("\n[bold cyan]--- Path Settings ---[/]")
            with Horizontal():
                yield Label("Rules Directory:", classes="setting-label")
                yield Input(value=self.config_manager.get("rules_dir", ""), id="rules_dir", classes="setting-input")

            yield Label("\n[bold cyan]--- Email Reporting ---[/]")
            with Horizontal():
                yield Checkbox(
                    "Enable Email Reporting:",
                    value=self.config_manager.get("email_reporting.enabled", False),
                    id="email_enabled",
                )
            with Horizontal():
                yield Label("SMTP Server:", classes="setting-label")
                yield Input(value=self.config_manager.get("email_reporting.smtp_server", ""), id="smtp_server",
                            classes="setting-input")
            with Horizontal():
                yield Label("SMTP Port:", classes="setting-label")
                yield Input(value=str(self.config_manager.get("email_reporting.smtp_port", 587)), id="smtp_port",
                            type="integer", classes="setting-input")
            with Horizontal():
                yield Label("SMTP Username:", classes="setting-label")
                yield Input(value=self.config_manager.get("email_reporting.smtp_username", ""), id="smtp_username",
                            classes="setting-input")
            with Horizontal():
                yield Label("SMTP Password:", classes="setting-label")
                yield Input(value=self.config_manager.get("email_reporting.smtp_password", ""), id="smtp_password",
                            password=True, classes="setting-input")
            with Horizontal():
                yield Label("Sender Email:", classes="setting-label")
                yield Input(value=self.config_manager.get("email_reporting.sender_email", ""), id="sender_email",
                            classes="setting-input")
            with Horizontal():
                yield Label("Recipients (comma sep):", classes="setting-label")
                recipients = ", ".join(self.config_manager.get("email_reporting.recipient_emails", []))
                yield Input(value=recipients, id="recipient_emails", classes="setting-input")
            with Horizontal():
                yield Checkbox(
                    "Use TLS:",
                    value=self.config_manager.get("email_reporting.use_tls", True),
                    id="use_tls",
                )

            with Horizontal(id="settings-buttons"):
                yield Button("Save", id="btn-settings-save", variant="primary")
                yield Button("Cancel", id="btn-settings-cancel", variant="error")

    def _save_settings(self) -> None:
        try:

            self.config_manager.set("scanner_threads", int(self.query_one("#scanner_threads", Input).value))
            self.config_manager.set("max_file_size_mb", float(self.query_one("#max_file_size_mb", Input).value))
            self.config_manager.set("yara_timeout", int(self.query_one("#yara_timeout", Input).value))

            self.config_manager.set("rules_dir", self.query_one("#rules_dir", Input).value)

            self.config_manager.set("email_reporting.enabled", self.query_one("#email_enabled", Checkbox).value)
            self.config_manager.set("email_reporting.smtp_server", self.query_one("#smtp_server", Input).value)
            self.config_manager.set("email_reporting.smtp_port", int(self.query_one("#smtp_port", Input).value))
            self.config_manager.set("email_reporting.smtp_username", self.query_one("#smtp_username", Input).value)
            self.config_manager.set("email_reporting.smtp_password", self.query_one("#smtp_password", Input).value)
            self.config_manager.set("email_reporting.sender_email", self.query_one("#sender_email", Input).value)
            recipients_str = self.query_one("#recipient_emails", Input).value
            recipients_list = [email.strip() for email in recipients_str.split(',') if email.strip()]
            self.config_manager.set("email_reporting.recipient_emails", recipients_list)
            self.config_manager.set("email_reporting.use_tls", self.query_one("#use_tls", Checkbox).value)

            self.config_manager.save_config()
            self.notify("Settings saved successfully.", title="Success")
            self.dismiss(True)

        except ValueError as e:
            self.notify(f"Invalid input: {e}", title="Error Saving Settings", severity="error")
        except Exception as e:
            self.notify(f"An error occurred: {e}", title="Error Saving Settings", severity="error")
            logger.error(f"Error saving settings: {e}")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-settings-save":
            self._save_settings()
        elif event.button.id == "btn-settings-cancel":
            self.dismiss(False)


class UpdateRulesModal(Screen):

    DEFAULT_CSS = """
    UpdateRulesModal {
        align: center middle;
    }
    #update-rules-modal {
        width: 70;
        height: 10;
        border: solid $accent;
        background: $surface;
    }
    #update-rules-modal > Vertical { width: 1fr; height: 1fr; }
    #update-rules-path-input { width: 1fr; margin: 1 0; }
    #update-rules-modal-buttons { width: 1fr; height: auto; margin-top: 1; }
    #update-rules-modal-buttons > Button { width: 1fr; }
    """

    def compose(self) -> ComposeResult:
        yield Container(
            Vertical(
                Label("[bold cyan]Enter Path to New YARA Rules (Directory or .zip)[/bold cyan]"),
                Input(
                    id="update-rules-path-input",
                    placeholder="/path/to/new_rules_directory_or_zip",
                ),
                Horizontal(
                    Button("Update", id="btn-update-confirm", variant="primary"),
                    Button("Cancel", id="btn-update-cancel", variant="error"),
                    id="update-rules-modal-buttons",
                ),
                id="update-rules-modal-content",
            ),
            id="update-rules-modal",
        )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-update-confirm":
            path_input = self.query_one("#update-rules-path-input", Input)
            path = path_input.value
            if path:
                local_path = Path(path)
                if local_path.exists():
                    self.dismiss(f"file://{local_path.absolute()}")
                else:
                    self.notify("Path does not exist!", title="Update Error", severity="error")
            else:
                self.dismiss(None)
        elif event.button.id == "btn-update-cancel":
            self.dismiss(None)


class SchedulerTableWidget(Static):

    def __init__(self, scheduler_adapter: SchedulerAdapter):
        super().__init__()
        self.scheduler_adapter = scheduler_adapter
        self.job_items: List[Dict[str, Any]] = []

    def compose(self) -> ComposeResult:
        table = DataTable(id="scheduler-table")
        table.add_columns("ID/Name", "Function", "Trigger", "Next Run")
        yield table
        yield Label("\n[dim]Select a job and press 'Delete' to remove.[/dim]", id="scheduler-help-text")

    async def refresh_list(self) -> None:
        try:
            items = await self.scheduler_adapter.list_jobs()
            self.job_items = items
            table = self.query_one("#scheduler-table", DataTable)
            cursor_row = table.cursor_row
            current_keys = {row[0] for row in table.rows.values()}

            table.clear()

            for item in items:
                trigger_str = item.get("trigger", "Unknown")
                if len(trigger_str) > 50:
                    trigger_str = trigger_str[:47] + "..."

                table.add_row(
                    item.get("id", ""),
                    item.get("func_name", "Unknown"),
                    trigger_str,
                    item.get("next_run_time", "N/A"),
                    key=item.get("id")
                )

            new_keys = {row[0] for row in table.rows.values()}
            if current_keys.intersection(new_keys) and 0 <= cursor_row < len(table.rows):
                table.cursor_row = cursor_row
            elif table.row_count > 0:
                table.cursor_row = 0


        except Exception as e:
            logger.error(f"Error refreshing scheduler list: {e}")

class AddScheduleModal(Screen):

    DEFAULT_CSS = """
    AddScheduleModal {
        align: center middle;
    }
    #add-schedule-modal {
        width: 80;
        height: 25;
        border: thick $accent;
        background: $surface;
        padding: 1 2;
    }
    #add-schedule-modal > VerticalScroll {
        width: 1fr;
        height: 1fr;
        border: none;
        scrollbar-gutter: stable;
    }
    #add-schedule-modal .input-row {
        height: auto;
        margin-bottom: 1;
    }
    #add-schedule-modal Label {
        width: 25;
        margin-right: 1;
        text-align: right;
    }
    #add-schedule-modal Input, #add-schedule-modal Select {
        width: 1fr;
    }
    #add-schedule-modal RadioSet {
        height: auto;
        margin-bottom: 1;
    }
    #add-schedule-modal #interval-inputs, #add-schedule-modal #cron-inputs {
        display: none; 
        margin-left: 4;
        height: auto;
    }
    #add-schedule-modal #interval-inputs.-active, #add-schedule-modal #cron-inputs.-active {
        display: block;
    }
    #add-schedule-modal #schedule-buttons {
        margin-top: 1;
        width: 1fr;
        height: auto;
    }
    #add-schedule-modal #schedule-buttons > Button {
        width: 1fr;
        margin: 0 1;
    }
    """

    def compose(self) -> ComposeResult:
        with Container(id="add-schedule-modal"):
            with VerticalScroll():
                yield Label("[bold cyan]--- Add New Scheduled Task ---[/]")
                with Horizontal(classes="input-row"):
                    yield Label("Task Name (ID):", classes="setting-label")
                    yield Input(placeholder="e.g., daily_scan_docs", id="task_name", classes="setting-input")
                with Horizontal(classes="input-row"):
                    yield Label("Task Type:", classes="setting-label")
                    yield Select(
                        [("Scan Path", "scan"), ("Update Rules", "update-rules")],
                        prompt="Select task...",
                        id="task_type",
                        classes="setting-input"
                    )
                with Horizontal(classes="input-row"):
                    yield Label("Task Args (JSON List):", classes="setting-label")
                    yield Input(placeholder='e.g., ["/path/to/scan"] or null', id="task_args", classes="setting-input")
                with Horizontal(classes="input-row"):
                    yield Label("Task Kwargs (JSON Dict):", classes="setting-label")
                    yield Input(placeholder='e.g., {"quarantine_matches": true} or null', id="task_kwargs",
                                classes="setting-input")

                yield Label("\n[bold cyan]--- Trigger ---[/]")
                yield RadioSet(
                    RadioButton("Interval", id="trigger_interval"),
                    RadioButton("Cron", id="trigger_cron"),
                    id="trigger_type"
                )
                with Vertical(id="interval-inputs"):
                    with Horizontal(classes="input-row"):
                        yield Label("Seconds Between Runs:", classes="setting-label")
                        yield Input(placeholder="e.g., 3600", type="integer", id="interval_seconds",
                                    classes="setting-input")
                with Vertical(id="cron-inputs"):
                    with Horizontal(classes="input-row"):
                        yield Label("Cron Expression (6 fields):", classes="setting-label")
                        yield Input(placeholder="sec min hour day month day_of_week (* * * * * *)",
                                    id="cron_expression", classes="setting-input")

            with Horizontal(id="schedule-buttons"):
                yield Button("Add Task", id="btn-schedule-add", variant="primary")
                yield Button("Cancel", id="btn-schedule-cancel", variant="error")

    @on(RadioSet.Changed, "#trigger_type")
    def update_trigger_inputs(self, event: RadioSet.Changed) -> None:
        interval_inputs = self.query_one("#interval-inputs", Vertical)
        cron_inputs = self.query_one("#cron-inputs", Vertical)
        if event.pressed.id == "trigger_interval":
            interval_inputs.add_class("-active")
            cron_inputs.remove_class("-active")
        elif event.pressed.id == "trigger_cron":
            cron_inputs.add_class("-active")
            interval_inputs.remove_class("-active")

    def _get_task_data(self) -> Optional[Dict[str, Any]]:
        task_data = {}
        try:
            task_data["name"] = self.query_one("#task_name", Input).value
            if not task_data["name"]:
                raise ValueError("Task Name (ID) is required.")

            task_data["task_type"] = self.query_one("#task_type", Select).value
            if not task_data["task_type"]:
                raise ValueError("Task Type must be selected.")

            args_str = self.query_one("#task_args", Input).value.strip()
            task_data["args"] = json.loads(args_str) if args_str else []
            if not isinstance(task_data["args"], list):
                raise ValueError("Task Args must be a valid JSON list (e.g., [\"value\"]) or empty.")

            kwargs_str = self.query_one("#task_kwargs", Input).value.strip()
            task_data["kwargs"] = json.loads(kwargs_str) if kwargs_str else {}
            if not isinstance(task_data["kwargs"], dict):
                raise ValueError("Task Kwargs must be a valid JSON dictionary (e.g., {\"key\": true}) or empty.")

            trigger_type_set = self.query_one("#trigger_type", RadioSet)
            if trigger_type_set.pressed_button is None:
                raise ValueError("Trigger Type (Interval or Cron) must be selected.")
            task_data["trigger_type"] = trigger_type_set.pressed_button.id.split('_')[1]

            task_data["trigger_args"] = {}
            if task_data["trigger_type"] == "interval":
                seconds = self.query_one("#interval_seconds", Input).value
                if not seconds or not seconds.isdigit():
                    raise ValueError("Interval Seconds must be a positive integer.")
                task_data["trigger_args"]["seconds"] = int(seconds)
            elif task_data["trigger_type"] == "cron":
                expr = self.query_one("#cron_expression", Input).value
                if not expr or len(expr.split()) != 6:
                    raise ValueError("Cron Expression must have 6 fields separated by spaces.")
                fields = expr.split()
                task_data["trigger_args"] = {
                    "second": fields[0], "minute": fields[1], "hour": fields[2],
                    "day": fields[3], "month": fields[4], "day_of_week": fields[5],
                }
            return task_data

        except json.JSONDecodeError as e:
            self.notify(f"Invalid JSON input: {e}", title="Input Error", severity="error")
            return None
        except ValueError as e:
            self.notify(str(e), title="Input Error", severity="error")
            return None
        except Exception as e:
            logger.error(f"Error collecting schedule data: {e}")
            self.notify(f"An unexpected error occurred: {e}", title="Error", severity="error")
            return None

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-schedule-add":
            task_data = self._get_task_data()
            if task_data:
                self.dismiss(task_data)
        elif event.button.id == "btn-schedule-cancel":
            self.dismiss(None)


class FalconDefenderApp:

    def __init__(self):
        self.config_manager = ConfigManager()
        self.yara_manager = YaraManager(self.config_manager)
        self.quarantine_manager = QuarantineManager(self.config_manager)

        self.scheduler_manager = SchedulerManager()
        self.scanner = Scanner(self.config_manager, self.yara_manager, self.quarantine_manager)

        self.updater = Updater(Path(self.config_manager.get("rules_dir")), self.config_manager)
        self.report_manager = ReportManager(Path(self.config_manager.get("report_dir")), self.config_manager)

        scheduled_tasks.register_instance("scanner", self.scanner)
        scheduled_tasks.register_instance("updater", self.updater)
        scheduled_tasks.register_instance("yara_manager", self.yara_manager)
        scheduled_tasks.register_instance("report_manager", self.report_manager)

        self.event_queue: asyncio.Queue = asyncio.Queue()

        self.scanner_adapter = ScannerAdapter(self.scanner, self.event_queue)
        self.scheduler_adapter = SchedulerAdapter(self.scheduler_manager, self.scanner, self.updater, self.event_queue)

        self.quarantine_adapter = QuarantineAdapter(self.quarantine_manager, self.event_queue)
        self.updater_adapter = UpdaterAdapter(self.updater, self.yara_manager, self.event_queue)

        self.event_handler = TUIEventHandler()
        self.last_scan_path: Optional[str] = None


class MainApp(App):
    DEFAULT_KEY_LEVEL = "app"
    TITLE = "Falcon Defender"

    BINDINGS = [
        Binding("s", "start_scan", "Start Scan", show=True),
        Binding("p", "pause_scan", "Pause", show=True),
        Binding("r", "resume_scan", "Resume", show=True),
        Binding("c", "cancel_scan", "Cancel", show=True),
        Binding("u", "update_rules", "Update Rules", show=True),
        Binding("l", "show_logs", "Logs", show=True),
        Binding("d", "export_report", "Export", show=True),
        Binding("h", "refresh_ui", "Refresh", show=True),
        Binding("q", "quit", "Quit", show=True),
        Binding("ctrl+s", "show_settings", "Settings", show=True),
        Binding("ctrl+n", "add_scheduled_task", "Add Schedule (Ctrl+N)", show=True),
        Binding("delete", "remove_scheduled_job", "Remove Job", show=False),
    ]

    CSS = """
    Screen {
        layout: vertical;
    }

    #header-section {
        height: 10;
        border: solid $accent;
        background: $panel;
    }

    #main-content {
        height: 1fr;
        layout: horizontal;
    }

    #left-pane {
        width: 1fr;
        border: solid $accent;
        background: $panel;
    }

    #right-pane {
        width: 2fr;
        border: solid $accent;
        background: $panel;
    }

    #bottom-tabs {
        height: 3;
        border: solid $accent;
        background: $panel;
    }

    #control-panel {
        height: 3;
        border: solid $accent;
        background: $panel;
    }

    #control-panel > Horizontal {
        width: 1fr;
        height: 1fr;
    }

    Button {
        width: 1fr;
    }
    .-hidden {
        display: none;
    }
    """

    def __init__(self, tui_instance: FalconDefenderApp):
        super().__init__()
        self.tui = tui_instance
        self.logo_widget: Optional[AnimatedLogo] = None
        self.stats_widget: Optional[ScanStatsPanel] = None
        self.matches_widget: Optional[MatchesTableWidget] = None
        self.log_widget: Optional[LogViewerWidget] = None
        self.scheduler_widget: Optional[SchedulerTableWidget] = None

    def compose(self) -> ComposeResult:
        self.logo_widget = AnimatedLogo()
        self.stats_widget = ScanStatsPanel()
        self.matches_widget = MatchesTableWidget()
        self.log_widget = LogViewerWidget()
        self.scheduler_widget = SchedulerTableWidget(self.tui.scheduler_adapter)

        yield Header()

        yield Container(
            self.logo_widget,
            id="header-section",
        )

        yield Container(
            Container(
                self.stats_widget,
                id="left-pane",
            ),
            Container(
                Label("[bold]Detected Matches[/bold]"),
                self.matches_widget,
                id="right-pane",
            ),
            id="main-content",
        )

        yield Tabs(
            Tab("Logs", id="log-tab"),
            Tab("Scheduler", id="scheduler-tab"),
            id="bottom-tabs"
        )

        yield Container(
            TabPane("Logs Content", self.log_widget, id="log-pane"),
            TabPane("Scheduler Tasks", self.scheduler_widget, id="scheduler-pane", classes="-hidden"),
        )

        yield Container(
            Horizontal(
                Button("Start Scan (S)", id="btn-start", variant="primary"),
                Button("Pause (P)", id="btn-pause", variant="warning"),
                Button("Resume (R)", id="btn-resume", variant="warning"),
                Button("Cancel (C)", id="btn-cancel", variant="error"),
                Button("Update Rules (U)", id="btn-update", variant="primary"),
                Button("Quit (Q)", id="btn-quit", variant="error"),
            ),
            id="control-panel",
        )

        yield Footer()

    async def on_mount(self) -> None:
        self.log_widget.add_log("FalconDefender TUI started", "INFO")
        self.set_interval(1, self.logo_widget.refresh)
        asyncio.create_task(self._watch_events())

    async def _watch_events(self) -> None:
        while True:
            try:
                event = await asyncio.wait_for(self.tui.event_queue.get(), timeout=0.1)

                if event.get("type") == "progress":
                    data = event.get("data", {})
                    self.stats_widget.scanned = data.get("scanned", 0)
                    self.stats_widget.total = data.get("total", 1)
                    self.stats_widget.files_per_sec = data.get("files_per_sec", 0.0)
                    self.stats_widget.elapsed = data.get("elapsed", 0.0)

                elif event.get("type") == "match":
                    data = event.get("data", {})
                    self.matches_widget.add_match(data)
                    self.stats_widget.matches += 1
                    self.log_widget.add_log(
                        "Threat detected: " + data.get("file", "unknown") + " (" + data.get("rule", "unknown") + ")",
                        "WARNING"
                    )

                elif event.get("type") == "info":
                    msg = event.get("data", {}).get("msg", "")
                    self.log_widget.add_log(msg, "INFO")

                elif event.get("type") == "error":
                    msg = event.get("data", {}).get("msg", "")
                    self.log_widget.add_log(msg, "ERROR")
                    self.logo_widget.state = ScanState.ERROR.value

                elif event.get("type") == "done":
                    msg = event.get("data", {}).get("msg", "")
                    self.log_widget.add_log(msg, "INFO")
                    self.logo_widget.state = ScanState.IDLE.value

            except asyncio.TimeoutError:
                continue
            except Exception as e:
                logger.error(f"Error watching events: {e}")

    def action_show_settings(self) -> None:
        def settings_callback(saved: bool) -> None:
            if saved:
                self.log_widget.add_log("Settings saved. Some changes may require restart.", "INFO")
            else:
                self.log_widget.add_log("Settings cancelled.", "INFO")

        self.push_screen(SettingsScreen(self.tui.config_manager), callback=settings_callback)

    def action_refresh_ui(self) -> None:
        self.log_widget.add_log("Refreshing UI...", "INFO")
        asyncio.create_task(self._do_refresh())

    async def _do_refresh(self) -> None:
        try:

            loop = asyncio.get_event_loop()
            changed = await loop.run_in_executor(
                None,
                self.tui.yara_manager.check_for_updates_and_reload
            )
            if changed:
                self.log_widget.add_log("YARA rules reloaded after check.", "INFO")
            else:
                self.log_widget.add_log("YARA rules are up-to-date.", "INFO")

        except Exception as e:
            logger.error(f"Error during refresh: {e}")
            self.log_widget.add_log(f"Refresh error: {e}", "ERROR")
        finally:
            self.log_widget.add_log("Refresh complete.", "INFO")

    async def action_remove_scheduled_job(self) -> None:
        if self.query_one(Tabs).active != "scheduler-tab":
            return

        table = self.query_one("#scheduler-table", DataTable)
        if not table.is_valid_row_index(table.cursor_row):
            self.notify("No job selected.", title="Remove Job", severity="warning")
            return
        try:
            row_data = table.get_row_at(table.cursor_row)
            job_id = row_data[0]
            if not job_id:
                raise ValueError("Selected row has an empty Job ID.")
        except IndexError:
            logger.error(f"Could not get row data for cursor row {table.cursor_row}")
            self.notify("Could not retrieve data for selected row.", title="Error", severity="error")
            return
        except Exception as e:
            logger.error(f"Could not get job ID for removal: {e}")
            self.notify(f"Could not determine selected Job ID: {e}", title="Error", severity="error")
            raise

        confirm_message = f"Permanently remove scheduled job '{job_id}'?"

        def confirm_callback(confirmed: bool) -> None:
            if confirmed:
                self.log_widget.add_log(f"Removing scheduled job: {job_id}", "INFO")
                asyncio.create_task(self._do_remove_job(job_id))

        self.push_screen(ConfirmActionModal(confirm_message), callback=confirm_callback)

    async def _do_remove_job(self, job_id: str) -> None:
        success = await self.tui.scheduler_adapter.remove_job(job_id)
        if success:
            await self.scheduler_widget.refresh_list()


    def action_add_scheduled_task(self) -> None:

        def on_add_schedule_confirm(task_data: Optional[Dict[str, Any]]) -> None:
            if task_data:
                self.log_widget.add_log(f"Attempting to add scheduled task: {task_data['name']}", "INFO")
                asyncio.create_task(self._do_add_schedule(task_data))
            else:
                self.log_widget.add_log("Add schedule cancelled.", "INFO")

        self.push_screen(AddScheduleModal(), callback=on_add_schedule_confirm)


    async def _do_add_schedule(self, task_data: Dict[str, Any]) -> None:
        success = await self.tui.scheduler_adapter.add_job(task_data)
        if success:
            if self.query_one(Tabs).active == "scheduler-tab":
                await self.scheduler_widget.refresh_list()



    def action_start_scan(self) -> None:

        def on_scan_confirm(result: tuple) -> None:
            path_str, quarantine_mode = result

            if not path_str:
                self.log_widget.add_log("Scan cancelled by user.", "INFO")
                return

            try:
                scan_path = Path(path_str)
                if not scan_path.exists():
                    self.log_widget.add_log(f"Error: Path does not exist: {path_str}", "ERROR")
                    self.notify("Path does not exist!", title="Scan Error", severity="error")
                    return
                elif not scan_path.is_dir() and not scan_path.is_file():
                    self.log_widget.add_log(f"Error: Path is not a file or directory: {path_str}", "ERROR")
                    self.notify("Path is not a file or directory!", title="Scan Error", severity="error")
                    return
            except Exception as e:
                self.log_widget.add_log(f"Error validating path '{path_str}': {e}", "ERROR")
                self.notify(f"Invalid path: {e}", title="Scan Error", severity="error")
                return

            self.tui.last_scan_path = path_str
            self.logo_widget.state = ScanState.SCANNING.value
            self.matches_widget.clear_matches()
            self.stats_widget.scanned = 0
            self.stats_widget.total = 1
            self.stats_widget.matches = 0
            self.log_widget.add_log(f"Starting scan: {path_str} (Quarantine: {quarantine_mode})", "INFO")
            asyncio.create_task(

                self.tui.scanner_adapter.start_scan(str(scan_path), quarantine_matches=quarantine_mode)
            )

        self.push_screen(ScanPathInputModal(), callback=on_scan_confirm)

    @on(Tabs.TabActivated, "#bottom-tabs")
    def on_tab_activated(self, event: Tabs.TabActivated) -> None:

        active_pane_id = None
        if event.tab.id == "log-tab":
            active_pane_id = "log-pane"
        elif event.tab.id == "scheduler-tab":
            active_pane_id = "scheduler-pane"
            asyncio.create_task(self.scheduler_widget.refresh_list())

        for pane in self.query(TabPane):
            if pane.id == active_pane_id:
                pane.remove_class("-hidden")
            else:
                pane.add_class("-hidden")

    def action_pause_scan(self) -> None:
        asyncio.create_task(self.tui.scanner_adapter.pause())
        self.logo_widget.state = ScanState.PAUSED.value

    def action_resume_scan(self) -> None:
        asyncio.create_task(self.tui.scanner_adapter.resume())
        self.logo_widget.state = ScanState.SCANNING.value

    def action_cancel_scan(self) -> None:
        asyncio.create_task(self.tui.scanner_adapter.cancel())
        self.logo_widget.state = ScanState.IDLE.value

    def action_update_rules(self) -> None:

        def on_update_path_confirm(source_uri: Optional[str]) -> None:
            if source_uri:
                self.logo_widget.state = ScanState.UPDATING.value
                self.log_widget.add_log(f"Starting rule update from {source_uri}...", "INFO")
                asyncio.create_task(self._do_update_rules(source_uri))
            else:
                self.log_widget.add_log("Rule update cancelled.", "INFO")

        self.push_screen(UpdateRulesModal(), callback=on_update_path_confirm)

    async def _do_update_rules(self, source_uri: str) -> None:
        try:
            result = await self.tui.updater_adapter.update_rules(source_uri)
            if not result:
                self.log_widget.add_log("Rule update failed", "ERROR")
                self.notify("Rule update failed. Check logs.", title="Update Error", severity="error")
        except Exception as e:
            logger.error(f"Error during rule update task: {e}")
            self.log_widget.add_log(f"Rule update error: {e}", "ERROR")
            self.notify(f"Update error: {e}", title="Update Error", severity="error")
        finally:
            current_state = await self.tui.scanner_adapter.status()
            if current_state["state"] == ScanState.UPDATING.value:
                self.logo_widget.state = ScanState.IDLE.value

    def action_show_logs(self) -> None:
        self.query_one(Tabs).active = "log-tab"

    def action_export_report(self) -> None:

        def on_export_confirm(filename: Optional[str]) -> None:
            if filename:
                self.log_widget.add_log(f"Exporting matches to {filename}...", "INFO")
                asyncio.create_task(self._do_export_and_email(filename))
            else:
                self.log_widget.add_log("Export cancelled.", "INFO")

        self.push_screen(ExportReportModal(), callback=on_export_confirm)

    async def _do_export_and_email(self, filename: str) -> None:
        try:
            current_matches = self.matches_widget.matches
            if not current_matches:
                self.log_widget.add_log("No matches to export.", "WARNING")
                self.notify("No matches found to export.", title="Export Info", severity="warning")
                return

            formatted_matches = []
            for match in current_matches:
                match_info = match.get("match_info", {})
                formatted_matches.append({
                    "file_path": match.get("file"),
                    "rule_name": match.get("rule"),
                    "description": match_info.get("description", "N/A"),
                    "confidence": match_info.get("confidence", "N/A"),
                    "action": match_info.get("action", "Detected (TUI Export)"),

                    "namespace": match_info.get("namespace"),
                    "tags": match_info.get("tags"),
                    "meta": match_info.get("meta"),
                    "strings": match_info.get("strings"),
                })

            export_report_data = {
                "report_generated_at": datetime.now().isoformat(),
                "source": "TUI Export",

                "scanned_path": self.tui.last_scan_path or "N/A (Path not available from TUI)",
                "total_files_scanned": "N/A (TUI Export)",

                "total_matches_in_report": len(formatted_matches),
                "matches": formatted_matches
            }

            loop = asyncio.get_event_loop()
            file_path = await loop.run_in_executor(
                None,
                self.tui.report_manager.save_data_as_json,
                export_report_data,
                filename
            )

            if file_path:
                self.log_widget.add_log(f"Matches exported successfully to {file_path}", "INFO")
                self.notify(f"Report saved to {file_path}", title="Export Successful")

                email_success = await loop.run_in_executor(
                    None,
                    self.tui.report_manager.send_email_report,
                    export_report_data
                )

                if email_success:
                    self.log_widget.add_log("Exported report sent via email.", "INFO")
                else:
                    self.log_widget.add_log("Failed to send email report. Check logs/config.", "ERROR")
                    self.notify("Failed to send email report.", title="Email Error", severity="error")
            else:
                self.log_widget.add_log(f"Failed to save export file {filename}.", "ERROR")
                self.notify(f"Failed to save {filename}", title="Export Error", severity="error")

        except Exception as e:
            logger.error(f"Error during export/email: {e}")
        self.log_widget.add_log(f"Export/Email Error: {e}", "ERROR")
        self.notify(f"An error occurred: {e}", title="Export Error", severity="error")

    def action_quit(self) -> None:
        self.exit()

def run_tui() -> None:
    try:
        tui = FalconDefenderApp()
        app = MainApp(tui)
        app.run()
    except KeyboardInterrupt:
        print("\nFalconDefender TUI terminated by user.")
    except Exception as e:
        logger.error(f"Failed to start TUI: {e}")
        print(f"Error: Failed to start TUI. {e}")
        print("Falling back to standard CLI mode.")
