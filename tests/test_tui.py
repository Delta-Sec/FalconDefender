'''
Tests for the FalconDefender TUI application.
'''

import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

from textual.app import App
from textual.widgets import DataTable, Input, Tabs

# Assuming falcon.app is structured to allow these imports
from falcon.app import MainApp, ScanPathInputModal, ConfirmActionModal
from falcon.tui_integration import ScanState
from falcon.config import ConfigManager
from falcon.yara_manager import YaraManager
from falcon.scanner import Scanner
from falcon.quarantine import QuarantineManager
from falcon.updater import Updater
from falcon.tui_integration import ScannerAdapter, QuarantineAdapter, UpdaterAdapter


class MockFalconDefenderApp:
    """A mock for the FalconDefenderApp logic class."""
    def __init__(self):
        self.config_manager = MagicMock(spec=ConfigManager)
        self.config_manager.get.return_value = "/tmp/rules"
        self.yara_manager = MagicMock(spec=YaraManager)
        self.scanner = MagicMock(spec=Scanner)
        self.quarantine_manager = MagicMock(spec=QuarantineManager)
        self.updater = MagicMock(spec=Updater)
        
        self.event_queue = asyncio.Queue()
        self.scanner_adapter = ScannerAdapter(self.scanner, self.event_queue)
        self.quarantine_adapter = QuarantineAdapter(self.quarantine_manager, self.event_queue)
        self.updater_adapter = UpdaterAdapter(self.updater, self.yara_manager, self.event_queue)
        self.last_scan_path = None


@pytest.fixture
def mock_tui_logic():
    """Fixture to provide a mocked TUI logic instance."""
    return MockFalconDefenderApp()


@pytest.mark.asyncio
async def test_tui_start_scan_modal(mock_tui_logic):
    """Test that the scan modal opens and triggers a scan."""
    app = MainApp(mock_tui_logic)
    mock_tui_logic.scanner_adapter.start_scan = AsyncMock()

    async with app.run_test() as driver:
        await driver.press("s")
        assert isinstance(app.screen, ScanPathInputModal)

        modal = app.screen
        path_input = modal.query_one("#scan-path-input", Input)
        path_input.value = "/test/path"
        await driver.click("#btn-scan-confirm")

        assert not isinstance(app.screen, ScanPathInputModal)
        mock_tui_logic.scanner_adapter.start_scan.assert_awaited_once_with("/test/path")


@pytest.mark.asyncio
async def test_tui_scan_actions(mock_tui_logic):
    """Test pause, resume, and cancel scan actions."""
    app = MainApp(mock_tui_logic)
    mock_tui_logic.scanner_adapter.pause = AsyncMock()
    mock_tui_logic.scanner_adapter.resume = AsyncMock()
    mock_tui_logic.scanner_adapter.cancel = AsyncMock()

    async with app.run_test() as driver:
        app.logo_widget.state = ScanState.SCANNING.value

        await driver.press("p")
        mock_tui_logic.scanner_adapter.pause.assert_awaited_once()
        assert app.logo_widget.state == ScanState.PAUSED.value

        await driver.press("r")
        mock_tui_logic.scanner_adapter.resume.assert_awaited_once()
        assert app.logo_widget.state == ScanState.SCANNING.value

        await driver.press("c")
        mock_tui_logic.scanner_adapter.cancel.assert_awaited_once()
        assert app.logo_widget.state == ScanState.IDLE.value


@pytest.mark.asyncio
async def test_tui_update_rules(mock_tui_logic):
    """Test the rule update functionality."""
    app = MainApp(mock_tui_logic)
    mock_tui_logic.updater_adapter.update_rules = AsyncMock(return_value=True)

    async with app.run_test() as driver:
        await driver.press("u")
        await asyncio.sleep(0.1)
        mock_tui_logic.updater_adapter.update_rules.assert_awaited_once()


@pytest.mark.asyncio
async def test_tui_match_event_display(mock_tui_logic):
    """Test that a match event updates the UI correctly."""
    app = MainApp(mock_tui_logic)
    
    async with app.run_test() as driver:
        match_event = {
            "type": "match",
            "data": {
                "id": "123", "file": "file.txt", "rule": "rule1", "severity": "high", "timestamp": "now"
            }
        }
        await mock_tui_logic.event_queue.put(match_event)
        await asyncio.sleep(0.2)  # Allow event processing

        table = app.query_one("#matches-table", DataTable)
        assert table.row_count == 1
        assert app.stats_widget.matches == 1


@pytest.mark.asyncio
async def test_tui_quit_action(mock_tui_logic):
    """Test the quit action."""
    app = MainApp(mock_tui_logic)
    async with app.run_test() as driver:
        with patch.object(app, 'exit') as mock_exit:
            await driver.press("q")
            mock_exit.assert_called_once()

