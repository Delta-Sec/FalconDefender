import asyncio
import logging
from pathlib import Path
from typing import Optional, Dict, Any, List, Callable
from datetime import datetime
from enum import Enum

from . import scheduled_tasks
from .scanner import Scanner
from .scheduler import SchedulerManager
from .quarantine import QuarantineManager
from .updater import Updater
from .yara_manager import YaraManager

logger = logging.getLogger(__name__)


class ScanState(Enum):
    IDLE = "Idle"
    SCANNING = "Scanning"
    PAUSED = "Paused"
    UPDATING = "Updating"
    ERROR = "Error"


class QuarantineAdapter:

    def __init__(self, quarantine_manager: QuarantineManager, event_queue: asyncio.Queue):
        self.quarantine_manager = quarantine_manager
        self.event_queue = event_queue

    async def list_quarantined(self) -> List[Dict[str, Any]]:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            None,
            self.quarantine_manager.list_quarantined_files
        )

    async def restore_file(self, record_id: int) -> bool:
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(
            None,
            self.quarantine_manager.restore_file,
            record_id
        )
        
        if result:
            await self.event_queue.put({
                "type": "info",
                "data": {"msg": f"File {record_id} restored successfully"}
            })
        else:
            await self.event_queue.put({
                "type": "error",
                "data": {"msg": f"Failed to restore file {record_id}"}
            })
        
        return result

    async def delete_file(self, record_id: int) -> bool:
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(
            None,
            self.quarantine_manager.delete_quarantined_file,
            record_id
        )
        
        if result:
            await self.event_queue.put({
                "type": "info",
                "data": {"msg": f"File {record_id} deleted successfully"}
            })
        else:
            await self.event_queue.put({
                "type": "error",
                "data": {"msg": f"Failed to delete file {record_id}"}
            })
        
        return result


class UpdaterAdapter:

    def __init__(self, updater: Updater, yara_manager: YaraManager, event_queue: asyncio.Queue):
        self.updater = updater
        self.yara_manager = yara_manager
        self.event_queue = event_queue

    async def update_rules(self, source_url: str, expected_checksum: Optional[str] = None) -> bool:
        await self.event_queue.put({
            "type": "info",
            "data": {"msg": f"Starting rule update from {source_url}"}
        })

        loop = asyncio.get_event_loop()
        try:
            result = await loop.run_in_executor(
                None,
                self.updater.update_rules,
                source_url,
                expected_checksum
            )

            if result:
                await loop.run_in_executor(
                    None,
                    self.yara_manager.load_rules,
                    True
                )
                
                await self.event_queue.put({
                    "type": "info",
                    "data": {"msg": "Rules updated and reloaded successfully"}
                })
                return True
            else:
                await self.event_queue.put({
                    "type": "error",
                    "data": {"msg": "Failed to update rules"}
                })
                return False

        except Exception as e:
            logger.error(f"Error updating rules: {e}")
            await self.event_queue.put({
                "type": "error",
                "data": {"msg": f"Rule update error: {str(e)}"}
            })
            return False

    async def update_program(self, source_url: str, expected_checksum: Optional[str] = None) -> bool:

        await self.event_queue.put({
            "type": "info",
            "data": {"msg": f"Starting program update from {source_url}"}
        })

        loop = asyncio.get_event_loop()
        try:
            result = await loop.run_in_executor(
                None,
                self.updater.update_program,
                source_url,
                expected_checksum
            )

            if result:
                await self.event_queue.put({
                    "type": "info",
                    "data": {"msg": "Program update file downloaded. Check logs for instructions."}
                })
            else:
                await self.event_queue.put({
                    "type": "error",
                    "data": {"msg": "Failed to download program update"}
                })

            return result

        except Exception as e:
            logger.error(f"Error updating program: {e}")
            await self.event_queue.put({
                "type": "error",
                "data": {"msg": f"Program update error: {str(e)}"}
            })
            return False


class ScannerAdapter:

    def __init__(self, scanner: Scanner, event_queue: asyncio.Queue):
        self.scanner = scanner
        self.event_queue = event_queue
        self.state = ScanState.IDLE
        self.pause_event = asyncio.Event()
        self.cancel_event = asyncio.Event()
        self.scan_task: Optional[asyncio.Task] = None
        self.stats = {
            "scanned": 0,
            "total": 0,
            "matches": 0,
            "files_per_sec": 0.0,
            "elapsed": 0.0,
        }
        self.scan_start_time: Optional[datetime] = None

    async def start_scan(
        self,
        path: str,
        quarantine_matches: bool = False,
        incremental: bool = False
    ) -> None:
        if self.state != ScanState.IDLE:
            await self.event_queue.put({
                "type": "error",
                "data": {"msg": f"Cannot start scan: scanner is {self.state.value}"}
            })
            return

        self.state = ScanState.SCANNING
        self.pause_event.clear()
        self.cancel_event.clear()
        self.stats = {"scanned": 0, "total": 0, "matches": 0, "files_per_sec": 0.0, "elapsed": 0.0}
        self.scan_start_time = datetime.now()

        await self.event_queue.put({
            "type": "info",
            "data": {"msg": f"Starting scan of {path}"}
        })

        self.scan_task = asyncio.create_task(
            self._run_scan(Path(path), quarantine_matches, incremental)
        )

    async def _run_scan(
        self,
        path: Path,
        quarantine_matches: bool,
        incremental: bool
    ) -> None:

        try:

            self.scanner.set_event_queue(self.event_queue)

            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(
                None,
                self.scanner.scan_path,
                path,
                incremental,
                quarantine_matches
            )

            elapsed = (datetime.now() - self.scan_start_time).total_seconds()
            self.stats["elapsed"] = elapsed
            self.stats["scanned"] = result.get("total_files_scanned", 0)
            self.stats["total"] = result.get("total_files_scanned", 0)
            self.stats["matches"] = len(result.get("matches", []))

            if elapsed > 0:
                self.stats["files_per_sec"] = self.stats["scanned"] / elapsed
            else:
                self.stats["files_per_sec"] = 0.0

            for match in result.get("matches", []):
                await self.event_queue.put({
                    "type": "match",
                    "data": {
                        "id": hash(match.get("file_path", "")),
                        "file": match.get("file_path"),
                        "rule": match.get("rule_name"),
                        "severity": self._get_severity(match),
                        "sha256": match.get("file_hash", "N/A"),
                        "timestamp": datetime.now().isoformat(),
                        "match_info": match,
                    }
                })

            await self.event_queue.put({
                "type": "progress",
                "data": self.stats.copy()
            })

            await self.event_queue.put({
                "type": "done",
                "data": {"msg": f"Scan completed. Found {self.stats['matches']} threats in {elapsed:.1f}s"}
            })

            self.state = ScanState.IDLE

        except asyncio.CancelledError:
            logger.info("Scan cancelled")
            await self.event_queue.put({
                "type": "info",
                "data": {"msg": "Scan cancelled by user"}
            })
            self.state = ScanState.IDLE

        except Exception as e:
            logger.error(f"Scan error: {e}")
            await self.event_queue.put({
                "type": "error",
                "data": {"msg": f"Scan error: {str(e)}"}
            })
            self.state = ScanState.ERROR

    async def pause(self) -> None:

        if self.state == ScanState.SCANNING:
            self.state = ScanState.PAUSED
            self.pause_event.set()
            await self.event_queue.put({
                "type": "info",
                "data": {"msg": "Scan paused"}
            })

    async def resume(self) -> None:

        if self.state == ScanState.PAUSED:
            self.state = ScanState.SCANNING
            self.pause_event.clear()
            await self.event_queue.put({
                "type": "info",
                "data": {"msg": "Scan resumed"}
            })

    async def cancel(self) -> None:

        if self.state in (ScanState.SCANNING, ScanState.PAUSED):
            self.cancel_event.set()
            if self.scan_task:
                self.scan_task.cancel()
            self.state = ScanState.IDLE
            await self.event_queue.put({
                "type": "info",
                "data": {"msg": "Scan cancelled"}
            })

    def status(self) -> Dict[str, Any]:

        return {
            "state": self.state.value,
            **self.stats
        }

    @staticmethod
    def _get_severity(match: Dict[str, Any]) -> str:

        confidence = match.get("confidence", "medium")
        if isinstance(confidence, str):
            confidence = confidence.lower()
            if "high" in confidence or "critical" in confidence:
                return "high"
            elif "low" in confidence:
                return "low"
        return "medium"


class TUIEventHandler:

    def __init__(self):
        self.event_handlers: Dict[str, List[Callable]] = {}

    def register_handler(self, event_type: str, handler: Callable) -> None:

        if event_type not in self.event_handlers:
            self.event_handlers[event_type] = []
        self.event_handlers[event_type].append(handler)

    async def emit(self, event_type: str, data: Dict[str, Any]) -> None:

        if event_type in self.event_handlers:
            for handler in self.event_handlers[event_type]:
                try:
                    if asyncio.iscoroutinefunction(handler):
                        await handler(data)
                    else:
                        handler(data)
                except Exception as e:
                    logger.error(f"Error in event handler for {event_type}: {e}")


class SchedulerAdapter:

    def __init__(self, scheduler_manager: SchedulerManager, scanner: Scanner, updater: Updater, event_queue: asyncio.Queue):
        self.scheduler_manager = scheduler_manager
        self.scanner = scanner
        self.updater = updater
        self.event_queue = event_queue

    async def list_jobs(self) -> List[Dict[str, Any]]:

        loop = asyncio.get_event_loop()
        try:
            jobs = await loop.run_in_executor(None, self.scheduler_manager.get_jobs)
            job_list = []
            for job in jobs:
                try:
                    next_run = job.next_run_time.isoformat() if job.next_run_time else "N/A"
                except Exception:
                    next_run = "Error calculating"
                job_list.append({
                    "id": job.id,
                    "name": job.name,
                    "trigger": str(job.trigger),
                    "next_run_time": next_run,
                    "func_name": job.func.__name__ if hasattr(job.func, '__name__') else str(job.func)
                })
            return job_list
        except Exception as e:
            logger.error(f"Error listing scheduled jobs: {e}")
            await self.event_queue.put({
                "type": "error",
                "data": {"msg": f"Failed to list scheduled jobs: {e}"}
            })
            return []


    async def remove_job(self, job_id: str) -> bool:

        loop = asyncio.get_event_loop()
        try:
            await loop.run_in_executor(None, self.scheduler_manager.remove_job, job_id)
            await self.event_queue.put({
                "type": "info",
                "data": {"msg": f"Scheduled job '{job_id}' removed successfully"}
            })
            return True
        except Exception as e:
            logger.error(f"Error removing scheduled job '{job_id}': {e}")
            await self.event_queue.put({
                "type": "error",
                "data": {"msg": f"Failed to remove job '{job_id}': {e}"}
            })
            return False

    async def add_job(self, task_data: Dict[str, Any]) -> bool:

        loop = asyncio.get_event_loop()
        try:
            task_name = task_data["task_type"]
            if task_name == "scan":
                func_to_schedule = scheduled_tasks.run_scan_task 
            elif task_name == "update-rules":
                func_to_schedule = scheduled_tasks.run_update_task 
            else:
                 raise ValueError(f"Unknown task type for TUI scheduling: {task_name}")

            def add_job_in_thread():
                try:
                    self.scheduler_manager.add_job(
                        func=func_to_schedule,
                        trigger=task_data["trigger_type"],
                        name=task_data["name"],
                        args=task_data.get("args"),
                        kwargs=task_data.get("kwargs"),
                        misfire_grace_time=None,
                        **task_data.get("trigger_args", {})
                    )
                except Exception as thread_e:
                    logger.error(f"Error calling scheduler_manager.add_job in thread for '{task_data.get('name', 'unknown')}': {thread_e}", exc_info=True)
                    raise thread_e

            await loop.run_in_executor(
                None,
                add_job_in_thread
            )

            await self.event_queue.put({
                "type": "info",
                "data": {"msg": f"Scheduled task '{task_data['name']}' added successfully"}
            })
            return True

        except Exception as e:
            logger.error(f"Error adding scheduled job '{task_data.get('name', 'unknown')}': {e}")
            await self.event_queue.put({
                "type": "error",
                "data": {"msg": f"Failed to add job '{task_data.get('name', 'unknown')}': {e}"}
            })
            return False
