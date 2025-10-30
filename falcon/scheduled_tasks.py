import logging
from pathlib import Path
from typing import List, Dict, Any

_instance_registry: Dict[str, Any] = {}

logger = logging.getLogger(__name__)

def register_instance(name: str, instance: Any) -> None:

    _instance_registry[name] = instance
    logger.info(f"Registered instance: {name}")

def _get_instance(name: str) -> Any:
    instance = _instance_registry.get(name)
    if not instance:

        logger.error(f"Scheduled task failed: Instance '{name}' not found in registry.")
        raise RuntimeError(f"Instance '{name}' not available for scheduled task.")
    return instance


def run_scan_task(*args: Any, **kwargs: Any) -> None:

    logger.info(f"Scheduler executing run_scan_task with args={args}, kwargs={kwargs}")
    scan_results = None
    try:
        scanner = _get_instance("scanner")
        report_manager = _get_instance("report_manager")

        if args:
            scan_path = Path(args[0])

            scan_results = scanner.scan_path(scan_path, **kwargs)
            logger.info(f"Scheduled scan task completed for '{scan_path}'. Found {len(scan_results.get('matches',[]))} matches.")


            logger.info(f"Attempting to send email report for scheduled scan of '{scan_path}'...")
            email_success = report_manager.send_email_report(scan_results)
            if email_success:
                logger.info("Scheduled scan email report sent successfully.")
            else:
                logger.warning("Failed to send scheduled scan email report. Check logs and config.")

        else:
            logger.error("Scheduled scan task failed: No path argument provided.")

    except Exception as e:
        logger.error(f"Error during scheduled scan task: {e}", exc_info=True)

def run_update_task(*args: Any, **kwargs: Any) -> None:

    logger.info(f"Scheduler executing run_update_task with args={args}, kwargs={kwargs}")
    try:
        updater = _get_instance("updater")

        success = updater.update_rules(**kwargs)
        if success:
            logger.info("Scheduled rule update task completed successfully.")

            yara_manager = _get_instance("yara_manager")
            yara_manager.load_rules(force_recompile=True)
            logger.info("Attempted to reload YARA rules after scheduled update.")

        else:
            logger.warning("Scheduled rule update task failed.")
    except Exception as e:
        logger.error(f"Error during scheduled update task: {e}", exc_info=True)
