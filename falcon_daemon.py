import time
import signal
import logging
import sys
from pathlib import Path

try:
    project_root = Path(__file__).resolve().parent
    sys.path.insert(0, str(project_root))
    logger = logging.getLogger(__name__)
except Exception as e:
    logging.basicConfig(level=logging.WARNING)
    logging.warning(f"Failed to set project path: {e}")
    sys.exit(1)

try:
    from falcon.config import ConfigManager
    from falcon.yara_manager import YaraManager
    from falcon.scanner import Scanner
    from falcon.updater import Updater
    from falcon.report import ReportManager
    from falcon.scheduler import SchedulerManager
    from falcon import scheduled_tasks
    from falcon.quarantine import QuarantineManager as QM_internal

except ImportError as e:
    print(f"Error importing modules: {e}")
    print(f"Python Path: {sys.path}")
    print("Ensure all modules (config, yara_manager, etc.) exist in the 'falcon' directory.")
    sys.exit(1)

try:
    log_file_path = Path.home() / ".falcon" / "falcon_daemon.log"
    log_file_path.parent.mkdir(parents=True, exist_ok=True)
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(name)s - %(message)s',
        handlers=[
            logging.FileHandler(log_file_path),
            logging.StreamHandler(sys.stdout)
        ]
    )
    logger = logging.getLogger(__name__)
    logger.info(f"Daemon logging configured. Log file at: {log_file_path}")

except Exception as e:
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(name)s - %(message)s')
    logger = logging.getLogger(__name__)
    logger.error(f"Failed to configure file logging: {e}. Defaulting to stdout.")

keep_running = True

def handle_signal(signum, frame):

    global keep_running
    if keep_running:
        logger.info(f"Received signal {signum}. Initiating graceful shutdown...")
        keep_running = False

if __name__ == "__main__":
    logger.info("Starting FalconDefender Scheduler Daemon...")
    
    scheduler_manager = None

    try:
        logger.info("Initializing core components...")
        config_manager = ConfigManager()
        yara_manager = YaraManager(config_manager)
        quarantine_manager = QM_internal(config_manager)
        scanner = Scanner(config_manager, yara_manager, quarantine_manager)
        updater = Updater(Path(config_manager.get("rules_dir")), config_manager)
        report_manager = ReportManager(Path(config_manager.get("report_dir")), config_manager)

        scheduler_manager = SchedulerManager()
        logger.info("Core components initialized.")

        logger.info("Registering instances for scheduled tasks...")
        scheduled_tasks.register_instance("scanner", scanner)
        scheduled_tasks.register_instance("updater", updater)
        scheduled_tasks.register_instance("yara_manager", yara_manager)
        scheduled_tasks.register_instance("report_manager", report_manager)
        logger.info("Instances registered successfully.")

        try:
            logger.info("Adding periodic scheduler wakeup job (every 60 seconds)...")
            scheduler_manager.add_job(
                func=scheduler_manager.scheduler.wakeup,
                trigger='interval',
                seconds=60,
                name='_internal_scheduler_wakeup',
            )
            logger.info("Scheduler wakeup job added.")
        except Exception as e:
            logger.error(f"Failed to add scheduler wakeup job: {e}", exc_info=True)

    except Exception as e:
        logger.error(f"Critical error during daemon initialization: {e}", exc_info=True)
        sys.exit(1)

    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGINT, handle_signal)

    logger.info("Daemon running. Scheduler is active in the background. Waiting for signals.")
    try:
        while keep_running:
            time.sleep(1)
    except Exception as e:
        logger.error(f"Daemon main loop encountered an unexpected error: {e}", exc_info=True)
    finally:
        logger.info("Shutting down scheduler manager...")
        if scheduler_manager and scheduler_manager.scheduler.running:
            try:
                scheduler_manager.shutdown()
                logger.info("Scheduler manager shut down successfully.")
            except Exception as e:
                 logger.error(f"Error during scheduler shutdown: {e}", exc_info=True)
        logger.info("FalconDefender Scheduler Daemon stopped.")
