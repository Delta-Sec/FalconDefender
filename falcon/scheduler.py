import logging
import os
from datetime import datetime
from typing import Callable, Any, Dict, Optional

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.jobstores.sqlalchemy import SQLAlchemyJobStore
from apscheduler.executors.pool import ThreadPoolExecutor, ProcessPoolExecutor

logger = logging.getLogger(__name__)

class SchedulerManager:


    def __init__(self, db_path: str = os.path.expanduser('~/.falcon/scheduler.sqlite')):
        self._db_path = db_path
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        jobstores = {
            'default': SQLAlchemyJobStore(url=f'sqlite:///{self._db_path}')
        }
        executors = {
            'default': ThreadPoolExecutor(20),
            'processpool': ProcessPoolExecutor(5)
        }
        job_defaults = {
            'coalesce': True,
            'max_instances': 1
        }
        self.scheduler = BackgroundScheduler(
            jobstores=jobstores,
            executors=executors,
            job_defaults=job_defaults,
            timezone='UTC'
        )
        self.scheduler.start()
        logger.info(f"Scheduler initialized and started with persistence at {self._db_path}")

    def add_job(self, func: Callable, trigger: str, name: str, args: Optional[list] = None, kwargs: Optional[dict] = None, **trigger_args):
        logger.info(f"Attempting to add/replace job '{name}' (func={func}, trigger={trigger}, args={args}, kwargs={kwargs}, trigger_args={trigger_args})") # <-- ADD THIS LOG
        try:
            job = self.scheduler.add_job(
                func=func,
                trigger=trigger,
                id=name,
                name=name,
                args=args,
                kwargs=kwargs,
                replace_existing=True,
                **trigger_args
            )
            logger.info(f"APScheduler add_job call successful for '{name}'. Job details: {job}") # <-- ADD THIS LOG
        except Exception as e:

            logger.error(f"APScheduler add_job call FAILED for '{name}': {e}", exc_info=True) # <-- MODIFIED LOG (added exc_info)

    def remove_job(self, name: str):

        try:
            self.scheduler.remove_job(name)
            logger.info(f"Removed job '{name}'.")
        except Exception as e:
            logger.error(f"Error removing job '{name}': {e}")

    def get_jobs(self):
        return self.scheduler.get_jobs()

    def shutdown(self):
        self.scheduler.shutdown()
        logger.info("Scheduler shut down.")

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

    def my_scan_task(path: str, scan_type: str):
        logger.info(f"Executing scan task: {scan_type} scan on {path} at {datetime.now()}")

    scheduler_manager = SchedulerManager(db_path='./test_scheduler.sqlite')


    scheduler_manager.add_job(
        my_scan_task, 'interval', 'daily_quick_scan', 
        args=['/home/ubuntu/test_data', 'quick'], seconds=10
    )

    scheduler_manager.add_job(
        my_scan_task, 'cron', 'full_system_scan', 
        args=['/', 'full'], hour=2, minute=0
    )

    scheduler_manager.add_job(
        my_scan_task, 'cron', 'weekly_deep_scan', 
        args=['/home/ubuntu/important_data', 'deep'], day_of_week='mon', hour=10, minute=30
    )

    print("Scheduled jobs:")
    for job in scheduler_manager.get_jobs():
        print(f"- {job.id}: next run at {job.next_run_time}")

    try:
        import time
        time.sleep(30)
    except (KeyboardInterrupt, SystemExit):
        pass
    finally:
        scheduler_manager.shutdown()
        print("Scheduler example finished.")

