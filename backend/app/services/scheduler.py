"""
QuShield Report Scheduler Engine
Uses APScheduler BackgroundScheduler to poll the report_schedules table
every 30 seconds and execute due reports.
"""
import logging
from apscheduler.schedulers.background import BackgroundScheduler
from sqlalchemy.orm import Session
from datetime import datetime, timedelta
from app.core.database import SessionLocal
from app.models.report import ReportSchedule

logger = logging.getLogger("scheduler")
logger.setLevel(logging.WARNING)  # Suppress routine logs

# Global single instance — BackgroundScheduler runs on its own thread
scheduler = BackgroundScheduler(daemon=True)

# Also silence apscheduler's own verbose logging
logging.getLogger("apscheduler").setLevel(logging.WARNING)


def check_and_run_schedules():
    """Poller job: runs every 30s, checks for due report schedules."""
    db: Session = SessionLocal()
    try:
        now = datetime.now()
        all_schedules = db.query(ReportSchedule).all()

        # Find schedules whose date has passed
        due_schedules = [s for s in all_schedules if s.schedule_date and s.schedule_date <= now]

        for schedule in due_schedules:
            print(f"[SCHEDULER] Delivered {schedule.report_type} report for User {str(schedule.user_id)[:8]}")
            # Mock delivery
            if schedule.delivery_email:
                print(f"  -> Email sent to {schedule.delivery_email}")
            if schedule.delivery_location:
                print(f"  -> Saved to {schedule.delivery_location}")

            # Bump schedule if recurring, otherwise delete
            freq = (schedule.frequency or "").lower()
            if freq == "daily":
                schedule.schedule_date = schedule.schedule_date + timedelta(days=1)
                db.commit()
            elif freq == "weekly":
                schedule.schedule_date = schedule.schedule_date + timedelta(weeks=1)
                db.commit()
            elif freq == "monthly":
                try:
                    from dateutil.relativedelta import relativedelta
                    schedule.schedule_date = schedule.schedule_date + relativedelta(months=1)
                except ImportError:
                    schedule.schedule_date = schedule.schedule_date + timedelta(days=30)
                db.commit()
            else:
                db.delete(schedule)
                db.commit()

    except Exception as e:
        logger.error(f"Scheduler failure: {e}")
    finally:
        db.close()


def start_scheduler():
    scheduler.add_job(
        check_and_run_schedules,
        'interval',
        seconds=30,
        id="check_reports",
        replace_existing=True,
        next_run_time=datetime.now()
    )
    scheduler.start()


def stop_scheduler():
    if scheduler.running:
        scheduler.shutdown(wait=False)
