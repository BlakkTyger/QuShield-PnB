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
from app.models.auth import User
from app.models.scan import ScanJob
from app.models.generated_report import GeneratedReport
from app.services.report_generator import ReportGenerator

logger = logging.getLogger("scheduler")
logger.setLevel(logging.WARNING)  # Suppress routine logs

# Global single instance — BackgroundScheduler runs on its own thread
scheduler = BackgroundScheduler(daemon=True)

# Also silence apscheduler's own verbose logging
logging.getLogger("apscheduler").setLevel(logging.WARNING)


def _generate_scheduled_report(db: Session, schedule: ReportSchedule) -> bool:
    """Generate and save report for a scheduled job when download_link is enabled.
    
    Returns True if report was successfully generated and saved.
    """
    if not schedule.download_link:
        return False
    
    try:
        # Get the user who scheduled this report
        user = db.query(User).filter(User.id == schedule.user_id).first()
        if not user:
            logger.error(f"User {schedule.user_id} not found for scheduled report")
            return False
        
        # Get the latest completed scan for this user's reports
        # For scheduled reports, we target the most recent completed scan
        scan_job = db.query(ScanJob).filter(
            ScanJob.user_id == schedule.user_id,
            ScanJob.status == "completed"
        ).order_by(ScanJob.created_at.desc()).first()
        
        if not scan_job:
            logger.warning(f"No completed scan found for user {schedule.user_id}")
            return False
        
        # Generate the report (this already saves it via _save_report)
        generator = ReportGenerator(db, user)
        generator.generate_report(
            str(scan_job.id),
            schedule.report_type,
            format="pdf"
        )
        
        # The report was already saved by generate_report(), just verify it exists
        saved_report = db.query(GeneratedReport).filter(
            GeneratedReport.user_id == user.id,
            GeneratedReport.report_type == schedule.report_type,
            GeneratedReport.format == "pdf"
        ).order_by(GeneratedReport.generated_at.desc()).first()
        
        if saved_report:
            logger.info(f"Scheduled report generated and saved: {saved_report.id}")
            return True
        return False
        
    except Exception as e:
        logger.error(f"Failed to generate scheduled report: {e}")
        return False


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
            
            # Generate actual report if download_link is enabled
            if schedule.download_link:
                success = _generate_scheduled_report(db, schedule)
                if success:
                    print(f"  -> Download link generated and saved")
                else:
                    print(f"  -> Failed to generate download link")

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
