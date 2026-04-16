from celery import Celery
from celery.schedules import crontab
from app.core.config import settings

celery_app = Celery(
    "worker",
    broker=settings.REDIS_URL,
    backend=settings.REDIS_URL,
    include=["app.services.scan_tasks"],
)

celery_app.conf.beat_schedule = {
    # Periodic infrastructure scan (existing)
    "hourly-network-scan": {
        "task": "app.services.scan_tasks.trigger_periodic_scan",
        "schedule": crontab(minute=0),
        "args": ("localhost",),
    },
    # Phase 4.3 — SLA breach detection runs every hour
    "hourly-sla-breach-check": {
        "task": "app.services.scan_tasks.check_sla_breaches",
        "schedule": crontab(minute=5),  # offset by 5 min from the scan trigger
    },
}
