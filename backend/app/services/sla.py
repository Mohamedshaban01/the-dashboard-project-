"""
SLA clock for Findings.
Phase 4.3 — Found 404 Hardening Plan.

Default SLA windows (overridable via settings):
  CRITICAL : 7 days
  HIGH     : 30 days
  MEDIUM   : 90 days
  LOW      : 180 days
  INFO     : no SLA (None)

The Celery beat task `check_sla_breaches` runs hourly to detect and action
any OPEN Finding whose due_date has passed.
"""
import logging
from datetime import date, datetime, timedelta
from typing import Optional

from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.scan import ActionItem, Finding, FindingStatus, SeverityLevel

logger = logging.getLogger(__name__)


# ── SLA configuration ─────────────────────────────────────────────────────────

_DEFAULT_SLA_DAYS: dict[str, int] = {
    "critical": 7,
    "high":     30,
    "medium":   90,
    "low":      180,
    "info":     0,   # 0 = no SLA
}


def _sla_days(severity_str: str) -> int:
    """Return the SLA window in days for a given severity string."""
    key = severity_str.lower() if severity_str else "low"
    attr = f"SLA_DAYS_{key.upper()}"
    if hasattr(settings, attr):
        return int(getattr(settings, attr))
    return _DEFAULT_SLA_DAYS.get(key, 180)


def due_date_for(severity) -> Optional[date]:
    """
    Compute the SLA due date for a new Finding.

    Args:
        severity: A SeverityLevel enum value or string.

    Returns:
        A `datetime.date` (today + SLA window), or None for INFO findings.
    """
    sev_str = severity.value if hasattr(severity, "value") else str(severity)
    days = _sla_days(sev_str)
    if days == 0:
        return None
    return date.today() + timedelta(days=days)


# ── Breach detection ─────────────────────────────────────────────────────────

def check_and_action_breaches(db: Session) -> int:
    """
    Find all OPEN Findings past their due_date, emit an ActionItem for each,
    and return the number of breaches detected.

    Called by the Celery beat task `check_sla_breaches`.
    """
    today = date.today()
    breached = (
        db.query(Finding)
        .filter(
            Finding.status == FindingStatus.OPEN,
            Finding.due_date.isnot(None),
            Finding.due_date < today,
        )
        .all()
    )

    count = 0
    for finding in breached:
        # Avoid duplicate OVERDUE action items for the same finding
        existing = (
            db.query(ActionItem)
            .filter(
                ActionItem.title == f"[SLA BREACH] {finding.title}",
                ActionItem.priority == "OVERDUE",
            )
            .first()
        )
        if existing:
            continue

        overdue_days = (today - finding.due_date).days
        action = ActionItem(
            scan_id=None,  # finding-level, not scan-level
            title=f"[SLA BREACH] {finding.title}",
            description=(
                f"Finding '{finding.title}' has been OPEN for "
                f"{overdue_days} day(s) past its SLA due date ({finding.due_date}). "
                f"Severity: {finding.severity.value if finding.severity else 'unknown'}. "
                f"First seen: {finding.first_seen.date() if finding.first_seen else 'unknown'}."
            ),
            priority="OVERDUE",
            status="OPEN",
            type="SLA_BREACH",
            created_at=datetime.utcnow(),
        )
        db.add(action)
        count += 1

        # Publish Redis event for WebSocket notification
        try:
            from app.services.event_publisher import publisher
            import asyncio

            async def _emit():
                await publisher.publish("SLA_BREACH", {
                    "finding_id": finding.id,
                    "title": finding.title,
                    "overdue_days": overdue_days,
                    "severity": finding.severity.value if finding.severity else "unknown",
                })

            loop = asyncio.new_event_loop()
            loop.run_until_complete(_emit())
            loop.close()
        except Exception as exc:
            logger.warning("SLA breach event publish failed: %s", exc)

    if count:
        db.commit()
        logger.info("SLA breach check: %d new overdue action items created.", count)

    return count
