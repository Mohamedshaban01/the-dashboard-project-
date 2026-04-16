"""
Celery scan tasks — Nmap infrastructure scan → Nuclei deep scan → Risk Engine → AI → Event publish.

Key design decisions:
  - All async helpers are called through _run_async() to safely use asyncio inside
    a synchronous Celery worker without nested event-loop conflicts.
  - Each phase (intelligence, nuclei, risk) fails independently so one broken
    integration never aborts the entire scan pipeline.
  - Scan status is always updated (COMPLETED or FAILED) in the finally block.
"""

import asyncio
import logging
from datetime import datetime
from urllib.parse import urlparse

from app.core.celery_app import celery_app
from app.core.database import SessionLocal
from app.models.scan import Scan, Vulnerability, ScanStatus, ScanAsset, AssetService
from app.services.nmap_wrapper import NmapWrapper
from app.services.event_publisher import publisher
from sqlalchemy import select

logger = logging.getLogger(__name__)


# ── Async helper ─────────────────────────────────────────────────────────────

def _run_async(coro):
    """
    Run an async coroutine safely from within a synchronous Celery task.
    Creates a fresh event loop and sets it as current to avoid "Future attached
    to a different loop" errors from inherited module-level async engines.
    """
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        return loop.run_until_complete(coro)
    finally:
        try:
            loop.run_until_complete(loop.shutdown_asyncgens())
        except Exception:
            pass
        loop.close()
        asyncio.set_event_loop(None)


def _make_async_session():
    """
    Create a fresh async engine + session factory bound to the current event loop.
    Required in Celery workers to avoid the module-level engine's pool being
    attached to the main process's event loop.
    """
    from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
    from app.core.config import settings
    engine = create_async_engine(settings.ASYNC_DATABASE_URL, pool_pre_ping=True)
    return engine, async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


# ── URL / host sanitiser ──────────────────────────────────────────────────────

def _sanitise_target(raw: str) -> str:
    """
    Extract a clean hostname or IP from a URL string.
    Preserves CIDR notation (e.g. 192.168.1.0/24).
    """
    if "://" in raw:
        parsed = urlparse(raw)
        return parsed.hostname or raw.split("/")[0]
    # CIDR — keep as-is
    if "/" in raw and not raw.startswith("/"):
        return raw
    return raw


# ── Redis concurrency lock (Phase 2.4) ───────────────────────────────────────────────

def _acquire_scan_lock(target_id: str) -> bool:
    """
    Acquire a Redis SETNX lock for *target_id*.

    Returns True if the lock was acquired (scan may proceed).
    Returns False if another scan is already running for this target.
    TTL is 90 minutes — longer than any expected scan duration.
    """
    try:
        import redis as _redis
        r = _redis.from_url(settings.REDIS_URL, socket_connect_timeout=3)
        acquired = r.set(f"scan_lock:{target_id}", "1", nx=True, ex=5400)
        r.close()
        return bool(acquired)
    except Exception as exc:
        # If Redis is unreachable, allow the scan to proceed rather than
        # silently blocking all scans.  Log a warning so ops can investigate.
        logger.warning("scan_lock: Redis unreachable (%s) — skipping lock check.", exc)
        return True


def _release_scan_lock(target_id: str) -> None:
    """Release the Redis concurrency lock for *target_id*."""
    try:
        import redis as _redis
        r = _redis.from_url(settings.REDIS_URL, socket_connect_timeout=3)
        r.delete(f"scan_lock:{target_id}")
        r.close()
    except Exception as exc:
        logger.warning("scan_lock: could not release lock for %s: %s", target_id, exc)


# ── AI orchestrator pipeline (called from run_scan_task when mode='ai') ───────

async def _run_ai_pipeline(scan_id: str) -> None:
    """
    Run the full AgentOrchestrator pipeline for a single scan.

    This is an *async* function executed inside a fresh event loop by
    _run_async() so it is safe to call from a synchronous Celery worker.
    Uses _make_async_session() to avoid the module-level engine pool being
    attached to the main process's event loop.
    """
    from app.services.agent_orchestrator import AgentOrchestrator

    engine, maker = _make_async_session()
    try:
        async with maker() as db:
            scan_res = await db.execute(select(Scan).filter(Scan.id == scan_id))
            scan = scan_res.scalars().first()
            if not scan:
                logger.error("[AI pipeline] Scan %s not found — aborting.", scan_id)
                return
            target_url = (scan.target.base_url if scan.target else None) or scan.target_url
            auth_credentials = scan.target.auth_credentials if scan.target else None
            if not target_url:
                logger.error("[AI pipeline] Scan %s has no target URL — aborting.", scan_id)
                return
            orchestrator = AgentOrchestrator(scan_id, db)
            await orchestrator.run_full_scan(target_url, auth_credentials)
    finally:
        await engine.dispose()


# ── Main scan task ─────────────────────────────────────────────────────────────

@celery_app.task(bind=True, max_retries=2, default_retry_delay=30)
def run_scan_task(self, scan_id: str, mode: str = "nmap"):
    """
    Unified scan task — dispatches to the correct pipeline based on `mode`.

    mode='nmap'  (default): Nmap → Nuclei → Risk Engine → Asset Monitor
    mode='ai':              Full AgentOrchestrator pipeline (Phase 1 hardening)

    Both modes survive a backend restart since they run inside the Celery worker.
    Previously, mode='ai' ran inside FastAPI BackgroundTasks and was lost on restart.
    """
    # ── AI mode: delegate entirely to the async orchestrator ─────────────────
    if mode == "ai":
        logger.info("[Scan %s] Dispatching to AI orchestrator pipeline.", scan_id)
        return _run_async(_run_ai_pipeline(scan_id))

    # ── Nmap mode: existing pipeline below (unchanged) ────────────────────────
    db = SessionLocal()
    scan = db.query(Scan).filter(Scan.id == scan_id).first()

    if not scan:
        logger.error("Scan %s not found — aborting.", scan_id)
        db.close()
        return

    # ── Concurrency lock: at most one scan per target at a time (Phase 2.4) ──
    if scan.target_id and not _acquire_scan_lock(str(scan.target_id)):
        scan.status = ScanStatus.FAILED
        scan.failure_reason = "concurrency_limit"
        db.commit()
        db.close()
        logger.warning(
            "[Scan %s] Rejected — target %s already has a running scan.",
            scan_id, scan.target_id,
        )
        return

    vuln_count = 0
    acquired_lock = bool(scan.target_id)  # track whether we need to release

    try:
        # ── Status: RUNNING ──────────────────────────────────────────────────
        scan.status = ScanStatus.RUNNING
        scan.started_at = datetime.utcnow()
        if scan.configuration is None:
            scan.configuration = {}
        db.commit()

        # ── Resolve target host ──────────────────────────────────────────────
        raw_target = (scan.target.base_url if scan.target else None) or scan.target_url
        if not raw_target:
            raise ValueError(f"No valid target URL for scan {scan_id}")
        clean_target = _sanitise_target(raw_target)

        # ── Phase 1: Nmap ────────────────────────────────────────────────────
        logger.info("[Scan %s] Phase 1: Nmap → %s", scan_id, clean_target)
        scanner = NmapWrapper()
        results = scanner.scan_target(clean_target, scan.scan_type)

        seen_hosts: set[str] = set()
        all_vulns: list[dict] = []

        for host_data in results:
            ip = host_data["ip"]
            if ip in seen_hosts:
                continue
            seen_hosts.add(ip)

            asset = ScanAsset(
                scan_id=scan.id,
                ip_address=ip,
                hostname=host_data.get("hostnames"),
                mac_address=host_data.get("mac"),
                mac_vendor=host_data.get("mac_vendor"),
                os_name=host_data.get("os_name"),
                os_accuracy=host_data.get("os_accuracy"),
                device_type=host_data.get("device_type", "unknown"),
                is_new="true",
            )
            db.add(asset)
            db.flush()

            for port_data in host_data["ports"]:
                db.add(AssetService(
                    asset_id=asset.id,
                    port=port_data["port"],
                    protocol=port_data["protocol"],
                    state=port_data["state"],
                    service_name=port_data["service"],
                    product=port_data["product"],
                    version=port_data["version"],
                    cpe=port_data.get("cpe"),
                    extra_info=port_data.get("extra_info"),
                ))
                vuln = Vulnerability(
                    scan_id=scan.id,
                    host=ip,
                    port=port_data["port"],
                    protocol=port_data["protocol"],
                    service=port_data["service"],
                    type="Service Exposure",
                    severity=port_data["severity"].lower(),
                    url=f"{port_data['protocol']}://{ip}:{port_data['port']}",
                    description=f"Service: {port_data['product']} {port_data['version']}",
                    remediation="Update service or restrict access with firewall rules.",
                )
                db.add(vuln)
                vuln_count += 1
                all_vulns.append({
                    "host": ip,
                    "severity": port_data["severity"].lower(),
                    "cve_id": "",
                    "description": f"Service: {port_data['product']}",
                })

        # ── Phase 2: AI Intelligence (Gemini) ─────────────────────────────
        logger.info("[Scan %s] Phase 2: AI Intelligence analysis", scan_id)
        try:
            from app.services.intelligence_agent import IntelligenceAgent

            async def _ai_analysis():
                _engine, _maker = _make_async_session()
                try:
                    async with _maker() as async_db:
                        await IntelligenceAgent(async_db).batch_analyze(scan.id, results)
                finally:
                    await _engine.dispose()

            _run_async(_ai_analysis())
        except Exception as exc:
            logger.warning("[Scan %s] Intelligence analysis skipped: %s", scan_id, exc)

        # ── Phase 3: Nuclei deep scan ──────────────────────────────────────
        # Use the full URL (raw_target) so Nuclei scans the correct port,
        # not just the sanitised hostname which strips non-standard ports.
        nuclei_target = raw_target if raw_target and "://" in raw_target else clean_target
        logger.info("[Scan %s] Phase 3: Nuclei → %s", scan_id, nuclei_target)
        try:
            from app.services.nuclei_wrapper import NucleiWrapper
            for finding in NucleiWrapper().scan_target(nuclei_target, scan_type=scan.scan_type):
                db.add(Vulnerability(
                    scan_id=scan.id,
                    type=finding["type"],
                    severity=finding["severity"],
                    description=finding["description"],
                    url=finding["url"],
                    host=clean_target,
                    service="http" if "http" in finding["url"] else "unknown",
                    cve_id=finding.get("cve_id", ""),
                    proof_of_concept=str(finding.get("evidence", "")),
                    remediation="Refer to CVE mitigation guidance.",
                    status="OPEN",
                ))
                vuln_count += 1
                all_vulns.append({
                    "host": clean_target,
                    "severity": finding["severity"],
                    "cve_id": finding.get("cve_id", ""),
                    "description": finding["description"],
                })
        except Exception as exc:
            logger.warning("[Scan %s] Nuclei scan skipped: %s", scan_id, exc)

        # ── Phase 4: Risk Engine ───────────────────────────────────────────
        logger.info("[Scan %s] Phase 4: Risk Engine", scan_id)
        try:
            from app.services.unified_risk_engine import UnifiedRiskEngine

            async def _risk_analysis():
                _engine, _maker = _make_async_session()
                try:
                    async with _maker() as async_db:
                        risk_engine = UnifiedRiskEngine(async_db)
                        await risk_engine.update_scan_risk(scan.id)
                        await risk_engine.generate_action_items(scan.id)
                finally:
                    await _engine.dispose()

            _run_async(_risk_analysis())
        except Exception as exc:
            logger.error("[Scan %s] Risk Engine failed: %s", scan_id, exc)

        # ── Phase 5: Asset Monitor ─────────────────────────────────────────
        try:
            from app.services.asset_monitor import AssetMonitor
            AssetMonitor.process_scan_results(db, scan.id, results)
        except Exception as exc:
            logger.warning("[Scan %s] Asset monitor skipped: %s", scan_id, exc)

        # ── Phase 4.2: Finding deduplication ───────────────────────────────
        _run_finding_dedup(scan_id, str(scan.target_id) if scan.target_id else None)

        # ── Finalise: COMPLETED ────────────────────────────────────────────
        scan.status = ScanStatus.COMPLETED
        scan.completed_at = datetime.utcnow()
        db.commit()
        db.refresh(scan)

        thoughts = scan.agent_thoughts or {}
        _run_async(publisher.publish("RISK_UPDATE", {
            "scan_id": scan.id,
            "overall_score": round(scan.risk_score or 0.0, 2),
            "health_score": round(float(thoughts.get("health_score", 100.0 - (scan.risk_score or 0))), 2),
            "vuln_count": vuln_count,
        }))
        logger.info("[Scan %s] Completed — %d vulnerabilities found.", scan_id, vuln_count)

    except Exception as exc:
        logger.exception("[Scan %s] Fatal error: %s", scan_id, exc)
        scan.status = ScanStatus.FAILED
        scan.failure_reason = str(exc)[:120]
        scan.risk_score = 0
        try:
            self.retry(exc=exc)
        except Exception:
            pass  # max_retries exceeded — final failure logged above
    finally:
        db.commit()
        if acquired_lock and scan and scan.target_id:
            _release_scan_lock(str(scan.target_id))
        db.close()


# ── Phase 4.2: Finding deduplication (called after each scan) ─────────────────

def _run_finding_dedup(scan_id: str, target_id: str | None) -> None:
    """Run finding deduplication in a synchronous DB session."""
    db = SessionLocal()
    try:
        from app.services.finding_dedup import deduplicate_scan
        new_findings = deduplicate_scan(scan_id, target_id, db)
        logger.info("[Scan %s] Finding dedup: %d new findings.", scan_id, new_findings)
    except Exception as exc:
        logger.warning("[Scan %s] Finding dedup failed: %s", scan_id, exc)
    finally:
        db.close()


# ── Phase 4.3: SLA breach detection (hourly Celery beat task) ─────────────────

@celery_app.task
def check_sla_breaches():
    """
    Detect OPEN Findings past their SLA due_date, create OVERDUE ActionItems,
    and publish sla_breach events. Registered in celery_app.beat_schedule.
    """
    db = SessionLocal()
    try:
        from app.services.sla import check_and_action_breaches
        count = check_and_action_breaches(db)
        logger.info("SLA breach check completed: %d breaches actioned.", count)
        return count
    except Exception as exc:
        logger.error("SLA breach check failed: %s", exc)
        return 0
    finally:
        db.close()


# ── Periodic scan trigger ─────────────────────────────────────────────────────

@celery_app.task
def trigger_periodic_scan(target: str = "localhost"):
    """Create a new scan record and enqueue it for processing."""
    db = SessionLocal()
    try:
        scan = Scan(target_url=target, scan_type="quick")
        db.add(scan)
        db.commit()
        db.refresh(scan)
        run_scan_task.delay(scan_id=scan.id)
        logger.info("Triggered periodic scan %s for %s", scan.id, target)
    except Exception as exc:
        logger.error("Failed to trigger periodic scan: %s", exc)
    finally:
        db.close()
