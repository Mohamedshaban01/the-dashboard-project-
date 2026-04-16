"""
Finding deduplication service.
Phase 4.2 — Found 404 Hardening Plan.

Each unique security issue per target is represented by a single `Finding` row.
`Vulnerability` rows are *observations* — re-detecting the same issue on a second
scan creates a new Vulnerability linked to the existing Finding, rather than
a duplicate Finding.

Fingerprint formula
-------------------
sha256(target_id + "|" + vuln_type + "|" + normalised_url + "|" + parameter + "|" + match_sig)

  normalised_url   — scheme + host + path, query string and fragment stripped
  parameter        — empty string when None
  match_sig        — template_id if from Nuclei, else first 64 chars of description
"""
import hashlib
import logging
from datetime import datetime
from urllib.parse import urlparse, urlunparse

from sqlalchemy.orm import Session

from app.models.scan import Finding, FindingStatus, SeverityLevel, Vulnerability
from app.services.sla import due_date_for  # imported lazily to avoid circular deps

logger = logging.getLogger(__name__)


# ── Fingerprint helpers ──────────────────────────────────────────────────────

def _normalise_url(raw_url: str) -> str:
    """Strip query string and fragment; keep scheme + host + path."""
    try:
        p = urlparse(raw_url)
        return urlunparse((p.scheme, p.netloc, p.path, "", "", ""))
    except Exception:
        return raw_url or ""


def fingerprint(
    target_id: str,
    vuln_type: str | None,
    url: str | None,
    parameter: str | None,
    template_id: str | None,
    description: str | None,
) -> str:
    """
    Return a hex SHA-256 fingerprint that is stable across re-scans of the same issue.
    """
    norm_url = _normalise_url(url or "")
    match_sig = template_id or (description or "")[:64]
    raw = "|".join([
        target_id or "",
        (vuln_type or "").lower(),
        norm_url,
        parameter or "",
        match_sig,
    ])
    return hashlib.sha256(raw.encode()).hexdigest()


# ── Main deduplication entry point ───────────────────────────────────────────

def deduplicate_scan(scan_id: str, target_id: str | None, db: Session) -> int:
    """
    Link every Vulnerability in *scan_id* to its canonical Finding record.

    Algorithm for each vulnerability:
    1. Compute the fingerprint.
    2. Look up an existing Finding for this target + fingerprint.
    3a. If found:
        - Update Finding.last_seen.
        - If status was FIXED → transition to REOPENED and log.
        - Link Vulnerability.finding_id.
    3b. If not found:
        - Create a new Finding with first_seen = now, due_date from SLA.
        - Link Vulnerability.finding_id.

    Returns the number of new Findings created.
    """
    vulns = db.query(Vulnerability).filter(Vulnerability.scan_id == scan_id).all()
    new_findings = 0

    for vuln in vulns:
        fp = fingerprint(
            target_id=target_id or "",
            vuln_type=vuln.type,
            url=vuln.url,
            parameter=vuln.parameter,
            template_id=vuln.template_id,
            description=vuln.description,
        )

        existing = (
            db.query(Finding)
            .filter(Finding.target_id == target_id, Finding.fingerprint == fp)
            .first()
        )

        if existing:
            existing.last_seen = datetime.utcnow()
            if existing.status == FindingStatus.FIXED:
                logger.info(
                    "Finding %s reopened — re-detected in scan %s", existing.id, scan_id
                )
                existing.status = FindingStatus.REOPENED
            vuln.finding_id = existing.id
        else:
            severity = vuln.severity or SeverityLevel.LOW
            title = vuln.title or vuln.type or "Untitled Finding"

            finding = Finding(
                target_id=target_id,
                fingerprint=fp,
                title=title,
                vuln_type=vuln.type,
                severity=severity,
                cvss_score=vuln.cvss_score,
                status=FindingStatus.OPEN,
                first_seen=datetime.utcnow(),
                last_seen=datetime.utcnow(),
                due_date=due_date_for(severity),
            )
            db.add(finding)
            db.flush()  # get finding.id before linking
            vuln.finding_id = finding.id
            new_findings += 1

    db.commit()
    logger.info(
        "Dedup complete for scan %s: %d vulns processed, %d new findings created",
        scan_id, len(vulns), new_findings,
    )
    return new_findings
