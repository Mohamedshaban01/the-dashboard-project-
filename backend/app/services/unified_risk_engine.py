import logging
from datetime import datetime
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from sqlalchemy.orm import selectinload
from app.models.scan import Scan, Vulnerability, ScanStatus, SeverityLevel, VulnStatus, ActionItem, ScanAsset, AssetService, NetworkAsset
from app.services.cvss import (
    environmental_score as cvss_env_score,
    parse_vector,
    severity_to_default_vector,
)

logger = logging.getLogger(__name__)

class UnifiedRiskEngine:
    """
    Unified, deterministic risk engine for SME security orchestration.
    Calculates risk based on tool-provided CVSS scores, asset criticality, and port weightings.
    """
    
    HIGH_RISK_PORTS = {
        21: ("FTP", 15),
        23: ("Telnet", 20),
        445: ("SMB", 20),
        3389: ("RDP", 15),
        6379: ("Redis", 10),
        3000: ("Dev App", 5),
        8080: ("Proxy/App", 5),
        5432: ("PostgreSQL", 10),
        3306: ("MySQL", 10)
    }

    SEVERITY_WEIGHTS = {
        SeverityLevel.CRITICAL: 25,
        SeverityLevel.HIGH: 15,
        SeverityLevel.MEDIUM: 7,
        SeverityLevel.LOW: 2,
        SeverityLevel.INFO: 0
    }

    ASSET_VALUE_MAP = {
        "CRITICAL": 1.5,
        "HIGH": 1.2,
        "MEDIUM": 1.0,
        "LOW": 0.8
    }

    def __init__(self, db: AsyncSession):
        self.db: AsyncSession = db
        # Ensure HIGH_RISK_PORTS is available as explicit float for linter
        self.port_weights: dict = self.__class__.HIGH_RISK_PORTS

    def _resolve_target_context(self, scan: Scan) -> tuple[str, str, str]:
        """Return (asset_value, data_sensitivity, exposure) from the scan's target."""
        asset_value = "MEDIUM"
        data_sensitivity = "NONE"
        exposure = "external"
        target_ip = ""

        if scan.target:
            target_ip = scan.target.base_url or scan.target_url or ""
            if hasattr(scan.target, "asset_value") and scan.target.asset_value:
                asset_value = str(scan.target.asset_value).upper()
            if hasattr(scan.target, "data_sensitivity") and scan.target.data_sensitivity:
                data_sensitivity = str(scan.target.data_sensitivity).upper()

        _private = ("10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.",
                    "172.2", "172.30.", "172.31.", "127.", "localhost")
        if any(target_ip.startswith(p) for p in _private):
            exposure = "internal"

        return asset_value, data_sensitivity, exposure

    def calculate_scan_risk(self, scan: Scan) -> float:
        """
        Legacy scalar interface — delegates to calculate_scan_risk_v2 and returns
        just the score float for backward compatibility.
        """
        return self.calculate_scan_risk_v2(scan)["score"]

    def calculate_scan_risk_v2(self, scan: Scan) -> dict:
        """
        Phase 4.1 — CVSS v3.1 environmental risk score with per-vulnerability breakdown.

        Algorithm:
        1. For each vulnerability, obtain a CVSS vector (stored or default from severity).
        2. Compute the CVSS environmental score adjusted for asset_value, data_sensitivity,
           and whether the target is internet-exposed.
        3. Add a confidence multiplier (0-1) from Nuclei where available.
        4. Accumulate scores; cap at 100.
        5. Return {"score": float, "breakdown": [...]} and store on Scan.risk_breakdown.
        """
        if not scan.vulnerabilities and not scan.assets:
            return {"score": 0.0, "breakdown": []}

        asset_value, data_sensitivity, exposure = self._resolve_target_context(scan)
        breakdown: list[dict] = []
        total_score = 0.0

        # ── Vulnerability contributions ───────────────────────────────────────
        for vuln in scan.vulnerabilities:
            # Resolve CVSS vector — prefer stored value, fall back to severity default
            vector_str = vuln.cvss_vector if vuln.cvss_vector else severity_to_default_vector(
                vuln.severity.value if vuln.severity else "low"
            )
            try:
                metrics = parse_vector(vector_str)
                env_score = cvss_env_score(metrics, asset_value, data_sensitivity, exposure)
            except Exception:
                env_score = float(UnifiedRiskEngine.SEVERITY_WEIGHTS.get(vuln.severity, 2))

            confidence = float(vuln.confidence_score) if vuln.confidence_score is not None else 1.0
            contribution = round(env_score * confidence, 2)
            total_score += contribution

            reason_parts = []
            if vuln.cve_id:
                reason_parts.append(vuln.cve_id)
            if vuln.title:
                reason_parts.append(vuln.title)
            elif vuln.type:
                reason_parts.append(vuln.type)
            reason = ", ".join(reason_parts) if reason_parts else (vuln.description or "")[:80]

            breakdown.append({
                "vuln_id": vuln.id,
                "cvss_vector": vector_str,
                "cvss_env_score": round(env_score, 2),
                "confidence": confidence,
                "contribution": contribution,
                "severity": vuln.severity.value if vuln.severity else "low",
                "reason": reason,
                "url": vuln.url or "",
            })

        # ── Port-exposure contributions (kept for infra scans) ─────────────
        for asset in scan.assets:
            for service in asset.services:
                port_data = UnifiedRiskEngine.HIGH_RISK_PORTS.get(service.port)
                if port_data:
                    name, weight = port_data
                    # Use a conservative CVSS-like score scaled from the weight
                    port_score = round(weight * 0.3, 2)  # max weight 20 → ~6.0
                    total_score += port_score
                    breakdown.append({
                        "vuln_id": None,
                        "cvss_vector": None,
                        "cvss_env_score": port_score,
                        "confidence": 1.0,
                        "contribution": port_score,
                        "severity": "high" if weight >= 15 else "medium",
                        "reason": f"Exposed {name} service (port {service.port}) on {asset.ip_address}",
                        "url": f"{service.protocol or 'tcp'}://{asset.ip_address}:{service.port}",
                    })

        final_score = round(min(100.0, total_score), 2)
        breakdown.sort(key=lambda x: x["contribution"], reverse=True)

        return {"score": final_score, "breakdown": breakdown}

    def calculate_health_score(self, scan: Scan) -> float:
        """
        Legacy-inspired Health Score (100 = Safe, 0 = Dangerous).
        Provides a better "At-a-glance" metric for SME owners.
        """
        score_val = 100.0
        
        # 1. Vulnerability Penalty
        for vuln in scan.vulnerabilities:
            if vuln.severity == SeverityLevel.CRITICAL:
                score_val -= 20.0
            elif vuln.severity == SeverityLevel.HIGH:
                score_val -= 10.0
            elif vuln.severity == SeverityLevel.MEDIUM:
                score_val -= 5.0
        
        # 2. Port Penalty
        for asset in scan.assets:
            for service in asset.services:
                if service.state == 'open' and service.port in [21, 23, 445, 3389]:
                    score_val -= 15.0

        # 3. Cap
        if scan.vulnerabilities and score_val > 90.0:
            score_val = 90.0

        return max(0.0, score_val)

    async def update_scan_risk(self, scan_id: str) -> float:
        """Calculates and saves Risk score, Health score, and the CVSS breakdown."""
        _s_res = await self.db.execute(
            select(Scan)
            .options(
                selectinload(Scan.vulnerabilities),
                selectinload(Scan.assets).selectinload(ScanAsset.services),
                selectinload(Scan.target)
            )
            .filter(Scan.id == scan_id)
        )
        scan = _s_res.scalars().first()

        if scan:
            result = self.calculate_scan_risk_v2(scan)
            risk_score = result["score"]
            health_score = self.calculate_health_score(scan)

            scan.risk_score = risk_score
            scan.risk_breakdown = result  # {"score": ..., "breakdown": [...]}

            if not isinstance(scan.agent_thoughts, dict):
                scan.agent_thoughts = {}
            thoughts: dict = scan.agent_thoughts
            thoughts["health_score"] = health_score
            scan.agent_thoughts = thoughts

            await self.db.commit()
            logger.info("Updated scores for scan %s: Risk=%.2f, Health=%.2f", scan_id, risk_score, health_score)
            return risk_score
        return 0.0

    async def generate_action_items(self, scan_id: str):
        """
        Deterministic task generation.
        Translates raw findings into ActionItem records.
        """
        _s_res = await self.db.execute(
            select(Scan)
            .options(
                selectinload(Scan.vulnerabilities),
                selectinload(Scan.assets).selectinload(ScanAsset.services)
            )
            .filter(Scan.id == scan_id)
        )
        scan = _s_res.scalars().first()
        
        if not scan:
            return []

        new_actions = []
        
        # 1. Create actions from HIGH/CRITICAL vulnerabilities
        for vuln in scan.vulnerabilities:
            if vuln.severity in [SeverityLevel.CRITICAL, SeverityLevel.HIGH]:
                title = vuln.title or f"Fix {vuln.type or 'Vulnerability'}"
                description = vuln.description or f"Critical security issue detected on {vuln.url or 'target'}."
                
                # Deduplicate
                _e_res = await self.db.execute(
                    select(ActionItem).filter(
                        ActionItem.scan_id == scan_id,
                        ActionItem.title == title
                    )
                )
                existing = _e_res.scalars().first()
                
                if not existing:
                    action = ActionItem(
                        scan_id=scan_id,
                        title=title,
                        description=description,
                        priority=vuln.severity.value.upper(),
                        status="OPEN",
                        type="REMEDIATION",
                        created_at=datetime.utcnow()
                    )
                    self.db.add(action)
                    new_actions.append(action)

        # 2. Create actions for dangerously open ports
        for asset in scan.assets:
            for service in asset.services:
                ports_map = UnifiedRiskEngine.HIGH_RISK_PORTS
                if isinstance(ports_map, dict) and service.port in ports_map:
                    port_data = ports_map[service.port]
                    if isinstance(port_data, tuple) and len(port_data) >= 1:
                        name = port_data[0]
                        title = f"Secure {name} service on {asset.ip_address}"
                        description = f"The {name} service (Port {service.port}) is exposed. SMEs should restrict this or use a VPN."
                    
                    _e_res = await self.db.execute(
                        select(ActionItem).filter(
                            ActionItem.scan_id == scan_id,
                            ActionItem.title == title
                        )
                    )
                    existing = _e_res.scalars().first()
                    
                    if not existing:
                        action = ActionItem(
                            scan_id=scan_id,
                            title=title,
                            description=description,
                            priority="HIGH",
                            status="OPEN",
                            type="CONFIGURATION",
                            created_at=datetime.utcnow()
                        )
                        self.db.add(action)
                        new_actions.append(action)

        await self.db.commit()
        return new_actions
