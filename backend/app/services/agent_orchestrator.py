"""
PentesterFlow AI Agent Orchestration
Multi-agent system for intelligent security testing
"""
import json
import logging
from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional
from datetime import datetime
from enum import Enum

import google.generativeai as genai
from app.core.config import settings
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.models.scan import AgentLog, Scan, Vulnerability, Endpoint, SeverityLevel, VulnStatus
# Removed legacy integrations (Wazuh, Elastic, SOAR) as they were deprecated.
# from app.services.wazuh_integration import wazuh_service
# from app.services.elastic_integration import elastic_service
# from app.services.soar_orchestrator import soar_service
from app.services.unified_risk_engine import UnifiedRiskEngine
from app.services.ws_manager import manager

logger = logging.getLogger(__name__)


# ============================================================================
# BASE AGENT
# ============================================================================

class AgentState(str, Enum):
    IDLE = "idle"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class BaseAgent(ABC):
    """Abstract base class for all PentesterFlow agents"""
    
    def __init__(self, name: str, scan_id: str, db_session: AsyncSession, max_rps: int = 10):
        self.name = name
        self.scan_id = scan_id
        self.db = db_session
        self.state = AgentState.IDLE
        self.llm = None

        # ── Rate limiter (Phase 2.4 hardening) ──────────────────────────────
        # Shared across all HTTP calls made by this agent instance.
        # max_rps is read from Target.max_rps by the orchestrator and passed down.
        try:
            from aiolimiter import AsyncLimiter
            self.rate_limiter: Optional[Any] = AsyncLimiter(max(1, max_rps), time_period=1)
        except ImportError:
            # aiolimiter not yet installed — degrade gracefully (no rate limiting)
            self.rate_limiter = None
            logger.warning("aiolimiter not installed — RPS rate limiting is disabled.")

        # Initialize LLM if available
        if settings.GEMINI_API_KEY:
            genai.configure(api_key=settings.GEMINI_API_KEY)
            try:
                self.llm = genai.GenerativeModel('gemini-2.0-flash')
            except Exception:
                self.llm = genai.GenerativeModel('gemini-pro')
    
    async def log_action(self, action: str, reasoning: Optional[Dict] = None, 
                   input_data: Optional[Dict] = None, output_data: Optional[Dict] = None):
        """Log agent action to database for transparency"""
        log_entry = AgentLog(
            scan_id=self.scan_id,
            agent_name=self.name,
            action=action,
            reasoning=reasoning,
            input_data=input_data,
            output_data=output_data
        )
        self.db.add(log_entry)
        await self.db.commit()
        await manager.broadcast(f"[{self.name.upper()}] {action}")
        logger.info(f"[{self.name}] {action}")
    
    def llm_reason(self, prompt: str, internal_hostnames: list[str] | None = None) -> str:
        """
        Send a redacted prompt to the LLM and return the response.

        Phase 3.3 hardening:
        - LLM_PROVIDER=none short-circuits immediately (no network call).
        - Prompt is redacted for cookies, auth headers, PII, and internal hosts
          before leaving the process.
        - Both the daily budget and the per-scan circuit breaker are checked;
          if either is exceeded, an empty string is returned so the caller's
          deterministic path still works.
        """
        if settings.LLM_PROVIDER == "none":
            return ""

        llm = self.llm
        if llm is None:
            return "[LLM not configured - demo mode]"

        # ── Redact sensitive data ────────────────────────────────────────────
        from app.services.llm_guard import (
            LLMBudgetExceeded, estimate_tokens, get_daily_budget, redact,
        )
        safe_prompt = redact(prompt, internal_hostnames=internal_hostnames)

        # ── Check budgets ────────────────────────────────────────────────────
        estimated = estimate_tokens(safe_prompt)
        try:
            get_daily_budget().consume(estimated)
            if hasattr(self, "_circuit_breaker") and self._circuit_breaker is not None:
                self._circuit_breaker.consume(estimated)
        except LLMBudgetExceeded as exc:
            logger.error("LLM budget exceeded — skipping LLM call: %s", exc)
            return ""

        try:
            response = llm.generate_content(safe_prompt)
            return str(response.text)
        except Exception as e:
            logger.error(f"LLM error: {e}")
            return f"[LLM error: {str(e)}]"
    
    @abstractmethod
    async def execute(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Execute the agent's main task"""
        raise NotImplementedError("Each agent must implement execute")


# ============================================================================
# RECONNAISSANCE AGENT
# ============================================================================

class ReconAgent(BaseAgent):
    """
    Crawls application, discovers endpoints, and profiles tech stack.
    Uses Playwright for JS rendering (or falls back to requests).
    """

    def __init__(self, scan_id: str, db_session=None, browser_context=None, max_rps: int = 10):
        super().__init__("recon_agent", scan_id, db_session, max_rps=max_rps)
        self.browser_context = browser_context

    async def execute(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute reconnaissance on target.

        Args:
            context: {target_url: str, auth_credentials: dict, scope_guard: ScopeGuard}

        Returns:
            {endpoints: list, tech_stack: dict, forms: list}
        """
        self.state = AgentState.RUNNING
        target_url = context.get("target_url", "")
        scope_guard = context.get("scope_guard")  # ScopeGuard | None

        await self.log_action(
            action="start_recon",
            input_data={"target_url": target_url},
            reasoning={"goal": "Discover all endpoints and understand application structure"}
        )
        
        discovery_result = {
            "endpoints": [],
            "tech_stack": {},
            "assets": []
        }
        
        try:
            # INTEGRATION: Infrastructure Recon (Nmap)
            # This ensures we find ports like 6379 (Redis) even if they aren't linked in web pages
            from app.services.nmap_wrapper import NmapWrapper
            from urllib.parse import urlparse
            
            parsed = urlparse(target_url)
            clean_target = parsed.hostname or parsed.path.split('/')[0]
            
            logger.info(f"[{self.name}] Running infrastructure recon on {clean_target}")
            scanner = NmapWrapper()
            nmap_results = scanner.scan_target(clean_target, "quick")
            discovery_result["assets"] = nmap_results

            # Standard web crawling...
            discovered_endpoints = []
            tech_stack = {}
            forms = []
            # Try Playwright-based crawling
            # Try Playwright-based crawling
            playwright_success = False
            if self.browser_context:
                try:
                    from playwright.async_api import Error as PlaywrightError
                    import asyncio
                    
                    page = await self.browser_context.new_page()
                    
                    # Two-tier wait_until strategy
                    try:
                        await page.goto(target_url, wait_until="networkidle", timeout=15000)
                    except (PlaywrightError, asyncio.TimeoutError, Exception):
                        # Fallback to domcontentloaded for slower apps
                        await page.goto(target_url, wait_until="domcontentloaded", timeout=15000)
                    
                    # Extract all links
                    links = await page.eval_on_selector_all(
                        "a[href]",
                        "elements => elements.map(el => el.href)"
                    )
                    
                    # Extract forms
                    form_elements = await page.eval_on_selector_all(
                        "form",
                        """forms => forms.map(form => ({
                            action: form.action,
                            method: form.method || 'GET',
                            inputs: Array.from(form.querySelectorAll('input')).map(i => ({
                                name: i.name,
                                type: i.type,
                                id: i.id
                            }))
                        }))"""
                    )
                    forms = form_elements
                    
                    # Detect tech stack from headers and page content
                    response = await page.goto(target_url)
                    headers = response.headers if response else {}
                    
                    tech_stack = self._detect_tech_stack(headers, await page.content())
                    
                    # Filter and dedupe links — scope_guard drops out-of-scope URLs
                    for link in links:
                        if link in [e["url"] for e in discovered_endpoints]:
                            continue
                        if scope_guard and not scope_guard.is_in_scope(link):
                            continue  # silently drop — cross-origin links are expected
                        discovered_endpoints.append({
                            "url": link,
                            "method": "GET",
                            "parameters": {}
                        })

                    await page.close()
                    playwright_success = True
                    
                except Exception as e:
                    logger.warning(f"[{self.scan_id}] Playwright crawler error: {e}")
                    # Allow fallback
            
            if not playwright_success:
                # Fallback to simple requests-based discovery
                import httpx
                async with httpx.AsyncClient() as client:
                    response = await client.get(target_url, follow_redirects=True, timeout=30)
                    tech_stack = self._detect_tech_stack(dict(response.headers), response.text)
                    discovered_endpoints.append({
                        "url": target_url,
                        "method": "GET",
                        "parameters": {}
                    })
            
            # Save discovered endpoints to database
            _scan_res = await self.db.execute(select(Scan).filter(Scan.id == self.scan_id))
            scan = _scan_res.scalars().first()
            if scan and scan.target_id:
                # Safe slicing for linter
                max_ep = min(50, len(discovered_endpoints))
                safe_endpoints = [discovered_endpoints[i] for i in range(max_ep)]
                async with self.db.begin():
                    for ep in safe_endpoints:
                        endpoint = Endpoint(
                            target_id=scan.target_id,
                            url=ep["url"],
                            method=ep["method"],
                            parameters=ep.get("parameters"),
                            authentication_required=False
                        )
                        self.db.add(endpoint)
            
            self.state = AgentState.COMPLETED
            
            result = {
                "endpoints": discovered_endpoints,
                "tech_stack": tech_stack,
                "forms": forms,
                "assets": discovery_result.get("assets", []),
                "total_discovered": len(discovered_endpoints)
            }
            
            await self.log_action(
                action="recon_complete",
                output_data=result,
                reasoning={"analysis": f"Discovered {len(discovered_endpoints)} endpoints"}
            )
            
            return result
            
        except Exception as e:
            self.state = AgentState.FAILED
            await self.log_action(
                action="recon_failed",
                output_data={"error": str(e)}
            )
            return {"error": str(e), "endpoints": [], "tech_stack": {}}
    
    def _detect_tech_stack(self, headers: Dict, content: str) -> Dict:
        """Detect technologies from headers and page content"""
        tech = {}
        
        # Server header
        if "server" in headers:
            tech["server"] = headers["server"]
        if "x-powered-by" in headers:
            tech["powered_by"] = headers["x-powered-by"]
        
        # Common frameworks from content
        content_lower = content.lower()
        if "react" in content_lower or "_react" in content_lower:
            tech["frontend"] = "React"
        elif "vue" in content_lower:
            tech["frontend"] = "Vue.js"
        elif "angular" in content_lower:
            tech["frontend"] = "Angular"
        
        if "wordpress" in content_lower or "wp-content" in content_lower:
            tech["cms"] = "WordPress"
        elif "drupal" in content_lower:
            tech["cms"] = "Drupal"
        
        return tech


# ============================================================================
# ATTACK AGENT
# ============================================================================

class AttackAgent(BaseAgent):
    """
    Executes vulnerability scanning via Nuclei.

    Phase 1.2 hardening: the previous implementation used hardcoded
    SQLi/XSS/SSRF/BOLA payloads and port-number heuristics.  These were
    neither DAST nor defensible — Nuclei findings had no raw evidence.

    This version delegates entirely to NucleiWrapper and stores
    raw_request / raw_response / evidence_hash on every Vulnerability
    so findings are auditable and deduplicable.
    """

    def __init__(self, scan_id: str, db_session=None, max_rps: int = 10):
        super().__init__("attack_agent", scan_id, db_session, max_rps=max_rps)

        # Maps Nmap service names → Nuclei template tags
        # Used to narrow template selection based on what Recon discovered.
        self.SERVICE_TO_TEMPLATE: Dict[str, List[str]] = {
            "http":       ["tags:cve,exposures,misconfiguration", "tags:default-logins,takeovers"],
            "https":      ["tags:cve,exposures,misconfiguration", "tags:ssl,takeovers"],
            "http-proxy": ["tags:misconfiguration,exposures"],
            "ftp":        ["tags:default-logins,misconfiguration,cve"],
            "ssh":        ["tags:default-logins,misconfiguration"],
            "smtp":       ["tags:misconfiguration,cve"],
            "mysql":      ["tags:default-logins,misconfiguration"],
            "postgresql": ["tags:default-logins,misconfiguration"],
            "redis":      ["tags:default-logins,misconfiguration"],
            "smb":        ["tags:cve,misconfiguration"],
        }

    async def execute(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Run Nuclei against the target URL, persist findings with evidence.

        Args:
            context: {target_url: str, assets: list[dict]}

        Returns:
            {findings: list, tested_count: int, vulnerability_count: int}
        """
        import asyncio

        self.state = AgentState.RUNNING
        target_url: str = context.get("target_url", "")
        assets: List[Dict] = context.get("assets", [])
        scope_guard = context.get("scope_guard")  # ScopeGuard | None — blocks out-of-scope
        max_rps: int = context.get("max_rps", 10)  # Passed from orchestrator, read from Target

        await self.log_action(
            action="start_attack",
            input_data={"target_url": target_url, "asset_count": len(assets)},
            reasoning={"strategy": "Delegate to Nuclei with templates mapped from Nmap-discovered services"},
        )

        # ── Scope check before touching the network ─────────────────────────────
        if scope_guard:
            from app.services.scope_guard import ScopeViolation
            try:
                scope_guard.assert_in_scope(target_url)
            except ScopeViolation as sv:
                await self.log_action(
                    action="scope_violation",
                    input_data={"url": target_url},
                    reasoning={"reason": str(sv)},
                )
                return {"findings": [], "tested_count": 0, "vulnerability_count": 0,
                        "error": str(sv)}

        findings: List[Dict] = []

        try:
            from app.services.nuclei_wrapper import NucleiWrapper

            nuclei = NucleiWrapper()

            # ── Template selection from Nmap service map ──────────────────────
            targeted_templates: set = set()
            for host in assets:
                if not isinstance(host, dict):
                    continue
                for port_data in host.get("ports", []):
                    if not isinstance(port_data, dict):
                        continue
                    service = port_data.get("service", "unknown").lower()
                    if service in self.SERVICE_TO_TEMPLATE:
                        targeted_templates.update(self.SERVICE_TO_TEMPLATE[service])

            if not targeted_templates:
                targeted_templates.add("tags:cve,exposures")

            await self.log_action(
                action="template_selection",
                input_data={
                    "services": [
                        p.get("service")
                        for h in assets
                        for p in (h.get("ports", []) if isinstance(h, dict) else [])
                    ]
                },
                output_data={"templates": list(targeted_templates)},
                reasoning={"strategy": "Mapped discovered services to targeted Nuclei template tags"},
            )

            # ── Run Nuclei (blocking) in executor ─────────────────────────────────
            # max_rps is injected as -rate-limit N in nuclei_wrapper (Phase 2.4)
            loop = asyncio.get_event_loop()
            raw_findings: List[Dict] = await loop.run_in_executor(
                None,
                lambda: nuclei.scan_target(target_url, scan_type="full", max_rps=max_rps),
            )

            # ── Persist each finding with full evidence ────────────────────────
            for f in raw_findings:
                async with self.db.begin():
                    vuln = Vulnerability(
                        scan_id=self.scan_id,
                        type=f.get("type", "Unknown"),
                        severity=SeverityLevel(f.get("severity", "info") if f.get("severity", "info") in SeverityLevel._value2member_map_ else "info"),
                        status=VulnStatus.OPEN,
                        url=f.get("url") or target_url,
                        cve_id=f.get("cve_id"),
                        description=f.get("description"),
                        evidence=f.get("evidence"),
                        confidence_score=1.0,  # Nuclei = confirmed match, not heuristic
                        # Phase 1.2 evidence fields
                        raw_request=f.get("raw_request"),
                        raw_response=f.get("raw_response"),
                        evidence_hash=f.get("evidence_hash"),
                        detected_by=f.get("detected_by", "nuclei"),
                        template_id=f.get("template_id"),
                    )
                    self.db.add(vuln)
                findings.append(f)

            # ── Optional: LLM enrichment of descriptions (summaries only) ─────
            # The LLM never invents findings — it only rewrites descriptions
            # in plain English for non-technical IT managers.
            if self.llm and findings:
                cap = min(10, len(findings))
                for finding in findings[:cap]:
                    try:
                        summary = self.llm_reason(
                            f"Summarise this security finding in 2 sentences for a non-technical IT manager.\n"
                            f"Template: {finding.get('template_id')}\n"
                            f"Severity: {finding.get('severity')}\n"
                            f"URL: {finding.get('url')}\n"
                            f"Description: {finding.get('description')}"
                        )
                        finding["llm_summary"] = summary
                    except Exception as llm_err:
                        logger.debug(f"LLM enrichment failed for finding: {llm_err}")

            self.state = AgentState.COMPLETED
            result = {
                "findings": findings,
                "tested_count": len(raw_findings),
                "vulnerability_count": len(findings),
            }
            await self.log_action(
                action="attack_complete",
                output_data=result,
                reasoning={"summary": f"Nuclei found {len(findings)} issues on {target_url}"},
            )
            return result

        except Exception as exc:
            self.state = AgentState.FAILED
            await self.log_action(action="attack_failed", output_data={"error": str(exc)})
            return {"error": str(exc), "findings": [], "tested_count": 0}





# ============================================================================
# VALIDATION AGENT
# ============================================================================

class ValidationAgent(BaseAgent):
    """
    Deterministically validates findings by re-probing the target.

    Phase 1.3 hardening: the previous implementation sent each finding
    to the LLM and parsed "REAL" / "FALSE_POSITIVE" from the response.
    One bad prompt, one model change, and real vulnerabilities disappeared.

    This version uses validation_probe.reprobe() — it re-sends the stored
    raw_request, diffs the response with difflib, and decides deterministically.
    The LLM may add an optional written justification when
    settings.LLM_VALIDATION_ENABLED is True, but it NEVER overrides the reprobe.
    """

    def __init__(self, scan_id: str, db_session=None, max_rps: int = 10):
        super().__init__("validation_agent", scan_id, db_session, max_rps=max_rps)

    async def execute(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Reprobe every finding; mark non-reproducible ones as FALSE_POSITIVE.

        Args:
            context: {findings: list[dict]}
        Returns:
            {validated: list, false_positives: list, validated_count: int, filtered_count: int}
        """
        self.state = AgentState.RUNNING
        findings = context.get("findings", [])
        scope_guard = context.get("scope_guard")  # ScopeGuard | None

        await self.log_action(
            action="start_validation",
            input_data={"finding_count": len(findings)},
            reasoning={
                "goal": "Deterministic reprobe of every finding — "
                        "LLM provides optional commentary but never the verdict"
            },
        )

        validated = []
        false_positives = []

        from app.services.validation_probe import reprobe
        import httpx

        # Load the ORM rows for this scan so we can read stored evidence fields
        _v_res = await self.db.execute(
            select(Vulnerability).filter(Vulnerability.scan_id == self.scan_id)
        )
        # Key by (url, type) for fast lookup
        vuln_map: Dict[tuple, Vulnerability] = {
            (v.url, v.type): v for v in _v_res.scalars().all()
        }

        async with httpx.AsyncClient(follow_redirects=True, timeout=15) as client:
            for finding in findings:
                key = (finding.get("url"), finding.get("type"))
                vuln = vuln_map.get(key)

                # ── Scope check before every reprobe (Phase 2.4) ───────────────
                reprobe_url = finding.get("url", "")
                if scope_guard and reprobe_url:
                    from app.services.scope_guard import ScopeViolation
                    try:
                        scope_guard.assert_in_scope(reprobe_url)
                    except ScopeViolation as sv:
                        await self.log_action(
                            action="scope_violation",
                            input_data={"url": reprobe_url},
                            reasoning={"reason": str(sv)},
                        )
                        false_positives.append(finding)  # treat out-of-scope as unconfirmed
                        continue

                # ── Rate limiting before reprobe ───────────────────────────────
                if self.rate_limiter:
                    await self.rate_limiter.acquire()

                result = await reprobe(
                    raw_request=finding.get("raw_request") or (vuln.raw_request if vuln else None),
                    raw_response=finding.get("raw_response") or (vuln.raw_response if vuln else None),
                    url=finding.get("url", ""),
                    detected_by=finding.get("detected_by") or (vuln.detected_by if vuln else None),
                    template_id=finding.get("template_id") or (vuln.template_id if vuln else None),
                    http_client=client,
                )

                # ── Optional LLM justification (commentary only) ──────────────
                llm_notes = ""
                if settings.LLM_VALIDATION_ENABLED and self.llm:
                    try:
                        llm_notes = self.llm_reason(
                            f"In one sentence, justify why this finding is "
                            f"{'confirmed' if result.confirmed else 'a false positive'}:\n"
                            f"Type: {finding.get('type')}\n"
                            f"URL: {finding.get('url')}\n"
                            f"Reprobe diff ratio: {result.diff_ratio:.2f}\n"
                            f"Reason: {result.reason}"
                        )
                    except Exception:
                        pass

                # ── Persist verdict ──────────────────────────────────────────
                if vuln:
                    async with self.db.begin():
                        vuln.status = VulnStatus.OPEN if result.confirmed else VulnStatus.FALSE_POSITIVE
                        # Append validation audit trail to description
                        suffix = f"\n[Validation: {result.reason}, diff={result.diff_ratio:.2f}]"
                        if llm_notes:
                            suffix += f"\n[LLM notes: {llm_notes}]"
                        vuln.description = (vuln.description or "") + suffix

                if result.confirmed:
                    validated.append(finding)
                else:
                    false_positives.append(finding)

        self.state = AgentState.COMPLETED

        result_summary = {
            "validated": validated,
            "false_positives": false_positives,
            "validated_count": len(validated),
            "filtered_count": len(false_positives),
        }

        await self.log_action(
            action="validation_complete",
            output_data=result_summary,
            reasoning={
                "analysis": f"Reprobe: {len(validated)} confirmed, {len(false_positives)} rejected"
            },
        )

        return result_summary




# ============================================================================
# SIEM & SOAR AGENT (NEW)
# ============================================================================

class SIEMAgent(BaseAgent):
    """
    Pulls data from Wazuh/Elasticsearch, analyzes with Gemini, and triggers SOAR playbooks.
    """
    def __init__(self, scan_id: str, db_session=None):
        super().__init__("siem_agent", scan_id, db_session)

    async def execute(self, context: Dict[str, Any]) -> Dict[str, Any]:
        self.state = AgentState.RUNNING
        
        await self.log_action(action="start_siem_analysis", reasoning={"goal": "Analyze SIEM logs and trigger SOAR actions"})
        
        import os
        from typing import List
        elastic_alerts: List[Dict] = []
        wazuh_agents: List[Dict] = []
        
        if not os.environ.get("ELASTIC_URL"):
            await self.log_action(action="siem_error", output_data={"error": "ELASTIC_URL not configured in environment"})
            
        if not os.environ.get("WAZUH_URL"):
            await self.log_action(action="siem_error", output_data={"error": "WAZUH_URL not configured in environment"})
        
        findings = []
        actions_taken = []
        
        # 2. Analyze with LLM
        if elastic_alerts:
            # For demo, take first 5 alerts
            limit_count = min(5, len(elastic_alerts))
            safe_alerts = [elastic_alerts[i] for i in range(limit_count)]
            for alert in safe_alerts:
                prompt = f"""You are a SOC Analyst AI. Analyze this SIEM alert:
{json.dumps(alert)}
Is this a real threat? Reply exactly with format:
VERDICT: [THREAT/BENIGN]
CONFIDENCE: [0.0-1.0]
ACTION: [BLOCK_IP/ISOLATE_HOST/NONE]
TARGET: [IP or Agent ID]
REASON: [Brief explanation]
"""
                response = self.llm_reason(prompt)
                
                if "THREAT" in response:
                    # Parse action
                    action_line = [line for line in response.split('\\n') if "ACTION:" in line]
                    target_line = [line for line in response.split('\\n') if "TARGET:" in line]
                    
                    if action_line and target_line:
                        action = action_line[0].split("ACTION:")[1].strip()
                        target = target_line[0].split("TARGET:")[1].strip()
                        
                        if action != "NONE":
                            # 3. Trigger SOAR (Placeholder)
                            success = False # await soar_service.trigger_playbook(...)
                            actions_taken.append({
                                "action": action,
                                "target": target,
                                "success": success
                            })
                            findings.append({"alert": alert, "analysis": response})
        
        self.state = AgentState.COMPLETED
        result = {
            "alerts_analyzed": len(elastic_alerts),
            "threats_found": len(findings),
            "soar_actions": actions_taken
        }
        await self.log_action(action="siem_analysis_complete", output_data=result)
        return result


# ============================================================================
# REPORTING AGENT
# ============================================================================

class ReportingAgent(BaseAgent):
    """
    Generates human-readable reports with PoC and remediation.
    """
    
    def __init__(self, scan_id: str, db_session=None):
        super().__init__("reporting_agent", scan_id, db_session)
    
    async def execute(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate comprehensive security report.
        
        Args:
            context: {validated_findings: list, scan_summary: dict}
        
        Returns:
            {report_markdown: str, executive_summary: str, poc_scripts: list}
        """
        self.state = AgentState.RUNNING
        scan_summary = context.get("scan_summary", {})
        
        # Explicit DB query to filter false positives
        _f_res = await self.db.execute(
            select(Vulnerability).filter(
                Vulnerability.scan_id == self.scan_id,
                Vulnerability.status != VulnStatus.FALSE_POSITIVE
            )
        )
        findings_orm = _f_res.scalars().all()
        findings = [
            {
                "type": f.type,
                "severity": getattr(f.severity, "value", "unknown") if f.severity else "unknown",
                "url": f.url,
                "parameter": f.parameter,
                "confidence": f.confidence_score,
                "description": f.description
            } for f in findings_orm
        ]
        
        await self.log_action(
            action="start_reporting",
            input_data={"finding_count": len(findings)},
            reasoning={"goal": "Generate executive summary and technical report"}
        )
        
        # Generate executive summary with LLM
        executive_summary = await self._generate_executive_summary(findings, scan_summary)
        
        # Generate PoC scripts for critical findings
        poc_scripts = []
        for finding in findings:
            if finding.get("severity") in ["critical", "high"]:
                poc = await self._generate_poc(finding)
                poc_scripts.append(poc)
                
                # Update database with PoC
                async with self.db.begin():
                    _v_res = await self.db.execute(select(Vulnerability).filter(
                        Vulnerability.scan_id == self.scan_id,
                        Vulnerability.url == finding["url"],
                        Vulnerability.type == finding["type"]
                    ))
                    vuln = _v_res.scalars().first()
                    if vuln:
                        vuln.proof_of_concept = poc["script"]
                        vuln.remediation = poc["remediation"]
        
        # Build full markdown report
        report_markdown = self._build_report(findings, executive_summary, poc_scripts, scan_summary)
        
        # Save to scan safely
        async with self.db.begin():
            _s_res = await self.db.execute(select(Scan).filter(Scan.id == self.scan_id))
            scan = _s_res.scalars().first()
            if scan:
                new_thoughts = {
                    "executive_summary": executive_summary,
                    "finding_count": len(findings),
                    "poc_count": len(poc_scripts)
                }
                # Type-safe assignment for linter
                scan.agent_thoughts = new_thoughts
        
        self.state = AgentState.COMPLETED
        
        result = {
            "report_markdown": report_markdown,
            "executive_summary": executive_summary,
            "poc_scripts": poc_scripts
        }
        
        await self.log_action(
            action="reporting_complete",
            output_data={"report_length": len(report_markdown)},
            reasoning={"summary": f"Generated report with {len(poc_scripts)} PoC scripts"}
        )
        
        return result
    
    async def _generate_executive_summary(self, findings: List, scan_summary: Dict) -> str:
        """Generate CEO-friendly executive summary"""
        critical_count = len([f for f in findings if f.get("severity") == "critical"])
        high_count = len([f for f in findings if f.get("severity") == "high"])
        
        prompt = f"""You are a cybersecurity expert writing for a non-technical CEO.

Scan Summary:
- Target: {scan_summary.get('target_url', 'Unknown')}
- Total Findings: {len(findings)}
- Critical: {critical_count}
- High: {high_count}

Write a 3-4 sentence executive summary that:
1. States the overall security posture (Good/Moderate/Poor)
2. Highlights the most concerning finding if any
3. Recommends immediate next steps

Use simple language, avoid jargon."""
        
        return self.llm_reason(prompt)
    
    async def _generate_poc(self, finding: Dict) -> Dict:
        """Generate proof-of-concept script for a finding"""
        vuln_type = finding.get("type", "Unknown")
        url = finding.get("url", "")
        
        # Simple PoC templates
        poc_templates = {
            "SQL Injection": f"""# SQL Injection PoC
# Target: {url}
import requests

payload = "' OR '1'='1"
response = requests.get(f"{url}?id={{payload}}")
print(f"Status: {{response.status_code}}")
print(f"Vulnerable: {{'error' in response.text.lower() or len(response.text) > 1000}}")
""",
            "Cross-Site Scripting (XSS)": f"""# XSS PoC
# Target: {url}
# Open in browser with payload in URL:
# {url}?q=<script>alert(document.domain)</script>
""",
            "Broken Object Level Authorization (BOLA)": f"""# BOLA/IDOR PoC
# Target: {url}
import requests

# Test accessing another user's resource
for user_id in range(1, 10):
    response = requests.get(f"{url.replace('/1', f'/{{user_id}}')}")
    if response.status_code == 200:
        print(f"User {{user_id}}: Accessible - potential BOLA!")
"""
        }
        
        remediation_templates = {
            "SQL Injection": "Use parameterized queries or prepared statements. Never concatenate user input directly into SQL queries.",
            "Cross-Site Scripting (XSS)": "Encode all user input before rendering in HTML. Use Content-Security-Policy headers.",
            "Broken Object Level Authorization (BOLA)": "Implement proper authorization checks. Validate that the authenticated user owns the requested resource."
        }
        
        return {
            "type": vuln_type,
            "script": poc_templates.get(vuln_type, f"# PoC for {vuln_type}\n# Manual testing required"),
            "remediation": remediation_templates.get(vuln_type, "Review and fix the vulnerability according to OWASP guidelines.")
        }
    
    def _build_report(self, findings: List, executive_summary: str, 
                      poc_scripts: List, scan_summary: Dict) -> str:
        """Build complete markdown report"""
        report = f"""# Security Assessment Report

**Target:** {scan_summary.get('target_url', 'Unknown')}  
**Date:** {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}  
**Scan ID:** {self.scan_id}

---

## Executive Summary

{executive_summary}

---

## Findings Summary

| Severity | Count |
|----------|-------|
| Critical | {len([f for f in findings if f.get('severity') == 'critical'])} |
| High | {len([f for f in findings if f.get('severity') == 'high'])} |
| Medium | {len([f for f in findings if f.get('severity') == 'medium'])} |
| Low | {len([f for f in findings if f.get('severity') == 'low'])} |

---

## Detailed Findings

"""
        for i, finding in enumerate(findings, 1):
            report += f"""### {i}. {finding.get('type', 'Unknown')}

- **Severity:** {finding.get('severity', 'Unknown').upper()}
- **URL:** `{finding.get('url', 'N/A')}`
- **Parameter:** {finding.get('parameter', 'N/A')}
- **Confidence:** {finding.get('confidence', 0) * 100:.0f}%

**Description:** {finding.get('description', 'No description')}

---

"""
        
        if poc_scripts:
            report += "## Proof of Concept Scripts\n\n"
            for poc in poc_scripts:
                report += f"""### {poc['type']}

```python
{poc['script']}
```

**Remediation:** {poc['remediation']}

---

"""
        
        return report


# ============================================================================
# ORCHESTRATOR
# ============================================================================

class AgentOrchestrator:
    """
    Coordinates all agents in the correct sequence.
    Implements the found 404 agent workflow.
    """
    
    def __init__(self, scan_id: str, db_session: AsyncSession):
        self.scan_id = scan_id
        self.db = db_session
    
    async def run_full_scan(self, target_url: str, auth_credentials: Optional[Dict] = None) -> Optional[Dict]:
        """
        Execute complete scan workflow through all agents.

        Phase 2.3 hardening: each stage is wrapped in a checkpoint guard.
        If a Celery retry is triggered after a phase completed, that phase
        is skipped and the pipeline resumes from where it left off.

        Order: 1. RECON -> 2. ATTACK -> 3. VALIDATION -> 4. REPORTING
        """
        # ── Ordered checkpoint ladder ─────────────────────────────────────────
        CHECKPOINT_ORDER = [
            None,           # not started
            "recon_done",
            "attack_done",
            "validated",
            "risk_scored",
            "reported",
        ]

        def _past(cp: str, current: Optional[str]) -> bool:
            """Return True if *current* checkpoint is at or after *cp*."""
            try:
                return CHECKPOINT_ORDER.index(current) >= CHECKPOINT_ORDER.index(cp)
            except ValueError:
                return False  # unknown value → treat as not reached

        async def _set_checkpoint(val: str) -> None:
            """Persist scan.checkpoint and commit immediately."""
            _row = (await self.db.execute(
                select(Scan).filter(Scan.id == self.scan_id)
            )).scalars().first()
            if _row:
                _row.checkpoint = val
                await self.db.commit()
            logger.info("[%s] Checkpoint: %s", self.scan_id, val)

        results: Dict = {
            "scan_id": self.scan_id,
            "target_url": target_url,
            "stages": {}
        }
        stages_dict = results["stages"]
        if not isinstance(stages_dict, dict):
            stages_dict = {}
            results["stages"] = stages_dict

        # ── Reload scan + target from DB ─────────────────────────────────────
        # Ensures checkpoint is current on Celery retry AND reads per-target
        # safety settings (max_rps, scope_allowlist) added in Phase 2.4.
        _s_res = await self.db.execute(
            select(Scan).filter(Scan.id == self.scan_id)
        )
        scan = _s_res.scalars().first()
        current_cp = scan.checkpoint if scan else None

        # ── Read per-target safety settings (Phase 2.4) ───────────────────────
        max_rps: int = 10               # default — overridden below if Target exists
        scope_allowlist: Optional[List] = None  # default — derived from target_url by ScopeGuard

        if scan and scan.target_id:
            from app.models.scan import Target
            _t_res = await self.db.execute(
                select(Target).filter(Target.id == scan.target_id)
            )
            _target = _t_res.scalars().first()
            if _target:
                max_rps = _target.max_rps or 10
                scope_allowlist = _target.scope_allowlist or None

        # Build one ScopeGuard for the entire scan — all agents share it.
        from app.services.scope_guard import ScopeGuard
        scope_guard = ScopeGuard(scope_allowlist=scope_allowlist, base_url=target_url)
        logger.info(
            "[%s] ScopeGuard allowlist=%s  max_rps=%d",
            self.scan_id, scope_guard.allowlist, max_rps,
        )

        if scan:
            from app.models.scan import ScanStatus
            scan.status = ScanStatus.RUNNING
            scan.started_at = scan.started_at or datetime.utcnow()
            scan.start_time = scan.started_at
            await self.db.commit()
            await manager.broadcast(f"[SYSTEM] Starting AI Scan for {target_url}")

        # ── Playwright context setup ──────────────────────────────────────────
        playwright = None
        browser = None
        browser_context = None

        try:
            from playwright.async_api import async_playwright
            playwright = await async_playwright().start()
            browser = await playwright.chromium.launch(headless=True)
            browser_context = await browser.new_context()
        except Exception as e:
            logger.debug(f"Failed to initialize Playwright: {e}")

        try:
            # ── Stage 1: Reconnaissance ───────────────────────────────────────
            if not _past("recon_done", current_cp):
                recon_agent = ReconAgent(
                    self.scan_id, self.db,
                    browser_context=browser_context,
                    max_rps=max_rps,
                )
                recon_result = await recon_agent.execute({
                    "target_url": target_url,
                    "auth_credentials": auth_credentials,
                    "scope_guard": scope_guard,   # agent calls guard.assert_in_scope(url)
                })
                if isinstance(stages_dict, dict):
                    stages_dict["recon"] = recon_result
                await _set_checkpoint("recon_done")
            else:
                logger.info("[%s] Checkpoint: skipping recon (already done)", self.scan_id)
                recon_result = {"assets": [], "endpoints": [], "tech_stack": {}, "forms": []}

            # DETERMINISTIC CHAINING: trigger specific scan modes based on Nmap results
            assets = recon_result.get("assets", [])
            has_web = False
            has_smb = False
            for asset in assets:
                if not isinstance(asset, dict):
                    continue
                for service in asset.get("ports", []):
                    if not isinstance(service, dict):
                        continue
                    if service.get("port") in [80, 443, 8080, 3000]:
                        has_web = True
                    if service.get("port") == 445:
                        has_smb = True

            logger.info(f"[{self.scan_id}] Deterministic chaining: web={has_web}, smb={has_smb}")

            # ── Stage 2: Attack (Nuclei-backed) ───────────────────────────────
            if not _past("attack_done", current_cp):
                attack_agent = AttackAgent(self.scan_id, self.db, max_rps=max_rps)
                attack_result = await attack_agent.execute({
                    "target_url": target_url,
                    "assets": recon_result.get("assets", []),
                    "chained_modes": {"web": has_web, "smb": has_smb},
                    "scope_guard": scope_guard,   # passed to nuclei and HTTP probes
                    "max_rps": max_rps,           # threaded into nuclei.scan_target()
                })
                if isinstance(stages_dict, dict):
                    stages_dict["attack"] = attack_result
                await _set_checkpoint("attack_done")
            else:
                logger.info("[%s] Checkpoint: skipping attack (already done)", self.scan_id)
                attack_result = {"findings": []}

            # ── Stage 3: Validation (deterministic reprobe) ───────────────────
            if not _past("validated", current_cp):
                validation_agent = ValidationAgent(self.scan_id, self.db, max_rps=max_rps)
                validation_result = await validation_agent.execute({
                    "findings": attack_result.get("findings", []),
                    "scope_guard": scope_guard,   # guards every reprobe request
                })
                if isinstance(stages_dict, dict):
                    stages_dict["validation"] = validation_result
                await _set_checkpoint("validated")
            else:
                logger.info("[%s] Checkpoint: skipping validation (already done)", self.scan_id)
                validation_result = {"validated": [], "false_positives": []}

            # ── Stage 4: Risk scoring ─────────────────────────────────────────
            risk_score = 0.0
            if not _past("risk_scored", current_cp):
                risk_engine = UnifiedRiskEngine(self.db)
                risk_score = await risk_engine.update_scan_risk(self.scan_id)
                await risk_engine.generate_action_items(self.scan_id)
                await _set_checkpoint("risk_scored")
            else:
                logger.info("[%s] Checkpoint: skipping risk scoring (already done)", self.scan_id)
                # Read existing risk score from DB
                _s_r = (await self.db.execute(select(Scan).filter(Scan.id == self.scan_id))).scalars().first()
                risk_score = _s_r.risk_score if _s_r else 0.0

            # ── Stage 5: Reporting ────────────────────────────────────────────
            if not _past("reported", current_cp):
                reporting_agent = ReportingAgent(self.scan_id, self.db)
                report_result = await reporting_agent.execute({
                    "scan_summary": {
                        "target_url": target_url,
                        "endpoint_count": len(recon_result.get("endpoints", [])),
                        "tech_stack": recon_result.get("tech_stack", {})
                    }
                })
                if isinstance(stages_dict, dict):
                    stages_dict["reporting"] = report_result

                # Optional AI asset advisory (non-blocking)
                try:
                    from app.services.intelligence_agent import IntelligenceAgent
                    ai_agent = IntelligenceAgent(self.db)
                    for asset in recon_result.get("assets", [])[:3]:
                        await ai_agent.analyze_asset(self.scan_id, asset)
                except Exception as ai_err:
                    logger.error(f"Failed to generate AI advisory: {ai_err}")

                await _set_checkpoint("reported")
            else:
                logger.info("[%s] Checkpoint: skipping reporting (already done)", self.scan_id)

            # ── Finalise: mark COMPLETED ───────────────────────────────────────
            _s_res2 = await self.db.execute(select(Scan).filter(Scan.id == self.scan_id))
            scan = _s_res2.scalars().first()
            if scan:
                scan.risk_score = risk_score
                scan.status = ScanStatus.COMPLETED
                scan.completed_at = datetime.utcnow()
                scan.end_time = scan.completed_at
                await self.db.commit()

            await manager.broadcast("[SYSTEM] Scan cycle complete.")
            results["status"] = "completed"

        except Exception as e:
            logger.error(f"Orchestrator failed: {e}")
            results["status"] = "failed"
            results["error"] = str(e)

            _s_res = await self.db.execute(select(Scan).filter(Scan.id == self.scan_id))
            scan = _s_res.scalars().first()
            if scan:
                from app.models.scan import ScanStatus
                scan.status = ScanStatus.FAILED
                scan.failure_reason = str(e)[:120]
                await self.db.commit()
            await manager.broadcast(f"[ERROR] Orchestrator failed: {e}")

        finally:
            if browser_context:
                await browser_context.close()
            if browser:
                await browser.close()
            if playwright:
                await playwright.stop()
            await self.db.close()

        return results



    async def run_siem_pipeline(self) -> Dict:
        """
        Execute just the SIEM analysis workflow (pull logs, analyze, trigger SOAR).
        Gated behind settings.SIEM_ENABLED — returns a 'disabled' status when off.
        """
        results = {
            "scan_id": self.scan_id,
            "stages": {}
        }

        if not settings.SIEM_ENABLED:
            results["status"] = "disabled"
            results["detail"] = (
                "SIEM integration disabled (SIEM_ENABLED=False). "
                "Set SIEM_ENABLED=true in .env to activate."
            )
            return results

        try:
            # Run SIEM Agent
            siem_agent = SIEMAgent(self.scan_id, self.db)
            siem_result = await siem_agent.execute({})
            # Use local narrowing for linter
            stages_dict = results["stages"]
            if isinstance(stages_dict, dict):
                stages_dict["siem"] = siem_result
            results["status"] = "completed"
        except Exception as e:
            logger.error(f"SIEM pipeline failed: {e}")
            results["status"] = "failed"
            results["error"] = str(e)
        finally:
            await self.db.close()

        return results

