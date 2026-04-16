"""
found 404 Database Models
Extended models for AI-driven DAST platform
"""
from sqlalchemy import Column, Integer, String, Float, DateTime, Enum, ForeignKey, Text, Boolean, JSON, Date, UniqueConstraint
from sqlalchemy.orm import relationship
from datetime import datetime
import enum
import uuid
from app.core.database import Base


# ============================================================================
# ENUMS
# ============================================================================

class ScanStatus(str, enum.Enum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class SeverityLevel(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class VulnStatus(str, enum.Enum):
    OPEN = "open"
    FIXED = "fixed"
    FALSE_POSITIVE = "false_positive"
    ACCEPTED = "accepted"


# ============================================================================
# TARGETS
# ============================================================================

class Target(Base):
    """
    Represents a target application/URL to be scanned.
    Maps to PentesterFlow spec 'targets' table.
    """
    __tablename__ = "targets"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = Column(String(255), nullable=False)
    base_url = Column(Text, nullable=False)
    source = Column(String(50), default="manual")  # manual, discovery, aws
    tech_stack = Column(JSON, nullable=True)  # Detected technologies
    auth_method = Column(String(50), nullable=True)  # none, basic, jwt, cookie
    auth_credentials = Column(JSON, nullable=True)  # Encrypted in production
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Business Context
    asset_value = Column(Enum("CRITICAL", "HIGH", "MEDIUM", "LOW", name="asset_value_enum"), default="MEDIUM")
    data_sensitivity = Column(Enum("PII", "FINANCIAL", "NONE", name="data_sensitivity_enum"), default="NONE")

    # ── Scope & safety (Phase 2.4 hardening) ──────────────────────────────────
    scope_allowlist = Column(JSON, nullable=True)
    # List of hostnames or CIDR ranges the scanner may touch.
    # Default (None): only the hostname extracted from base_url is allowed.
    # Example: ["example.com", "192.168.1.0/24"]
    max_rps = Column(Integer, default=10)
    # Maximum outbound HTTP requests per second for all agents scanning this target.
    max_concurrent_scans = Column(Integer, default=1)
    # Maximum simultaneous Celery scan tasks for this target.
    # Second scan is rejected with failure_reason="concurrency_limit".

    # Relationships
    scans = relationship("Scan", back_populates="target", cascade="all, delete-orphan")
    endpoints = relationship("Endpoint", back_populates="target", cascade="all, delete-orphan")



# ============================================================================
# SCANS
# ============================================================================

class Scan(Base):
    """
    Represents a security scan session.
    Updated for found 404.
    """
    __tablename__ = "scans"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    target_id = Column(String(36), ForeignKey("targets.id"), nullable=True)
    
    # Legacy field for backward compatibility
    target_url = Column(String, index=True, nullable=True)
    
    status = Column(Enum(ScanStatus), default=ScanStatus.QUEUED)
    scan_type = Column(String(50), default="full")  # full, quick, custom
    
    start_time = Column(DateTime, nullable=True)
    end_time = Column(DateTime, nullable=True)
    
    # AI Agent integration
    agent_thoughts = Column(JSON, nullable=True)  # Store agent reasoning chain
    configuration = Column(JSON, nullable=True)  # Scan configuration options
    
    # Legacy fields
    risk_score = Column(Float, default=0.0)
    started_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)

    # ── Phase 4.1: CVSS risk breakdown ───────────────────────────────────────
    risk_breakdown = Column(JSON, nullable=True)
    # Structured breakdown produced by UnifiedRiskEngine.calculate_scan_risk_v2()
    # Format: {"score": 74.3, "breakdown": [{"vuln_id": ..., "cvss": ..., ...}]}

    # ── Phase 2 reliability fields ─────────────────────────────────────────────
    failure_reason = Column(String(128), nullable=True)
    # Known values:
    #   "orphaned_on_restart"  — set by scan_reaper on startup
    #   "concurrency_limit"    — set by scan_tasks when Redis lock not acquired
    #   "<exception message>"  — first 120 chars of unexpected exception

    checkpoint = Column(String(32), nullable=True)
    # Ordered values (None → set sequentially as each phase completes):
    #   recon_done | attack_done | validated | risk_scored | reported
    # Used by run_full_scan to skip phases already completed on a Celery retry.

    # Relationships
    target = relationship("Target", back_populates="scans")
    vulnerabilities = relationship("Vulnerability", back_populates="scan", cascade="all, delete-orphan")
    agent_logs = relationship("AgentLog", back_populates="scan", cascade="all, delete-orphan")
    assets = relationship("ScanAsset", back_populates="scan", cascade="all, delete-orphan")
    actions = relationship("ActionItem", back_populates="scan", cascade="all, delete-orphan")

    @property
    def vulnerabilities_count(self):
        return len(self.vulnerabilities)

    @property
    def assets_count(self):
        return len(self.assets)

    @property
    def target_display(self):
        if self.target_url:
            return self.target_url
        if self.target:
            return self.target.base_url
        return "Unknown"


# ============================================================================
# VULNERABILITIES
# ============================================================================

class Vulnerability(Base):
    """
    Stores discovered vulnerabilities with AI validation.
    Updated for found 404.
    """
    __tablename__ = "vulnerabilities"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id = Column(String(36), ForeignKey("scans.id"))
    
    type = Column(String(100), nullable=True)  # SQLi, XSS, BOLA, IDOR, etc.
    severity = Column(Enum(SeverityLevel), default=SeverityLevel.LOW)
    status = Column(Enum(VulnStatus), default=VulnStatus.OPEN)
    
    url = Column(Text, nullable=False)
    parameter = Column(Text, nullable=True)
    
    # Evidence and validation
    evidence = Column(JSON, nullable=True)  # Request/response pairs
    confidence_score = Column(Float, nullable=True)  # 0-1 confidence
    ai_validation_result = Column(JSON, nullable=True)  # LLM analysis
    
    # Remediation & Workflow
    proof_of_concept = Column(Text, nullable=True)
    remediation = Column(Text, nullable=True)
    ticket_id = Column(String(100), nullable=True) # Jira/Linear ID
    assigned_to = Column(String(100), nullable=True) # User email or ID
    
    # Legacy fields for backward compat
    host = Column(String, nullable=True)
    port = Column(Integer, nullable=True)
    protocol = Column(String, nullable=True)
    service = Column(String, nullable=True)
    cve_id = Column(String, nullable=True)
    description = Column(Text, nullable=True)
    
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Simplified fields for non-technical users
    title = Column(String(255), nullable=True) # Explicit title (e.g. "Log4j RCE")
    simplified_description = Column(Text, nullable=True) # AI-generated simple explanation
    remediation_steps = Column(Text, nullable=True) # Actionable steps

    # ── Nuclei evidence fields (Phase 1.2 hardening) ──────────────────────────
    raw_request = Column(Text, nullable=True)
    raw_response = Column(Text, nullable=True)
    evidence_hash = Column(String(64), nullable=True)
    detected_by = Column(String(32), nullable=True)
    template_id = Column(String(128), nullable=True)

    # ── Phase 4.1: CVSS fields ─────────────────────────────────────────────────
    cvss_vector = Column(String(128), nullable=True)   # e.g. "CVSS:3.1/AV:N/AC:L/..."
    cvss_score = Column(Float, nullable=True)          # Parsed base score 0-10

    # ── Phase 4.2: Finding deduplication FK ───────────────────────────────────
    finding_id = Column(String(36), ForeignKey("findings.id"), nullable=True, index=True)

    scan = relationship("Scan", back_populates="vulnerabilities")
    finding = relationship("Finding", back_populates="observations")



# ============================================================================
# FINDINGS  (Phase 4.2 — deduplication lifecycle)
# ============================================================================

class FindingStatus(str, enum.Enum):
    OPEN = "open"
    FIXED = "fixed"
    ACCEPTED = "accepted"
    REOPENED = "reopened"
    FALSE_POSITIVE = "false_positive"


class Finding(Base):
    """
    Deduplicated, persistent record of a security issue per target.
    Vulnerabilities are *observations* of a Finding — the same issue
    re-detected on a second scan links to the existing Finding row.

    Fingerprint is sha256(target_id + vuln_type + normalised_url + parameter
                          + evidence_match_signature) and is unique per target.
    """
    __tablename__ = "findings"
    __table_args__ = (
        UniqueConstraint("target_id", "fingerprint", name="uq_finding_target_fingerprint"),
    )

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    target_id = Column(String(36), ForeignKey("targets.id"), nullable=True, index=True)
    fingerprint = Column(String(64), nullable=False, index=True)

    title = Column(String(255), nullable=False)
    vuln_type = Column(String(100), nullable=True)
    severity = Column(Enum(SeverityLevel), default=SeverityLevel.LOW)
    cvss_score = Column(Float, nullable=True)

    status = Column(Enum(FindingStatus), default=FindingStatus.OPEN)
    first_seen = Column(DateTime, default=datetime.utcnow, nullable=False)
    last_seen = Column(DateTime, default=datetime.utcnow, nullable=False)

    # SLA clock (Phase 4.3)
    due_date = Column(Date, nullable=True)

    # Ownership
    owner_user_id = Column(String(36), nullable=True)

    # Relationships
    target = relationship("Target")
    observations = relationship("Vulnerability", back_populates="finding")


# ============================================================================
# AGENT LOGS
# ============================================================================

class AgentLog(Base):
    """
    Logs AI agent actions and reasoning for transparency.
    New table for found 404.
    """
    __tablename__ = "agent_logs"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id = Column(String(36), ForeignKey("scans.id"))
    
    agent_name = Column(String(100))  # recon, attack, validation, reporting
    action = Column(String(100))  # crawl, test, validate, generate_report
    reasoning = Column(JSON, nullable=True)  # Chain of thought
    input_data = Column(JSON, nullable=True)
    output_data = Column(JSON, nullable=True)
    
    timestamp = Column(DateTime, default=datetime.utcnow)

    scan = relationship("Scan", back_populates="agent_logs")


# ============================================================================
# ENDPOINTS
# ============================================================================

class Endpoint(Base):
    """
    Discovered API endpoints for a target.
    New table for found 404.
    """
    __tablename__ = "endpoints"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    target_id = Column(String(36), ForeignKey("targets.id"))
    
    url = Column(Text, nullable=False)
    method = Column(String(10), default="GET")  # GET, POST, PUT, DELETE, etc.
    parameters = Column(JSON, nullable=True)  # Discovered params
    authentication_required = Column(Boolean, default=False)
    
    discovered_at = Column(DateTime, default=datetime.utcnow)
    last_tested = Column(DateTime, nullable=True)

    target = relationship("Target", back_populates="endpoints")


# ============================================================================
# LEGACY MODELS (kept for backward compatibility)
# ============================================================================

class ScanAsset(Base):
    """Legacy: Network assets discovered during scan"""
    __tablename__ = "scan_assets"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(String(36), ForeignKey("scans.id"), index=True)
    
    # Identity
    ip_address = Column(String, index=True)
    hostname = Column(String, nullable=True)
    mac_address = Column(String, nullable=True)
    mac_vendor = Column(String, nullable=True)
    
    # OS
    os_name = Column(String, nullable=True)
    os_accuracy = Column(Integer, nullable=True)
    
    # Meta
    device_type = Column(String, default="unknown")
    is_new = Column(String, default="false") # Flag for notification
    ai_insight = Column(JSON, nullable=True) # Generated by IntelligenceAgent
    
    scan = relationship("Scan", back_populates="assets")
    services = relationship("AssetService", back_populates="asset", cascade="all, delete-orphan")


class AssetService(Base):
    """
    Detailed running services found on an asset.
    """
    __tablename__ = "asset_services"

    id = Column(Integer, primary_key=True, index=True)
    asset_id = Column(Integer, ForeignKey("scan_assets.id", ondelete="CASCADE"), index=True)
    
    port = Column(Integer, nullable=False)
    protocol = Column(String(10), default="tcp") # tcp/udp
    state = Column(String(20), default="open") # open, filtered, closed
    
    # Identity
    service_name = Column(String(100), nullable=True)
    product = Column(String(100), nullable=True)
    version = Column(String(100), nullable=True)
    cpe = Column(String(255), nullable=True)
    extra_info = Column(Text, nullable=True)
    
    asset = relationship("ScanAsset", back_populates="services")


class NetworkAsset(Base):
    """Legacy: Persistent network inventory"""
    __tablename__ = "network_assets"
    
    id = Column(Integer, primary_key=True, index=True)
    ip_address = Column(String, unique=True, index=True)
    mac_address = Column(String, nullable=True, index=True)
    hostname = Column(String, nullable=True)
    os_name = Column(String, nullable=True)
    device_type = Column(String, default="unknown")
    status = Column(String, default="active")
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow)
    open_ports = Column(String, nullable=True)

    # Risk Engine Fields
    criticality = Column(Enum("CRITICAL", "HIGH", "MEDIUM", "LOW", name="asset_criticality_enum"), default="MEDIUM")
    risk_score = Column(Float, default=0.0)


class ActionItem(Base):
    """Legacy: Action items from scans"""
    __tablename__ = "action_items"
    
    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(String(36), ForeignKey("scans.id"))
    
    title = Column(String)
    description = Column(String)
    priority = Column(String)
    status = Column(String, default="OPEN")
    type = Column(String)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    scan = relationship("Scan", back_populates="actions")
