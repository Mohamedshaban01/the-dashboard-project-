"""phase4: CVSS columns, Finding table, SLA due_date

Revision ID: f1e2d3c4b5a6
Revises: e1f2a3b4c5d6
Create Date: 2026-04-15 00:01:00.000000

Phase 4 — Credible risk model:
  4.1  Add cvss_vector + cvss_score to vulnerabilities
       Add risk_breakdown JSONB to scans
  4.2  Create findings table with unique fingerprint per target
       Add finding_id FK on vulnerabilities
  4.3  due_date already on findings table (created above)
"""
from alembic import op
import sqlalchemy as sa

revision = "f1e2d3c4b5a6"
down_revision = "e1f2a3b4c5d6"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # ── 4.1: CVSS columns on vulnerabilities ─────────────────────────────────
    op.add_column("vulnerabilities", sa.Column("cvss_vector", sa.String(128), nullable=True))
    op.add_column("vulnerabilities", sa.Column("cvss_score",  sa.Float(),      nullable=True))

    # ── 4.1: risk_breakdown on scans ─────────────────────────────────────────
    op.add_column("scans", sa.Column("risk_breakdown", sa.JSON(), nullable=True))

    # ── 4.2: findings table ───────────────────────────────────────────────────
    # Create enum types via raw SQL using IF NOT EXISTS guards.
    # severitylevel may already exist from Base.metadata.create_all() on older DBs.
    op.execute(
        "DO $$ BEGIN "
        "  CREATE TYPE severitylevel AS ENUM ('critical','high','medium','low','info'); "
        "EXCEPTION WHEN duplicate_object THEN NULL; "
        "END $$"
    )
    op.execute(
        "DO $$ BEGIN "
        "  CREATE TYPE findingstatus AS ENUM ('open','fixed','accepted','reopened','false_positive'); "
        "EXCEPTION WHEN duplicate_object THEN NULL; "
        "END $$"
    )
    op.execute("""
        CREATE TABLE IF NOT EXISTS findings (
            id VARCHAR(36) PRIMARY KEY,
            target_id VARCHAR(36) REFERENCES targets(id),
            fingerprint VARCHAR(64) NOT NULL,
            title VARCHAR(255) NOT NULL,
            vuln_type VARCHAR(100),
            severity severitylevel,
            cvss_score FLOAT,
            status findingstatus NOT NULL DEFAULT 'open',
            first_seen TIMESTAMP NOT NULL DEFAULT NOW(),
            last_seen TIMESTAMP NOT NULL DEFAULT NOW(),
            due_date DATE,
            owner_user_id VARCHAR(36),
            CONSTRAINT uq_finding_target_fingerprint UNIQUE (target_id, fingerprint)
        )
    """)
    op.execute("CREATE INDEX IF NOT EXISTS ix_findings_target_id   ON findings(target_id)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_findings_fingerprint ON findings(fingerprint)")

    # ── 4.2: finding_id FK on vulnerabilities ─────────────────────────────────
    op.add_column(
        "vulnerabilities",
        sa.Column("finding_id", sa.String(36), sa.ForeignKey("findings.id"), nullable=True),
    )
    op.execute("CREATE INDEX IF NOT EXISTS ix_vulns_finding_id ON vulnerabilities(finding_id)")


def downgrade() -> None:
    op.drop_index("ix_vulns_finding_id",       table_name="vulnerabilities")
    op.drop_column("vulnerabilities", "finding_id")
    op.drop_index("ix_findings_fingerprint",   table_name="findings")
    op.drop_index("ix_findings_target_id",     table_name="findings")
    op.drop_table("findings")
    op.execute("DROP TYPE IF EXISTS findingstatus")
    op.drop_column("scans", "risk_breakdown")
    op.drop_column("vulnerabilities", "cvss_score")
    op.drop_column("vulnerabilities", "cvss_vector")
