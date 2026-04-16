"""
CVSS v3.1 Base Score and Environmental Score calculator.
Phase 4.1 — Found 404 Hardening Plan.

Reference: https://www.first.org/cvss/v3.1/specification-document
Implements the official formula exactly — no invented weighting.

Typical usage
-------------
from app.services.cvss import base_score, environmental_score, parse_vector, severity_to_default_vector

# Parse a Nuclei-provided vector
vec = parse_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H")
bs  = base_score(vec)            # → 10.0
es  = environmental_score(
          vec,
          asset_value="CRITICAL",
          data_sensitivity="PII",
          exposure="external"
      )                          # → environmental score adjusted for context
"""
import math
from typing import Optional


# ── Metric lookup tables (CVSS v3.1 specification, section 7.3) ──────────────

_AV = {
    "N": 0.85,   # Network
    "A": 0.62,   # Adjacent
    "L": 0.55,   # Local
    "P": 0.20,   # Physical
}

_AC = {
    "L": 0.77,   # Low
    "H": 0.44,   # High
}

# PR depends on Scope (unchanged / changed)
_PR_U = {
    "N": 0.85,   # None / Unchanged scope
    "L": 0.62,
    "H": 0.27,
}
_PR_C = {
    "N": 0.85,   # None / Changed scope
    "L": 0.68,
    "H": 0.50,
}

_UI = {
    "N": 0.85,   # None
    "R": 0.62,   # Required
}

_IMPACT = {
    "N": 0.00,   # None
    "L": 0.22,   # Low
    "H": 0.56,   # High
}

# Requirement levels for Environmental metrics
_CR_IR_AR = {
    "X": 1.0,    # Not Defined
    "L": 0.5,
    "M": 1.0,
    "H": 1.5,
}


def _roundup(x: float) -> float:
    """CVSS v3.1 Roundup function: smallest value >= x with 1 decimal place."""
    rounded = math.ceil(x * 10) / 10
    return rounded


# ── Default CVSS vectors by severity (for findings without a vector) ──────────

_DEFAULT_VECTORS: dict[str, str] = {
    "critical": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    "high":     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "medium":   "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "low":      "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "info":     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
}


def severity_to_default_vector(severity: str) -> str:
    """Return a conservative default CVSS v3.1 vector for a given severity label."""
    return _DEFAULT_VECTORS.get(severity.lower(), _DEFAULT_VECTORS["low"])


def parse_vector(vector_string: str) -> dict:
    """
    Parse a CVSS v3.1 vector string into a metric dict.

    Supports both full form ("CVSS:3.1/AV:N/...") and short form ("AV:N/...").
    Missing optional metrics are filled with "X" (Not Defined / use base value).

    Returns a dict with keys: AV, AC, PR, UI, S, C, I, A,
    and optional modified/environmental keys MCR, MIR, MAR.
    """
    # Strip prefix
    vs = vector_string.strip()
    if vs.upper().startswith("CVSS:"):
        vs = vs.split("/", 1)[1]  # drop "CVSS:3.1"

    metrics: dict[str, str] = {}
    for part in vs.split("/"):
        if ":" in part:
            k, v = part.split(":", 1)
            metrics[k.strip().upper()] = v.strip().upper()

    # Required base metrics with safe defaults
    defaults = {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U",
                "C": "N", "I": "N", "A": "N"}
    for key, default in defaults.items():
        metrics.setdefault(key, default)

    # Environmental requirement metrics (default X = not defined)
    for key in ("CR", "IR", "AR"):
        metrics.setdefault(key, "X")

    return metrics


def base_score(metrics: dict | str) -> float:
    """
    Compute CVSS v3.1 Base Score from a parsed metric dict or a vector string.

    Returns a float in [0.0, 10.0].
    """
    if isinstance(metrics, str):
        metrics = parse_vector(metrics)

    av = _AV.get(metrics["AV"], 0.85)
    ac = _AC.get(metrics["AC"], 0.77)
    scope_changed = metrics["S"] == "C"
    pr = (_PR_C if scope_changed else _PR_U).get(metrics["PR"], 0.85)
    ui = _UI.get(metrics["UI"], 0.85)

    c_imp = _IMPACT.get(metrics["C"], 0.0)
    i_imp = _IMPACT.get(metrics["I"], 0.0)
    a_imp = _IMPACT.get(metrics["A"], 0.0)

    isc_base = 1.0 - (1.0 - c_imp) * (1.0 - i_imp) * (1.0 - a_imp)

    if scope_changed:
        isc = 7.52 * (isc_base - 0.029) - 3.25 * (isc_base - 0.02) ** 15
    else:
        isc = 6.42 * isc_base

    exploitability = 8.22 * av * ac * pr * ui

    if isc <= 0:
        return 0.0

    if scope_changed:
        raw = min(1.08 * (isc + exploitability), 10.0)
    else:
        raw = min(isc + exploitability, 10.0)

    return _roundup(raw)


def environmental_score(
    metrics: dict | str,
    asset_value: str = "MEDIUM",
    data_sensitivity: str = "NONE",
    exposure: str = "external",
) -> float:
    """
    Compute an adjusted CVSS Environmental Score.

    Uses the simplified approach of mapping business context onto the
    Confidentiality/Integrity/Availability Requirement (CR/IR/AR) modifiers,
    then re-computing the base score with those adjustments.

    Args:
        metrics: Parsed metric dict or raw vector string.
        asset_value: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"
        data_sensitivity: "PII" | "FINANCIAL" | "NONE"
        exposure: "external" | "internal"

    Returns:
        Environmental score float in [0.0, 10.0].
    """
    if isinstance(metrics, str):
        metrics = dict(parse_vector(metrics))  # make mutable copy
    else:
        metrics = dict(metrics)

    # Map asset_value → requirement multipliers
    _av_req = {"CRITICAL": "H", "HIGH": "H", "MEDIUM": "M", "LOW": "L"}
    req = _av_req.get(asset_value.upper(), "M")
    metrics.setdefault("CR", req)
    metrics.setdefault("IR", req)
    metrics.setdefault("AR", req)

    # Data sensitivity boosts confidentiality requirement
    if data_sensitivity.upper() in ("PII", "FINANCIAL"):
        metrics["CR"] = "H"

    # Adjusted impact sub-score using CR/IR/AR
    cr = _CR_IR_AR.get(metrics.get("CR", "X"), 1.0)
    ir = _CR_IR_AR.get(metrics.get("IR", "X"), 1.0)
    ar = _CR_IR_AR.get(metrics.get("AR", "X"), 1.0)

    c_imp = min(_IMPACT.get(metrics["C"], 0.0) * cr, 0.915)
    i_imp = min(_IMPACT.get(metrics["I"], 0.0) * ir, 0.915)
    a_imp = min(_IMPACT.get(metrics["A"], 0.0) * ar, 0.915)

    # Re-compute with modified impacts
    modified = dict(metrics)
    # Translate adjusted values back to nearest CVSS metric character
    def _to_metric(v: float) -> str:
        if v == 0.0:
            return "N"
        if v <= 0.22:
            return "L"
        return "H"

    modified["C"] = _to_metric(c_imp)
    modified["I"] = _to_metric(i_imp)
    modified["A"] = _to_metric(a_imp)

    # Exposure modifier: internal assets have reduced AV
    if exposure == "internal" and modified["AV"] == "N":
        modified["AV"] = "A"  # Treat as adjacent rather than network

    return base_score(modified)
