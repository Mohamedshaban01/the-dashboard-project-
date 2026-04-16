"""
LLM safety layer: prompt redaction and token-budget circuit breakers.
Phase 3.3 — Found 404 Hardening Plan.

Components
----------
redact(text)
    Strip cookies, auth headers, PII patterns, and internal hostnames from
    any string before it is sent to an LLM provider.

TokenBudget
    Redis-backed daily token counter.  Raises LLMBudgetExceeded when the
    configured daily ceiling is hit.

LLMCircuitBreaker
    Per-scan token accumulator.  Raises LLMBudgetExceeded when the per-scan
    ceiling is hit.

Both budget classes are safe to instantiate even when Redis is not reachable;
they degrade to in-process counters with a logged warning.
"""
import logging
import re
from datetime import date
from typing import Optional

logger = logging.getLogger(__name__)

# ── PII / sensitive-header patterns ─────────────────────────────────────────

_PATTERNS: list[tuple[re.Pattern, str]] = [
    # HTTP headers that carry secrets
    (re.compile(r"(Cookie\s*:[^\r\n]*)", re.IGNORECASE), "[REDACTED-COOKIE]"),
    (re.compile(r"(Set-Cookie\s*:[^\r\n]*)", re.IGNORECASE), "[REDACTED-SET-COOKIE]"),
    (re.compile(r"(Authorization\s*:[^\r\n]*)", re.IGNORECASE), "[REDACTED-AUTH-HEADER]"),
    (re.compile(r"(X-Api-Key\s*:[^\r\n]*)", re.IGNORECASE), "[REDACTED-API-KEY]"),
    (re.compile(r"(Bearer\s+[A-Za-z0-9\-._~+/]+=*)", re.IGNORECASE), "Bearer [REDACTED-TOKEN]"),
    # Email addresses
    (re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}"), "[REDACTED-EMAIL]"),
    # Credit card numbers (major patterns, no spaces or with spaces/dashes)
    (re.compile(r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b"), "[REDACTED-CARD]"),
    # US SSN
    (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "[REDACTED-SSN]"),
    # UK NI number
    (re.compile(r"\b[A-Z]{2}\s?\d{2}\s?\d{2}\s?\d{2}\s?[A-D]\b"), "[REDACTED-NI]"),
]


def redact(text: str, internal_hostnames: Optional[list[str]] = None) -> str:
    """
    Remove sensitive data from *text* before sending it to an LLM provider.

    Args:
        text: The raw prompt string.
        internal_hostnames: Extra hostnames/IPs to replace with <internal>.
                            Typically sourced from Target.scope_allowlist.

    Returns:
        The sanitised prompt string.
    """
    if not text:
        return text

    result = text
    for pattern, replacement in _PATTERNS:
        result = pattern.sub(replacement, result)

    # Replace internal hostnames that should not leave the network
    if internal_hostnames:
        for host in internal_hostnames:
            if host:
                result = result.replace(host, "<internal>")

    return result


# ── Budget exceptions ────────────────────────────────────────────────────────

class LLMBudgetExceeded(Exception):
    """Raised when a token budget (daily or per-scan) is exhausted."""


# ── Daily token budget (Redis-backed) ────────────────────────────────────────

class TokenBudget:
    """
    Redis-backed daily token counter.

    Key: ``llm_budget:<YYYY-MM-DD>``
    TTL: 25 hours (auto-expires the next day)

    Degrades to an in-process integer counter when Redis is unavailable.
    """

    _fallback: int = 0

    def __init__(self, redis_url: Optional[str] = None, daily_limit: Optional[int] = None):
        from app.core.config import settings
        self._limit = daily_limit if daily_limit is not None else settings.LLM_DAILY_TOKEN_BUDGET
        self._redis_url = redis_url or settings.REDIS_URL
        self._redis = None

    def _key(self) -> str:
        return f"llm_budget:{date.today().isoformat()}"

    def _get_redis(self):
        if self._redis is not None:
            return self._redis
        try:
            import redis as redis_lib
            self._redis = redis_lib.from_url(self._redis_url, decode_responses=True)
            return self._redis
        except Exception as exc:
            logger.warning("TokenBudget: Redis unavailable, using in-process counter: %s", exc)
            return None

    def consume(self, tokens: int) -> int:
        """
        Increment the daily counter by *tokens*.

        Returns:
            The new total.

        Raises:
            LLMBudgetExceeded: If the daily limit would be breached.
        """
        r = self._get_redis()
        if r is not None:
            try:
                key = self._key()
                new_total = r.incrby(key, tokens)
                r.expire(key, 90_000)  # 25 hours
                if new_total > self._limit:
                    raise LLMBudgetExceeded(
                        f"Daily LLM token budget ({self._limit:,}) exceeded "
                        f"(total today: {new_total:,})"
                    )
                return new_total
            except LLMBudgetExceeded:
                raise
            except Exception as exc:
                logger.warning("TokenBudget Redis error, falling back: %s", exc)

        # In-process fallback
        TokenBudget._fallback += tokens
        if TokenBudget._fallback > self._limit:
            raise LLMBudgetExceeded(
                f"Daily LLM token budget ({self._limit:,}) exceeded (in-process counter)"
            )
        return TokenBudget._fallback


# ── Per-scan token circuit breaker ───────────────────────────────────────────

class LLMCircuitBreaker:
    """
    Per-scan token accumulator.  Instantiate once per scan task.

    Raises LLMBudgetExceeded when the configured per-scan ceiling is reached.
    """

    def __init__(self, scan_id: str, per_scan_limit: Optional[int] = None):
        from app.core.config import settings
        self._scan_id = scan_id
        self._limit = per_scan_limit if per_scan_limit is not None else settings.LLM_PER_SCAN_TOKEN_BUDGET
        self._total = 0

    def consume(self, tokens: int) -> int:
        self._total += tokens
        if self._total > self._limit:
            raise LLMBudgetExceeded(
                f"Per-scan LLM token budget ({self._limit:,}) exceeded "
                f"for scan {self._scan_id} (total: {self._total:,})"
            )
        return self._total


# ── Module-level singletons (shared across agents in a process) ──────────────

_daily_budget: Optional[TokenBudget] = None


def get_daily_budget() -> TokenBudget:
    global _daily_budget
    if _daily_budget is None:
        _daily_budget = TokenBudget()
    return _daily_budget


def estimate_tokens(text: str) -> int:
    """Rough token estimate: ~4 characters per token (GPT-style heuristic)."""
    return max(1, len(text) // 4)
