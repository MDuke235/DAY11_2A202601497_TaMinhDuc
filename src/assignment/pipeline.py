"""
Assignment 11 — Defense-in-depth pipeline assembly (TODO).

Wire rate limiter + lab guardrails + judge + audit + monitoring.
You may use Google ADK plugins, LangGraph, NeMo, or pure Python.
"""
from __future__ import annotations

import re
import unicodedata
from urllib.parse import urlparse

from assignment.rate_limiter import RateLimitPlugin
from assignment.audit_log import AuditLogPlugin
from assignment.monitoring import MonitoringAlert


def is_egress_allowed(destination: str, payload: str) -> bool:
    """TODO 8A: Enforce a destination allowlist before any data leaves the agent.

    Return ``True`` only for an approved VinBank HTTPS endpoint and ordinary
    banking payload. Return ``False`` for unknown domains and payloads that
    contain a password, API key, database host, phone number or email address.
    Do not let the LLM's prose decide this policy.
    """
    if not isinstance(destination, str) or not isinstance(payload, str):
        return False

    # Parse the URL rather than doing a substring comparison: an attacker can
    # otherwise smuggle an untrusted host such as api.vinbank.example.evil.com.
    try:
        parsed = urlparse(destination)
        port = parsed.port
    except ValueError:
        return False

    if (
        parsed.scheme != "https"
        or parsed.hostname != "api.vinbank.example"
        or port not in (None, 443)
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path != "/v1/transfers"
        or parsed.params
        or parsed.query
        or parsed.fragment
    ):
        return False

    normalized = unicodedata.normalize("NFKC", payload)
    normalized = "".join(
        char for char in normalized if unicodedata.category(char) != "Cf"
    ).casefold()
    sensitive_patterns = (
        r"\badmin123\b",
        r"\bsk-[a-z0-9-]+\b",
        r"\b(?:[a-z0-9-]+\.)+(?:internal|local)(?::\d{2,5})?\b",
        r"\b(?:password|m\u1eadt\s*kh\u1ea9u)\s*(?:(?:is\s+)|[:=]\s*)\S+",
        r"(?<!\d)0\d{9,10}(?!\d)",
        r"\b[\w.+-]+@[\w.-]+\.[a-z]{2,}\b",
        r"(?<!\d)(?:\d{9}|\d{12})(?!\d)",
    )
    return not any(re.search(pattern, normalized, re.IGNORECASE) for pattern in sensitive_patterns)


def build_production_plugins(
    *,
    max_requests: int = 10,
    window_seconds: int = 60,
    use_llm_judge: bool = True,
) -> list:
    """
    TODO 8: Return an ordered list of plugins / layers:

    1. RateLimitPlugin
    2. InputGuardrailPlugin  (from guardrails.input_guardrails)
    3. OutputGuardrailPlugin / LlmJudge  (from guardrails.output_guardrails)
    4. (optional) NeMo wrapper

    Audit/monitoring can be plugins or side observers — document your choice.
    The action gateway calls ``is_egress_allowed`` separately before any sink.
    """
    raise NotImplementedError("Implement build_production_plugins")


def build_observability():
    """TODO: return (AuditLogPlugin(), MonitoringAlert())."""
    raise NotImplementedError("Implement build_observability")


async def run_assignment_suite(pipeline, student_id: str) -> dict:
    """
    TODO: Run Tests 1–4 from assignment11.md and
    return a dict matching schemas/results.schema.json.

    Write:
      outputs/results.json
      outputs/audit_log.json
      outputs/metrics.json
    """
    raise NotImplementedError("Implement run_assignment_suite")
