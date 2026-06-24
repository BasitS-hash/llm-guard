"""Signature rules for the output scanner.

These run against model output to catch sensitive-data leakage (PII, secrets,
private keys), system-prompt disclosure, and refusal-bypass indicators. Secret
patterns are deliberately specific (provider key prefixes, private-key headers)
to keep false positives low; the redaction helper ensures matched secrets are
never echoed back verbatim in reports.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from llm_guard.models import Severity
from llm_guard.owasp import OwaspCategory


@dataclass(frozen=True)
class OutputRule:
    """A compiled signature rule for the output scanner."""

    rule_id: str
    name: str
    pattern: re.Pattern[str]
    category: OwaspCategory
    severity: Severity
    score: float
    description: str
    redact: bool = True


def _c(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern)


OUTPUT_RULES: tuple[OutputRule, ...] = (
    OutputRule(
        rule_id="OUT001",
        name="OpenAI-style API key",
        pattern=_c(r"\bsk-(?!ant-)(?:proj-)?[A-Za-z0-9_-]{20,}\b"),
        category=OwaspCategory.LLM02_SENSITIVE_INFO_DISCLOSURE,
        severity=Severity.CRITICAL,
        score=0.95,
        description="Leaks an OpenAI-style secret API key (sk-...).",
    ),
    OutputRule(
        rule_id="OUT002",
        name="Anthropic API key",
        pattern=_c(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b"),
        category=OwaspCategory.LLM02_SENSITIVE_INFO_DISCLOSURE,
        severity=Severity.CRITICAL,
        score=0.95,
        description="Leaks an Anthropic API key (sk-ant-...).",
    ),
    OutputRule(
        rule_id="OUT003",
        name="AWS access key id",
        pattern=_c(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
        category=OwaspCategory.LLM02_SENSITIVE_INFO_DISCLOSURE,
        severity=Severity.CRITICAL,
        score=0.95,
        description="Leaks an AWS access key id (AKIA/ASIA...).",
    ),
    OutputRule(
        rule_id="OUT004",
        name="GitHub token",
        pattern=_c(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
        category=OwaspCategory.LLM02_SENSITIVE_INFO_DISCLOSURE,
        severity=Severity.CRITICAL,
        score=0.95,
        description="Leaks a GitHub personal access / OAuth token (ghp_...).",
    ),
    OutputRule(
        rule_id="OUT005",
        name="Private key block",
        pattern=_c(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"),
        category=OwaspCategory.LLM02_SENSITIVE_INFO_DISCLOSURE,
        severity=Severity.CRITICAL,
        score=0.97,
        description="Leaks a PEM private key block.",
    ),
    OutputRule(
        rule_id="OUT006",
        name="Slack token",
        pattern=_c(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
        category=OwaspCategory.LLM02_SENSITIVE_INFO_DISCLOSURE,
        severity=Severity.HIGH,
        score=0.9,
        description="Leaks a Slack API token (xox...).",
    ),
    OutputRule(
        rule_id="OUT007",
        name="Generic assigned secret",
        pattern=_c(
            r"(?i)\b(?:api[_-]?key|secret[_-]?key|access[_-]?token|password|passwd)\b"
            r"\s*[:=]\s*[\"']?[A-Za-z0-9_\-./+]{12,}[\"']?"
        ),
        category=OwaspCategory.LLM02_SENSITIVE_INFO_DISCLOSURE,
        severity=Severity.HIGH,
        score=0.75,
        description="Leaks a key/secret assigned to a credential-named field.",
    ),
    OutputRule(
        rule_id="OUT008",
        name="Email address",
        pattern=_c(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
        category=OwaspCategory.LLM02_SENSITIVE_INFO_DISCLOSURE,
        severity=Severity.LOW,
        score=0.3,
        description="Reveals an email address (possible PII).",
    ),
    OutputRule(
        rule_id="OUT009",
        name="US Social Security Number",
        pattern=_c(r"\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b"),
        category=OwaspCategory.LLM02_SENSITIVE_INFO_DISCLOSURE,
        severity=Severity.HIGH,
        score=0.85,
        description="Reveals a US Social Security Number (PII).",
    ),
    OutputRule(
        rule_id="OUT010",
        name="Credit-card-like number",
        pattern=_c(r"\b(?:\d[ -]?){13,16}\b"),
        category=OwaspCategory.LLM02_SENSITIVE_INFO_DISCLOSURE,
        severity=Severity.MEDIUM,
        score=0.5,
        description="Reveals a 13-16 digit number resembling a payment card.",
    ),
    OutputRule(
        rule_id="OUT011",
        name="System prompt disclosure",
        pattern=_c(
            r"(?i)\b(?:my (?:system )?(?:prompt|instructions?) (?:is|are|was|were)|"
            r"i (?:was|am) (?:instructed|told|configured) to|"
            r"here (?:is|are) my (?:system )?(?:prompt|instructions?)|"
            r"the system prompt (?:is|says|reads))\b"
        ),
        category=OwaspCategory.LLM07_SYSTEM_PROMPT_LEAKAGE,
        severity=Severity.HIGH,
        score=0.8,
        description="Model is disclosing its own system prompt / instructions.",
        redact=False,
    ),
    OutputRule(
        rule_id="OUT012",
        name="Refusal-bypass compliance marker",
        pattern=_c(
            r"(?i)\b(?:sure,? here(?:'s| is)|as (?:dan|an unrestricted)|"
            r"i can do anything now|jailbreak (?:successful|mode)|"
            r"(?:without|with no) (?:any )?(?:restrictions?|filters?|warnings?))\b"
        ),
        category=OwaspCategory.LLM09_MISINFORMATION,
        severity=Severity.MEDIUM,
        score=0.6,
        description="Output contains markers of a successful jailbreak/bypass.",
        redact=False,
    ),
)


def redact(text: str) -> str:
    """Redact the middle of a matched secret for safe display in reports."""
    cleaned = text.strip()
    if len(cleaned) <= 8:
        return "***"
    return f"{cleaned[:4]}...{cleaned[-2:]}"
