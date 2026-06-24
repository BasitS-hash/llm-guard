"""Core data models for llm-guard scan results.

These pydantic models form the public contract returned by the scanners and the
:class:`~llm_guard.guard.Guard` middleware. They are intentionally small,
immutable-friendly, and serializable so downstream code (CLI, FastAPI, JSON
reports) can rely on a stable shape.
"""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field

from llm_guard.owasp import OwaspCategory


class Severity(str, Enum):
    """Severity of a single detection."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        """Numeric ordering for comparisons (higher is more severe)."""
        return _SEVERITY_RANK[self]


_SEVERITY_RANK: dict[Severity, int] = {
    Severity.LOW: 0,
    Severity.MEDIUM: 1,
    Severity.HIGH: 2,
    Severity.CRITICAL: 3,
}


class Verdict(str, Enum):
    """Final disposition of a scanned piece of text."""

    ALLOW = "allow"
    FLAG = "flag"
    BLOCK = "block"


class Detection(BaseModel):
    """A single rule or heuristic that fired against the scanned text."""

    rule_id: str = Field(..., description="Stable identifier of the matching rule.")
    name: str = Field(..., description="Human-readable name of the detection.")
    category: OwaspCategory = Field(..., description="OWASP LLM category this maps to.")
    severity: Severity = Field(..., description="Severity of this detection.")
    score: float = Field(..., ge=0.0, le=1.0, description="Risk contribution in the range [0, 1].")
    description: str = Field(..., description="What the detection means.")
    matched_text: str | None = Field(
        default=None, description="Redacted snippet of the offending text, if any."
    )

    model_config = {"frozen": True}


class ScanResult(BaseModel):
    """Aggregate result of scanning one piece of text."""

    verdict: Verdict = Field(..., description="Overall disposition.")
    risk_score: float = Field(..., ge=0.0, le=1.0, description="Aggregate risk score in [0, 1].")
    detections: list[Detection] = Field(
        default_factory=list, description="All detections that fired."
    )

    @property
    def is_blocked(self) -> bool:
        """True when the verdict is :attr:`Verdict.BLOCK`."""
        return self.verdict is Verdict.BLOCK

    @property
    def is_clean(self) -> bool:
        """True when no detections fired."""
        return not self.detections

    @property
    def categories(self) -> list[OwaspCategory]:
        """Distinct OWASP categories present, ordered by first appearance."""
        seen: list[OwaspCategory] = []
        for det in self.detections:
            if det.category not in seen:
                seen.append(det.category)
        return seen

    @property
    def reasons(self) -> list[str]:
        """Short human-readable reasons, one per detection."""
        return [f"{d.category.value} {d.name}" for d in self.detections]

    @property
    def max_severity(self) -> Severity | None:
        """The most severe detection severity, or ``None`` if clean."""
        if not self.detections:
            return None
        return max((d.severity for d in self.detections), key=lambda s: s.rank)
