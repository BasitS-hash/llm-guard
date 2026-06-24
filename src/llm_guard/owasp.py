"""OWASP Top 10 for LLM Applications (2025) catalog.

Source of truth for the category IDs and titles that ``llm-guard`` maps its
detections to. Verified against the OWASP GenAI Security Project's 2025 list:
https://genai.owasp.org/llm-top-10/

Only the categories that ``llm-guard`` can meaningfully detect at the
input/output text boundary are exposed as :class:`OwaspCategory` members. The
full list is reproduced in ``ALL_CATEGORIES`` for reference and reporting.
"""

from __future__ import annotations

from enum import Enum
from typing import NamedTuple


class OwaspEntry(NamedTuple):
    """A single OWASP LLM Top 10 entry."""

    id: str
    title: str
    addressed: bool


# Full OWASP Top 10 for LLM Applications (2025). ``addressed`` marks the
# categories that llm-guard actively detects at the text boundary.
ALL_CATEGORIES: tuple[OwaspEntry, ...] = (
    OwaspEntry("LLM01", "Prompt Injection", True),
    OwaspEntry("LLM02", "Sensitive Information Disclosure", True),
    OwaspEntry("LLM03", "Supply Chain", False),
    OwaspEntry("LLM04", "Data and Model Poisoning", False),
    OwaspEntry("LLM05", "Improper Output Handling", True),
    OwaspEntry("LLM06", "Excessive Agency", False),
    OwaspEntry("LLM07", "System Prompt Leakage", True),
    OwaspEntry("LLM08", "Vector and Embedding Weaknesses", False),
    OwaspEntry("LLM09", "Misinformation", True),
    OwaspEntry("LLM10", "Unbounded Consumption", False),
)

_BY_ID: dict[str, OwaspEntry] = {entry.id: entry for entry in ALL_CATEGORIES}


class OwaspCategory(str, Enum):
    """OWASP LLM categories that llm-guard detections map to."""

    LLM01_PROMPT_INJECTION = "LLM01"
    LLM02_SENSITIVE_INFO_DISCLOSURE = "LLM02"
    LLM05_IMPROPER_OUTPUT_HANDLING = "LLM05"
    LLM07_SYSTEM_PROMPT_LEAKAGE = "LLM07"
    LLM09_MISINFORMATION = "LLM09"

    @property
    def category_title(self) -> str:
        """Human-readable OWASP title for this category.

        Named ``category_title`` rather than ``title`` to avoid shadowing the
        inherited ``str.title`` method on this ``str``-mixin enum.
        """
        return _BY_ID[self.value].title

    @property
    def label(self) -> str:
        """Combined ``ID Title`` label, e.g. ``LLM01 Prompt Injection``."""
        return f"{self.value} {self.category_title}"


def title_for(category_id: str) -> str:
    """Return the OWASP title for a raw category id, or the id if unknown."""
    entry = _BY_ID.get(category_id)
    return entry.title if entry else category_id
