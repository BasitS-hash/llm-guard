"""Tests for the OWASP catalog and core data models."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from llm_guard.models import Detection, ScanResult, Severity, Verdict
from llm_guard.owasp import ALL_CATEGORIES, OwaspCategory, title_for


def test_owasp_list_has_ten_entries() -> None:
    assert len(ALL_CATEGORIES) == 10
    ids = [e.id for e in ALL_CATEGORIES]
    assert ids == [f"LLM{n:02d}" for n in range(1, 11)]


def test_owasp_titles_match_2025_list() -> None:
    by_id = {e.id: e.title for e in ALL_CATEGORIES}
    assert by_id["LLM01"] == "Prompt Injection"
    assert by_id["LLM02"] == "Sensitive Information Disclosure"
    assert by_id["LLM05"] == "Improper Output Handling"
    assert by_id["LLM07"] == "System Prompt Leakage"
    assert by_id["LLM09"] == "Misinformation"


def test_addressed_categories_match_enum() -> None:
    addressed_ids = {e.id for e in ALL_CATEGORIES if e.addressed}
    enum_ids = {c.value for c in OwaspCategory}
    assert addressed_ids == enum_ids


def test_category_label_and_title() -> None:
    cat = OwaspCategory.LLM01_PROMPT_INJECTION
    assert cat.category_title == "Prompt Injection"
    assert cat.label == "LLM01 Prompt Injection"


def test_title_for_unknown_id_returns_id() -> None:
    assert title_for("LLM99") == "LLM99"
    assert title_for("LLM01") == "Prompt Injection"


def test_severity_ranking() -> None:
    assert Severity.CRITICAL.rank > Severity.HIGH.rank
    assert Severity.HIGH.rank > Severity.MEDIUM.rank
    assert Severity.MEDIUM.rank > Severity.LOW.rank


def test_detection_is_frozen() -> None:
    det = Detection(
        rule_id="X",
        name="x",
        category=OwaspCategory.LLM01_PROMPT_INJECTION,
        severity=Severity.LOW,
        score=0.1,
        description="d",
    )
    with pytest.raises(ValidationError):
        det.score = 0.9  # type: ignore[misc]


def test_detection_score_validation() -> None:
    with pytest.raises(ValidationError):
        Detection(
            rule_id="X",
            name="x",
            category=OwaspCategory.LLM01_PROMPT_INJECTION,
            severity=Severity.LOW,
            score=5.0,  # out of [0, 1]
            description="d",
        )


def test_scan_result_clean_helpers() -> None:
    clean = ScanResult(verdict=Verdict.ALLOW, risk_score=0.0, detections=[])
    assert clean.is_clean
    assert not clean.is_blocked
    assert clean.categories == []
    assert clean.max_severity is None


def test_scan_result_max_severity_and_categories() -> None:
    dets = [
        Detection(
            rule_id="A",
            name="a",
            category=OwaspCategory.LLM01_PROMPT_INJECTION,
            severity=Severity.LOW,
            score=0.2,
            description="d",
        ),
        Detection(
            rule_id="B",
            name="b",
            category=OwaspCategory.LLM02_SENSITIVE_INFO_DISCLOSURE,
            severity=Severity.CRITICAL,
            score=0.9,
            description="d",
        ),
    ]
    result = ScanResult(verdict=Verdict.BLOCK, risk_score=0.92, detections=dets)
    assert result.max_severity is Severity.CRITICAL
    assert len(result.categories) == 2
    assert result.is_blocked
