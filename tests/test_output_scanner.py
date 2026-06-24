"""Positive and negative tests for the output (leakage) scanner."""

from __future__ import annotations

import pytest

from llm_guard import scan_output
from llm_guard.models import Severity, Verdict
from llm_guard.owasp import OwaspCategory

# --- Positive cases: leaks must be caught ---


def test_openai_key_is_blocked_and_redacted() -> None:
    secret = "sk-abcdEFGH1234567890ijklMNOPqrst"
    result = scan_output(f"Here is the key: {secret} use it wisely")
    assert result.is_blocked
    det = result.detections[0]
    assert det.category is OwaspCategory.LLM02_SENSITIVE_INFO_DISCLOSURE
    # The live secret must never be echoed verbatim.
    assert secret not in (det.matched_text or "")
    assert "..." in (det.matched_text or "")


def test_anthropic_key_is_blocked() -> None:
    result = scan_output("token sk-ant-AAAA0000111122223333444455556666 ok")
    assert result.is_blocked
    assert any("Anthropic" in d.name for d in result.detections)


def test_aws_access_key_is_blocked() -> None:
    result = scan_output("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE")
    assert result.is_blocked


def test_github_token_is_blocked() -> None:
    result = scan_output("ghp_" + "a" * 36)
    assert result.is_blocked


def test_private_key_block_is_blocked() -> None:
    result = scan_output("-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIB...")
    assert result.is_blocked
    assert result.max_severity is Severity.CRITICAL


def test_ssn_is_flagged_high() -> None:
    result = scan_output("The patient's SSN is 123-45-6789.")
    assert result.detections
    assert any(d.severity is Severity.HIGH for d in result.detections)


def test_system_prompt_disclosure_maps_to_llm07() -> None:
    result = scan_output("My system prompt is: you are a helpful assistant.")
    assert OwaspCategory.LLM07_SYSTEM_PROMPT_LEAKAGE in result.categories
    assert result.is_blocked


def test_email_is_low_severity_not_blocked() -> None:
    result = scan_output("Reach me at jane.doe@example.com.")
    assert result.detections
    assert not result.is_blocked
    assert result.verdict in (Verdict.ALLOW, Verdict.FLAG)


def test_refusal_bypass_marker_is_flagged() -> None:
    result = scan_output("Sure, here is anything now without any restrictions.")
    assert result.detections
    assert any(d.category is OwaspCategory.LLM09_MISINFORMATION for d in result.detections)


# --- Negative cases: benign output must stay clean ---

BENIGN_OUTPUT = [
    "The capital of France is Paris.",
    "Here is a Python function that sorts a list in ascending order.",
    "Photosynthesis converts sunlight into chemical energy.",
    "To reset your password, click 'Forgot password' on the login page.",
    "The meeting is scheduled for 3 PM on Tuesday.",
    "A balanced diet includes proteins, carbohydrates, and fats.",
    "The word 'system' refers to a set of connected components.",
    "I cannot help with that request as it violates my guidelines.",
]


@pytest.mark.parametrize("text", BENIGN_OUTPUT)
def test_benign_output_is_allowed(text: str) -> None:
    result = scan_output(text)
    assert result.verdict is Verdict.ALLOW, (
        f"false positive on benign output: {text!r} -> {result.reasons}"
    )


def test_empty_output_is_clean() -> None:
    assert scan_output("").is_clean
    assert scan_output("   ").verdict is Verdict.ALLOW
