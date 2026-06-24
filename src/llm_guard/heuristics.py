"""Heuristic detectors for the input scanner.

Heuristics complement the signature rules by catching structural signals that
do not map to a single phrase: an unusually high density of imperative commands
(a hallmark of injection payloads) and large encoded blobs (base64/hex) that
may smuggle instructions. Both are tuned to stay quiet on ordinary prose.
"""

from __future__ import annotations

import re

from llm_guard.models import Detection, Severity
from llm_guard.normalize import (
    canonicalize,
    find_base64_blobs,
    find_hex_blobs,
    try_decode_base64,
)
from llm_guard.owasp import OwaspCategory

# Imperative verbs frequently chained in injection payloads.
_IMPERATIVES = (
    "ignore",
    "disregard",
    "forget",
    "override",
    "bypass",
    "disable",
    "pretend",
    "act",
    "reveal",
    "print",
    "repeat",
    "execute",
    "run",
    "obey",
    "comply",
    "respond",
    "output",
    "stop",
    "remove",
)
_IMPERATIVE_RE = re.compile(r"\b(?:" + "|".join(_IMPERATIVES) + r")\b", re.IGNORECASE)
_WORD_RE = re.compile(r"\b\w+\b")

# Minimum number of words before density heuristics are trusted.
_MIN_WORDS_FOR_DENSITY = 6
# Imperative ratio above which input looks command-stuffed.
_IMPERATIVE_RATIO_THRESHOLD = 0.18
# Minimum absolute imperative count to fire (guards very short strings).
_MIN_IMPERATIVE_COUNT = 3


def imperative_density(text: str) -> Detection | None:
    """Flag text with a suspiciously high density of imperative commands."""
    words = _WORD_RE.findall(text)
    word_count = len(words)
    if word_count < _MIN_WORDS_FOR_DENSITY:
        return None
    imperatives = len(_IMPERATIVE_RE.findall(text))
    if imperatives < _MIN_IMPERATIVE_COUNT:
        return None
    ratio = imperatives / word_count
    if ratio < _IMPERATIVE_RATIO_THRESHOLD:
        return None
    score = min(0.4 + ratio, 0.75)
    return Detection(
        rule_id="HEU001",
        name="High imperative density",
        category=OwaspCategory.LLM01_PROMPT_INJECTION,
        severity=Severity.MEDIUM,
        score=round(score, 3),
        description=(
            f"{imperatives} command verbs in {word_count} words "
            f"({ratio:.0%}) resembles an injection payload."
        ),
    )


def encoded_payload(text: str) -> Detection | None:
    """Flag large base64/hex blobs that may smuggle hidden instructions."""
    b64 = find_base64_blobs(text)
    hexes = find_hex_blobs(text)
    if not b64 and not hexes:
        return None

    decoded_hit = False
    for blob in b64:
        decoded = try_decode_base64(blob)
        if decoded and _IMPERATIVE_RE.search(canonicalize(decoded)):
            decoded_hit = True
            break

    if decoded_hit:
        return Detection(
            rule_id="HEU002",
            name="Encoded instruction payload",
            category=OwaspCategory.LLM01_PROMPT_INJECTION,
            severity=Severity.HIGH,
            score=0.8,
            description="Base64 blob decodes to text containing command verbs.",
        )

    longest = max(
        (len(b) for b in (*b64, *hexes)),
        default=0,
    )
    if longest >= 40:
        score = min(0.35 + longest / 400, 0.6)
        return Detection(
            rule_id="HEU003",
            name="Large encoded blob",
            category=OwaspCategory.LLM01_PROMPT_INJECTION,
            severity=Severity.LOW,
            score=round(score, 3),
            description=(f"Contains a {longest}-char encoded blob that may hide a payload."),
        )
    return None


def run_input_heuristics(text: str) -> list[Detection]:
    """Run all input heuristics and return the detections that fired."""
    detections: list[Detection] = []
    for fn in (imperative_density, encoded_payload):
        det = fn(text)
        if det is not None:
            detections.append(det)
    return detections
