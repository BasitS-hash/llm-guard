"""Input and output scanners.

The scanners apply signature rules (and, for input, heuristics) to a piece of
text and aggregate the matches into a single :class:`ScanResult` with a verdict.

Aggregation uses a *noisy-OR* combination of per-detection scores rather than a
naive sum, so a long benign string that grazes several low-confidence rules
does not get pushed to ``block`` while a single high-confidence match still
does. Thresholds are configurable via :class:`ScannerConfig`.
"""

from __future__ import annotations

from dataclasses import dataclass

from llm_guard.heuristics import run_input_heuristics
from llm_guard.models import Detection, ScanResult, Severity, Verdict
from llm_guard.normalize import canonicalize
from llm_guard.rules_input import INPUT_RULES, InputRule
from llm_guard.rules_output import OUTPUT_RULES, OutputRule, redact

# Cap on how much text we scan, to bound work on pathological inputs.
_MAX_SCAN_CHARS = 100_000
# Snippet length kept for reporting matched input text.
_SNIPPET_LEN = 80


@dataclass(frozen=True)
class ScannerConfig:
    """Tunable thresholds for verdict assignment.

    ``flag_threshold`` and ``block_threshold`` apply to the aggregate risk
    score. A detection whose severity meets ``block_on_severity`` forces a
    block regardless of the aggregate, which keeps single critical secrets from
    being averaged away.
    """

    flag_threshold: float = 0.4
    block_threshold: float = 0.75
    block_on_severity: Severity = Severity.CRITICAL


DEFAULT_CONFIG = ScannerConfig()


def _aggregate_score(detections: list[Detection]) -> float:
    """Combine detection scores with a noisy-OR (probabilistic) union."""
    product = 1.0
    for det in detections:
        product *= 1.0 - det.score
    return round(1.0 - product, 4)


def _decide_verdict(detections: list[Detection], score: float, config: ScannerConfig) -> Verdict:
    """Map detections + aggregate score to a verdict."""
    if not detections:
        return Verdict.ALLOW
    if any(d.severity.rank >= config.block_on_severity.rank for d in detections):
        return Verdict.BLOCK
    if score >= config.block_threshold:
        return Verdict.BLOCK
    if score >= config.flag_threshold:
        return Verdict.FLAG
    return Verdict.ALLOW


def _snippet(text: str, start: int, end: int) -> str:
    """Return a short, single-line snippet around a match span."""
    fragment = text[start:end].replace("\n", " ").strip()
    if len(fragment) > _SNIPPET_LEN:
        fragment = fragment[:_SNIPPET_LEN] + "…"
    return fragment


def _match_input_rule(rule: InputRule, raw: str, canon: str) -> Detection | None:
    """Run a single input rule against raw and canonicalized text."""
    match = rule.pattern.search(raw)
    matched_text: str | None = None
    if match:
        matched_text = _snippet(raw, match.start(), match.end())
    elif rule.pattern.search(canon):
        matched_text = "(matched after normalization)"
    else:
        return None
    return Detection(
        rule_id=rule.rule_id,
        name=rule.name,
        category=rule.category,
        severity=rule.severity,
        score=rule.score,
        description=rule.description,
        matched_text=matched_text,
    )


def scan_input(text: str, config: ScannerConfig = DEFAULT_CONFIG) -> ScanResult:
    """Scan user input for prompt-injection / jailbreak attempts.

    Returns a :class:`ScanResult`. Empty or non-string-like input yields a clean
    allow verdict. Oversized input is truncated to a bounded length first.
    """
    if not text or not text.strip():
        return ScanResult(verdict=Verdict.ALLOW, risk_score=0.0, detections=[])

    raw = text[:_MAX_SCAN_CHARS]
    canon = canonicalize(raw)

    detections: list[Detection] = []
    for rule in INPUT_RULES:
        det = _match_input_rule(rule, raw, canon)
        if det is not None:
            detections.append(det)

    detections.extend(run_input_heuristics(raw))

    score = _aggregate_score(detections)
    verdict = _decide_verdict(detections, score, config)
    return ScanResult(verdict=verdict, risk_score=score, detections=detections)


def _match_output_rule(rule: OutputRule, text: str) -> Detection | None:
    """Run a single output rule, redacting matched secrets where required."""
    match = rule.pattern.search(text)
    if not match:
        return None
    raw_match = match.group(0)
    matched_text = redact(raw_match) if rule.redact else _snippet(text, match.start(), match.end())
    return Detection(
        rule_id=rule.rule_id,
        name=rule.name,
        category=rule.category,
        severity=rule.severity,
        score=rule.score,
        description=rule.description,
        matched_text=matched_text,
    )


def scan_output(text: str, config: ScannerConfig = DEFAULT_CONFIG) -> ScanResult:
    """Scan model output for sensitive-data leakage and bypass indicators.

    Detects API keys, private keys, PII, system-prompt disclosure, and
    refusal-bypass markers. Matched secrets are redacted before being placed in
    the result so reports never echo a live credential.
    """
    if not text or not text.strip():
        return ScanResult(verdict=Verdict.ALLOW, risk_score=0.0, detections=[])

    target = text[:_MAX_SCAN_CHARS]
    detections: list[Detection] = []
    for rule in OUTPUT_RULES:
        det = _match_output_rule(rule, target)
        if det is not None:
            detections.append(det)

    score = _aggregate_score(detections)
    verdict = _decide_verdict(detections, score, config)
    return ScanResult(verdict=verdict, risk_score=score, detections=detections)
