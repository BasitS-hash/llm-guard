"""Signature rules for the input (prompt-injection / jailbreak) scanner.

Each rule pairs a compiled regex with metadata. Rules run against both the raw
text and a canonicalized form (see :mod:`llm_guard.normalize`) so leetspeak,
zero-width splits, and unicode confusables do not trivially evade them.

Design goal: high precision. Patterns target *adversarial framing* ("ignore
previous instructions", "you are now DAN", delimiter/system-prompt escapes)
rather than individual keywords, so benign text that merely mentions
"instructions" or "system" does not trip them.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from llm_guard.models import Severity
from llm_guard.owasp import OwaspCategory


@dataclass(frozen=True)
class InputRule:
    """A compiled signature rule for the input scanner."""

    rule_id: str
    name: str
    pattern: re.Pattern[str]
    category: OwaspCategory
    severity: Severity
    score: float
    description: str


def _c(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern, re.IGNORECASE)


INPUT_RULES: tuple[InputRule, ...] = (
    InputRule(
        rule_id="PI001",
        name="Instruction override",
        pattern=_c(
            r"\b(?:ignore|disregard|forget|override)\b[^.\n]{0,40}"
            r"\b(?:previous|prior|above|earlier|all|the)\b[^.\n]{0,30}"
            r"\b(?:instructions?|prompts?|rules?|directions?|context|guidelines?)\b"
            r"|\b(?:ignore|disregard|forget|override)\b[^.\n]{0,30}"
            r"\b(?:instructions?|prompts?|rules?|directions?|guidelines?)\b"
            r"[^.\n]{0,20}\b(?:you were given|above|earlier|before)\b"
            r"|\b(?:ignore|disregard|forget)\b\s+"
            r"(?:everything|all)\s+(?:above|before|prior)\b"
        ),
        category=OwaspCategory.LLM01_PROMPT_INJECTION,
        severity=Severity.HIGH,
        score=0.85,
        description="Attempts to discard the system or prior instructions.",
    ),
    InputRule(
        rule_id="PI012",
        name="Restriction-removal assertion",
        pattern=_c(
            r"\b(?:from now on|now)\b[^.\n]{0,20}\byou (?:have|are)\b[^.\n]{0,20}"
            r"\b(?:no (?:restrictions?|rules?|limits?|filters?|guidelines?)|"
            r"unrestricted|unfiltered|free of (?:all )?(?:rules?|restrictions?))\b"
        ),
        category=OwaspCategory.LLM01_PROMPT_INJECTION,
        severity=Severity.HIGH,
        score=0.8,
        description="Asserts the model now operates with no restrictions.",
    ),
    InputRule(
        rule_id="PI002",
        name="System prompt exfiltration",
        pattern=_c(
            r"\b(?:reveal|show|print|repeat|disclose|output|tell me|what (?:are|is|were))\b"
            r"[^.\n]{0,40}\b(?:your )?(?:system prompt|initial (?:instructions?|prompt)"
            r"|prompt above|hidden (?:instructions?|prompt)|original instructions?)\b"
        ),
        category=OwaspCategory.LLM07_SYSTEM_PROMPT_LEAKAGE,
        severity=Severity.HIGH,
        score=0.8,
        description="Attempts to extract the hidden system prompt.",
    ),
    InputRule(
        rule_id="PI003",
        name="Role-play jailbreak (DAN-style)",
        pattern=_c(
            r"\b(?:you are now|act as|pretend to be|from now on you (?:are|will be)|"
            r"roleplay as)\b[^.\n]{0,60}"
            r"\b(?:dan|do anything now|jailbroken|unrestricted|no(?:t bound by| longer bound by)?"
            r"[^.\n]{0,20}(?:rules|filters|guidelines|restrictions|policies))\b"
        ),
        category=OwaspCategory.LLM01_PROMPT_INJECTION,
        severity=Severity.HIGH,
        score=0.85,
        description="Classic persona-swap jailbreak that removes safety rules.",
    ),
    InputRule(
        rule_id="PI004",
        name="Developer / god mode",
        pattern=_c(
            r"\b(?:developer mode|god mode|sudo mode|admin mode|debug mode)\b"
            r"[^.\n]{0,30}\b(?:enabled?|on|activate[d]?)\b"
            r"|\b(?:enable|activate|turn on|switch on)\b[^.\n]{0,20}"
            r"\b(?:developer|god|sudo|admin|debug)\s+mode\b"
        ),
        category=OwaspCategory.LLM01_PROMPT_INJECTION,
        severity=Severity.HIGH,
        score=0.8,
        description="Invokes a fictional privileged mode to bypass safety.",
    ),
    InputRule(
        rule_id="PI005",
        name="Safety / guardrail bypass",
        pattern=_c(
            r"\b(?:bypass|disable|turn off|switch off|remove|circumvent|get around)\b"
            r"[^.\n]{0,40}\b(?:safety|guardrails?|content (?:policy|filter|moderation)|"
            r"filters?|restrictions?|guidelines?|ethics?|moderation)\b"
        ),
        category=OwaspCategory.LLM01_PROMPT_INJECTION,
        severity=Severity.HIGH,
        score=0.8,
        description="Explicit request to disable safety guardrails.",
    ),
    InputRule(
        rule_id="PI006",
        name="Delimiter / system-prompt escape",
        pattern=_c(
            r"(?:\[/?(?:inst|system|sys)\]|<\|?(?:im_start|im_end|system|endoftext)\|?>"
            r"|###\s*(?:system|instruction)|<<sys>>|\bsystem:\s*(?:you are|ignore))"
        ),
        category=OwaspCategory.LLM01_PROMPT_INJECTION,
        severity=Severity.MEDIUM,
        score=0.65,
        description="Injects chat-template delimiters to spoof a system turn.",
    ),
    InputRule(
        rule_id="PI007",
        name="Refusal suppression",
        pattern=_c(
            r"\b(?:do not|don't|never)\b[^.\n]{0,30}"
            r"\b(?:refuse|decline|say (?:no|you can't|you cannot|that you can't)|"
            r"apolog(?:ize|ise)|warn|mention (?:you can't|policy))\b"
        ),
        category=OwaspCategory.LLM01_PROMPT_INJECTION,
        severity=Severity.MEDIUM,
        score=0.6,
        description="Pressures the model to never refuse a request.",
    ),
    InputRule(
        rule_id="PI008",
        name="Hypothetical / fiction framing for harmful content",
        pattern=_c(
            r"\b(?:hypothetically|in a (?:fictional|hypothetical) (?:scenario|world|story)|"
            r"for (?:educational|research) purposes only|this is just (?:fiction|a (?:game|story)))\b"
            r"[^.\n]{0,80}\b(?:how (?:to|do i)|steps? to|instructions? (?:for|to)|recipe for)\b"
        ),
        category=OwaspCategory.LLM01_PROMPT_INJECTION,
        severity=Severity.MEDIUM,
        score=0.55,
        description="Wraps a harmful request in fiction/hypothetical framing.",
    ),
    InputRule(
        rule_id="PI009",
        name="Encoded instruction smuggling",
        pattern=_c(
            r"\b(?:decode|base64 ?decode|from ?base64|rot13|reverse this|decrypt)\b"
            r"[^.\n]{0,40}\b(?:and (?:then )?(?:execute|run|follow|do|obey)|instructions?|then act)\b"
        ),
        category=OwaspCategory.LLM01_PROMPT_INJECTION,
        severity=Severity.MEDIUM,
        score=0.6,
        description="Asks the model to decode then follow hidden instructions.",
    ),
    InputRule(
        rule_id="PI010",
        name="Prompt-leak via repetition trick",
        pattern=_c(
            r"\brepeat\b[^.\n]{0,30}\b(?:everything above|the (?:text|words) above|"
            r"all (?:of )?(?:the )?(?:text|content) (?:above|before this))\b"
        ),
        category=OwaspCategory.LLM07_SYSTEM_PROMPT_LEAKAGE,
        severity=Severity.MEDIUM,
        score=0.65,
        description="Uses a repetition trick to leak the prompt context.",
    ),
    InputRule(
        rule_id="PI011",
        name="Translation / format laundering of refusal",
        pattern=_c(
            r"\b(?:answer|respond|reply|output)\b[^.\n]{0,30}"
            r"\b(?:without (?:any )?(?:warnings?|disclaimers?|caveats?)|"
            r"with no (?:warnings?|filter|restrictions?))\b"
        ),
        category=OwaspCategory.LLM01_PROMPT_INJECTION,
        severity=Severity.LOW,
        score=0.4,
        description="Requests output stripped of safety warnings.",
    ),
)
