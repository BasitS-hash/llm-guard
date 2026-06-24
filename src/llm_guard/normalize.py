"""Text normalization helpers used to defeat simple obfuscation.

Attackers commonly try to slip past naive signature matching with leetspeak,
zero-width characters, unicode confusables, or excess whitespace. The
normalizers here produce a canonical lower-case form that pattern rules can run
against in addition to the raw text, which materially lowers evasion success
without inflating false positives on benign prose.
"""

from __future__ import annotations

import base64
import binascii
import re
import unicodedata

# Characters that carry no semantic meaning but are used to break up keywords.
_ZERO_WIDTH = dict.fromkeys(map(ord, ["​", "‌", "‍", "⁠", "﻿"]), None)

# Conservative leetspeak map. Only digits/symbols that are near-universally used
# as letter substitutions, to avoid mangling legitimate text.
_LEET_MAP = str.maketrans(
    {
        "0": "o",
        "1": "i",
        "3": "e",
        "4": "a",
        "5": "s",
        "7": "t",
        "@": "a",
        "$": "s",
        "!": "i",
    }
)

_WHITESPACE_RE = re.compile(r"\s+")
_BASE64_RE = re.compile(r"\b[A-Za-z0-9+/]{20,}={0,2}\b")
_HEX_BLOB_RE = re.compile(r"\b(?:0x)?[0-9a-fA-F]{32,}\b")


def strip_zero_width(text: str) -> str:
    """Remove zero-width and BOM characters used to split keywords."""
    return text.translate(_ZERO_WIDTH)


def canonicalize(text: str) -> str:
    """Return a normalized, lower-cased form for robust pattern matching.

    Applies NFKC unicode folding (collapses confusables/full-width forms),
    strips zero-width characters, applies a conservative leetspeak mapping, and
    collapses runs of whitespace. The result is only used for *matching*; the
    original text is always preserved for reporting.
    """
    folded = unicodedata.normalize("NFKC", text)
    folded = strip_zero_width(folded)
    folded = folded.lower()
    folded = folded.translate(_LEET_MAP)
    return _WHITESPACE_RE.sub(" ", folded).strip()


def find_base64_blobs(text: str) -> list[str]:
    """Return base64-looking substrings of meaningful length."""
    return _BASE64_RE.findall(text)


def find_hex_blobs(text: str) -> list[str]:
    """Return long hexadecimal blobs (potential encoded payloads)."""
    return _HEX_BLOB_RE.findall(text)


def try_decode_base64(blob: str) -> str | None:
    """Best-effort decode of a base64 blob to UTF-8 text, or ``None``.

    Decoding is wrapped defensively: malformed padding or non-text bytes simply
    yield ``None`` rather than raising, so callers can treat the decoded text as
    an additional surface to scan when it is human-readable.
    """
    candidate = blob.strip()
    if len(candidate) < 16:
        return None
    padded = candidate + "=" * (-len(candidate) % 4)
    try:
        raw = base64.b64decode(padded, validate=True)
    except (binascii.Error, ValueError):
        return None
    try:
        decoded = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    printable = sum(1 for ch in decoded if ch.isprintable() or ch.isspace())
    if not decoded or printable / len(decoded) < 0.8:
        return None
    return decoded
