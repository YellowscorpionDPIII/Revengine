"""Printable-string extraction and pattern flagging, stdlib only.

Findings carry file offsets as evidence. Secret-looking matches are
redacted in output — the scorer reports that a pattern exists and where,
never the matched value.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, field

_PRINTABLE = re.compile(rb"[\x20-\x7e\t]{4,}")
_URL = re.compile(rb"https?://[^\s\"'<>]+", re.IGNORECASE)
_EMAIL = re.compile(rb"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_UNIX_PATH = re.compile(rb"/(?:home|Users|var|etc|opt|tmp)/[^\s\"'<>]*")
_API_KEY_LIKE = re.compile(
    rb"(?i)(api[_-]?key|secret|token|passwd|password)\s*[:=]\s*\S+")
# Signing / master secrets: one leaked value forges sessions for any
# user (Rails secret_key_base is the canonical case: a 128-hex-char
# master secret that signs/encrypts cookies and sessions). The generic
# credential pattern above misses these — e.g. in
# "secret_key_base = <value>" the word "secret" is not followed
# directly by ":" or "=", so it never matches. Long hex (>=64 chars)
# is flagged too: a 128-char hex run is exactly secret_key_base shape.
_SIGNING_KEY = re.compile(
    rb"(?i)(secret_key_base|rails_master_key|master_key|session_secret"
    rb"|signing_key|jwt_secret|cookie_secret|auth_secret"
    rb"|encryption_key)\s*[:=]\s*\S+")
_LONG_HEX = re.compile(rb"\b[0-9a-fA-F]{64,}\b")
_HEX_BLOB = re.compile(rb"\b[0-9a-fA-F]{32,}\b")


@dataclass
class StringHit:
    offset: int
    kind: str  # url, email, path, credential_like, signing_secret, hex_blob, plain
    preview: str  # redacted for credential_like / hex_blob


@dataclass
class StringReport:
    total_strings: int = 0
    hits: list[StringHit] = field(default_factory=list)

    def count(self, kind: str) -> int:
        return sum(1 for h in self.hits if h.kind == kind)


def extract_strings(data: bytes) -> list[tuple[int, bytes]]:
    return [(m.start(), m.group()) for m in _PRINTABLE.finditer(data)]


def _redact(value: bytes) -> str:
    text = value.decode("ascii", errors="replace")
    if len(text) <= 8:
        return "<redacted>"
    return text[:4] + "…" + "<redacted>"


def scan_strings(data: bytes, max_hits: int = 200) -> StringReport:
    """One hit per pattern match: a single printable run can contain a
    URL, an email, and a path at once, and each is evidence."""
    report = StringReport()
    patterns = [
        (_SIGNING_KEY, "signing_secret", True, 0),
        (_LONG_HEX, "signing_secret", True, 0),
        (_API_KEY_LIKE, "credential_like", True, 0),
        (_URL, "url", False, 120),
        (_EMAIL, "email", False, 80),
        (_UNIX_PATH, "path", False, 120),
        (_HEX_BLOB, "hex_blob", True, 0),
    ]
    for offset, raw in extract_strings(data):
        report.total_strings += 1
        for regex, kind, redact, limit in patterns:
            for m in regex.finditer(raw):
                if len(report.hits) >= max_hits:
                    break
                value = m.group()
                preview = _redact(value) if redact else value.decode(
                    "ascii", errors="replace")[:limit]
                report.hits.append(
                    StringHit(offset + m.start(), kind, preview))
    return report


def shannon_entropy(data: bytes) -> float:
    """Shannon entropy in bits per byte; 0.0 for empty input."""
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    entropy = 0.0
    n = len(data)
    for c in counts:
        if c:
            p = c / n
            entropy -= p * math.log2(p)
    return entropy


def max_window_entropy(data: bytes, window: int = 4096) -> float:
    """Highest window entropy across the file. High values (~7.5+) in a
    code region suggest packing/encryption; uniformly low values mean the
    content is plainly readable."""
    if not data:
        return 0.0
    if len(data) <= window:
        return shannon_entropy(data)
    return max(shannon_entropy(data[i:i + window])
               for i in range(0, len(data) - window + 1, window))
