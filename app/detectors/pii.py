"""
PII detector / redactor.

Runs on both the outbound path (user -> LLM provider) so raw PII never
leaves your network boundary, and can be run on the inbound path
(LLM provider -> user) to catch a model regurgitating training data
or leaking data pulled from a RAG/tool call.

Everything here is regex + checksum based (Luhn for card numbers) —
deterministic and auditable, no dependency on an external NLP model.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field


@dataclass
class PIIFinding:
    category: str
    count: int


@dataclass
class RedactionResult:
    redacted_text: str
    findings: list[PIIFinding] = field(default_factory=list)

    @property
    def had_pii(self) -> bool:
        return len(self.findings) > 0

    def to_dict(self) -> dict:
        return {
            "had_pii": self.had_pii,
            "findings": [{"category": f.category, "count": f.count} for f in self.findings],
        }


_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_PHONE_RE = re.compile(
    r"(?<!\d)(\+?\d{1,3}[\s.-]?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}(?!\d)"
)
_SSN_RE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
_CARD_RE = re.compile(r"\b(?:\d[ -]*?){13,19}\b")
_IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
_AWS_KEY_RE = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
_GENERIC_SECRET_RE = re.compile(
    r"\b(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b|"
    r"\bghp_[A-Za-z0-9]{36}\b|"
    r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"
)


def _luhn_valid(number: str) -> bool:
    digits = [int(d) for d in re.sub(r"\D", "", number)]
    if len(digits) < 13:
        return False
    checksum = 0
    parity = len(digits) % 2
    for i, d in enumerate(digits):
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


def redact(text: str) -> RedactionResult:
    if not text:
        return RedactionResult(redacted_text=text)

    findings: list[PIIFinding] = []
    redacted = text

    def _sub(pattern: re.Pattern, label: str, validator=None):
        nonlocal redacted
        matches = list(pattern.finditer(redacted))
        if validator:
            matches = [m for m in matches if validator(m.group(0))]
        if matches:
            findings.append(PIIFinding(category=label, count=len(matches)))
            # Replace back-to-front so earlier spans stay valid.
            for m in reversed(matches):
                redacted = redacted[: m.start()] + f"[REDACTED_{label}]" + redacted[m.end():]

    _sub(_AWS_KEY_RE, "AWS_ACCESS_KEY")
    _sub(_GENERIC_SECRET_RE, "API_SECRET")
    _sub(_EMAIL_RE, "EMAIL")
    _sub(_SSN_RE, "SSN")
    _sub(_CARD_RE, "CARD_NUMBER", validator=_luhn_valid)
    _sub(_PHONE_RE, "PHONE")
    _sub(_IPV4_RE, "IP_ADDRESS")

    return RedactionResult(redacted_text=redacted, findings=findings)
