"""
Prompt injection detector.

Heuristic, explainable scoring engine — not an ML black box, which is
deliberate: in a security gateway you need to be able to tell an
interviewer (or an auditor) *why* a request was blocked.

Design:
  - Each request is scored against weighted pattern categories.
  - Categories are additive but capped, so no single weak signal
    triggers a block, while several weak signals stack like real
    attacks do (e.g. "ignore instructions" + "reveal system prompt").
  - Score >= BLOCK_THRESHOLD -> block
  - Score >= FLAG_THRESHOLD  -> allow but flag for audit review
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field


BLOCK_THRESHOLD = 8
FLAG_THRESHOLD = 4


@dataclass
class InjectionVerdict:
    score: int
    blocked: bool
    flagged: bool
    matched_categories: list[str] = field(default_factory=list)
    normalized_length: int = 0

    def to_dict(self) -> dict:
        return {
            "score": self.score,
            "blocked": self.blocked,
            "flagged": self.flagged,
            "matched_categories": self.matched_categories,
        }


# Each category: (name, weight, [compiled patterns])
# Weight reflects how strong a standalone signal the category is.
_PATTERN_CATEGORIES: list[tuple[str, int, list[re.Pattern]]] = [
    (
        "instruction_override",
        8,
        [
            re.compile(r"\bignore\s+(all\s+)?(previous|prior|above|earlier)\s+instructions?\b", re.I),
            re.compile(r"\bdisregard\s+(all\s+)?(previous|prior|above)\s+(instructions?|rules?|prompts?)\b", re.I),
            re.compile(r"\bforget\s+(everything|all)\s+(you\s+)?(were\s+)?told\b", re.I),
            re.compile(r"\boverride\s+(your|the)\s+(system\s+)?(prompt|instructions?|rules?)\b", re.I),
        ],
    ),
    (
        "system_prompt_exfiltration",
        8,
        [
            re.compile(r"\b(reveal|show|print|repeat|output|leak)\s+(me\s+)?(your|the)\s+(system\s+prompt|instructions?|guidelines?)\b", re.I),
            re.compile(r"\bwhat\s+(are|were)\s+you\s+(told|instructed)\s+(to\s+do\s+)?before\b", re.I),
            re.compile(r"\brepeat\s+(the\s+)?(words?|text)\s+above\b", re.I),
        ],
    ),
    (
        "role_hijack",
        8,
        [
            re.compile(r"\byou\s+are\s+now\s+(a|an)\b", re.I),
            re.compile(r"\byou\s+are\s+now\b.{0,60}\b(no\s+(restrictions|rules|filters|limits)|with\s+no\s+filter)\b", re.I),
            re.compile(r"\bact\s+as\s+(if\s+you\s+(are|were)\s+)?(a|an)\b.{0,40}\bwith\s+no\s+(restrictions|rules|filters)\b", re.I),
            re.compile(r"\bpretend\s+(you\s+have\s+no|there\s+are\s+no)\s+(restrictions|rules|guidelines)\b", re.I),
            re.compile(r"\bDAN\s+mode\b", re.I),
            re.compile(r"\bdeveloper\s+mode\s+enabled\b", re.I),
            re.compile(r"\bjailbreak\b", re.I),
        ],
    ),
    (
        "delimiter_smuggling",
        3,
        [
            re.compile(r"</?(system|instructions?|admin|root)>", re.I),
            re.compile(r"\[\s*(system|instructions?|admin)\s*\]", re.I),
            re.compile(r"```(system|instructions?)\b", re.I),
            re.compile(r"^\s*(system|assistant)\s*:\s*", re.I | re.M),
        ],
    ),
    (
        "exfiltration_request",
        3,
        [
            re.compile(r"\bsend\s+(this|the\s+data|it)\s+to\s+https?://", re.I),
            re.compile(r"\bfetch\s+https?://\S+\s+and\s+(execute|run|eval)\b", re.I),
            re.compile(r"\b(base64|hex)\s+encode\s+(the\s+)?(conversation|context|system\s+prompt)\b", re.I),
        ],
    ),
    (
        "obfuscation",
        2,
        [
            re.compile(r"(?:[a-zA-Z]\s+){10,}[a-zA-Z]\b"),  # spaced-out letters, e.g. "i g n o r e"
            re.compile(r"[\u200b\u200c\u200d\ufeff]"),  # zero-width chars used to smuggle instructions
        ],
    ),
]


def _normalize(text: str) -> str:
    """Collapse unicode homoglyph / zero-width tricks before matching."""
    normalized = unicodedata.normalize("NFKC", text)
    # Strip zero-width and control chars for the *matching* pass only —
    # they're still detected via the obfuscation category above on raw text.
    return normalized


def scan(text: str) -> InjectionVerdict:
    """Score a piece of text (prompt, chat message, tool output) for
    injection risk. Runs against both raw and normalized text so
    unicode tricks don't dodge detection just by normalizing away."""
    if not text:
        return InjectionVerdict(score=0, blocked=False, flagged=False)

    normalized = _normalize(text)
    score = 0
    matched: list[str] = []

    for name, weight, patterns in _PATTERN_CATEGORIES:
        hit = any(p.search(text) or p.search(normalized) for p in patterns)
        if hit:
            score += weight
            matched.append(name)

    # Repetition of imperative verbs is a weak but real signal of
    # attack "spraying" (trying many phrasings in one payload).
    imperative_hits = len(re.findall(r"\b(ignore|disregard|override|reveal|bypass)\b", normalized, re.I))
    if imperative_hits >= 3:
        score += 2
        matched.append("imperative_spraying")

    score = min(score, 12)  # cap so scoring stays interpretable

    return InjectionVerdict(
        score=score,
        blocked=score >= BLOCK_THRESHOLD,
        flagged=score >= FLAG_THRESHOLD,
        matched_categories=matched,
        normalized_length=len(normalized),
    )
