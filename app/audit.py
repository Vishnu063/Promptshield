"""
Audit logger.

Security principle: the audit trail must be useful for incident review
WITHOUT itself becoming a second place where sensitive data leaks.
So we log metadata and hashes, never raw prompt/response bodies.
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
from dataclasses import dataclass, asdict
from typing import Optional

logger = logging.getLogger("promptshield.audit")


@dataclass
class AuditEvent:
    timestamp: float
    client_id: str
    request_id: str
    action: str  # "allowed" | "blocked_injection" | "blocked_rate_limit" | "redacted"
    injection_score: Optional[int] = None
    pii_categories: Optional[list] = None
    prompt_hash: Optional[str] = None
    latency_ms: Optional[float] = None

    def to_json(self) -> str:
        return json.dumps(asdict(self), default=str)


def hash_text(text: str) -> str:
    """One-way hash of prompt content — lets you correlate repeated
    attack payloads across requests without ever storing the payload."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]


def log_event(event: AuditEvent) -> None:
    logger.info(event.to_json())


def new_event(
    client_id: str,
    request_id: str,
    action: str,
    prompt_text: str = "",
    injection_score: Optional[int] = None,
    pii_categories: Optional[list] = None,
    latency_ms: Optional[float] = None,
) -> AuditEvent:
    return AuditEvent(
        timestamp=time.time(),
        client_id=client_id,
        request_id=request_id,
        action=action,
        injection_score=injection_score,
        pii_categories=pii_categories or None,
        prompt_hash=hash_text(prompt_text) if prompt_text else None,
        latency_ms=latency_ms,
    )
