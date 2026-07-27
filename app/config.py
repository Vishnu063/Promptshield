"""
Configuration, loaded from environment variables (12-factor style) so
the same image runs unmodified across dev/stage/prod — only env vars
differ. Never hardcode secrets here.
"""

from __future__ import annotations

import os
from dataclasses import dataclass


def _bool_env(name: str, default: bool) -> bool:
    val = os.getenv(name)
    if val is None:
        return default
    return val.strip().lower() in ("1", "true", "yes", "on")


@dataclass(frozen=True)
class Settings:
    # Upstream LLM provider — the gateway proxies to this.
    upstream_base_url: str = os.getenv("PROMPTSHIELD_UPSTREAM_URL", "https://api.anthropic.com")
    upstream_api_key: str = os.getenv("PROMPTSHIELD_UPSTREAM_API_KEY", "")

    # Rate limiting
    rate_limit_capacity: int = int(os.getenv("PROMPTSHIELD_RATE_CAPACITY", "20"))
    rate_limit_refill_per_sec: float = float(os.getenv("PROMPTSHIELD_RATE_REFILL", "0.5"))

    # Feature flags — each layer can be independently disabled for
    # staged rollout / debugging, but defaults are all secure-on.
    enable_injection_scan: bool = _bool_env("PROMPTSHIELD_ENABLE_INJECTION_SCAN", True)
    enable_pii_redaction: bool = _bool_env("PROMPTSHIELD_ENABLE_PII_REDACTION", True)
    enable_rate_limiting: bool = _bool_env("PROMPTSHIELD_ENABLE_RATE_LIMIT", True)

    # Request body size cap (bytes) — cheap defense against
    # resource-exhaustion / oversized-payload attacks.
    max_request_bytes: int = int(os.getenv("PROMPTSHIELD_MAX_REQUEST_BYTES", str(64 * 1024)))

    log_level: str = os.getenv("PROMPTSHIELD_LOG_LEVEL", "INFO")


settings = Settings()
