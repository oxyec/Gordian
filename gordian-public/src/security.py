"""Shared control-plane authentication and safe event serialization."""
from __future__ import annotations

import os
import re
import secrets
from typing import Any


def configured_api_key() -> str:
    key = os.environ.get("GORDIAN_API_KEY", "").strip()
    if len(key) < 32:
        raise ValueError("Set GORDIAN_API_KEY to a random secret of at least 32 characters before starting the server")
    return key


def valid_api_key(presented: str, expected: str) -> bool:
    return bool(expected) and secrets.compare_digest(presented.encode(), expected.encode())


_CONTROL = re.compile(r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07]*(?:\x07|\x1b\\))|[\x00-\x08\x0b-\x1f\x7f]")
_SECRET = re.compile(r"(?i)\b(authorization|proxy-authorization|cookie|set-cookie|api[_-]?key|access[_-]?token|password|secret)\s*[:=]\s*[^\r\n]+")
_PROVIDER_TOKEN = re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|(?:AKIA|ASIA)[A-Z0-9]{16})\b")
_URL_CREDENTIALS = re.compile(r"(https?://)[^/\s:@]+:[^/\s@]+@")


def safe_text(text: str) -> str:
    text = _CONTROL.sub("", text)[:8192]
    text = _URL_CREDENTIALS.sub(r"\1[REDACTED]@", text)
    return _PROVIDER_TOKEN.sub("[REDACTED]", _SECRET.sub(r"\1: [REDACTED]", text))


def redact(value: Any, *, key: str = "") -> Any:
    """Omit raw evidence/argv entirely; regexes alone cannot identify all secrets."""
    if key.lower() in {"raw_line", "command", "commands", "argv", "request_headers", "headers"}:
        return "[REDACTED]"
    if any(word in key.lower() for word in ("password", "secret", "token", "api_key", "authorization", "cookie")):
        return "[REDACTED]"
    if isinstance(value, dict):
        return {str(k): redact(v, key=str(k)) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [redact(item) for item in value]
    if isinstance(value, str):
        return safe_text(value)
    return value
