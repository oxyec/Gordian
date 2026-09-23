"""Live event contract for offensive integrations."""

from __future__ import annotations

from datetime import datetime, timezone
import logging
from typing import Any, Callable
from ..security import redact

log = logging.getLogger(__name__)

LiveLogHook = Callable[[dict[str, Any]], None]


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def build_event(
    event_type: str,
    *,
    tool: str = "hub",
    level: str = "INFO",
    message: str = "",
    **payload: Any,
) -> dict[str, Any]:
    return redact({
        "timestamp": utc_now_iso(),
        "tool": tool,
        "level": level,
        "type": event_type,
        "message": message,
        "payload": payload,
    })


def emit_event(hook: LiveLogHook | None, event: dict[str, Any]) -> None:
    if hook is None:
        return
    try:
        hook(redact(event))
    except Exception:  # pragma: no cover - callback failures should never crash pipeline
        log.exception("live log hook raised while handling event: %s", event.get("type"))
