"""Optional local dashboard server for live offensive/pipeline events.

Provides:
- WebSocket stream endpoint: /ws
- REST health endpoint: /health
- REST retained events endpoint: /events
- REST aggregate metrics endpoint: /metrics
"""

from __future__ import annotations

from collections import Counter, deque
from dataclasses import dataclass
import asyncio
import json
import logging
from ..security import configured_api_key, valid_api_key, redact
from typing import Any

try:  # Optional dependency: only required when dashboard mode is enabled.
    from aiohttp import web
except Exception:  # pragma: no cover - import errors are handled at runtime.
    web = None

log = logging.getLogger(__name__)


class DashboardUnavailableError(RuntimeError):
    """Raised when dashboard mode is enabled without runtime dependencies."""


@dataclass(frozen=True)
class DashboardServerConfig:
    host: str = "127.0.0.1"
    port: int = 8765
    retain_events: int = 2000


class DashboardServer:
    def __init__(self, config: DashboardServerConfig) -> None:
        self.config = config
        self._events: deque[dict[str, Any]] = deque(maxlen=max(50, config.retain_events))
        self._sequence = 0
        self._runner: web.AppRunner | None = None if web else None
        self._site: web.TCPSite | None = None if web else None
        self._clients: set[web.WebSocketResponse] = set() if web else set()
        self._broadcast_queue: asyncio.Queue[dict[str, Any]] | None = None
        self._broadcast_task: asyncio.Task | None = None
        self._started = False

    @property
    def base_url(self) -> str:
        return f"http://{self.config.host}:{self.config.port}"

    @property
    def ws_url(self) -> str:
        return f"ws://{self.config.host}:{self.config.port}/ws"

    async def start(self) -> None:
        if web is None:
            raise DashboardUnavailableError(
                "Dashboard server requires aiohttp. Install it with: pip install aiohttp"
            )
        if self._started:
            return

        api_key = configured_api_key()

        @web.middleware
        async def authenticate(request, handler):
            origin = request.headers.get("Origin")
            trusted = {self.base_url, f"http://localhost:{self.config.port}"}
            if origin is not None and origin not in trusted:
                raise web.HTTPForbidden()
            if not valid_api_key(request.headers.get("X-API-Key", ""), api_key):
                raise web.HTTPUnauthorized()
            return await handler(request)

        app = web.Application(middlewares=[authenticate], client_max_size=16 * 1024)
        app.add_routes(
            [
                web.get("/health", self._handle_health),
                web.get("/events", self._handle_events),
                web.get("/metrics", self._handle_metrics),
                web.get("/ws", self._handle_ws),
            ]
        )
        self._runner = web.AppRunner(app)
        await self._runner.setup()
        self._site = web.TCPSite(self._runner, host=self.config.host, port=self.config.port)
        await self._site.start()

        self._broadcast_queue = asyncio.Queue(maxsize=256)
        self._broadcast_task = asyncio.create_task(self._broadcast_loop())
        self._started = True
        log.info("dashboard server started at %s (ws: %s)", self.base_url, self.ws_url)

    async def stop(self) -> None:
        if not self._started:
            return

        if self._broadcast_task is not None:
            self._broadcast_task.cancel()
            try:
                await self._broadcast_task
            except asyncio.CancelledError:
                log.debug("dashboard broadcast task cancelled")

        clients = list(self._clients)
        for ws in clients:
            try:
                await ws.close()
            except Exception:
                log.debug("failed to close dashboard websocket client", exc_info=True)

        self._clients.clear()

        if self._runner is not None:
            await self._runner.cleanup()

        self._runner = None
        self._site = None
        self._broadcast_queue = None
        self._broadcast_task = None
        self._started = False
        log.info("dashboard server stopped")

    def publish(self, event: dict[str, Any]) -> None:
        if not self._started:
            return

        self._sequence += 1
        enriched = redact(dict(event))
        if len(json.dumps(enriched, default=str).encode()) > 16 * 1024:
            return
        enriched["sequence"] = self._sequence
        self._events.append(enriched)

        queue = self._broadcast_queue
        if queue is None:
            return

        try:
            queue.put_nowait(enriched)
        except asyncio.QueueFull:
            log.warning("dashboard event queue full; dropping event")

    async def _broadcast_loop(self) -> None:
        queue = self._broadcast_queue
        if queue is None:
            return

        while True:
            event = await queue.get()
            payload = json.dumps(event, ensure_ascii=False)
            dead: list[web.WebSocketResponse] = []
            for ws in tuple(self._clients):
                try:
                    await asyncio.wait_for(ws.send_str(payload), timeout=2)
                except Exception:
                    dead.append(ws)
                    log.debug(
                        "failed to broadcast dashboard event to websocket client",
                        exc_info=True,
                    )

            for ws in dead:
                self._clients.discard(ws)
                await ws.close()

    async def _handle_health(self, _request: web.Request) -> web.Response:
        return web.json_response(
            {
                "ok": True,
                "clients": len(self._clients),
                "retained_events": len(self._events),
                "base_url": self.base_url,
                "ws_url": self.ws_url,
            }
        )

    async def _handle_events(self, request: web.Request) -> web.Response:
        limit_raw = request.query.get("limit")
        try:
            limit = int(limit_raw) if limit_raw is not None else len(self._events)
        except ValueError:
            limit = len(self._events)

        limit = max(1, min(limit, len(self._events) if self._events else 1))
        events = list(self._events)[-limit:]
        return web.json_response(
            {
                "count": len(events),
                "events": events,
            }
        )

    async def _handle_metrics(self, _request: web.Request) -> web.Response:
        type_counts = Counter()
        tool_counts = Counter()
        level_counts = Counter()

        for event in self._events:
            type_counts[str(event.get("type", "event"))] += 1
            tool_counts[str(event.get("tool", "hub"))] += 1
            level_counts[str(event.get("level", "INFO"))] += 1

        return web.json_response(
            {
                "event_count": len(self._events),
                "clients": len(self._clients),
                "by_type": dict(type_counts),
                "by_tool": dict(tool_counts),
                "by_level": dict(level_counts),
            }
        )

    async def _handle_ws(self, request: web.Request) -> web.StreamResponse:
        if len(self._clients) >= 16:
            raise web.HTTPServiceUnavailable()
        ws = web.WebSocketResponse(heartbeat=30, max_msg_size=1024)
        await ws.prepare(request)
        self._clients.add(ws)

        bootstrap = {
            "type": "dashboard.bootstrap",
            "message": "Initial retained events",
            "payload": {
                "events": list(self._events),
                "event_count": len(self._events),
            },
        }
        try:
            await ws.send_str(json.dumps(bootstrap, ensure_ascii=False))
            async for _msg in ws:
                # Read-only stream endpoint; ignore client messages.
                continue
        except Exception:
            log.debug("dashboard websocket session failed", exc_info=True)
        finally:
            self._clients.discard(ws)

        return ws
