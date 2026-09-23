"""Bounded event delivery; authentication lives in routes.py."""
from __future__ import annotations

import asyncio
from collections import deque
from dataclasses import dataclass
import json
from typing import Any

from fastapi import WebSocket, WebSocketDisconnect
from src.security import redact


@dataclass
class _Client:
    queue: asyncio.Queue[str]
    writer: asyncio.Task[None] | None = None


class WebSocketManager:
    def __init__(self, max_retained: int = 2000) -> None:
        self._clients: dict[WebSocket, _Client] = {}
        self._events: deque[dict[str, Any]] = deque(maxlen=min(2000, max(1, max_retained)))
        self._sequence = 0
        self._writers: set[asyncio.Task[None]] = set()

    @property
    def client_count(self) -> int:
        return len(self._clients)

    async def connect(self, ws: WebSocket) -> bool:
        if len(self._clients) >= 32:
            await ws.close(code=1013)
            return False
        await ws.accept()
        client = _Client(asyncio.Queue(maxsize=128))
        client.queue.put_nowait(json.dumps({"type": "dashboard.bootstrap", "payload": {
            "events": list(self._events), "event_count": len(self._events),
            "client_count": len(self._clients) + 1}}, default=str))
        self._clients[ws] = client
        client.writer = asyncio.create_task(self._write(ws, client))
        self._writers.add(client.writer)
        client.writer.add_done_callback(self._writers.discard)
        return True

    async def _write(self, ws: WebSocket, client: _Client) -> None:
        try:
            while True:
                payload = await client.queue.get()
                await asyncio.wait_for(ws.send_text(payload), timeout=5)
        except (TimeoutError, OSError, RuntimeError):
            pass
        finally:
            self._clients.pop(ws, None)
            try:
                await asyncio.wait_for(ws.close(code=1001), timeout=1)
            except (TimeoutError, OSError, RuntimeError):
                pass

    async def disconnect(self, ws: WebSocket) -> None:
        client = self._clients.pop(ws, None)
        if client and client.writer and client.writer is not asyncio.current_task():
            client.writer.cancel()
            await asyncio.gather(client.writer, return_exceptions=True)

    def publish(self, scan_id: str, event: dict[str, Any]) -> None:
        self._sequence += 1
        enriched = {**redact(event), "sequence": self._sequence, "scan_id": scan_id}
        payload = json.dumps(enriched, default=str, ensure_ascii=False)
        if len(payload.encode()) > 16 * 1024:
            return
        self._events.append(enriched)
        for ws, client in list(self._clients.items()):
            try:
                client.queue.put_nowait(payload)
            except asyncio.QueueFull:
                self._clients.pop(ws, None)
                if client.writer:
                    client.writer.cancel()

    async def listen(self, ws: WebSocket) -> None:
        try:
            while True:
                message = await ws.receive_text()
                if len(message) > 1024:
                    break
        except (WebSocketDisconnect, RuntimeError):
            pass
        finally:
            await self.disconnect(ws)

    async def close(self) -> None:
        writers = list(self._writers)
        for writer in writers:
            writer.cancel()
        await asyncio.gather(*writers, return_exceptions=True)
        self._clients.clear()
