from __future__ import annotations

import asyncio
import json
import socket

import pytest
from aiohttp import ClientSession

from src.offensive.dashboard import DashboardServer, DashboardServerConfig
from src.offensive.events import build_event


def _free_tcp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


@pytest.mark.asyncio
async def test_dashboard_server_exposes_health_events_metrics_and_ws_stream(monkeypatch) -> None:
    key = "test-only-not-a-secret-" * 2
    monkeypatch.setenv("GORDIAN_API_KEY", key)
    port = _free_tcp_port()
    server = DashboardServer(DashboardServerConfig(host="127.0.0.1", port=port, retain_events=50))

    await server.start()
    try:
        async with ClientSession(headers={"X-API-Key": key}) as session:
            health_url = f"http://127.0.0.1:{port}/health"
            events_url = f"http://127.0.0.1:{port}/events"
            metrics_url = f"http://127.0.0.1:{port}/metrics"
            ws_url = f"ws://127.0.0.1:{port}/ws"

            async with session.get(health_url) as response:
                assert response.status == 200
                payload = await response.json()
                assert payload["ok"] is True
                assert payload["retained_events"] == 0

            seed_event = build_event("pipeline.start", message="seed")
            server.publish(seed_event)

            async with session.get(events_url) as response:
                assert response.status == 200
                payload = await response.json()
                assert payload["count"] == 1
                assert payload["events"][0]["type"] == "pipeline.start"

            async with session.get(metrics_url) as response:
                assert response.status == 200
                payload = await response.json()
                assert payload["event_count"] == 1
                assert payload["by_type"]["pipeline.start"] == 1

            async with session.ws_connect(ws_url) as ws:
                bootstrap_raw = await asyncio.wait_for(ws.receive(), timeout=2)
                bootstrap_payload = json.loads(bootstrap_raw.data)
                assert bootstrap_payload["type"] == "dashboard.bootstrap"
                assert bootstrap_payload["payload"]["event_count"] == 1

                streamed = build_event("offensive.finding", tool="ffuf", message="stream")
                server.publish(streamed)

                stream_raw = await asyncio.wait_for(ws.receive(), timeout=2)
                stream_payload = json.loads(stream_raw.data)
                assert stream_payload["type"] == "offensive.finding"
                assert stream_payload["tool"] == "ffuf"
    finally:
        await server.stop()
