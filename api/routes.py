"""REST + WebSocket route definitions for the Gordian API.

All endpoints are versioned under ``/api/v1``.

REST:
    POST /api/v1/scan/start     — kick off a new scan
    GET  /api/v1/scan/status     — current scan progress & stats
    GET  /api/v1/scan/list       — list all scans (history)
    GET  /api/v1/graph           — attack graph nodes + edges
    GET  /api/v1/findings        — deduplicated offensive findings
    GET  /api/v1/kill-chains     — shortest-path kill chains
    GET  /api/v1/info            — server metadata

WebSocket:
    WS   /api/v1/live            — real-time event stream
"""

from __future__ import annotations

import logging
import secrets
import time
from typing import Any

from fastapi import APIRouter, HTTPException, Query, Request, WebSocket
from src.security import valid_api_key

from .models import (
    FindingsResponse,
    GraphResponse,
    ScanStartRequest,
    ScanStartResponse,
    ScanStatusEnum,
    ScanStatusResponse,
    ServerInfoResponse,
)

log = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1", tags=["gordian"])


# ── Helpers ──────────────────────────────────────────────────────────

def _manager(request: Request):
    """Retrieve the ScanManager from app state."""
    return request.app.state.scan_manager


def _ws_manager(request_or_ws):
    """Retrieve the WebSocketManager from app state."""
    if hasattr(request_or_ws, "app"):
        return request_or_ws.app.state.ws_manager
    return None


# ── Server Info ──────────────────────────────────────────────────────

@router.get("/info", response_model=ServerInfoResponse)
async def server_info(request: Request) -> ServerInfoResponse:
    """Return server metadata and configuration."""
    mgr = _manager(request)
    return ServerInfoResponse(
        name="Gordian",
        version="2.0.0-api",
        status="online",
        storage_backend=mgr.storage_backend_name,
        max_concurrent_scans=mgr.max_concurrent,
        active_scans=mgr.active_scan_count,
        api_version="v1",
    )


# ── Scan Lifecycle ───────────────────────────────────────────────────

@router.post("/scan/start", response_model=ScanStartResponse)
async def scan_start(request: Request, body: ScanStartRequest) -> ScanStartResponse:
    """Start a new attack-path scan.

    Accepts target, offensive mode, CVE profile, and all other knobs
    as a JSON body. The scan runs in the background; poll ``/scan/status``
    or connect to the ``/live`` WebSocket for real-time updates.
    """
    mgr = _manager(request)
    try:
        record = await mgr.start_scan(body)
    except RuntimeError as exc:
        raise HTTPException(status_code=429, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    return ScanStartResponse(
        scan_id=record.scan_id,
        status=ScanStatusEnum(record.status),
        message=f"Scan {record.scan_id} started",
    )


@router.post("/scan/{scan_id}/cancel")
async def scan_cancel(request: Request, scan_id: str) -> dict[str, Any]:
    """Cancel a running scan.

    Returns 200 with ``cancelled: true`` if the scan was running, or 404 if
    the scan is unknown or already finished.
    """
    mgr = _manager(request)
    cancelled = await mgr.cancel_scan(scan_id)
    if not cancelled:
        raise HTTPException(
            status_code=404,
            detail=f"Scan {scan_id} is not running (already finished or unknown)",
        )
    return {"scan_id": scan_id, "cancelled": True}


@router.get("/scan/status", response_model=ScanStatusResponse)
async def scan_status(
    request: Request,
    scan_id: str | None = Query(None, description="Specific scan ID (omit for latest)"),
) -> ScanStatusResponse:
    """Return the current progress and statistics for a scan."""
    mgr = _manager(request)
    return mgr.get_status(scan_id)


@router.get("/scan/list")
async def scan_list(
    request: Request,
    limit: int = Query(50, ge=1, le=500, description="Max scans to return"),
) -> list[dict[str, Any]]:
    """List all scans — most recent first."""
    mgr = _manager(request)
    return mgr.list_scans(limit=limit)


# ── Graph ────────────────────────────────────────────────────────────

@router.get("/graph", response_model=GraphResponse)
async def get_graph(
    request: Request,
    scan_id: str | None = Query(None, description="Specific scan ID (omit for latest)"),
) -> GraphResponse:
    """Return the attack graph (hosts + edges) for 3D visualisation.

    The React Web Dashboard uses this endpoint to draw the interactive
    network map. Each host becomes a node, each exploit edge an arrow.
    """
    mgr = _manager(request)
    data = mgr.get_graph_data(scan_id)
    return GraphResponse(**data)


# ── Kill Chains ──────────────────────────────────────────────────────

@router.get("/kill-chains")
async def get_kill_chains(
    request: Request,
    scan_id: str | None = Query(None, description="Specific scan ID (omit for latest)"),
) -> list[dict[str, Any]]:
    """Return Dijkstra shortest-path kill chains.

    Each chain shows the cheapest exploit path from an attacker entry
    point to a crown-jewel host, including MITRE ATT&CK mappings.
    """
    mgr = _manager(request)
    return mgr.get_kill_chains(scan_id)


# ── Findings ─────────────────────────────────────────────────────────

@router.get("/findings", response_model=FindingsResponse)
async def get_findings(
    request: Request,
    scan_id: str | None = Query(None, description="Specific scan ID (omit for latest)"),
) -> FindingsResponse:
    """Return deduplicated offensive findings from Nmap, FFUF, Nuclei, etc."""
    mgr = _manager(request)
    data = mgr.get_findings(scan_id)
    return FindingsResponse(**data)


# ── WebSocket Live Stream ────────────────────────────────────────────

@router.post("/auth/ws-ticket")
async def websocket_ticket(request: Request) -> dict[str, str]:
    """Exchange an authenticated request for a short-lived, single-use browser ticket."""
    tickets = request.app.state.ws_tickets
    now = time.monotonic()
    for token, (expires, _origin) in list(tickets.items()):
        if expires <= now:
            tickets.pop(token, None)
    if len(tickets) >= 256:
        raise HTTPException(status_code=429, detail="Too many outstanding WebSocket tickets")
    token = secrets.token_urlsafe(32)
    tickets[token] = (now + 30, request.headers.get("origin"))
    return {"ticket": token}

@router.websocket("/live")
async def websocket_live(ws: WebSocket) -> None:
    """Real-time event stream.

    On connect, the server sends a ``dashboard.bootstrap`` message
    containing all retained events. After that, every pipeline event
    is pushed as a JSON string::

        {"type": "offensive.finding", "message": "...", "confidence": 0.9, ...}

    The client should only read; sent messages are ignored.
    """
    origin = ws.headers.get("origin")
    if origin is not None and origin not in ws.app.state.allowed_origins:
        await ws.close(code=1008)
        return
    authorized = valid_api_key(ws.headers.get("x-api-key", ""), ws.app.state.api_key)
    if not authorized:
        ticket = ws.query_params.get("ticket", "")
        grant = ws.app.state.ws_tickets.pop(ticket, None)
        authorized = bool(grant and grant[0] > time.monotonic() and grant[1] == origin)
    if not authorized:
        await ws.close(code=1008)
        return
    ws_mgr = ws.app.state.ws_manager
    if await ws_mgr.connect(ws):
        await ws_mgr.listen(ws)
