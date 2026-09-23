"""FastAPI application factory for Gordian.

Usage::

    from api.app import create_app
    app = create_app(args)
    uvicorn.run(app, host="0.0.0.0", port=args.api_port)

The factory wires together:
- CORS middleware (so the React dashboard can talk to the API)
- ScanManager (with the user-selected storage backend)
- WebSocketManager (real-time event broadcast)
- All REST + WS routes under ``/api/v1``
"""

from __future__ import annotations

import argparse
import logging
import os
from contextlib import asynccontextmanager
from typing import Any, AsyncGenerator

from fastapi import FastAPI, HTTPException, Request
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from .models import ErrorResponse
from .routes import router
from .state import ScanManager
from .websocket import WebSocketManager
from src.security import configured_api_key, valid_api_key

_HTTP_ERROR_CODES = {
    400: "bad_request",
    401: "unauthorized",
    403: "forbidden",
    404: "not_found",
    409: "conflict",
    422: "unprocessable_entity",
    429: "rate_limited",
    500: "internal_error",
    503: "service_unavailable",
}


def _error_payload(status_code: int, message: str, detail: Any = None) -> dict:
    return ErrorResponse(
        error=_HTTP_ERROR_CODES.get(status_code, "error"),
        message=message,
        status_code=status_code,
        detail=detail,
    ).model_dump()

log = logging.getLogger(__name__)


@asynccontextmanager
async def _lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Startup / shutdown hooks."""
    log.info(
        "Gordian API online — storage=%s, max_concurrent_scans=%d, port=%s",
        app.state.scan_manager.storage_backend_name,
        app.state.scan_manager.max_concurrent,
        getattr(app.state, "_api_port", "?"),
    )
    try:
        yield
    finally:
        if hasattr(app.state.scan_manager, "close"):
            await app.state.scan_manager.close()
        await app.state.ws_manager.close()
        log.info("Gordian API shutting down")


def create_app(args: argparse.Namespace | None = None) -> FastAPI:
    """Build and return a fully configured FastAPI instance."""

    storage_backend = getattr(args, "storage", "ram") if args else "ram"
    max_concurrent = getattr(args, "max_concurrent_scans", 1) if args else 1
    api_port = getattr(args, "api_port", 8000) if args else 8000
    api_key = configured_api_key()

    app = FastAPI(
        title="Gordian — Attack Path Intelligence API",
        description=(
            "Headless, API-first backend for the Gordian cyber-security "
            "reconnaissance and attack-path analysis engine. "
            "Provides REST endpoints for scan management, graph data, "
            "findings, and a WebSocket stream for real-time events."
        ),
        version="2.0.0",
        docs_url="/docs",
        redoc_url="/redoc",
        lifespan=_lifespan,
    )

    # ── CORS ──
    # Default to loopback origins only. Override via GORDIAN_CORS_ORIGINS
    # (comma-separated) when serving a remote frontend.
    cors_env = os.environ.get("GORDIAN_CORS_ORIGINS", "").strip()
    if cors_env:
        cors_origins = [o.strip() for o in cors_env.split(",") if o.strip()]
    else:
        cors_origins = [
            "http://localhost:5173", "http://127.0.0.1:5173",  # vite dev
            "http://localhost:3000", "http://127.0.0.1:3000",
            f"http://localhost:{api_port}", f"http://127.0.0.1:{api_port}",
        ]
    if "*" in cors_origins:
        raise ValueError("GORDIAN_CORS_ORIGINS must list explicit trusted origins")
    app.state.api_key = api_key
    app.state.allowed_origins = frozenset(cors_origins)
    app.state.ws_tickets = {}
    app.add_middleware(
        CORSMiddleware,
        allow_origins=cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.middleware("http")
    async def _api_key_middleware(request: Request, call_next):
        # Let CORSMiddleware answer preflight; all data/control routes require a key.
        if request.url.path.startswith("/api/") and request.method != "OPTIONS":
            origin = request.headers.get("origin")
            if origin and origin not in app.state.allowed_origins:
                return JSONResponse(status_code=403, content=_error_payload(403, "Untrusted origin"))
            if not valid_api_key(request.headers.get("x-api-key", ""), api_key):
                return JSONResponse(status_code=401, content=_error_payload(401, "Missing or invalid X-API-Key header"))
        return await call_next(request)

    # ── State management ──
    ws_manager = WebSocketManager(max_retained=2000)

    scan_manager = ScanManager(
        storage_backend=storage_backend,
        max_concurrent=max_concurrent,
        default_args=args,
        db_path=str(getattr(args, "db_path", "gordian_scans.db")) if args else "gordian_scans.db",
    )

    # Wire WebSocket broadcast into the ScanManager
    scan_manager.set_event_broadcaster(ws_manager.publish)

    app.state.scan_manager = scan_manager
    app.state.ws_manager = ws_manager
    app.state._api_port = api_port

    # ── Uniform error responses ──
    @app.exception_handler(HTTPException)
    async def _http_exc_handler(request: Request, exc: HTTPException):
        return JSONResponse(
            status_code=exc.status_code,
            content=_error_payload(exc.status_code, str(exc.detail)),
        )

    @app.exception_handler(RequestValidationError)
    async def _validation_exc_handler(request: Request, exc: RequestValidationError):
        return JSONResponse(
            status_code=422,
            content=jsonable_encoder(
                _error_payload(422, "Request validation failed", detail=[
                    {k: v for k, v in error.items() if k in {"loc", "msg", "type"}}
                    for error in exc.errors()
                ])
            ),
        )

    @app.exception_handler(Exception)
    async def _unhandled_exc_handler(request: Request, exc: Exception):
        log.exception("unhandled error on %s %s", request.method, request.url.path)
        return JSONResponse(
            status_code=500,
            content=_error_payload(500, "Internal server error"),
        )

    # ── Routes ──
    app.include_router(router)

    # ── Root redirect to docs ──
    @app.get("/", include_in_schema=False)
    async def _root():
        from fastapi.responses import RedirectResponse
        return RedirectResponse(url="/docs")

    return app
