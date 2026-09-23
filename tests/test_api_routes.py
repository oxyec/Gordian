from __future__ import annotations

from types import SimpleNamespace
import os
import pytest

from fastapi.testclient import TestClient

from api.app import create_app
from api.models import ScanProgress, ScanStatsSnapshot, ScanStatusEnum, ScanStatusResponse


class _DummyManager:
    storage_backend_name = "ram"
    max_concurrent = 2
    active_scan_count = 1

    def __init__(self) -> None:
        self.raise_on_start = False
        self.last_status_scan_id: str | None = None
        self.last_graph_scan_id: str | None = None
        self.last_findings_scan_id: str | None = None
        self.last_kill_chain_scan_id: str | None = None
        self.cancel_returns = True
        self.last_cancel_scan_id: str | None = None

    async def cancel_scan(self, scan_id: str) -> bool:
        self.last_cancel_scan_id = scan_id
        return self.cancel_returns

    async def start_scan(self, _body):
        if self.raise_on_start:
            raise RuntimeError("busy")
        return SimpleNamespace(scan_id="scan-123", status="running")

    def get_status(self, scan_id: str | None = None) -> ScanStatusResponse:
        self.last_status_scan_id = scan_id
        return ScanStatusResponse(
            scan_id="scan-123",
            status=ScanStatusEnum.RUNNING,
            progress=ScanProgress(stage="running", percent=22.0, message="working"),
            stats=ScanStatsSnapshot(hosts=3, edges=2, kill_chains=1, findings=0, patches=0),
            elapsed_seconds=1.2,
        )

    def list_scans(self, limit: int = 50):
        return [{"scan_id": "scan-123", "status": "running", "limit_seen": limit}]

    def get_graph_data(self, scan_id: str | None = None):
        self.last_graph_scan_id = scan_id
        return {
            "hosts": [],
            "edges": [],
            "entry_points": [],
            "crown_jewels": [],
            "node_count": 0,
            "edge_count": 0,
        }

    def get_findings(self, scan_id: str | None = None):
        self.last_findings_scan_id = scan_id
        return {"total": 0, "deduplicated": 0, "findings": []}

    def get_kill_chains(self, scan_id: str | None = None):
        self.last_kill_chain_scan_id = scan_id
        return []


@pytest.fixture(autouse=True)
def api_credentials(monkeypatch):
    monkeypatch.setenv("GORDIAN_API_KEY", "test-only-not-a-secret-" * 2)


def _make_client(manager: _DummyManager) -> TestClient:
    app = create_app()
    app.state.scan_manager = manager
    return TestClient(app, headers={"X-API-Key": os.environ["GORDIAN_API_KEY"]})


def test_info_endpoint_returns_server_metadata() -> None:
    manager = _DummyManager()
    with _make_client(manager) as client:
        response = client.get("/api/v1/info")

    assert response.status_code == 200
    payload = response.json()
    assert payload["storage_backend"] == "ram"
    assert payload["active_scans"] == 1


def test_scan_start_accepts_valid_payload_and_returns_scan_id() -> None:
    manager = _DummyManager()
    with _make_client(manager) as client:
        response = client.post(
            "/api/v1/scan/start",
            json={
                "target": "https://app.example.com",
                "network_file": "data/sample_network.json",
                "cve_file": "data/cve_feed.json",
                "output_dir": "reports",
            },
        )

    assert response.status_code == 200
    payload = response.json()
    assert payload["scan_id"] == "scan-123"
    assert payload["status"] == "running"


def test_scan_start_rejects_invalid_path_traversal() -> None:
    manager = _DummyManager()
    with _make_client(manager) as client:
        response = client.post(
            "/api/v1/scan/start",
            json={
                "network_file": "../etc/passwd",
            },
        )

    assert response.status_code == 422
    assert "parent traversal" in response.text


def test_scan_start_returns_429_when_manager_is_busy() -> None:
    manager = _DummyManager()
    manager.raise_on_start = True
    with _make_client(manager) as client:
        response = client.post("/api/v1/scan/start", json={"target": "example.com"})

    assert response.status_code == 429
    body = response.json()
    assert body["error"] == "rate_limited"
    assert body["message"] == "busy"
    assert body["status_code"] == 429


def test_status_graph_findings_and_kill_chains_forward_scan_id() -> None:
    manager = _DummyManager()
    with _make_client(manager) as client:
        status = client.get("/api/v1/scan/status", params={"scan_id": "scan-a"})
        graph = client.get("/api/v1/graph", params={"scan_id": "scan-b"})
        findings = client.get("/api/v1/findings", params={"scan_id": "scan-c"})
        kill_chains = client.get("/api/v1/kill-chains", params={"scan_id": "scan-d"})

    assert status.status_code == 200
    assert graph.status_code == 200
    assert findings.status_code == 200
    assert kill_chains.status_code == 200
    assert manager.last_status_scan_id == "scan-a"
    assert manager.last_graph_scan_id == "scan-b"
    assert manager.last_findings_scan_id == "scan-c"
    assert manager.last_kill_chain_scan_id == "scan-d"


def test_scan_list_validates_limit_query_param() -> None:
    manager = _DummyManager()
    with _make_client(manager) as client:
        ok = client.get("/api/v1/scan/list", params={"limit": 5})
        bad = client.get("/api/v1/scan/list", params={"limit": 0})

    assert ok.status_code == 200
    assert ok.json()[0]["limit_seen"] == 5
    assert bad.status_code == 422


def test_scan_cancel_returns_ok_when_running() -> None:
    manager = _DummyManager()
    with _make_client(manager) as client:
        response = client.post("/api/v1/scan/scan-xyz/cancel")
    assert response.status_code == 200
    body = response.json()
    assert body["scan_id"] == "scan-xyz"
    assert body["cancelled"] is True
    assert manager.last_cancel_scan_id == "scan-xyz"


def test_scan_cancel_returns_404_when_not_running() -> None:
    manager = _DummyManager()
    manager.cancel_returns = False
    with _make_client(manager) as client:
        response = client.post("/api/v1/scan/missing/cancel")
    assert response.status_code == 404
    body = response.json()
    assert body["error"] == "not_found"
    assert "not running" in body["message"]
    assert body["status_code"] == 404


def test_validation_error_uses_uniform_error_response() -> None:
    manager = _DummyManager()
    with _make_client(manager) as client:
        response = client.post("/api/v1/scan/start", json={"target": ""})
    assert response.status_code == 422
    body = response.json()
    assert body["error"] == "unprocessable_entity"
    assert body["status_code"] == 422
    assert isinstance(body["detail"], list)


def test_api_key_middleware_blocks_when_env_set(monkeypatch) -> None:
    monkeypatch.setenv("GORDIAN_API_KEY", "test-only-not-a-secret-" * 2)
    manager = _DummyManager()
    with _make_client(manager) as client:
        unauthorised = client.get("/api/v1/info", headers={"X-API-Key": "wrong"})
        authorised = client.get("/api/v1/info")
    assert unauthorised.status_code == 401
    assert unauthorised.json()["error"] == "unauthorized"
    assert authorised.status_code == 200
