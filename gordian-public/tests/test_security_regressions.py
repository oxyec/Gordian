"""Publication hardening: exercise boundaries with harmless local processes."""
import asyncio
from dataclasses import replace
from types import SimpleNamespace
import math
import sys

import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from api.app import create_app
from api.models import ScanStartRequest
from api.state import ScanManager
from src.offensive.command_factory import CommandFactory, CommandFactoryError, CommandSpec
from src.offensive.config import OffensiveConfig
from src.offensive.runner import AsyncToolRunner
from src.offensive.scope_policy import ScopePolicy, evaluate_target_scope
from src.remediation import suggest_patches
from src.scoring import _geometric_mean, edge_cost
from src.security import redact
from src.transformers import AttackGraph, find_all_kill_chains, find_shortest_attack_path
from tests.test_pathfinder import _host, _vuln


def test_server_requires_strong_configured_key(monkeypatch):
    monkeypatch.delenv("GORDIAN_API_KEY", raising=False)
    with pytest.raises(ValueError, match="GORDIAN_API_KEY"):
        create_app()


def test_http_and_websocket_authentication_and_ticket_replay(monkeypatch):
    key = "test-only-not-a-secret-" * 2
    monkeypatch.setenv("GORDIAN_API_KEY", key)
    with TestClient(create_app()) as client:
        assert client.get("/api/v1/info").status_code == 401
        assert client.get("/api/v1/info", headers={"X-API-Key": key, "Origin": "https://evil.example"}).status_code == 403
        with pytest.raises(WebSocketDisconnect):
            with client.websocket_connect("/api/v1/live"):
                pass
        with client.websocket_connect("/api/v1/live", headers={"X-API-Key": key}) as ws:
            assert ws.receive_json()["type"] == "dashboard.bootstrap"
        origin = "http://localhost:5173"
        response = client.post("/api/v1/auth/ws-ticket", headers={"X-API-Key": key, "Origin": origin})
        assert response.status_code == 200
        ticket = response.json()["ticket"]
        url = "/api/v1/live?ticket=" + ticket
        with client.websocket_connect(url, headers={"Origin": origin}) as ws:
            assert ws.receive_json()["type"] == "dashboard.bootstrap"
        with pytest.raises(WebSocketDisconnect):
            with client.websocket_connect(url, headers={"Origin": origin}):
                pass


@pytest.mark.parametrize("body", [
    {"tool_bin": {"nmap": "python"}},
    {"tool_extra_args": {"nmap": ["--script", "payload.nse"]}},
    {"tool_command": {"nmap": ["python", "-c", "print(1)"]}},
    {"network_file": "C:/private.json"}, {"cve_file": "/etc/private.json"},
    {"output_dir": "other"}, {"full_control": True}, {"cve_auto_download": True},
])
def test_remote_scan_request_rejects_execution_and_path_overrides(body):
    with pytest.raises(ValueError):
        ScanStartRequest(**body)


@pytest.mark.parametrize("target", ["-sV", "@targets.txt", "https://-sV/", "bad..example", "https://user:password@example.com"])
def test_target_cannot_be_an_option_or_credential(target):
    with pytest.raises(CommandFactoryError):
        CommandFactory(OffensiveConfig(target=target, tools=("nmap",))).build()


def test_wordlist_interpolation_stays_one_argument():
    wordlist = "lists/common.txt -rate 9999"
    argv = CommandFactory(OffensiveConfig(target="https://app.example.com", tools=("ffuf",), ffuf_wordlist=wordlist)).build()[0].argv
    assert argv[argv.index("-w") + 1] == wordlist
    assert "9999" not in argv


def test_scope_checks_whole_cidr_ipv6_and_empty_allowlist():
    assert not evaluate_target_scope("example.com", ScopePolicy())[0]
    policy = ScopePolicy(allow_cidrs=("192.0.2.0/24",), deny_cidrs=("192.0.2.128/25",))
    assert not evaluate_target_scope("192.0.2.0/24", policy)[0]
    assert not evaluate_target_scope("192.0.2.0/16", policy)[0]
    assert evaluate_target_scope("192.0.2.0/26", policy)[0]
    assert evaluate_target_scope("2001:db8::1", ScopePolicy(allow_cidrs=("2001:db8::/32",)))[0]


def test_remediation_preserves_runtime_alternate_route():
    graph = AttackGraph()
    graph.add_host(_host("a", entry=True))
    graph.add_host(_host("b", jewel=True, crit=10))
    first, fallback = _vuln("CVE-FIRST"), _vuln("CVE-FALLBACK", exploitability=.8)
    for vuln in (first, fallback):
        graph.add_edge("a", "b", 443, vuln, edge_cost(vuln, 10))
    result = suggest_patches(graph, find_all_kill_chains(graph), {v.cve_id: v for v in (first, fallback)})
    assert result and result[0].chains_remaining == 1
    assert graph.edge_count() == 2


def test_zero_cost_cycle_disconnected_nodes_and_stable_mean():
    graph = AttackGraph()
    for name in ("a", "b", "c", "isolated"):
        graph.add_host(_host(name))
    vuln = _vuln("CVE-TEST")
    for src, dst in (("a", "b"), ("b", "a"), ("b", "c")):
        graph.add_edge(src, dst, 443, vuln, 0)
    assert find_shortest_attack_path(graph, "a", "c").hops == 2
    assert find_shortest_attack_path(graph, "a", "isolated") is None
    assert math.isclose(_geometric_mean([.05] * 300), .05)
    for invalid in (-1., float("nan"), float("inf")):
        with pytest.raises(ValueError):
            graph.add_edge("a", "b", 443, vuln, invalid)
        with pytest.raises(ValueError):
            replace(vuln, cvss_v3=invalid)


def test_event_redaction_withholds_raw_evidence():
    result = redact({"command": ["tool", "credential"], "raw_line": "secret evidence", "metadata": {"api_key": "sensitive"}, "message": "\x1b[31mAuthorization: Bearer sensitive"})
    assert "sensitive" not in str(result)
    assert "secret evidence" not in str(result)
    assert "\x1b" not in str(result)


def test_completed_graph_survives_cache_eviction_and_restart(tmp_path):
    path = str(tmp_path / "scans.db")
    manager = ScanManager(storage_backend="sqlite", db_path=path)
    record = manager.storage.create_scan({})
    graph = AttackGraph()
    graph.add_host(_host("a", entry=True))
    graph.add_host(_host("b", jewel=True))
    vuln = _vuln("CVE-TEST")
    graph.add_edge("a", "b", 443, vuln, .1)
    manager._graphs[record.scan_id] = graph
    manager._kill_chains[record.scan_id] = find_all_kill_chains(graph)
    manager._cve_dbs[record.scan_id] = {vuln.cve_id: vuln}
    manager._findings[record.scan_id] = [{"raw_line": "private evidence"}]
    manager._mark_scan_completed(scan_id=record.scan_id, record=record, result=SimpleNamespace(
        kill_chains=1, patches_suggested=0, offensive_findings=1, elapsed_seconds=.1))
    manager.storage.close()
    restored = ScanManager(storage_backend="sqlite", db_path=path)
    try:
        assert restored.get_graph_data(record.scan_id)["edge_count"] == 1
        assert len(restored.get_kill_chains(record.scan_id)) == 1
        assert "private evidence" not in str(restored.get_findings(record.scan_id))
    finally:
        restored.storage.close()


class _NoFindings:
    def parse_line(self, _line):
        return []


@pytest.mark.asyncio
@pytest.mark.parametrize("cancel", [True, False])
async def test_cancel_and_timeout_kill_descendants(tmp_path, cancel):
    ready, marker = tmp_path / "ready", tmp_path / "survived"
    child = f"import time,pathlib; time.sleep(2); pathlib.Path({str(marker)!r}).write_text('bad'); time.sleep(20)"
    parent = f"import subprocess,sys,pathlib,time; subprocess.Popen([sys.executable,'-c',{child!r}]); pathlib.Path({str(ready)!r}).write_text('ready'); time.sleep(30)"
    runner = AsyncToolRunner(max_concurrency=1, timeout_seconds=30 if cancel else .75)
    task = asyncio.create_task(runner.run([CommandSpec("test", (sys.executable, "-c", parent))], parser_factory=lambda _: _NoFindings(), on_finding=lambda _: None))
    for _ in range(100):
        if ready.exists():
            break
        await asyncio.sleep(.02)
    assert ready.exists(), "supervised child did not start"
    if cancel:
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(task, 5)
    else:
        results = await asyncio.wait_for(task, 5)
        assert results[0].timed_out
    await asyncio.sleep(2.2)
    assert not marker.exists(), "descendant survived cancellation/timeout"
