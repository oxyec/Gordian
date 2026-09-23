from __future__ import annotations

import asyncio
import json
import sys

from src.models import ExploitCategory, Host, ReachableService, Service, Severity, Vulnerability
from src.offensive.config import OffensiveConfig, OffensiveMode
from src.offensive.hub import OffensiveIntegrationHub
from src.offensive.injector import GraphInjector
from src.offensive.parsers import Finding, NmapLineParser
import src.offensive.runner as runner_module
from src.offensive.runner import AsyncToolRunner
from src.offensive.command_factory import CommandSpec
from src.transformers import AttackGraph


def _entry_host() -> Host:
    return Host(
        id="attacker",
        hostname="attacker",
        ip_address="1.1.1.1",
        segment="INET",
        os="linux",
        is_attacker_entry=True,
        is_crown_jewel=False,
        criticality=1,
        services=(),
        reachable=(ReachableService("web", 443),),
    )


def _jewel_host() -> Host:
    return Host(
        id="web",
        hostname="web",
        ip_address="10.0.0.10",
        segment="DMZ",
        os="linux",
        is_attacker_entry=False,
        is_crown_jewel=True,
        criticality=9,
        services=(
            Service(
                name="https",
                port=443,
                protocol="tcp",
                version="1.0",
                cve_ids=("CVE-BASE",),
            ),
        ),
        reachable=(),
    )


def _base_vuln() -> Vulnerability:
    return Vulnerability(
        cve_id="CVE-BASE",
        cvss_v3=7.5,
        severity=Severity.HIGH,
        description="base",
        exploit_category=ExploitCategory.INITIAL_ACCESS,
        mitre_tactics=("TA0001",),
        mitre_techniques=("T1190",),
        exploitability=0.7,
        weaponized=True,
        epss_score=0.5,
        references=(),
    )


def _graph() -> tuple[AttackGraph, dict[str, Vulnerability]]:
    graph = AttackGraph()
    graph.add_host(_entry_host())
    graph.add_host(_jewel_host())
    vuln = _base_vuln()
    graph.add_edge("attacker", "web", 443, vuln, 0.1)
    return graph, {vuln.cve_id: vuln}


def test_graph_injector_adds_edge_for_sensitive_directory_finding():
    graph, cve_db = _graph()
    injector = GraphInjector(graph, cve_db, directory_injection=True)

    finding = Finding(
        tool="ffuf",
        finding_type="directory",
        technical="Found /config/backup.db via ffuf",
        raw_line="/config/backup.db [Status: 200, Size: 99, Words: 1, Lines: 1]",
        target_host_id="web",
        target_port=443,
        metadata={"path": "/config/backup.db", "status": 200, "size": 99},
    )

    before_edges = graph.edge_count()
    delta = injector.inject_finding(finding)

    assert delta.changed
    assert graph.edge_count() >= before_edges
    assert any(cve.startswith("GORDIAN-") for cve in cve_db)


def test_async_runner_streams_lines_without_blocking():
    parser = NmapLineParser("example.com")
    runner = AsyncToolRunner(max_concurrency=1, timeout_seconds=5)

    script = "\n".join(
        [
            "print('Nmap scan report for app-01 (10.2.2.2)')",
            "print('443/tcp open https nginx')",
            "print('script output: CVE-2024-2222')",
        ]
    )

    commands = [
        CommandSpec(
            tool="nmap",
            argv=(sys.executable, "-c", script),
        )
    ]

    seen = []

    async def _run():
        return await runner.run(
            commands,
            parser_factory=lambda _spec: parser,
            on_finding=lambda finding: seen.append(finding),
        )

    results = asyncio.run(_run())

    assert results[0].exit_code == 0
    assert results[0].findings_seen >= 2
    assert len(seen) >= 2


def test_async_runner_ffuf_uses_noninteractive_flag_and_new_session(monkeypatch):
    captured: dict[str, object] = {}

    class _NoopParser:
        def parse_line(self, _line: str):
            return []

    class _EmptyStream:
        async def readline(self) -> bytes:
            return b""

    class _FakeProcess:
        def __init__(self):
            self.stdout = _EmptyStream()
            self.stderr = _EmptyStream()
            self.returncode = 0

        async def wait(self) -> int:
            self.returncode = 0
            return 0

        def kill(self) -> None:
            self.returncode = -9

    async def _fake_create_subprocess_exec(*argv, **kwargs):
        captured["argv"] = argv
        captured["kwargs"] = kwargs
        return _FakeProcess()

    monkeypatch.setattr(runner_module, "_ffuf_supports_noninteractive", lambda _binary: True)
    monkeypatch.setattr(runner_module.asyncio, "create_subprocess_exec", _fake_create_subprocess_exec)

    runner = AsyncToolRunner(max_concurrency=1, timeout_seconds=5)
    command = CommandSpec(
        tool="ffuf",
        argv=("ffuf", "-u", "https://demo.testfire.net/FUZZ", "-w", "data/wordlists/seclists_common.txt"),
    )

    async def _run():
        return await runner.run(
            [command],
            parser_factory=lambda _spec: _NoopParser(),
            on_finding=lambda _finding: None,
        )

    results = asyncio.run(_run())

    assert results[0].exit_code == 0
    assert captured["argv"][-1] == "-noninteractive"
    assert captured["kwargs"]["start_new_session"] is True
    assert captured["kwargs"]["stdin"] == asyncio.subprocess.DEVNULL


def test_async_runner_review_mode_can_edit_command_before_execution():
    parser = NmapLineParser("example.com")

    original = CommandSpec(
        tool="nmap",
        argv=(sys.executable, "-c", "print('noop')"),
    )
    edited_argv = (
        sys.executable,
        "-c",
        "print('Nmap scan report for reviewed.example.com (10.1.1.9)')",
    )

    runner = AsyncToolRunner(
        max_concurrency=1,
        timeout_seconds=5,
        review_mode=True,
        command_reviewer=lambda _spec: CommandSpec(tool="nmap", argv=edited_argv),
    )

    findings = []

    async def _run():
        return await runner.run(
            [original],
            parser_factory=lambda _spec: parser,
            on_finding=lambda finding: findings.append(finding),
        )

    result = asyncio.run(_run())[0]

    assert result.argv == edited_argv
    assert result.exit_code == 0
    assert any(f.finding_type == "host" for f in findings)


def test_async_runner_review_mode_can_skip_command_execution():
    parser = NmapLineParser("example.com")
    runner = AsyncToolRunner(
        max_concurrency=1,
        timeout_seconds=5,
        review_mode=True,
        command_reviewer=lambda _spec: None,
    )

    async def _run():
        return await runner.run(
            [CommandSpec(tool="nmap", argv=(sys.executable, "-c", "print('will-not-run')"))],
            parser_factory=lambda _spec: parser,
            on_finding=lambda _finding: None,
        )

    result = asyncio.run(_run())[0]

    assert result.exit_code == 130
    assert result.findings_seen == 0


def test_offensive_hub_dry_run_generates_commands_and_keeps_graph_stable():
    graph, cve_db = _graph()
    cfg = OffensiveConfig(
        mode=OffensiveMode.DRY_RUN,
        target="https://web.example.com",
        tools=("nmap", "ffuf", "nuclei"),
    )
    hub = OffensiveIntegrationHub(cfg)

    summary = asyncio.run(hub.run(graph, cve_db))

    assert summary.mode == "dry-run"
    assert len(summary.commands) == 3
    assert summary.wordlist_profile is not None
    assert summary.findings == []
    assert summary.graph_updates["edges_added"] == 0


def test_offensive_hub_blocks_target_outside_scope_in_bugbounty_mode(tmp_path):
    graph, cve_db = _graph()
    scope = tmp_path / "scope.json"
    scope.write_text(
        json.dumps(
            {
                "allow_hosts": ["*.example.com"],
                "deny_hosts": [],
                "allow_cidrs": [],
                "deny_cidrs": [],
            }
        ),
        encoding="utf-8",
    )

    cfg = OffensiveConfig(
        mode=OffensiveMode.DRY_RUN,
        target="https://internal.not-example.net",
        tools=("nmap", "ffuf", "nuclei"),
        bugbounty_mode=True,
        scope_policy_file=str(scope),
        require_scope_match=True,
    )

    summary = asyncio.run(OffensiveIntegrationHub(cfg).run(graph, cve_db))

    assert summary.skipped_reason is not None
    assert "outside allow scope" in summary.skipped_reason
    assert summary.commands == []


def test_offensive_hub_applies_scope_rate_caps_and_headers(tmp_path):
    graph, cve_db = _graph()
    scope = tmp_path / "scope.json"
    scope.write_text(
        json.dumps(
            {
                "allow_hosts": ["*.example.com"],
                "max_nmap_rate": 12,
                "max_ffuf_threads": 4,
                "max_nuclei_rate": 18,
            }
        ),
        encoding="utf-8",
    )

    cfg = OffensiveConfig(
        mode=OffensiveMode.DRY_RUN,
        target="https://web.example.com",
        tools=("nmap", "ffuf", "nuclei"),
        request_headers=("Authorization: Bearer test",),
        scope_policy_file=str(scope),
        require_scope_match=True,
    )

    summary = asyncio.run(OffensiveIntegrationHub(cfg).run(graph, cve_db))
    by_tool = {cmd[0]: cmd for cmd in summary.commands}

    assert by_tool["nmap"][by_tool["nmap"].index("--max-rate") + 1] == "12"
    assert by_tool["ffuf"][by_tool["ffuf"].index("-t") + 1] == "4"
    assert "Authorization: Bearer test" in by_tool["ffuf"]
    assert by_tool["nuclei"][by_tool["nuclei"].index("-rl") + 1] == "18"
    assert "Authorization: Bearer test" in by_tool["nuclei"]


def test_offensive_hub_uses_graph_derived_wordlist_hints():
    graph, cve_db = _graph()
    web = graph.hosts["web"]
    graph.add_host(
        Host(
            id=web.id,
            hostname=web.hostname,
            ip_address=web.ip_address,
            segment=web.segment,
            os=web.os,
            is_attacker_entry=web.is_attacker_entry,
            is_crown_jewel=web.is_crown_jewel,
            criticality=web.criticality,
            services=(
                Service(
                    name="wordpress",
                    port=443,
                    protocol="tcp",
                    version="6.4",
                    cve_ids=web.services[0].cve_ids,
                ),
            ),
            reachable=web.reachable,
        )
    )

    cfg = OffensiveConfig(
        mode=OffensiveMode.DRY_RUN,
        target="https://web.example.com",
        tools=("ffuf",),
    )

    summary = asyncio.run(OffensiveIntegrationHub(cfg).run(graph, cve_db))

    assert "seclists_quickhits" in summary.wordlist_recommendations


def test_offensive_hub_deduplicates_findings_and_scores_confidence():
    graph, cve_db = _graph()
    cfg = OffensiveConfig(
        mode=OffensiveMode.AUTO,
        target="example.com",
        tools=("subfinder",),
        tool_command_overrides={
            "subfinder": (
                sys.executable,
                "-c",
                "print('dup.example.com');print('dup.example.com')",
            )
        },
    )

    summary = asyncio.run(OffensiveIntegrationHub(cfg).run(graph, cve_db))

    assert summary.deduplicated_findings == 1
    assert summary.duplicate_findings_dropped >= 1
    assert summary.mean_confidence > 0.0


def test_offensive_hub_respects_max_total_commands_budget():
    graph, cve_db = _graph()
    cfg = OffensiveConfig(
        mode=OffensiveMode.DRY_RUN,
        target="https://web.example.com",
        tools=("nmap", "ffuf", "nuclei"),
        max_total_commands=1,
    )

    summary = asyncio.run(OffensiveIntegrationHub(cfg).run(graph, cve_db))

    assert len(summary.commands) == 1
    assert summary.budget_stop_reason is not None
    assert "max_total_commands" in summary.budget_stop_reason


def test_offensive_hub_staged_followups_schedule_new_targets():
    graph, cve_db = _graph()
    cfg = OffensiveConfig(
        mode=OffensiveMode.AUTO,
        target="example.com",
        tools=("subfinder", "httpx"),
        max_total_commands=10,
        max_followup_targets=5,
        tool_command_overrides={
            "subfinder": (
                sys.executable,
                "-c",
                "print('api.example.com')",
            ),
            "httpx": (
                sys.executable,
                "-c",
                "import json, sys; t=sys.argv[1]; print(json.dumps({'url': f'http://{t}', 'status-code': 200, 'host': t, 'port': 80}))",
                "{target}",
            ),
        },
    )

    summary = asyncio.run(OffensiveIntegrationHub(cfg).run(graph, cve_db))

    command_joined = [" ".join(command) for command in summary.commands]
    assert any("example.com" in command for command in command_joined)
    assert any("api.example.com" in command for command in command_joined)


def test_offensive_hub_deduplicates_identical_host_findings_across_tools():
    graph, cve_db = _graph()
    cfg = OffensiveConfig(
        mode=OffensiveMode.AUTO,
        target="example.com",
        tools=("subfinder", "amass"),
        tool_command_overrides={
            "subfinder": (sys.executable, "-c", "print('dup.example.com')"),
            "amass": (sys.executable, "-c", "print('dup.example.com')"),
        },
    )

    summary = asyncio.run(OffensiveIntegrationHub(cfg).run(graph, cve_db))

    assert summary.deduplicated_findings == 1
    assert summary.duplicate_findings_dropped >= 1


def test_offensive_hub_survives_malformed_json_output_from_tool():
    graph, cve_db = _graph()
    cfg = OffensiveConfig(
        mode=OffensiveMode.AUTO,
        target="https://api.example.com",
        tools=("httpx",),
        tool_command_overrides={
            "httpx": (
                sys.executable,
                "-c",
                "print('{broken-json'); print('https://api.example.com [200]')",
            )
        },
    )

    summary = asyncio.run(OffensiveIntegrationHub(cfg).run(graph, cve_db))

    assert summary.tool_results
    assert summary.tool_results[0]["exit_code"] == 0
    assert summary.deduplicated_findings >= 1


def test_offensive_hub_handles_empty_tool_output_without_failure():
    graph, cve_db = _graph()
    cfg = OffensiveConfig(
        mode=OffensiveMode.AUTO,
        target="example.com",
        tools=("subfinder",),
        tool_command_overrides={"subfinder": (sys.executable, "-c", "import sys")},
    )

    summary = asyncio.run(OffensiveIntegrationHub(cfg).run(graph, cve_db))

    assert summary.tool_results
    assert summary.tool_results[0]["findings_seen"] == 0
    assert summary.findings == []


def test_offensive_hub_marks_timed_out_tool_runs():
    graph, cve_db = _graph()
    cfg = OffensiveConfig(
        mode=OffensiveMode.AUTO,
        target="example.com",
        tools=("subfinder",),
        timeout_seconds=5,
        tool_command_overrides={
            "subfinder": (
                sys.executable,
                "-c",
                "import time; print('slow.example.com'); time.sleep(6)",
            )
        },
    )

    summary = asyncio.run(OffensiveIntegrationHub(cfg).run(graph, cve_db))

    assert summary.tool_results
    assert summary.tool_results[0]["timed_out"] is True
