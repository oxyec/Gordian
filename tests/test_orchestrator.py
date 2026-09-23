"""End-to-end tests: runs the actual pipeline on fixture data and checks
the JSON report + remediation output. Also covers malformed inputs so
the error path doesn't silently rot."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

from src.extractors import ExtractError
from src.orchestrator import AttackGraphETL


@pytest.fixture
def fixture_dir(tmp_path: Path) -> Path:
    network = {
        "hosts": [
            {
                "id": "attacker",
                "hostname": "attacker",
                "ip_address": "1.1.1.1",
                "segment": "INET",
                "os": "linux",
                "is_attacker_entry": True,
                "criticality": 0,
                "services": [],
                "reachable": [["edge", 443]],
            },
            {
                "id": "edge",
                "hostname": "edge",
                "ip_address": "10.0.0.1",
                "segment": "DMZ",
                "os": "linux",
                "criticality": 3,
                "services": [
                    {"name": "apache", "port": 443, "protocol": "tcp",
                     "version": "2.4.49", "cves": ["CVE-100"]}
                ],
                "reachable": [["core", 445]],
            },
            {
                "id": "core",
                "hostname": "core",
                "ip_address": "10.0.0.2",
                "segment": "CORP",
                "os": "windows",
                "criticality": 7,
                "services": [
                    {"name": "smb", "port": 445, "protocol": "tcp",
                     "version": "SMBv3", "cves": ["CVE-200"]}
                ],
                "reachable": [["crown", 5432]],
            },
            {
                "id": "crown",
                "hostname": "crown",
                "ip_address": "10.0.0.3",
                "segment": "CROWN",
                "os": "linux",
                "is_crown_jewel": True,
                "criticality": 10,
                "services": [
                    {"name": "postgres", "port": 5432, "protocol": "tcp",
                     "version": "13", "cves": ["CVE-300"]}
                ],
                "reachable": [],
            },
        ]
    }
    cves = {
        "cves": [
            {
                "cve_id": "CVE-100", "cvss_v3": 9.8, "severity": "CRITICAL",
                "description": "edge RCE", "exploit_category": "INITIAL_ACCESS",
                "mitre_tactics": ["TA0001"], "mitre_techniques": ["T1190"],
                "exploitability": 0.9, "weaponized": True, "epss_score": 0.8,
            },
            {
                "cve_id": "CVE-200", "cvss_v3": 9.0, "severity": "CRITICAL",
                "description": "core pivot", "exploit_category": "LATERAL_MOVEMENT",
                "mitre_tactics": ["TA0008"], "mitre_techniques": ["T1210"],
                "exploitability": 0.85, "weaponized": True, "epss_score": 0.7,
            },
            {
                "cve_id": "CVE-300", "cvss_v3": 8.0, "severity": "HIGH",
                "description": "crown priv-esc", "exploit_category": "PRIVILEGE_ESCALATION",
                "mitre_tactics": ["TA0004"], "mitre_techniques": ["T1068"],
                "exploitability": 0.6, "weaponized": False, "epss_score": 0.2,
            },
        ]
    }
    (tmp_path / "network.json").write_text(json.dumps(network))
    (tmp_path / "cves.json").write_text(json.dumps(cves))
    return tmp_path


def test_pipeline_runs_end_to_end(fixture_dir: Path):
    out = fixture_dir / "reports"
    etl = AttackGraphETL(
        network_source=fixture_dir / "network.json",
        cve_source=fixture_dir / "cves.json",
        output_dir=out,
        quiet=True,
    )
    result = asyncio.run(etl.run())

    assert result.kill_chains == 1
    assert result.json_report.exists()
    assert result.markdown_report.exists()

    payload = json.loads(result.json_report.read_text())
    assert payload["total_paths"] == 1
    assert payload["graph_stats"]["nodes"] == 4
    chain = payload["kill_chains"][0]
    assert chain["target_host"] == "crown"
    assert chain["exploit_chain"] == ["CVE-100", "CVE-200", "CVE-300"]
    assert 0 < chain["risk_score"] <= 100


def test_pipeline_surfaces_remediation(fixture_dir: Path):
    etl = AttackGraphETL(
        network_source=fixture_dir / "network.json",
        cve_source=fixture_dir / "cves.json",
        output_dir=fixture_dir / "reports",
        quiet=True,
    )
    result = asyncio.run(etl.run())
    assert result.patches_suggested > 0

    payload = json.loads(result.json_report.read_text())
    patches = payload["patch_recommendations"]
    assert patches, "expected at least one patch recommendation"
    # Removing any of the three CVEs in the chain should break it completely.
    assert any(p["chains_broken"] == 1 for p in patches)


def test_pipeline_with_no_remediation_flag(fixture_dir: Path):
    etl = AttackGraphETL(
        network_source=fixture_dir / "network.json",
        cve_source=fixture_dir / "cves.json",
        output_dir=fixture_dir / "reports",
        run_remediation=False,
        quiet=True,
    )
    result = asyncio.run(etl.run())
    assert result.patches_suggested == 0


def test_missing_network_file_raises(tmp_path: Path):
    etl = AttackGraphETL(
        network_source=tmp_path / "does-not-exist.json",
        cve_source=tmp_path / "also-missing.json",
        output_dir=tmp_path / "reports",
        quiet=True,
    )
    with pytest.raises(FileNotFoundError):
        asyncio.run(etl.run())


def test_malformed_network_json_raises(tmp_path: Path):
    (tmp_path / "bad.json").write_text("{this is not json")
    (tmp_path / "cves.json").write_text('{"cves": []}')
    etl = AttackGraphETL(
        network_source=tmp_path / "bad.json",
        cve_source=tmp_path / "cves.json",
        output_dir=tmp_path / "reports",
        quiet=True,
    )
    with pytest.raises(ExtractError):
        asyncio.run(etl.run())


def test_network_missing_hosts_field_raises(tmp_path: Path):
    (tmp_path / "bad.json").write_text('{"segments": []}')
    (tmp_path / "cves.json").write_text('{"cves": []}')
    etl = AttackGraphETL(
        network_source=tmp_path / "bad.json",
        cve_source=tmp_path / "cves.json",
        output_dir=tmp_path / "reports",
        quiet=True,
    )
    with pytest.raises(ExtractError, match="hosts"):
        asyncio.run(etl.run())


def test_bad_reachable_entry_raises(tmp_path: Path):
    network = {
        "hosts": [{
            "id": "a", "hostname": "a", "ip_address": "1.1.1.1",
            "segment": "X", "os": "linux", "services": [],
            "reachable": ["not-a-pair"],
        }]
    }
    (tmp_path / "n.json").write_text(json.dumps(network))
    (tmp_path / "c.json").write_text('{"cves": []}')
    etl = AttackGraphETL(
        network_source=tmp_path / "n.json",
        cve_source=tmp_path / "c.json",
        output_dir=tmp_path / "reports",
        quiet=True,
    )
    with pytest.raises(ExtractError, match="reachable"):
        asyncio.run(etl.run())


def test_pipeline_asset_aware_filtering_emits_stats(fixture_dir: Path):
    cves_path = fixture_dir / "cves.json"
    payload = json.loads(cves_path.read_text())
    payload["cves"].append(
        {
            "cve_id": "CVE-NOISE-999",
            "cvss_v3": 9.5,
            "severity": "CRITICAL",
            "description": "Legacy mainframe parser issue",
            "exploit_category": "INITIAL_ACCESS",
            "mitre_tactics": ["TA0001"],
            "mitre_techniques": ["T1190"],
            "exploitability": 0.95,
            "weaponized": True,
            "epss_score": 0.8,
        }
    )
    cves_path.write_text(json.dumps(payload))

    events: list[dict] = []

    etl = AttackGraphETL(
        network_source=fixture_dir / "network.json",
        cve_source=cves_path,
        output_dir=fixture_dir / "reports",
        quiet=True,
        asset_aware_cves=True,
        asset_cve_min_score=2,
        asset_cve_keep_top=0,
    )
    result = asyncio.run(etl.run(live_log_hook=lambda event: events.append(event)))

    assert result.kill_chains == 1
    filter_events = [event for event in events if event.get("type") == "pipeline.extract.cve_filter"]
    assert filter_events
    latest = filter_events[-1]
    payload = latest.get("payload", {})
    assert payload.get("cves_before") == 4
    assert payload.get("cves_after") == 3


def test_pipeline_trend_report_compares_with_previous_run(fixture_dir: Path):
    out = fixture_dir / "reports"

    first = AttackGraphETL(
        network_source=fixture_dir / "network.json",
        cve_source=fixture_dir / "cves.json",
        output_dir=out,
        quiet=True,
    )
    asyncio.run(first.run())

    cves_path = fixture_dir / "cves.json"
    payload = json.loads(cves_path.read_text())
    payload["cves"] = [row for row in payload["cves"] if row["cve_id"] != "CVE-300"]
    cves_path.write_text(json.dumps(payload))

    second = AttackGraphETL(
        network_source=fixture_dir / "network.json",
        cve_source=cves_path,
        output_dir=out,
        quiet=True,
    )
    asyncio.run(second.run())

    report = json.loads((out / "attack_paths.json").read_text())
    trend = report.get("trend", {})

    assert trend.get("baseline_available") is True
    assert trend.get("closed_risk", 0) >= 0
    assert trend.get("new_cves_count", 0) >= 0
    assert trend.get("tool_success_rate_percent", 0) >= 0
    assert trend.get("estimated_false_positive_count", 0) >= 0

    tool_summary = trend.get("tool_results_summary", {})
    assert isinstance(tool_summary, dict)
    assert tool_summary.get("attempted", 0) >= 0
