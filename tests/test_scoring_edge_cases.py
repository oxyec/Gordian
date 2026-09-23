"""Edge cases for scoring + remediation that the main pathfinder tests don't cover.

Targets the Faz 1 hardening: criticality clamp, cost clamp, empty CVSS chain,
weaponisation warning, and rerouted patch logging.
"""

from __future__ import annotations

import logging

import pytest

from src import scoring
from src.models import (
    AttackPath,
    AttackStep,
    ExploitCategory,
    Host,
    ReachableService,
    Service,
    Severity,
    Vulnerability,
)
from src.remediation import suggest_patches
from src.scoring import path_risk_score
from src.transformers import build_graph, find_all_kill_chains


def _vuln(cve_id: str, **kwargs) -> Vulnerability:
    defaults = dict(
        cvss_v3=9.0,
        severity=Severity.CRITICAL,
        description="test",
        exploit_category=ExploitCategory.INITIAL_ACCESS,
        mitre_tactics=("TA0001",),
        mitre_techniques=("T1190",),
        exploitability=0.9,
        weaponized=True,
        epss_score=0.9,
    )
    defaults.update(kwargs)
    return Vulnerability(cve_id=cve_id, **defaults)


def _host(host_id: str, *, cve_ids=(), port=443, reachable=(), entry=False,
          jewel=False, crit=5) -> Host:
    svc = Service(name="svc", port=port, protocol="tcp", version="1", cve_ids=cve_ids)
    return Host(
        id=host_id, hostname=host_id, ip_address="10.0.0.1", segment="T",
        os="linux", is_attacker_entry=entry, is_crown_jewel=jewel,
        criticality=crit, services=(svc,) if cve_ids else (),
        reachable=tuple(ReachableService(h, p) for h, p in reachable),
    )


def _step(cve_id: str, cost: float = 0.5,
          category: ExploitCategory = ExploitCategory.INITIAL_ACCESS) -> AttackStep:
    return AttackStep(
        source_host_id="a", target_host_id="b", target_port=443,
        cve_id=cve_id, technique="T1190", category=category, cost=cost,
    )


def test_criticality_above_10_is_clamped():
    """Bad upstream data (criticality=99) must not push score above 100."""
    jewel = _host("j", jewel=True, crit=99)
    path = AttackPath(
        entry_host_id="a", target_host_id="j",
        steps=[_step("CVE-1")], total_cost=0.5, cvss_chain=[9.0],
    )
    score = path_risk_score(path, jewel, {"CVE-1": _vuln("CVE-1")})
    assert 0 <= score <= 100


def test_negative_criticality_is_clamped():
    jewel = _host("j", jewel=True, crit=-5)
    path = AttackPath(
        entry_host_id="a", target_host_id="j",
        steps=[_step("CVE-1")], total_cost=0.5, cvss_chain=[9.0],
    )
    score = path_risk_score(path, jewel, {"CVE-1": _vuln("CVE-1")})
    assert 0 <= score <= 100


def test_cost_above_one_does_not_produce_negative_confidence():
    """If a step cost is >1 (shouldn't happen but defensive), confidence floor
    must still hold — no NaN, no negative contribution."""
    jewel = _host("j", jewel=True, crit=10)
    path = AttackPath(
        entry_host_id="a", target_host_id="j",
        steps=[_step("CVE-1", cost=2.5)], total_cost=2.5, cvss_chain=[9.0],
    )
    score = path_risk_score(path, jewel, {"CVE-1": _vuln("CVE-1")})
    assert 0 <= score <= 100


def test_empty_cvss_chain_does_not_crash():
    """path.steps is empty path returns 0 early; but if steps exist with
    empty cvss_chain we still must not div-by-zero."""
    jewel = _host("j", jewel=True, crit=5)
    path = AttackPath(
        entry_host_id="a", target_host_id="j",
        steps=[_step("CVE-1")], total_cost=0.5, cvss_chain=[],
    )
    score = path_risk_score(path, jewel, {"CVE-1": _vuln("CVE-1")})
    assert 0 <= score <= 100


def test_empty_path_returns_zero():
    jewel = _host("j", jewel=True, crit=5)
    path = AttackPath(entry_host_id="a", target_host_id="j",
                      steps=[], total_cost=0.0, cvss_chain=[])
    assert path_risk_score(path, jewel) == 0.0


def test_missing_cve_db_logs_warning_once(caplog):
    scoring._warned_missing_cve_db = False  # reset module guard
    jewel = _host("j", jewel=True, crit=5)
    path = AttackPath(
        entry_host_id="a", target_host_id="j",
        steps=[_step("CVE-1")], total_cost=0.5, cvss_chain=[9.0],
    )
    with caplog.at_level(logging.WARNING, logger="src.scoring"):
        path_risk_score(path, jewel, cve_db=None)
        path_risk_score(path, jewel, cve_db=None)
    warnings = [r for r in caplog.records if "weaponisation" in r.message]
    assert len(warnings) == 1, "warning should fire exactly once per process"


def test_missing_mitre_technique_falls_back_to_unknown(caplog):
    hosts = [
        _host("attacker", entry=True, reachable=(("web", 443),)),
        _host("web", cve_ids=("CVE-X",), jewel=True, crit=10),
    ]
    cve_db = {"CVE-X": _vuln("CVE-X", mitre_techniques=())}
    with caplog.at_level(logging.WARNING, logger="src.transformers"):
        graph = build_graph(hosts, cve_db)
        chains = find_all_kill_chains(graph)
    assert chains and chains[0].steps[0].technique == "UNKNOWN"
    assert any("UNKNOWN" in r.message for r in caplog.records)


def test_rerouted_patches_are_logged_separately(caplog):
    """Two parallel paths through different CVEs: patching one CVE breaks
    that chain but attacker reroutes through the other. Net risk barely
    changes — patch should be filtered out and logged as rerouted."""
    hosts = [
        _host("attacker", entry=True, reachable=(("hopA", 443), ("hopB", 443))),
        _host("hopA", cve_ids=("CVE-A",), reachable=(("jewel", 443),)),
        _host("hopB", cve_ids=("CVE-B",), reachable=(("jewel", 443),)),
        _host("jewel", cve_ids=("CVE-J",), jewel=True, crit=10),
    ]
    cve_db = {
        "CVE-A": _vuln("CVE-A", exploitability=0.9),
        "CVE-B": _vuln("CVE-B", exploitability=0.9),
        "CVE-J": _vuln("CVE-J"),
    }
    graph = build_graph(hosts, cve_db)
    chains = find_all_kill_chains(graph)
    with caplog.at_level(logging.INFO, logger="src.remediation"):
        recs = suggest_patches(graph, chains, cve_db)
    # CVE-J sits on the shared chokepoint; it should be effective.
    assert any(r.cve_id == "CVE-J" for r in recs)
    # The "rerouted" log line should appear when at least one candidate is dropped.
    assert any("rerouted" in r.message for r in caplog.records)
