"""Locks in the parallel suggest_patches behaviour.

The parallel path MUST be byte-identical to sequential for the same inputs
— callers (reports, TUI, dashboards) rely on a deterministic CVE order and
exact risk_reduction values. If a future refactor breaks this, downstream
diffs and snapshots will silently drift.
"""

from __future__ import annotations

from src.models import (
    ExploitCategory,
    Host,
    PatchRecommendation,
    ReachableService,
    Service,
    Severity,
    Vulnerability,
)
from src.remediation import suggest_patches
from src.transformers import build_graph, find_all_kill_chains


def _vuln(cve_id: str, **kw) -> Vulnerability:
    defaults = dict(
        cvss_v3=9.0,
        severity=Severity.CRITICAL,
        description="x",
        exploit_category=ExploitCategory.INITIAL_ACCESS,
        mitre_tactics=("TA0001",),
        mitre_techniques=("T1190",),
        exploitability=0.9,
        weaponized=True,
        epss_score=0.5,
    )
    defaults.update(kw)
    return Vulnerability(cve_id=cve_id, **defaults)


def _host(host_id, **kw):
    cve_ids = kw.pop("cve_ids", ())
    port = kw.pop("port", 443)
    reachable = kw.pop("reachable", ())
    svc = Service(name="s", port=port, protocol="tcp", version="1", cve_ids=cve_ids)
    defaults = dict(
        hostname=host_id, ip_address="10.0.0.1", segment="T", os="linux",
        is_attacker_entry=False, is_crown_jewel=False, criticality=5,
        services=(svc,) if cve_ids else (),
        reachable=tuple(ReachableService(h, p) for h, p in reachable),
    )
    defaults.update(kw)
    return Host(id=host_id, **defaults)


def _multi_chain_graph():
    """Larger fixture with multiple parallel paths so suggest_patches has
    several candidates to evaluate concurrently."""
    hosts = [
        _host("attacker", is_attacker_entry=True, criticality=1,
              reachable=(("hopA", 443), ("hopB", 443), ("hopC", 443))),
        _host("hopA", cve_ids=("CVE-A",), reachable=(("jewel1", 443),)),
        _host("hopB", cve_ids=("CVE-B",), reachable=(("jewel1", 443), ("jewel2", 443))),
        _host("hopC", cve_ids=("CVE-C",), reachable=(("jewel2", 443),)),
        _host("jewel1", cve_ids=("CVE-J1",), is_crown_jewel=True, criticality=10),
        _host("jewel2", cve_ids=("CVE-J2",), is_crown_jewel=True, criticality=9),
    ]
    cve_db = {
        "CVE-A": _vuln("CVE-A"),
        "CVE-B": _vuln("CVE-B"),
        "CVE-C": _vuln("CVE-C", exploitability=0.5),
        "CVE-J1": _vuln("CVE-J1"),
        "CVE-J2": _vuln("CVE-J2", cvss_v3=7.5),
    }
    return hosts, cve_db


def _as_tuple(rec: PatchRecommendation) -> tuple:
    return (rec.cve_id, rec.cvss, rec.chains_broken,
            rec.chains_remaining, rec.risk_reduction)


def test_parallel_results_byte_identical_to_sequential():
    hosts, cve_db = _multi_chain_graph()
    graph = build_graph(hosts, cve_db)
    chains = find_all_kill_chains(graph)

    seq = suggest_patches(graph, chains, cve_db, top_n=10, max_workers=1)
    par = suggest_patches(graph, chains, cve_db, top_n=10, max_workers=4)

    assert [_as_tuple(r) for r in seq] == [_as_tuple(r) for r in par]


def test_parallel_handles_single_candidate_without_pool():
    """One CVE in chains → no pool overhead, sequential path returns same."""
    attacker = _host("attacker", is_attacker_entry=True, criticality=1,
                     reachable=(("jewel", 443),))
    jewel = _host("jewel", cve_ids=("CVE-X",), is_crown_jewel=True, criticality=10)
    cve_db = {"CVE-X": _vuln("CVE-X")}
    graph = build_graph([attacker, jewel], cve_db)
    chains = find_all_kill_chains(graph)

    res = suggest_patches(graph, chains, cve_db, max_workers=4)
    assert len(res) == 1
    assert res[0].cve_id == "CVE-X"


def test_parallel_skips_empty_baseline():
    res = suggest_patches(build_graph([], {}), [], {}, max_workers=4)
    assert res == []


def test_max_workers_none_uses_cpu_count_capped():
    """Default workers must scale with cpu_count but never above 8 or below 1.
    Doesn't assert exact value (varies by host), just that it runs cleanly."""
    hosts, cve_db = _multi_chain_graph()
    graph = build_graph(hosts, cve_db)
    chains = find_all_kill_chains(graph)
    res = suggest_patches(graph, chains, cve_db, max_workers=None)
    assert res, "default worker count should still produce recommendations"
