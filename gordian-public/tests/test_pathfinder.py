"""Graph + pathfinder regression tests.

    python -m pytest -v
"""

from __future__ import annotations

from src.models import (
    ExploitCategory,
    Host,
    ReachableService,
    Service,
    Severity,
    Vulnerability,
)
from src.scoring import path_risk_score
from src.transformers import (
    build_graph,
    find_all_kill_chains,
    find_shortest_attack_path,
)


def _vuln(
    cve_id: str,
    cvss: float = 9.0,
    exploitability: float = 0.9,
    category: ExploitCategory = ExploitCategory.INITIAL_ACCESS,
    technique: str = "T1190",
    weaponized: bool = True,
) -> Vulnerability:
    return Vulnerability(
        cve_id=cve_id,
        cvss_v3=cvss,
        severity=Severity.CRITICAL,
        description="test",
        exploit_category=category,
        mitre_tactics=("TA0001",),
        mitre_techniques=(technique,),
        exploitability=exploitability,
        weaponized=weaponized,
        epss_score=0.9,
    )


def _host(
    host_id: str,
    *,
    cve_ids: tuple[str, ...] = (),
    port: int = 443,
    reachable: tuple[tuple[str, int], ...] = (),
    entry: bool = False,
    jewel: bool = False,
    crit: int = 5,
) -> Host:
    service = Service(
        name="svc",
        port=port,
        protocol="tcp",
        version="1.0",
        cve_ids=cve_ids,
    )
    return Host(
        id=host_id,
        hostname=host_id,
        ip_address="10.0.0.1",
        segment="TEST",
        os="linux",
        is_attacker_entry=entry,
        is_crown_jewel=jewel,
        criticality=crit,
        services=(service,) if cve_ids else (),
        reachable=tuple(ReachableService(h, p) for h, p in reachable),
    )


def test_linear_chain_is_found():
    hosts = [
        _host("attacker", entry=True, reachable=(("web", 443),)),
        _host("web", cve_ids=("CVE-A",), reachable=(("db", 443),)),
        _host("db", cve_ids=("CVE-B",), jewel=True, crit=10),
    ]
    cve_db = {"CVE-A": _vuln("CVE-A"), "CVE-B": _vuln("CVE-B")}

    graph = build_graph(hosts, cve_db)
    path = find_shortest_attack_path(graph, "attacker", "db")

    assert path is not None
    assert path.hops == 2
    assert path.exploit_chain == ["CVE-A", "CVE-B"]


def test_isolated_jewel_returns_no_chain():
    hosts = [
        _host("attacker", entry=True, reachable=()),
        _host("db", cve_ids=("CVE-B",), jewel=True),
    ]
    graph = build_graph(hosts, {"CVE-B": _vuln("CVE-B")})
    assert find_all_kill_chains(graph) == []


def test_dijkstra_prefers_cheaper_chain():
    hosts = [
        _host("attacker", entry=True, reachable=(("hop_easy", 443), ("hop_hard", 443))),
        _host("hop_easy", cve_ids=("EASY",), reachable=(("jewel", 443),)),
        _host("hop_hard", cve_ids=("HARD",), reachable=(("jewel", 443),)),
        _host("jewel", cve_ids=("FINAL",), jewel=True, crit=10),
    ]
    cve_db = {
        "EASY": _vuln("EASY", cvss=9.8, exploitability=0.99),
        "HARD": _vuln("HARD", cvss=6.0, exploitability=0.3),
        "FINAL": _vuln("FINAL"),
    }
    graph = build_graph(hosts, cve_db)
    path = find_shortest_attack_path(graph, "attacker", "jewel")

    assert path is not None
    assert "EASY" in path.exploit_chain
    assert "HARD" not in path.exploit_chain


def test_unknown_cve_is_skipped_not_crashed():
    hosts = [
        _host("attacker", entry=True, reachable=(("web", 443),)),
        _host("web", cve_ids=("UNKNOWN",), jewel=True),
    ]
    graph = build_graph(hosts, {})
    assert graph.edge_count() == 0
    assert find_all_kill_chains(graph) == []


def test_reachability_respects_port():
    # Attacker can hit web-01:443. Web has its vuln on port 22, not 443.
    # No edge should exist — port mismatch.
    hosts = [
        _host("attacker", entry=True, reachable=(("web", 443),)),
        _host("web", cve_ids=("CVE-A",), port=22, jewel=True),
    ]
    graph = build_graph(hosts, {"CVE-A": _vuln("CVE-A")})
    assert graph.edge_count() == 0


def test_risk_score_is_bounded_and_varies():
    """A full kill chain should score higher than a short stub."""
    hosts_full = [
        _host("attacker", entry=True, reachable=(("foothold", 443),)),
        _host("foothold", cve_ids=("A",), reachable=(("pivot", 445),)),
        _host("pivot", cve_ids=("B",), port=445, reachable=(("jewel", 5432),)),
        _host("jewel", cve_ids=("C",), port=5432, jewel=True, crit=10),
    ]
    cve_db_full = {
        "A": _vuln("A", category=ExploitCategory.INITIAL_ACCESS),
        "B": _vuln("B", category=ExploitCategory.LATERAL_MOVEMENT),
        "C": _vuln("C", category=ExploitCategory.PRIVILEGE_ESCALATION),
    }
    g_full = build_graph(hosts_full, cve_db_full)
    chain_full = find_shortest_attack_path(g_full, "attacker", "jewel")
    score_full = path_risk_score(chain_full, g_full.hosts["jewel"], cve_db_full)

    hosts_stub = [
        _host("attacker", entry=True, reachable=(("jewel", 443),)),
        _host("jewel", cve_ids=("X",), jewel=True, crit=3),
    ]
    cve_db_stub = {"X": _vuln("X", category=ExploitCategory.INITIAL_ACCESS,
                              exploitability=0.3, weaponized=False)}
    g_stub = build_graph(hosts_stub, cve_db_stub)
    chain_stub = find_shortest_attack_path(g_stub, "attacker", "jewel")
    score_stub = path_risk_score(chain_stub, g_stub.hosts["jewel"], cve_db_stub)

    assert 0 <= score_stub <= score_full <= 100
    assert score_full > score_stub + 10  # meaningful gap, not both pinned to 100


def test_all_cves_in_use_reflects_graph():
    hosts = [
        _host("attacker", entry=True, reachable=(("web", 443),)),
        _host("web", cve_ids=("CVE-A",), jewel=True),
    ]
    graph = build_graph(hosts, {"CVE-A": _vuln("CVE-A")})
    assert graph.all_cves_in_use() == {"CVE-A"}
