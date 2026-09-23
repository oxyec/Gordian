"""End-to-end feedback loop: offensive findings feed back into Dijkstra.

This is the contract that makes Gordian's "tools feed each other" promise
real: a nuclei/httpx finding injected mid-run must (a) appear as a new edge
in the graph, (b) cause find_all_kill_chains to surface a NEW chain, and
(c) be considered by suggest_patches as a patch candidate.

If any of these break, the whole offensive integration is just expensive
logging.
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
from src.offensive.injector import GraphInjector
from src.offensive.parsers import Finding
from src.remediation import suggest_patches
from src.transformers import AttackGraph, build_graph, find_all_kill_chains


def _vuln(cve_id: str, **kw) -> Vulnerability:
    defaults = dict(
        cvss_v3=9.0,
        severity=Severity.CRITICAL,
        description="test",
        exploit_category=ExploitCategory.INITIAL_ACCESS,
        mitre_tactics=("TA0001",),
        mitre_techniques=("T1190",),
        exploitability=0.9,
        weaponized=True,
        epss_score=0.5,
    )
    defaults.update(kw)
    return Vulnerability(cve_id=cve_id, **defaults)


def _host(host_id: str, **kw) -> Host:
    cve_ids = kw.pop("cve_ids", ())
    port = kw.pop("port", 443)
    reachable = kw.pop("reachable", ())
    svc = Service(name="svc", port=port, protocol="tcp", version="1", cve_ids=cve_ids)
    defaults = dict(
        hostname=host_id,
        ip_address="10.0.0.1",
        segment="T",
        os="linux",
        is_attacker_entry=False,
        is_crown_jewel=False,
        criticality=5,
        services=(svc,) if cve_ids else (),
        reachable=tuple(ReachableService(h, p) for h, p in reachable),
    )
    defaults.update(kw)
    return Host(id=host_id, **defaults)


def test_injected_finding_creates_new_kill_chain_visible_to_dijkstra():
    """Start with attacker that has no path to crown jewel.
    Inject a nuclei finding on the jewel. Dijkstra must now find a chain."""
    attacker = _host("attacker", is_attacker_entry=True, criticality=1)
    jewel = _host("jewel", is_crown_jewel=True, criticality=10)
    graph = build_graph([attacker, jewel], {})

    # Baseline: no chains because there's no edge.
    assert find_all_kill_chains(graph) == []

    # Simulate a nuclei finding that confirms an exploitable service on jewel.
    nuclei_finding = Finding(
        tool="nuclei",
        finding_type="vulnerability",
        technical="rce on jewel",
        raw_line="{}",
        target_host_id="jewel",
        target_port=443,
        vulnerability=_vuln("CVE-2024-FRESH"),
    )

    injector = GraphInjector(graph, cve_db={})
    delta = injector.inject_finding(nuclei_finding)
    assert delta.edges_added >= 1
    assert delta.vulnerabilities_added >= 1

    # After injection, Dijkstra must now produce a chain ending at jewel.
    chains = find_all_kill_chains(graph)
    assert chains, "injected finding did not open a kill chain"
    assert any(c.target_host_id == "jewel" for c in chains)
    assert any("CVE-2024-FRESH" in c.exploit_chain for c in chains)


def test_injected_finding_promotes_cve_into_patch_recommendations():
    """The newly-discovered CVE should be considered by suggest_patches."""
    attacker = _host("attacker", is_attacker_entry=True, criticality=1)
    jewel = _host("jewel", is_crown_jewel=True, criticality=10)
    cve_db: dict[str, Vulnerability] = {}
    graph = build_graph([attacker, jewel], cve_db)

    injector = GraphInjector(graph, cve_db)
    injector.inject_finding(Finding(
        tool="nuclei",
        finding_type="vulnerability",
        technical="rce on jewel",
        raw_line="{}",
        target_host_id="jewel",
        target_port=443,
        vulnerability=_vuln("CVE-2024-FRESH"),
    ))

    chains = find_all_kill_chains(graph)
    patches = suggest_patches(graph, chains, cve_db)
    assert patches, "expected at least one patch recommendation"
    assert any(p.cve_id == "CVE-2024-FRESH" for p in patches), \
        f"injected CVE missing from patches: {[p.cve_id for p in patches]}"


def test_recon_finding_chains_into_exploit_finding():
    """Subfinder discovers a subdomain → injected as host → a follow-up nuclei
    finding on that subdomain becomes a chain target. Models the recon→exploit
    feeding loop the user explicitly asked for."""
    attacker = _host("attacker", is_attacker_entry=True, criticality=1)
    graph = build_graph([attacker], {})

    injector = GraphInjector(graph, cve_db={})

    # Stage 1 (recon): subfinder reports a new subdomain as a host.
    subfinder_host = Host(
        id="api.example.com", hostname="api.example.com", ip_address="0.0.0.0",
        segment="DISCOVERED", os="unknown",
        is_attacker_entry=False, is_crown_jewel=True,  # treat as crown jewel for the chain
        criticality=8, services=(), reachable=(),
    )
    recon_delta = injector.inject_finding(Finding(
        tool="subfinder", finding_type="host", technical="found",
        raw_line="api.example.com", host=subfinder_host,
        target_host_id="api.example.com",
    ))
    assert recon_delta.hosts_added == 1

    # Stage 2 (exploit): nuclei finds an RCE on that newly-known subdomain.
    exploit_delta = injector.inject_finding(Finding(
        tool="nuclei", finding_type="vulnerability", technical="rce",
        raw_line="{}", target_host_id="api.example.com", target_port=443,
        vulnerability=_vuln("CVE-2024-RECON-FED"),
    ))
    assert exploit_delta.edges_added >= 1

    chains = find_all_kill_chains(graph)
    assert any(c.target_host_id == "api.example.com" for c in chains), \
        "recon→exploit chain did not surface in Dijkstra"


def test_injected_finding_uses_existing_entry_point_when_available():
    """When the graph already has an attacker entry, injector should reuse
    it rather than spawning the synthetic 'external-scanner' host."""
    attacker = _host("attacker", is_attacker_entry=True, criticality=1)
    jewel = _host("jewel", is_crown_jewel=True, criticality=10)
    graph = build_graph([attacker, jewel], {})

    injector = GraphInjector(graph, cve_db={})
    injector.inject_finding(Finding(
        tool="nuclei", finding_type="vulnerability", technical="rce",
        raw_line="{}", target_host_id="jewel", target_port=443,
        vulnerability=_vuln("CVE-2024-X"),
    ))

    # 'external-scanner' must NOT exist — the real entry was already there.
    assert "external-scanner" not in graph.hosts

    chains = find_all_kill_chains(graph)
    assert chains
    assert chains[0].entry_host_id == "attacker"


def test_injector_spawns_scanner_entry_only_when_no_entry_exists():
    """If the graph has no entry point at all, injector falls back to a
    synthetic 'external-scanner' so the new edge is actually reachable.
    Without this, the injected finding would be a dead edge."""
    jewel = _host("jewel", is_crown_jewel=True, criticality=10)
    graph = build_graph([jewel], {})

    injector = GraphInjector(graph, cve_db={})
    injector.inject_finding(Finding(
        tool="nuclei", finding_type="vulnerability", technical="rce",
        raw_line="{}", target_host_id="jewel", target_port=443,
        vulnerability=_vuln("CVE-2024-Y"),
    ))

    assert "external-scanner" in graph.hosts
    chains = find_all_kill_chains(graph)
    assert chains
    assert chains[0].entry_host_id == "external-scanner"
