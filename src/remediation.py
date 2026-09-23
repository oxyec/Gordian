"""Remediation planner: which CVE should you patch first?

For every CVE that appears in at least one kill chain, we simulate
patching it (drop it from the CVE feed, rebuild the graph, recompute
chains) and measure how much total risk drops. The CVE with the
biggest drop is the one the blue team should prioritise.

This is more useful than "fix the highest-CVSS one" because it takes
graph structure into account: a mid-CVSS CVE sitting on a chokepoint
between attacker and every crown jewel is more urgent than a 10.0
sitting on a dead-end host.

Simulations use a read-only filtered view of the baseline graph. The
default is sequential: Python graph traversal is CPU-bound, so threads
do not guarantee a speedup. Callers may explicitly opt into a small pool.
"""

from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass

from .models import AttackPath, Host, PatchRecommendation, Vulnerability
from .scoring import path_risk_score
from .transformers import AttackGraph, find_all_kill_chains

log = logging.getLogger(__name__)


def _total_risk(chains: list[AttackPath], hosts_by_id: dict[str, Host],
                cve_db: dict[str, Vulnerability]) -> float:
    return sum(
        path_risk_score(c, hosts_by_id[c.target_host_id], cve_db)
        for c in chains
    )


@dataclass(frozen=True)
class _SimulationJob:
    """Inputs for one CVE patch simulation. Kept as a frozen dataclass so
    the worker function is unambiguously pure — no shared mutable state."""
    cve_id: str
    graph: AttackGraph
    cve_db: dict[str, Vulnerability]
    baseline_count: int
    baseline_risk: float


def _simulate_patch(job: _SimulationJob) -> PatchRecommendation | None:
    vuln = job.cve_db.get(job.cve_id)
    if vuln is None:
        return None
    # Preserve runtime-discovered edges; remove only the candidate CVE.
    # The baseline graph must remain unchanged throughout simulation.
    patched_graph = _PatchedGraph(job.graph, job.cve_id)
    remaining_chains = find_all_kill_chains(patched_graph)
    remaining_risk = _total_risk(remaining_chains, patched_graph.hosts, job.cve_db)
    return PatchRecommendation(
        cve_id=job.cve_id,
        cvss=vuln.cvss_v3,
        description=vuln.description,
        chains_broken=job.baseline_count - len(remaining_chains),
        chains_remaining=len(remaining_chains),
        risk_reduction=round(job.baseline_risk - remaining_risk, 1),
    )


class _PatchedGraph(AttackGraph):
    """Traversal-only view; the baseline must not mutate during simulation."""

    def __init__(self, graph: AttackGraph, excluded_cve: str) -> None:
        self._hosts = graph.hosts
        self._edges = graph._edges
        self._excluded_cve = excluded_cve

    def neighbors(self, host_id: str):
        return [edge for edge in super().neighbors(host_id)
                if edge[2].cve_id != self._excluded_cve]


def suggest_patches(
    graph: AttackGraph,
    baseline_chains: list[AttackPath],
    cve_db: dict[str, Vulnerability],
    top_n: int = 5,
    *,
    max_workers: int | None = None,
) -> list[PatchRecommendation]:
    if not baseline_chains or top_n <= 0:
        return []

    hosts_by_id = graph.hosts
    baseline_risk = _total_risk(baseline_chains, hosts_by_id, cve_db)

    cves_in_chains: set[str] = set()
    for chain in baseline_chains:
        cves_in_chains.update(chain.exploit_chain)

    sorted_cves = sorted(cves_in_chains)
    jobs = [
        _SimulationJob(
            cve_id=cve_id,
            graph=graph,
            cve_db=cve_db,
            baseline_count=len(baseline_chains),
            baseline_risk=baseline_risk,
        )
        for cve_id in sorted_cves
    ]

    # Cap workers: more threads than candidates wastes setup overhead, and
    # huge pools on small CPUs thrash the scheduler. 1 candidate → no pool.
    if max_workers is None:
        max_workers = 1
    max_workers = max(1, min(8, max_workers, len(jobs)))

    if max_workers <= 1 or len(jobs) <= 1:
        raw_results = [_simulate_patch(j) for j in jobs]
    else:
        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            raw_results = list(pool.map(_simulate_patch, jobs))

    # Preserve sorted-by-CVE order so the deterministic output is identical
    # to the pre-parallel implementation (callers may rely on tie-break order).
    recommendations: list[PatchRecommendation] = [r for r in raw_results if r is not None]

    # A patch that doesn't reduce total risk isn't a recommendation — usually
    # it means the attacker reroutes through an alternate path. We surface
    # those separately in the logs so the operator knows the simulator
    # considered them and why they were dropped.
    effective = [r for r in recommendations if r.risk_reduction > 0]
    effective.sort(
        key=lambda r: (r.risk_reduction, r.chains_broken, r.cvss), reverse=True
    )

    rerouted = [r for r in recommendations if r.risk_reduction <= 0 and r.chains_broken > 0]
    if rerouted:
        log.info(
            "%d patches break chains but attacker reroutes (no net risk drop): %s",
            len(rerouted),
            ", ".join(f"{r.cve_id} (broke {r.chains_broken})" for r in rerouted[:5]),
        )

    log.info(
        "evaluated %d patch candidates, %d actually reduce risk, %d rerouted",
        len(recommendations), len(effective), len(rerouted),
    )
    return effective[:top_n]
