"""Transform stage: build the attack graph and find kill chains.

Graph shape:
    nodes = hosts
    edges = (src -> dst, target_port, cve, cost)

An edge exists when all three conditions hold:
    1. `src.reachable` includes a (dst_id, port) pair — i.e. firewall lets
       the traffic through,
    2. `dst` has a service listening on that port,
    3. that service exposes a CVE we have scoring data for.

That matches how lateral movement actually works in a real network —
you don't attack "a host", you attack a specific port on it, and only
if segmentation lets you reach it.

Dijkstra runs over exploit cost, not hop count, so the shortest path is
the one a motivated attacker would actually take: cheap, weaponized,
high-value landing. heapq is used directly — no third-party graph lib,
to keep the dep surface at zero.
"""

from __future__ import annotations

import heapq
import logging
import math
from collections import defaultdict
from typing import Iterable

from .models import AttackPath, AttackStep, Host, Vulnerability
from .scoring import edge_cost

log = logging.getLogger(__name__)


class AttackGraph:
    """Directed weighted graph. Edge label includes the target port so a
    downstream report can tell you not just 'pivot to dc-01' but 'pivot
    to dc-01:445 via Zerologon'."""

    def __init__(self) -> None:
        self._hosts: dict[str, Host] = {}
        self._edges: dict[str, list[tuple[str, int, Vulnerability, float]]] = defaultdict(list)

    def add_host(self, host: Host) -> None:
        self._hosts[host.id] = host

    def add_edge(
        self, src_id: str, dst_id: str, port: int, vuln: Vulnerability, cost: float
    ) -> None:
        if not math.isfinite(cost) or cost < 0:
            raise ValueError("edge cost must be finite and non-negative")
        if src_id not in self._hosts or dst_id not in self._hosts:
            raise ValueError("edge endpoints must exist")
        self._edges[src_id].append((dst_id, port, vuln, cost))

    @property
    def hosts(self) -> dict[str, Host]:
        return self._hosts

    def neighbors(self, host_id: str) -> list[tuple[str, int, Vulnerability, float]]:
        return self._edges.get(host_id, [])

    def crown_jewels(self) -> list[Host]:
        return [h for h in self._hosts.values() if h.is_crown_jewel]

    def entry_points(self) -> list[Host]:
        return [h for h in self._hosts.values() if h.is_attacker_entry]

    def edge_count(self) -> int:
        return sum(len(v) for v in self._edges.values())

    def all_cves_in_use(self) -> set[str]:
        seen: set[str] = set()
        for edges in self._edges.values():
            for _dst, _port, vuln, _cost in edges:
                seen.add(vuln.cve_id)
        return seen


def build_graph(hosts: Iterable[Host], cve_db: dict[str, Vulnerability]) -> AttackGraph:
    graph = AttackGraph()
    hosts_list = list(hosts)
    for host in hosts_list:
        graph.add_host(host)

    unknown_targets: set[str] = set()
    unknown_cves: set[str] = set()

    for src in hosts_list:
        for ref in src.reachable:
            dst = graph.hosts.get(ref.host_id)
            if dst is None:
                unknown_targets.add(ref.host_id)
                continue
            for svc in dst.services_on_port(ref.port):
                for cve_id in svc.cve_ids:
                    vuln = cve_db.get(cve_id)
                    if vuln is None:
                        unknown_cves.add(cve_id)
                        continue
                    cost = edge_cost(vuln, dst.criticality)
                    graph.add_edge(src.id, dst.id, svc.port, vuln, cost)

    if unknown_targets:
        log.warning("dangling reachability entries (unknown hosts): %s", sorted(unknown_targets))
    if unknown_cves:
        log.debug("dropped %d edges for CVEs not in the feed: %s",
                  len(unknown_cves), sorted(unknown_cves))

    log.info("graph built: %d nodes, %d exploit edges",
             len(graph.hosts), graph.edge_count())
    return graph


def find_shortest_attack_path(
    graph: AttackGraph, source_id: str, target_id: str
) -> AttackPath | None:
    """Dijkstra over exploit costs. None if no reachable exploit chain exists."""
    if source_id not in graph.hosts or target_id not in graph.hosts:
        return None

    dist: dict[str, float] = {source_id: 0.0}
    prev: dict[str, tuple[str, int, Vulnerability, float]] = {}
    pq: list[tuple[float, str]] = [(0.0, source_id)]

    while pq:
        cost_so_far, node = heapq.heappop(pq)
        if node == target_id:
            break
        if cost_so_far > dist.get(node, float("inf")):
            continue
        for neighbor_id, port, vuln, edge_w in graph.neighbors(node):
            new_cost = cost_so_far + edge_w
            if new_cost < dist.get(neighbor_id, float("inf")):
                dist[neighbor_id] = new_cost
                prev[neighbor_id] = (node, port, vuln, edge_w)
                heapq.heappush(pq, (new_cost, neighbor_id))

    # source==target is rejected: a host attacking itself isn't an attack
    # path in this model (entry points and crown jewels are disjoint roles).
    if target_id not in dist or target_id == source_id:
        return None

    steps: list[AttackStep] = []
    cvss_chain: list[float] = []
    cursor = target_id
    while cursor in prev:
        parent, port, vuln, edge_w = prev[cursor]
        if vuln.mitre_techniques:
            technique = vuln.mitre_techniques[0]
        else:
            technique = "UNKNOWN"
            log.warning("CVE %s has no MITRE techniques; falling back to UNKNOWN", vuln.cve_id)
        steps.append(
            AttackStep(
                source_host_id=parent,
                target_host_id=cursor,
                target_port=port,
                cve_id=vuln.cve_id,
                technique=technique,
                category=vuln.exploit_category,
                cost=round(edge_w, 4),
            )
        )
        cvss_chain.append(vuln.cvss_v3)
        cursor = parent

    if not steps:
        return None

    steps.reverse()
    cvss_chain.reverse()
    return AttackPath(
        entry_host_id=source_id,
        target_host_id=target_id,
        steps=steps,
        total_cost=round(dist[target_id], 4),
        cvss_chain=cvss_chain,
    )


def find_all_kill_chains(graph: AttackGraph) -> list[AttackPath]:
    chains: list[AttackPath] = []
    for entry in graph.entry_points():
        for jewel in graph.crown_jewels():
            path = find_shortest_attack_path(graph, entry.id, jewel.id)
            if path and path.steps:
                chains.append(path)
    chains.sort(key=lambda p: p.total_cost)
    return chains
