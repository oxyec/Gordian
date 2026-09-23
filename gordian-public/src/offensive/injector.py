"""Inject streaming offensive findings into Gordian's attack graph."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib

from ..models import ExploitCategory, Host, ReachableService, Service, Severity, Vulnerability
from ..scoring import edge_cost
from ..transformers import AttackGraph
from .parsers import Finding


@dataclass
class GraphDelta:
    hosts_added: int = 0
    services_added: int = 0
    vulnerabilities_added: int = 0
    edges_added: int = 0

    @property
    def changed(self) -> bool:
        return bool(self.hosts_added or self.services_added or self.vulnerabilities_added or self.edges_added)


class GraphInjector:
    def __init__(
        self,
        graph: AttackGraph,
        cve_db: dict[str, Vulnerability],
        *,
        directory_injection: bool = True,
    ) -> None:
        self.graph = graph
        self.cve_db = cve_db
        self.directory_injection = directory_injection
        self._edge_keys: set[tuple[str, str, int, str]] = set()

        for src_id in graph.hosts:
            for dst_id, port, vuln, _cost in graph.neighbors(src_id):
                self._edge_keys.add((src_id, dst_id, port, vuln.cve_id))

    def inject_finding(self, finding: Finding) -> GraphDelta:
        if finding.finding_type == "directory" and not self.directory_injection:
            return GraphDelta()

        delta = GraphDelta()
        target_host_id = finding.target_host_id

        if finding.host is not None:
            added = self._upsert_host(finding.host)
            if added:
                delta.hosts_added += 1
            target_host_id = finding.host.id

        if target_host_id and target_host_id not in self.graph.hosts:
            placeholder = self._make_placeholder_host(target_host_id)
            self.graph.add_host(placeholder)
            delta.hosts_added += 1

        if finding.service is not None and target_host_id:
            if self._upsert_service(target_host_id, finding.service):
                delta.services_added += 1

        vuln = finding.vulnerability
        if vuln is None and target_host_id:
            vuln = self._build_synthetic_vuln(finding, target_host_id)

        if vuln is None or not target_host_id:
            return delta

        if vuln.cve_id not in self.cve_db:
            self.cve_db[vuln.cve_id] = vuln
            delta.vulnerabilities_added += 1

        target_port = finding.target_port or (finding.service.port if finding.service else 443)
        target = self.graph.hosts[target_host_id]

        entries = self.graph.entry_points()
        if not entries:
            scanner = self._ensure_scanner_entry()
            entries = [scanner]
            delta.hosts_added += 1

        for entry in entries:
            if entry.id == target_host_id:
                continue
            key = (entry.id, target_host_id, target_port, vuln.cve_id)
            if key in self._edge_keys:
                continue
            cost = edge_cost(vuln, target.criticality)
            self.graph.add_edge(entry.id, target_host_id, target_port, vuln, cost)
            self._edge_keys.add(key)
            delta.edges_added += 1

        return delta

    def _upsert_host(self, host: Host) -> bool:
        if host.id in self.graph.hosts:
            return False
        self.graph.add_host(host)
        return True

    def _upsert_service(self, host_id: str, service: Service) -> bool:
        host = self.graph.hosts[host_id]
        for existing in host.services:
            if existing.port == service.port and existing.name == service.name:
                return False

        updated = Host(
            id=host.id,
            hostname=host.hostname,
            ip_address=host.ip_address,
            segment=host.segment,
            os=host.os,
            is_attacker_entry=host.is_attacker_entry,
            is_crown_jewel=host.is_crown_jewel,
            criticality=host.criticality,
            services=host.services + (service,),
            reachable=host.reachable,
        )
        self.graph.add_host(updated)
        return True

    def _make_placeholder_host(self, host_id: str) -> Host:
        return Host(
            id=host_id,
            hostname=host_id,
            ip_address="0.0.0.0",
            segment="DISCOVERED",
            os="unknown",
            is_attacker_entry=False,
            is_crown_jewel=False,
            criticality=5,
            services=(),
            reachable=(),
        )

    def _ensure_scanner_entry(self) -> Host:
        scanner_id = "external-scanner"
        if scanner_id in self.graph.hosts:
            return self.graph.hosts[scanner_id]

        scanner = Host(
            id=scanner_id,
            hostname="external-scanner",
            ip_address="0.0.0.0",
            segment="INTERNET",
            os="linux",
            is_attacker_entry=True,
            is_crown_jewel=False,
            criticality=1,
            services=(),
            reachable=(),
        )
        self.graph.add_host(scanner)
        return scanner

    def _build_synthetic_vuln(self, finding: Finding, host_id: str) -> Vulnerability | None:
        if finding.finding_type == "directory":
            path = str(finding.metadata.get("path", "/"))
            seed = f"dir:{host_id}:{path}:{finding.tool}"
            description = f"Discovered hidden/sensitive web resource: {path}"
            category = ExploitCategory.CREDENTIAL_ACCESS
            severity = Severity.HIGH if _path_looks_sensitive(path) else Severity.MEDIUM
            cvss = 8.1 if severity is Severity.HIGH else 6.3
            exploitability = 0.82 if severity is Severity.HIGH else 0.64
            return self._make_vuln(seed, description, category, severity, cvss, exploitability)

        if finding.service is not None:
            service = finding.service
            seed = f"svc:{host_id}:{service.port}:{service.name}:{finding.tool}"
            description = f"Newly discovered reachable service: {service.name} on port {service.port}"
            return self._make_vuln(
                seed,
                description,
                ExploitCategory.INITIAL_ACCESS,
                Severity.MEDIUM,
                5.8,
                0.55,
            )

        return None

    def _make_vuln(
        self,
        seed: str,
        description: str,
        category: ExploitCategory,
        severity: Severity,
        cvss_v3: float,
        exploitability: float,
    ) -> Vulnerability:
        digest = hashlib.sha1(seed.encode("utf-8")).hexdigest()[:10].upper()
        return Vulnerability(
            cve_id=f"GORDIAN-{digest}",
            cvss_v3=cvss_v3,
            severity=severity,
            description=description,
            exploit_category=category,
            mitre_tactics=("TA0001",),
            mitre_techniques=("T1190",),
            exploitability=exploitability,
            weaponized=False,
            epss_score=0.3,
            references=(),
        )


def _path_looks_sensitive(path: str) -> bool:
    lowered = path.lower()
    return any(
        token in lowered
        for token in ("backup", "config", ".db", ".env", ".sql", ".bak", "secret", "credential")
    )
