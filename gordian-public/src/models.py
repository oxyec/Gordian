"""Domain types.

Hosts and Vulns are frozen — they are graph nodes and edge labels, and
we don't want to accidentally mutate one during a traversal. AttackPath
is mutable because we build it incrementally while backtracking Dijkstra's
predecessor chain.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
import math


class ExploitCategory(str, Enum):
    INITIAL_ACCESS = "INITIAL_ACCESS"
    LATERAL_MOVEMENT = "LATERAL_MOVEMENT"
    PRIVILEGE_ESCALATION = "PRIVILEGE_ESCALATION"
    CREDENTIAL_ACCESS = "CREDENTIAL_ACCESS"


class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass(frozen=True)
class Vulnerability:
    cve_id: str
    cvss_v3: float
    severity: Severity
    description: str
    exploit_category: ExploitCategory
    mitre_tactics: tuple[str, ...]
    mitre_techniques: tuple[str, ...]
    exploitability: float
    weaponized: bool
    epss_score: float
    references: tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        for name, upper in (("cvss_v3", 10.0), ("exploitability", 1.0), ("epss_score", 1.0)):
            value = getattr(self, name)
            if not math.isfinite(value) or not 0 <= value <= upper:
                raise ValueError(f"{name} must be finite and between 0 and {upper}")

    @property
    def difficulty(self) -> float:
        """Edge-cost primitive. Lower = an attacker prefers this hop."""
        base = 1.0 - self.exploitability
        if self.weaponized:
            base *= 0.6
        return max(base, 0.01)


@dataclass(frozen=True)
class Service:
    name: str
    port: int
    protocol: str
    version: str
    cve_ids: tuple[str, ...]


@dataclass(frozen=True)
class ReachableService:
    """A (host_id, port) pair the source host can talk to. Models firewall
    / segmentation rules rather than flat host-to-host reachability."""
    host_id: str
    port: int


@dataclass(frozen=True)
class Host:
    id: str
    hostname: str
    ip_address: str
    segment: str
    os: str
    is_attacker_entry: bool
    is_crown_jewel: bool
    criticality: int
    services: tuple[Service, ...]
    reachable: tuple[ReachableService, ...]

    def services_on_port(self, port: int) -> tuple[Service, ...]:
        return tuple(s for s in self.services if s.port == port)


@dataclass(frozen=True)
class AttackStep:
    source_host_id: str
    target_host_id: str
    target_port: int
    cve_id: str
    technique: str
    category: ExploitCategory
    cost: float


@dataclass
class AttackPath:
    entry_host_id: str
    target_host_id: str
    steps: list[AttackStep]
    total_cost: float
    cvss_chain: list[float]

    @property
    def hops(self) -> int:
        return len(self.steps)

    @property
    def max_cvss(self) -> float:
        return max(self.cvss_chain) if self.cvss_chain else 0.0

    @property
    def exploit_chain(self) -> list[str]:
        return [step.cve_id for step in self.steps]

    @property
    def unique_categories(self) -> set[ExploitCategory]:
        return {step.category for step in self.steps}


@dataclass
class PatchRecommendation:
    cve_id: str
    cvss: float
    description: str
    chains_broken: int
    chains_remaining: int
    risk_reduction: float
