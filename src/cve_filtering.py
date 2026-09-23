from __future__ import annotations

from dataclasses import dataclass
from ipaddress import ip_address
from typing import Iterable

from .models import Host, Vulnerability


_PORT_HINTS: dict[int, tuple[str, ...]] = {
    21: ("ftp",),
    22: ("ssh", "openssh"),
    25: ("smtp", "mail"),
    53: ("dns",),
    80: ("http", "web", "nginx", "apache"),
    110: ("pop3",),
    143: ("imap",),
    443: ("https", "tls", "web"),
    445: ("smb", "windows"),
    3389: ("rdp", "windows"),
    5432: ("postgres", "postgresql"),
    3306: ("mysql",),
    6379: ("redis",),
    27017: ("mongodb", "mongo"),
    8080: ("http", "web"),
    8443: ("https", "web"),
}


@dataclass(frozen=True)
class CVEFilterStats:
    before_count: int
    after_count: int
    direct_matches: int
    inferred_matches: int
    fallback_matches: int

    @property
    def dropped_count(self) -> int:
        return max(self.before_count - self.after_count, 0)


def filter_cves_for_hosts(
    hosts: list[Host],
    cve_db: dict[str, Vulnerability],
    *,
    enabled: bool,
    min_score: int = 2,
    keep_top: int = 120,
) -> tuple[dict[str, Vulnerability], CVEFilterStats]:
    if not enabled:
        stats = CVEFilterStats(
            before_count=len(cve_db),
            after_count=len(cve_db),
            direct_matches=0,
            inferred_matches=0,
            fallback_matches=0,
        )
        return dict(cve_db), stats

    if not cve_db:
        stats = CVEFilterStats(
            before_count=0,
            after_count=0,
            direct_matches=0,
            inferred_matches=0,
            fallback_matches=0,
        )
        return {}, stats

    direct_ids = _collect_direct_cve_ids(hosts, cve_db)
    service_tokens = _collect_service_tokens(hosts)
    os_tokens = _collect_os_tokens(hosts)

    selected: dict[str, Vulnerability] = {}
    direct_matches = 0
    inferred_matches = 0
    fallback_candidates: list[tuple[tuple[float, float, float], Vulnerability]] = []

    for cve_id, vulnerability in cve_db.items():
        if cve_id in direct_ids:
            selected[cve_id] = vulnerability
            direct_matches += 1
            continue

        score = _score_vulnerability(vulnerability, service_tokens, os_tokens)
        if score >= max(min_score, 1):
            selected[cve_id] = vulnerability
            inferred_matches += 1
            continue

        rank = (
            1.0 if vulnerability.weaponized else 0.0,
            vulnerability.exploitability,
            vulnerability.cvss_v3,
        )
        fallback_candidates.append((rank, vulnerability))

    fallback_matches = 0
    if keep_top > 0 and fallback_candidates:
        fallback_candidates.sort(key=lambda item: item[0], reverse=True)
        limit = min(max(keep_top, 0), len(fallback_candidates))
        for _, vulnerability in fallback_candidates[:limit]:
            if vulnerability.cve_id in selected:
                continue
            selected[vulnerability.cve_id] = vulnerability
            fallback_matches += 1

    stats = CVEFilterStats(
        before_count=len(cve_db),
        after_count=len(selected),
        direct_matches=direct_matches,
        inferred_matches=inferred_matches,
        fallback_matches=fallback_matches,
    )
    return selected, stats


def _collect_direct_cve_ids(hosts: list[Host], cve_db: dict[str, Vulnerability]) -> set[str]:
    known = set(cve_db.keys())
    direct: set[str] = set()
    for host in hosts:
        for service in host.services:
            for cve_id in service.cve_ids:
                if cve_id in known:
                    direct.add(cve_id)
    return direct


def _collect_service_tokens(hosts: list[Host]) -> set[str]:
    tokens: set[str] = set()
    for host in hosts:
        for service in host.services:
            tokens.update(_split_tokens(service.name))
            tokens.update(_split_tokens(service.version))
            tokens.update(_PORT_HINTS.get(service.port, ()))
    return {token for token in tokens if len(token) >= 3}


def _collect_os_tokens(hosts: list[Host]) -> set[str]:
    tokens: set[str] = set()
    for host in hosts:
        tokens.update(_split_tokens(host.os))
        ip = host.ip_address.strip()
        if ip:
            try:
                ip_addr = ip_address(ip)
            except ValueError:
                ip_addr = None
            if ip_addr is not None and ip_addr.version == 6:
                tokens.add("ipv6")
    return {token for token in tokens if len(token) >= 3}


def _score_vulnerability(
    vulnerability: Vulnerability,
    service_tokens: set[str],
    os_tokens: set[str],
) -> int:
    corpus = _build_corpus(vulnerability)
    score = 0

    service_hits = 0
    for token in service_tokens:
        if token in corpus:
            service_hits += 1
            if service_hits >= 3:
                break
    score += service_hits * 2

    os_hits = 0
    for token in os_tokens:
        if token in corpus:
            os_hits += 1
            if os_hits >= 2:
                break
    score += os_hits

    # Keep inferred matches asset-aware: unrelated high-severity CVEs should
    # not pass relevance gates without at least one contextual token hit.
    if (service_hits + os_hits) == 0:
        return 0

    if vulnerability.weaponized:
        score += 1
    if vulnerability.cvss_v3 >= 9.0:
        score += 1
    if vulnerability.exploitability >= 0.8:
        score += 1
    return score


def _build_corpus(vulnerability: Vulnerability) -> str:
    refs = " ".join(vulnerability.references)
    return f"{vulnerability.cve_id} {vulnerability.description} {refs}".lower()


def _split_tokens(value: str) -> Iterable[str]:
    token = []
    for ch in value.lower():
        if ch.isalnum() or ch in {"-", "_"}:
            token.append(ch)
            continue
        if token:
            yield "".join(token)
            token = []
    if token:
        yield "".join(token)
