from __future__ import annotations

from src.cve_filtering import filter_cves_for_hosts
from src.models import ExploitCategory, Host, ReachableService, Service, Severity, Vulnerability


def _host_with_services() -> Host:
    return Host(
        id="web-1",
        hostname="web-1",
        ip_address="10.10.10.10",
        segment="dmz",
        os="linux",
        is_attacker_entry=False,
        is_crown_jewel=False,
        criticality=6,
        services=(
            Service(
                name="nginx",
                port=443,
                protocol="tcp",
                version="1.22",
                cve_ids=("CVE-APP-1",),
            ),
        ),
        reachable=(ReachableService(host_id="db-1", port=5432),),
    )


def _vuln(
    cve_id: str,
    description: str,
    *,
    weaponized: bool = False,
    exploitability: float = 0.5,
    cvss: float = 7.0,
) -> Vulnerability:
    return Vulnerability(
        cve_id=cve_id,
        cvss_v3=cvss,
        severity=Severity.HIGH,
        description=description,
        exploit_category=ExploitCategory.INITIAL_ACCESS,
        mitre_tactics=("TA0001",),
        mitre_techniques=("T1190",),
        exploitability=exploitability,
        weaponized=weaponized,
        epss_score=0.5,
        references=(),
    )


def test_filter_cves_for_hosts_disabled_returns_original():
    hosts = [_host_with_services()]
    cve_db = {
        "CVE-APP-1": _vuln("CVE-APP-1", "nginx overflow"),
        "CVE-NOISE": _vuln("CVE-NOISE", "unrelated issue"),
    }

    filtered, stats = filter_cves_for_hosts(hosts, cve_db, enabled=False)

    assert set(filtered) == set(cve_db)
    assert stats.before_count == 2
    assert stats.after_count == 2


def test_filter_cves_for_hosts_keeps_direct_and_inferred_matches():
    hosts = [_host_with_services()]
    cve_db = {
        "CVE-APP-1": _vuln("CVE-APP-1", "directly linked by service cve list"),
        "CVE-NGINX-2": _vuln("CVE-NGINX-2", "nginx request smuggling vulnerability"),
        "CVE-NOISE": _vuln("CVE-NOISE", "legacy printer overflow"),
    }

    filtered, stats = filter_cves_for_hosts(
        hosts,
        cve_db,
        enabled=True,
        min_score=2,
        keep_top=0,
    )

    assert "CVE-APP-1" in filtered
    assert "CVE-NGINX-2" in filtered
    assert "CVE-NOISE" not in filtered
    assert stats.direct_matches >= 1
    assert stats.inferred_matches >= 1


def test_filter_cves_for_hosts_uses_fallback_top_rank():
    hosts = [_host_with_services()]
    cve_db = {
        "CVE-LOW": _vuln("CVE-LOW", "random bug", weaponized=False, exploitability=0.2, cvss=5.0),
        "CVE-HIGH": _vuln("CVE-HIGH", "random bug", weaponized=True, exploitability=0.9, cvss=9.1),
    }

    filtered, stats = filter_cves_for_hosts(
        hosts,
        cve_db,
        enabled=True,
        min_score=999,
        keep_top=1,
    )

    assert set(filtered) == {"CVE-HIGH"}
    assert stats.fallback_matches == 1
