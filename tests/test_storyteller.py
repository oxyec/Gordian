"""Coverage for Storyteller narrative templates across all tool types.

The dispatch logic walks (tool, finding_type) -> tool-only -> generic vuln ->
last resort. We hit each branch at least once so the fallback chain stays
correct as new tools are added to parsers.py.
"""

from __future__ import annotations

from src.models import ExploitCategory, Service, Severity, Vulnerability
from src.offensive.parsers import Finding
from src.offensive.storyteller import Storyteller


def _vuln(cve_id: str = "CVE-2024-0001", sev: Severity = Severity.HIGH) -> Vulnerability:
    return Vulnerability(
        cve_id=cve_id,
        cvss_v3=8.0,
        severity=sev,
        description="test",
        exploit_category=ExploitCategory.INITIAL_ACCESS,
        mitre_tactics=("TA0001",),
        mitre_techniques=("T1190",),
        exploitability=0.8,
        weaponized=True,
        epss_score=0.5,
    )


def _svc(name: str = "http", port: int = 8080) -> Service:
    return Service(name=name, port=port, protocol="tcp", version="1", cve_ids=())


def _f(tool: str, finding_type: str, **kwargs) -> Finding:
    return Finding(
        tool=tool, finding_type=finding_type, technical="t", raw_line="r", **kwargs,
    )


def test_ffuf_sensitive_path_calls_out_credentials():
    s = Storyteller()
    out = s.narrate(_f("ffuf", "directory", metadata={"path": "/.env"}))
    assert "credentials" in out or "secrets" in out


def test_ffuf_neutral_path_mentions_attack_surface():
    s = Storyteller()
    out = s.narrate(_f("ffuf", "directory", metadata={"path": "/api/v2/users"}))
    assert "attack surface" in out


def test_ffuf_vulnerability_branch_mentions_cve():
    s = Storyteller()
    out = s.narrate(_f("ffuf", "vulnerability",
                       vulnerability=_vuln("CVE-2024-1111"),
                       metadata={"path": "/admin"}))
    assert "CVE-2024-1111" in out
    assert "/admin" in out


def test_nmap_service_template():
    s = Storyteller()
    out = s.narrate(_f("nmap", "service", service=_svc("ssh", 22)))
    assert "ssh" in out and "22" in out


def test_nmap_host_narrative():
    s = Storyteller()
    out = s.narrate(_f("nmap", "host", target_host_id="db-01"))
    assert "db-01" in out


def test_nuclei_severity_appears_in_narrative():
    s = Storyteller()
    out = s.narrate(_f("nuclei", "vulnerability", vulnerability=_vuln(sev=Severity.CRITICAL)))
    assert "critical" in out.lower()


def test_recon_tool_host_narrative_uses_tool_name():
    s = Storyteller()
    for tool in ("subfinder", "amass", "bbot"):
        out = s.narrate(_f(tool, "host", target_host_id="api.example.com"))
        assert tool in out
        assert "api.example.com" in out


def test_katana_directory_uses_url_or_path():
    s = Storyteller()
    out = s.narrate(_f("katana", "directory", metadata={"url": "https://x/admin"}))
    assert "https://x/admin" in out


def test_httpx_service_mentions_tech_when_present():
    s = Storyteller()
    out = s.narrate(_f("httpx", "service", service=_svc("https", 443),
                       metadata={"tech": "nginx"}))
    assert "nginx" in out


def test_httpx_service_without_tech_falls_back_to_service_line():
    s = Storyteller()
    out = s.narrate(_f("httpx", "service", service=_svc("https", 443)))
    assert "443" in out


def test_secret_tools_warn_about_rotation():
    s = Storyteller()
    out = s.narrate(_f("gitleaks", "vulnerability",
                       metadata={"path": "/repo/.git/config", "rule": "aws-key"}))
    assert "rotate" in out.lower()
    assert "aws-key" in out


def test_visual_recon_mentions_screenshot():
    s = Storyteller()
    out = s.narrate(_f("gowitness", "directory", metadata={"url": "https://app.example.com"}))
    assert "screenshot" in out.lower()
    assert "https://app.example.com" in out


def test_unknown_tool_falls_back_to_vulnerability_template():
    s = Storyteller()
    out = s.narrate(_f("brand_new_tool", "vulnerability", vulnerability=_vuln("CVE-X")))
    assert "CVE-X" in out


def test_unknown_tool_without_vuln_falls_back_to_last_resort():
    s = Storyteller()
    out = s.narrate(_f("brand_new_tool", "weird_type"))
    assert "technical finding" in out.lower()


def test_all_tools_from_parser_for_tool_get_non_generic_narrative():
    """If a tool is listed in parser_for_tool, storyteller should produce
    something better than the last-resort sentence for its primary type."""
    s = Storyteller()
    cases = [
        ("subfinder", "host", {"target_host_id": "x"}),
        ("amass", "host", {"target_host_id": "x"}),
        ("bbot", "host", {"target_host_id": "x"}),
        ("katana", "directory", {"metadata": {"url": "https://x/y"}}),
        ("httpx", "host", {"target_host_id": "x"}),
        ("secretfinder", "directory", {"metadata": {"path": "/.env"}}),
        ("linkfinder", "directory", {"metadata": {"path": "/x.js"}}),
        ("gitleaks", "directory", {"metadata": {"path": "/x"}}),
        ("aquatone", "directory", {"metadata": {"url": "https://x"}}),
        ("gowitness", "directory", {"metadata": {"url": "https://x"}}),
    ]
    last_resort = "A new technical finding was observed"
    for tool, ftype, kwargs in cases:
        out = s.narrate(_f(tool, ftype, **kwargs))
        assert last_resort not in out, f"{tool}:{ftype} fell through to last resort: {out!r}"
