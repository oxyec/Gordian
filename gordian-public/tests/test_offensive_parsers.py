from __future__ import annotations

import json
import pytest

from src.offensive.parsers import FfufLineParser, NmapLineParser, NucleiLineParser, parser_for_tool


def test_nmap_parser_streams_host_service_and_cve_findings():
    parser = NmapLineParser("example.com")

    findings = []
    findings.extend(parser.parse_line("Nmap scan report for web-01 (10.1.1.10)"))
    findings.extend(parser.parse_line("443/tcp open https nginx 1.22"))
    findings.extend(parser.parse_line("vuln script result: CVE-2024-12345"))

    assert any(f.finding_type == "host" for f in findings)
    assert any(f.finding_type == "service" for f in findings)
    assert any(f.finding_type == "vulnerability" for f in findings)


def test_ffuf_parser_marks_sensitive_paths():
    parser = FfufLineParser("https://app.example.com")

    findings = parser.parse_line("/config/backup.db [Status: 200, Size: 1234, Words: 10, Lines: 2]")

    assert any(f.finding_type == "directory" for f in findings)
    vulns = [f for f in findings if f.finding_type == "vulnerability"]
    assert vulns
    assert "Sensitive resource" in vulns[0].technical


def test_nuclei_parser_reads_jsonl_line():
    parser = NucleiLineParser("https://api.example.com")
    line = json.dumps(
        {
            "template-id": "cves/2024/CVE-2024-1111",
            "host": "https://api.example.com",
            "info": {
                "severity": "high",
                "name": "Test Template",
                "description": "Detected CVE-2024-1111 in response",
            },
        }
    )

    findings = parser.parse_line(line)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.finding_type == "vulnerability"
    assert finding.vulnerability is not None
    assert finding.vulnerability.cve_id == "CVE-2024-1111"


def test_subfinder_parser_emits_host_findings():
    parser = parser_for_tool("subfinder", "example.com")

    findings = parser.parse_line("api.example.com")

    assert len(findings) == 1
    assert findings[0].finding_type == "host"
    assert findings[0].host is not None
    assert findings[0].host.id == "api.example.com"


def test_katana_parser_emits_directory_and_sensitive_vulnerability():
    parser = parser_for_tool("katana", "https://app.example.com")

    findings = parser.parse_line("https://app.example.com/.env")

    assert any(f.finding_type == "directory" for f in findings)
    assert any(f.finding_type == "vulnerability" for f in findings)


def test_httpx_parser_reads_json_and_generates_service_findings():
    parser = parser_for_tool("httpx", "https://api.example.com")
    line = json.dumps(
        {
            "url": "https://api.example.com",
            "status-code": 200,
            "tech": ["nginx", "graphql"],
        }
    )

    findings = parser.parse_line(line)

    assert any(f.finding_type == "host" for f in findings)
    assert any(f.finding_type == "service" for f in findings)


def test_gitleaks_parser_flags_secret_like_output():
    parser = parser_for_tool("gitleaks", "https://api.example.com")

    findings = parser.parse_line("AWS_ACCESS_KEY_ID detected in commit history")

    assert len(findings) == 1
    assert findings[0].finding_type == "vulnerability"
    assert findings[0].vulnerability is not None


def test_gowitness_parser_emits_visual_artifact_finding():
    parser = parser_for_tool("gowitness", "https://app.example.com")

    findings = parser.parse_line("saved screenshot to output/app.example.com.png")

    assert len(findings) == 1
    assert findings[0].finding_type == "directory"
    assert findings[0].metadata.get("screenshot_hint")


def test_ffuf_parser_reads_json_input_with_nested_fuzz_value():
    parser = FfufLineParser("https://app.example.com")
    line = json.dumps(
        {
            "input": {"FUZZ": "admin/config.bak"},
            "status": "200",
            "size": "321",
        }
    )

    findings = parser.parse_line(line)

    assert any(f.finding_type == "directory" for f in findings)
    assert any(f.finding_type == "vulnerability" for f in findings)


def test_ffuf_parser_ignores_malformed_json_line():
    parser = FfufLineParser("https://app.example.com")

    findings = parser.parse_line('{"broken":')

    assert findings == []


def test_nuclei_text_without_cve_returns_no_findings():
    parser = NucleiLineParser("https://api.example.com")

    findings = parser.parse_line("[info] no vulnerability identifier present")

    assert findings == []


def test_httpx_parser_from_text_hostname_builds_service_finding():
    parser = parser_for_tool("httpx", "https://api.example.com")

    findings = parser.parse_line("portal.example.com [200] [nginx]")

    assert len(findings) >= 1
    assert findings[0].finding_type == "service"
    assert findings[0].target_host_id == "portal.example.com"


def test_httpx_parser_extracts_cve_from_text_line():
    parser = parser_for_tool("httpx", "https://api.example.com")

    findings = parser.parse_line("https://api.example.com references CVE-2025-0001")

    assert any(f.finding_type == "vulnerability" for f in findings)
    vuln = [f for f in findings if f.finding_type == "vulnerability"][0]
    assert vuln.vulnerability is not None
    assert vuln.vulnerability.cve_id == "CVE-2025-0001"


def test_recon_parser_reads_json_line_payload():
    parser = parser_for_tool("amass", "example.com")

    findings = parser.parse_line('{"host":"edge.example.com"}')

    assert len(findings) == 1
    assert findings[0].finding_type == "host"
    assert findings[0].target_host_id == "edge.example.com"


def test_secretfinder_parser_can_emit_directory_and_secret_findings_from_single_line():
    parser = parser_for_tool("secretfinder", "https://app.example.com")

    findings = parser.parse_line("https://app.example.com/.env token=abc123")

    assert any(f.finding_type == "directory" for f in findings)
    assert any(f.finding_type == "vulnerability" for f in findings)


def test_visual_recon_parser_handles_screenshot_only_line():
    parser = parser_for_tool("aquatone", "https://app.example.com")

    findings = parser.parse_line("screenshots/home.png")

    assert len(findings) == 1
    assert findings[0].finding_type == "directory"
    assert findings[0].metadata.get("screenshot_hint") is not None


def test_parser_for_tool_rejects_unknown_tool():
    with pytest.raises(ValueError, match="unsupported parser tool"):
        parser_for_tool("unknown", "example.com")
