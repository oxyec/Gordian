from __future__ import annotations

import json
from pathlib import Path

import pytest

from src.offensive.parsers import FfufLineParser, HttpxLineParser, parser_for_tool


_FIXTURE_DIR = Path(__file__).parent / "fixtures" / "offensive"


def _fixture_lines(name: str) -> list[str]:
    path = _FIXTURE_DIR / name
    return [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


@pytest.mark.parametrize(
    ("tool", "target", "fixture_name", "expected_types", "min_findings"),
    [
        ("nmap", "api.example.com", "nmap_output.txt", {"host", "service", "vulnerability"}, 3),
        ("ffuf", "https://app.example.com", "ffuf_output.txt", {"directory", "vulnerability"}, 2),
        ("nuclei", "https://api.example.com", "nuclei_output.jsonl", {"vulnerability"}, 2),
        ("subfinder", "example.com", "subfinder_output.txt", {"host"}, 2),
        ("amass", "example.com", "amass_output.txt", {"host"}, 2),
        ("bbot", "example.com", "bbot_output.txt", {"host"}, 2),
        ("katana", "https://app.example.com", "katana_output.txt", {"directory", "vulnerability"}, 2),
        ("httpx", "https://api.example.com", "httpx_output.jsonl", {"host", "service"}, 2),
        ("secretfinder", "https://app.example.com", "secretfinder_output.txt", {"directory", "vulnerability"}, 2),
        ("linkfinder", "https://app.example.com", "linkfinder_output.txt", {"directory", "vulnerability"}, 2),
        ("gitleaks", "https://app.example.com", "gitleaks_output.txt", {"vulnerability"}, 1),
        ("aquatone", "https://app.example.com", "aquatone_output.txt", {"directory"}, 1),
        ("gowitness", "https://app.example.com", "gowitness_output.txt", {"directory"}, 1),
    ],
)
def test_tool_parsers_against_fixture_outputs(
    tool: str,
    target: str,
    fixture_name: str,
    expected_types: set[str],
    min_findings: int,
) -> None:
    parser = parser_for_tool(tool, target)
    findings = []
    for line in _fixture_lines(fixture_name):
        findings.extend(parser.parse_line(line))

    assert len(findings) >= min_findings
    finding_types = {finding.finding_type for finding in findings}
    assert expected_types.issubset(finding_types)


def test_ffuf_parser_tolerates_malformed_numeric_json_fields() -> None:
    parser = FfufLineParser("https://app.example.com")
    line = json.dumps({"url": "https://app.example.com/api", "status": "oops", "length": "bad"})

    findings = parser.parse_line(line)

    assert findings
    directory = next(item for item in findings if item.finding_type == "directory")
    assert directory.metadata.get("status") == 0
    assert directory.metadata.get("size") == 0


def test_httpx_parser_tolerates_non_numeric_port_field() -> None:
    parser = HttpxLineParser("https://api.example.com")
    line = json.dumps(
        {
            "url": "https://legacy.example.com",
            "status-code": 200,
            "host": "legacy.example.com",
            "port": "unknown",
            "tech": ["apache"],
        }
    )

    findings = parser.parse_line(line)

    services = [item for item in findings if item.finding_type == "service"]
    assert services
    assert services[0].target_port == 443


def test_recon_parser_reads_json_host_fields() -> None:
    parser = parser_for_tool("subfinder", "example.com")

    findings = parser.parse_line('{"host":"qa.example.com"}')

    assert findings
    assert findings[0].host is not None
    assert findings[0].host.id == "qa.example.com"
