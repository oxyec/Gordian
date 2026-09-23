from __future__ import annotations

import pytest

from api.models import GraphResponse, ScanStartRequest


def test_scan_start_request_normalises_target_and_tools() -> None:
    req = ScanStartRequest(
        target="  https://api.example.com  ",
        offensive_tools=[" NMAP ", "ffuf", "nmap", ""],
    )

    assert req.target == "https://api.example.com"
    assert req.offensive_tools == ["nmap", "ffuf"]


@pytest.mark.parametrize("field_name", ["network_file", "cve_file", "output_dir", "ffuf_wordlist"])
def test_scan_start_request_rejects_parent_traversal(field_name: str) -> None:
    with pytest.raises(ValueError, match="parent traversal"):
        ScanStartRequest(**{field_name: "../secrets.json"})


def test_scan_start_request_rejects_empty_target() -> None:
    with pytest.raises(ValueError, match="target cannot be empty"):
        ScanStartRequest(target="   ")


def test_scan_start_request_rejects_invalid_tool_bin_value() -> None:
    with pytest.raises(ValueError, match="server-owned"):
        ScanStartRequest(tool_bin={"nmap": "   "})


def test_graph_response_default_lists_are_not_shared() -> None:
    first = GraphResponse()
    second = GraphResponse()

    first.hosts.append({
        "id": "h1",
        "hostname": "h1",
        "ip_address": "10.0.0.1",
        "segment": "DMZ",
        "os": "linux",
        "services": [],
    })

    assert len(first.hosts) == 1
    assert len(second.hosts) == 0
