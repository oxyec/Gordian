"""Async extractors (the 'E' in ETL).

Kept deliberately thin. Real deployments would swap these for adapters
that hit Nmap XML, Nessus API, NVD, EPSS, CrowdStrike, or whatever —
the rest of the pipeline doesn't care where the data came from as long
as it parses into `Host` / `Vulnerability` objects.

I/O runs on a thread via `asyncio.to_thread` so the event loop stays
free. Overkill for tiny JSON blobs, but the orchestrator calls these
concurrently so the shape matters more than the saved milliseconds.
"""

from __future__ import annotations

import asyncio
import json
import logging
from pathlib import Path
from typing import Any

from .json_utils import load_json_file
from .models import (
    ExploitCategory,
    Host,
    ReachableService,
    Service,
    Severity,
    Vulnerability,
)

log = logging.getLogger(__name__)


class ExtractError(Exception):
    """Raised when input JSON is present but structurally wrong."""


def _read_sync(path: Path) -> dict[str, Any]:
    return load_json_file(path)


async def _read_json(path: Path) -> dict[str, Any]:
    log.debug("reading %s", path)
    if not path.exists():
        raise FileNotFoundError(f"input file not found: {path}")
    try:
        return await asyncio.to_thread(_read_sync, path)
    except json.JSONDecodeError as e:
        raise ExtractError(f"{path.name} is not valid JSON: {e}") from e


def _parse_reachable(entries: list[Any]) -> tuple[ReachableService, ...]:
    out: list[ReachableService] = []
    for entry in entries:
        if isinstance(entry, (list, tuple)) and len(entry) == 2:
            out.append(ReachableService(host_id=str(entry[0]), port=int(entry[1])))
        elif isinstance(entry, dict) and "host" in entry and "port" in entry:
            out.append(ReachableService(host_id=str(entry["host"]), port=int(entry["port"])))
        else:
            raise ExtractError(
                f"reachable entry must be [host_id, port] or {{host, port}}, got {entry!r}"
            )
    return tuple(out)


async def extract_network(path: Path) -> list[Host]:
    raw = await _read_json(path)
    if "hosts" not in raw:
        raise ExtractError(f"{path.name}: missing required field 'hosts'")

    hosts: list[Host] = []
    for h in raw["hosts"]:
        try:
            services = tuple(
                Service(
                    name=s["name"],
                    port=int(s["port"]),
                    protocol=s["protocol"],
                    version=s["version"],
                    cve_ids=tuple(s.get("cves", [])),
                )
                for s in h.get("services", [])
            )
            hosts.append(
                Host(
                    id=h["id"],
                    hostname=h["hostname"],
                    ip_address=h["ip_address"],
                    segment=h["segment"],
                    os=h["os"],
                    is_attacker_entry=h.get("is_attacker_entry", False),
                    is_crown_jewel=h.get("is_crown_jewel", False),
                    criticality=int(h.get("criticality", 0)),
                    services=services,
                    reachable=_parse_reachable(h.get("reachable", [])),
                )
            )
        except KeyError as e:
            raise ExtractError(f"host entry missing required field {e}") from e

    log.info("extracted %d hosts from %s", len(hosts), path.name)
    return hosts


async def extract_cve_feed(path: Path) -> dict[str, Vulnerability]:
    raw = await _read_json(path)
    if "cves" not in raw:
        raise ExtractError(f"{path.name}: missing required field 'cves'")

    by_id: dict[str, Vulnerability] = {}
    for c in raw["cves"]:
        try:
            vuln = Vulnerability(
                cve_id=c["cve_id"],
                cvss_v3=float(c["cvss_v3"]),
                severity=Severity(c["severity"]),
                description=c["description"],
                exploit_category=ExploitCategory(c["exploit_category"]),
                mitre_tactics=tuple(c.get("mitre_tactics", [])),
                mitre_techniques=tuple(c.get("mitre_techniques", [])),
                exploitability=float(c["exploitability"]),
                weaponized=bool(c.get("weaponized", False)),
                epss_score=float(c.get("epss_score", 0.0)),
                references=tuple(c.get("references", [])),
            )
        except KeyError as e:
            raise ExtractError(f"CVE entry missing required field {e}") from e
        except ValueError as e:
            raise ExtractError(f"CVE entry has bad value: {e}") from e
        by_id[vuln.cve_id] = vuln

    log.info("extracted %d CVE records from %s", len(by_id), path.name)
    return by_id
