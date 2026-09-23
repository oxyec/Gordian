"""Narrative translation for technical offensive findings.

Each Finding produced by `parsers.py` is paired with a human-readable
sentence that the report / dashboard / TUI live log can show non-technical
readers. We dispatch on `(tool, finding_type)` first, then fall back to a
tool-only template, then to a generic vulnerability template, then to a
last-resort sentence so every Finding always gets *something* useful.
"""

from __future__ import annotations

from .parsers import Finding


class Storyteller:
    def narrate(self, finding: Finding) -> str:
        narrator = _DISPATCH.get((finding.tool, finding.finding_type))
        if narrator is not None:
            return narrator(finding)

        tool_narrator = _TOOL_DISPATCH.get(finding.tool)
        if tool_narrator is not None:
            return tool_narrator(finding)

        if finding.vulnerability is not None:
            vuln = finding.vulnerability
            return (
                f"A new exploitable condition ({vuln.cve_id}) was observed "
                "and added to the attack graph."
            )

        return "A new technical finding was observed and linked to the attack model."


# ── Per-(tool, finding_type) narrators ───────────────────────────────

def _ffuf_directory(f: Finding) -> str:
    path = str(f.metadata.get("path", "unknown path"))
    if _looks_sensitive(path):
        return (
            f"A sensitive backup or configuration resource ({path}) was found, "
            "which could leak credentials or application secrets."
        )
    return f"A hidden web path ({path}) was discovered, increasing exposed attack surface."


def _ffuf_vulnerability(f: Finding) -> str:
    cve = f.vulnerability.cve_id if f.vulnerability else "an unconfirmed weakness"
    path = str(f.metadata.get("path", ""))
    where = f" at {path}" if path else ""
    return f"Fuzzing surfaced an exploitable response{where} mapped to {cve}."


def _nmap_host(f: Finding) -> str:
    host_id = f.target_host_id or "an unidentified host"
    return f"A new live host ({host_id}) was discovered and added to the attack graph."


def _nmap_service(f: Finding) -> str:
    svc = f.service
    if svc is None:
        return "An exposed service was discovered on the target."
    return (
        f"An exposed {svc.name} service is reachable on port {svc.port}, "
        "creating a potential entry point for lateral movement."
    )


def _nmap_vulnerability(f: Finding) -> str:
    cve = f.vulnerability.cve_id if f.vulnerability else "a service vulnerability"
    port = f" on port {f.target_port}" if f.target_port else ""
    return f"Service scanning matched {cve}{port}, suggesting a known exploit path."


def _nuclei_vulnerability(f: Finding) -> str:
    vuln = f.vulnerability
    if vuln is None:
        return "Nuclei flagged a finding that warrants manual triage."
    severity = vuln.severity.value.lower()
    return (
        f"Nuclei identified a {severity} severity weakness ({vuln.cve_id}), "
        "which may allow direct compromise if left unpatched."
    )


def _recon_host(f: Finding) -> str:
    host_id = f.target_host_id or "a new asset"
    return (
        f"A previously unknown asset ({host_id}) was uncovered via {f.tool} "
        "and is now part of the engagement scope."
    )


def _katana_directory(f: Finding) -> str:
    url = str(f.metadata.get("url") or f.metadata.get("path") or "an internal URL")
    return f"The crawler reached {url}, expanding the testable web surface."


def _katana_vulnerability(f: Finding) -> str:
    cve = f.vulnerability.cve_id if f.vulnerability else "a crawler-surfaced issue"
    return f"Crawling exposed content matching {cve} — worth deeper review."


def _httpx_host(f: Finding) -> str:
    host_id = f.target_host_id or "a host"
    return f"HTTP probing confirmed {host_id} responds to web requests."


def _httpx_service(f: Finding) -> str:
    svc = f.service
    if svc is None:
        return "An HTTP service was confirmed on the target."
    tech = f.metadata.get("tech") or f.metadata.get("technology")
    if tech:
        return (
            f"A {tech} web service is live on {svc.name}:{svc.port}, "
            "narrowing down likely exploit templates."
        )
    return f"A {svc.name} service responded on port {svc.port} during HTTP probing."


def _httpx_vulnerability(f: Finding) -> str:
    cve = f.vulnerability.cve_id if f.vulnerability else "a fingerprinted weakness"
    return f"HTTP fingerprinting matched {cve} against the exposed stack."


def _secret_directory(f: Finding) -> str:
    location = str(f.metadata.get("path") or f.metadata.get("url") or "an exposed file")
    return f"Possible secret material was spotted at {location} — verify before treating as live credentials."


def _secret_vulnerability(f: Finding) -> str:
    location = str(f.metadata.get("path") or f.metadata.get("url") or "an exposed location")
    kind = f.metadata.get("secret_type") or f.metadata.get("rule") or "a leaked credential"
    return f"{f.tool} surfaced {kind} at {location}; rotate immediately if confirmed."


def _visual_directory(f: Finding) -> str:
    target = str(f.metadata.get("url") or f.target_host_id or "a discovered web target")
    return f"A screenshot of {target} was captured for visual triage."


# ── Tool-only fallbacks (when finding_type doesn't match) ─────────────

def _ffuf_generic(f: Finding) -> str:
    return "Fuzzing surfaced new content that expands the attack surface."


def _recon_generic(f: Finding) -> str:
    return f"{f.tool} contributed a new reconnaissance signal to the attack model."


def _secret_generic(f: Finding) -> str:
    return f"{f.tool} flagged content that may contain leaked secrets."


def _visual_generic(f: Finding) -> str:
    return f"{f.tool} captured visual evidence of a web target."


# ── Dispatch tables ──────────────────────────────────────────────────

_DISPATCH = {
    ("ffuf", "directory"): _ffuf_directory,
    ("ffuf", "vulnerability"): _ffuf_vulnerability,
    ("nmap", "host"): _nmap_host,
    ("nmap", "service"): _nmap_service,
    ("nmap", "vulnerability"): _nmap_vulnerability,
    ("nuclei", "vulnerability"): _nuclei_vulnerability,
    ("subfinder", "host"): _recon_host,
    ("amass", "host"): _recon_host,
    ("bbot", "host"): _recon_host,
    ("katana", "directory"): _katana_directory,
    ("katana", "vulnerability"): _katana_vulnerability,
    ("httpx", "host"): _httpx_host,
    ("httpx", "service"): _httpx_service,
    ("httpx", "vulnerability"): _httpx_vulnerability,
    ("secretfinder", "directory"): _secret_directory,
    ("secretfinder", "vulnerability"): _secret_vulnerability,
    ("linkfinder", "directory"): _secret_directory,
    ("linkfinder", "vulnerability"): _secret_vulnerability,
    ("gitleaks", "directory"): _secret_directory,
    ("gitleaks", "vulnerability"): _secret_vulnerability,
    ("aquatone", "directory"): _visual_directory,
    ("gowitness", "directory"): _visual_directory,
}

_TOOL_DISPATCH = {
    "ffuf": _ffuf_generic,
    "subfinder": _recon_generic,
    "amass": _recon_generic,
    "bbot": _recon_generic,
    "secretfinder": _secret_generic,
    "linkfinder": _secret_generic,
    "gitleaks": _secret_generic,
    "aquatone": _visual_generic,
    "gowitness": _visual_generic,
}


def _looks_sensitive(path: str) -> bool:
    lowered = path.lower()
    return any(
        token in lowered
        for token in ("backup", "config", ".db", ".env", ".sql", ".bak", "secret", "credential")
    )
