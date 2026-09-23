"""Streaming line parsers for offensive tool outputs."""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
import re
from urllib.parse import urlparse
from typing import Any, Protocol

from ..models import ExploitCategory, Host, Service, Severity, Vulnerability

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,8}", re.IGNORECASE)
_NMAP_HOST_RE = re.compile(r"^Nmap scan report for (?P<host>.+?)(?: \((?P<ip>[^)]+)\))?$")
_NMAP_PORT_RE = re.compile(
    r"^(?P<port>\d+)\/(?P<proto>\w+)\s+open\s+(?P<service>[^\s]+)\s*(?P<version>.*)$"
)
_FFUF_RE = re.compile(
    r"^(?P<path>\/?\S+)\s+\[Status:\s*(?P<status>\d+),\s*Size:\s*(?P<size>\d+)"
)
_URL_RE = re.compile(r"https?://[^\s\"']+", re.IGNORECASE)
_DOMAIN_RE = re.compile(r"\b(?P<host>[a-z0-9][a-z0-9.-]*\.[a-z]{2,})\b", re.IGNORECASE)


@dataclass
class Finding:
    tool: str
    finding_type: str
    technical: str
    raw_line: str
    host: Host | None = None
    service: Service | None = None
    vulnerability: Vulnerability | None = None
    target_host_id: str | None = None
    target_port: int | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


class LineParser(Protocol):
    def parse_line(self, line: str) -> list[Finding]:
        ...


class NmapLineParser:
    def __init__(self, target: str) -> None:
        host = _host_from_target(target)
        self._current_host_id = host.id if host else None
        self._current_ip = host.ip_address if host else ""
        self._last_port: int | None = None

    def parse_line(self, line: str) -> list[Finding]:
        findings: list[Finding] = []

        host_match = _NMAP_HOST_RE.match(line)
        if host_match:
            host_token = host_match.group("host")
            ip = host_match.group("ip") or ""
            host = _host_from_token(host_token, ip=ip)
            self._current_host_id = host.id
            self._current_ip = ip or host.ip_address
            findings.append(
                Finding(
                    tool="nmap",
                    finding_type="host",
                    technical=f"Discovered host {host.hostname} during nmap scan",
                    raw_line=line,
                    host=host,
                    target_host_id=host.id,
                    metadata={"ip_address": host.ip_address},
                )
            )

        port_match = _NMAP_PORT_RE.match(line)
        if port_match and self._current_host_id:
            port = int(port_match.group("port"))
            proto = port_match.group("proto")
            name = port_match.group("service")
            version = port_match.group("version").strip()
            self._last_port = port
            svc = Service(
                name=name,
                port=port,
                protocol=proto,
                version=version or "unknown",
                cve_ids=(),
            )
            findings.append(
                Finding(
                    tool="nmap",
                    finding_type="service",
                    technical=f"Open service {name} on port {port}/{proto}",
                    raw_line=line,
                    service=svc,
                    target_host_id=self._current_host_id,
                    target_port=port,
                    metadata={"ip_address": self._current_ip},
                )
            )

        for cve in _extract_cves(line):
            if self._current_host_id is None:
                continue
            vuln = _vulnerability_from_cve(
                cve,
                description=f"nmap output indicates potential exposure: {line}",
                category=ExploitCategory.INITIAL_ACCESS,
                severity=Severity.HIGH,
                exploitability=0.75,
                cvss_v3=8.6,
            )
            findings.append(
                Finding(
                    tool="nmap",
                    finding_type="vulnerability",
                    technical=f"Potential vulnerability {vuln.cve_id} identified from nmap output",
                    raw_line=line,
                    vulnerability=vuln,
                    target_host_id=self._current_host_id,
                    target_port=self._last_port,
                )
            )

        return findings


class FfufLineParser:
    def __init__(self, target: str) -> None:
        parsed = urlparse(_as_url(target))
        self._host_id = _normalize_host_id(parsed.hostname or target)
        self._port = parsed.port or (443 if parsed.scheme == "https" else 80)
        self._base_url = f"{parsed.scheme}://{parsed.netloc}"

    def parse_line(self, line: str) -> list[Finding]:
        if not line:
            return []

        if line.startswith("{"):
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                payload = None
            if isinstance(payload, dict):
                return self._from_json(payload, line)

        match = _FFUF_RE.match(line)
        if not match:
            return []

        path = _normalize_path(match.group("path"))
        status = int(match.group("status"))
        size = int(match.group("size"))
        return self._build_findings(path=path, status=status, size=size, raw_line=line)

    def _from_json(self, payload: dict[str, Any], raw_line: str) -> list[Finding]:
        path = payload.get("url") or payload.get("path") or payload.get("input")
        if isinstance(path, dict):
            path = path.get("FUZZ")
        if not path:
            return []

        status = _coerce_int(payload.get("status"), default=0)
        size = _coerce_int(payload.get("length") or payload.get("size"), default=0)
        return self._build_findings(path=_normalize_path(str(path)), status=status, size=size, raw_line=raw_line)

    def _build_findings(self, *, path: str, status: int, size: int, raw_line: str) -> list[Finding]:
        findings: list[Finding] = [
            Finding(
                tool="ffuf",
                finding_type="directory",
                technical=f"Found {path} via ffuf (status {status})",
                raw_line=raw_line,
                target_host_id=self._host_id,
                target_port=self._port,
                metadata={"path": path, "status": status, "size": size, "url": f"{self._base_url}{path}"},
            )
        ]

        if _looks_sensitive(path):
            vuln = _synthetic_vuln(
                seed=f"ffuf:{self._host_id}:{path}:{status}",
                description=f"Sensitive web path exposed: {path}",
                category=ExploitCategory.CREDENTIAL_ACCESS,
                severity=Severity.HIGH,
                exploitability=0.85,
                cvss_v3=8.2,
            )
            findings.append(
                Finding(
                    tool="ffuf",
                    finding_type="vulnerability",
                    technical=f"Sensitive resource {path} may expose credentials or secrets",
                    raw_line=raw_line,
                    vulnerability=vuln,
                    target_host_id=self._host_id,
                    target_port=self._port,
                    metadata={"path": path, "status": status, "size": size},
                )
            )

        return findings


class NucleiLineParser:
    def __init__(self, target: str) -> None:
        parsed = urlparse(_as_url(target))
        self._default_host_id = _normalize_host_id(parsed.hostname or target)
        self._default_port = parsed.port or (443 if parsed.scheme == "https" else 80)

    def parse_line(self, line: str) -> list[Finding]:
        if not line:
            return []

        if line.startswith("{"):
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                return self._from_text(line)
            return self._from_json(payload, line)

        return self._from_text(line)

    def _from_json(self, payload: dict[str, Any], raw_line: str) -> list[Finding]:
        info = payload.get("info") if isinstance(payload.get("info"), dict) else {}
        severity = _severity_from_text(str(info.get("severity", "medium")))
        host_value = payload.get("host") or payload.get("matched-at") or ""
        parsed = urlparse(str(host_value)) if str(host_value).startswith(("http://", "https://")) else None
        host_id = _normalize_host_id((parsed.hostname if parsed else str(host_value)) or self._default_host_id)
        port = (parsed.port if parsed else None) or self._default_port

        cve_ids = _extract_cves(json.dumps(payload))
        cve_id = cve_ids[0] if cve_ids else _synthetic_cve_id(f"nuclei:{host_id}:{payload.get('template-id', 'template')}")
        exploitability = 0.9 if severity is Severity.CRITICAL else 0.8 if severity is Severity.HIGH else 0.6
        cvss = 9.4 if severity is Severity.CRITICAL else 8.0 if severity is Severity.HIGH else 6.4

        vuln = _vulnerability_from_cve(
            cve_id,
            description=str(info.get("description") or payload.get("matcher-name") or "Nuclei finding"),
            category=ExploitCategory.INITIAL_ACCESS,
            severity=severity,
            exploitability=exploitability,
            cvss_v3=cvss,
        )

        return [
            Finding(
                tool="nuclei",
                finding_type="vulnerability",
                technical=f"Nuclei detected {vuln.cve_id} on {host_id}",
                raw_line=raw_line,
                vulnerability=vuln,
                target_host_id=host_id,
                target_port=port,
                metadata={
                    "template_id": payload.get("template-id"),
                    "name": info.get("name"),
                    "severity": severity.value,
                },
            )
        ]

    def _from_text(self, line: str) -> list[Finding]:
        cves = _extract_cves(line)
        if not cves:
            return []
        severity = Severity.HIGH if "critical" in line.lower() else Severity.MEDIUM
        cve_id = cves[0]
        vuln = _vulnerability_from_cve(
            cve_id,
            description=f"nuclei text output: {line}",
            category=ExploitCategory.INITIAL_ACCESS,
            severity=severity,
            exploitability=0.8,
            cvss_v3=8.0 if severity is Severity.HIGH else 6.2,
        )
        return [
            Finding(
                tool="nuclei",
                finding_type="vulnerability",
                technical=f"Nuclei detected {cve_id}",
                raw_line=line,
                vulnerability=vuln,
                target_host_id=self._default_host_id,
                target_port=self._default_port,
            )
        ]


class ReconDomainLineParser:
    """Parser for domain-centric recon tools like subfinder, amass, and bbot."""

    def __init__(self, tool: str, target: str) -> None:
        self._tool = tool

    def parse_line(self, line: str) -> list[Finding]:
        if not line:
            return []

        host_token = _extract_host_from_json_line(line) or _extract_host_token(line)
        if host_token is None:
            return []

        host = _host_from_token(host_token)
        return [
            Finding(
                tool=self._tool,
                finding_type="host",
                technical=f"Discovered host {host.hostname} via {self._tool}",
                raw_line=line,
                host=host,
                target_host_id=host.id,
            )
        ]


class KatanaLineParser:
    def __init__(self, target: str) -> None:
        parsed = urlparse(_as_url(target))
        self._host_id = _normalize_host_id(parsed.hostname or target)
        self._port = parsed.port or (443 if parsed.scheme == "https" else 80)
        self._base_url = f"{parsed.scheme}://{parsed.netloc}"

    def parse_line(self, line: str) -> list[Finding]:
        if not line:
            return []

        url = _extract_url(line)
        if url is None and line.strip().startswith("/"):
            url = f"{self._base_url}{line.strip()}"
        if url is None:
            return []

        parsed = urlparse(url)
        path = _normalize_path(parsed.path or "/")
        findings: list[Finding] = [
            Finding(
                tool="katana",
                finding_type="directory",
                technical=f"Discovered endpoint {path} via katana",
                raw_line=line,
                target_host_id=self._host_id,
                target_port=parsed.port or self._port,
                metadata={"path": path, "url": url},
            )
        ]

        if _looks_sensitive(path):
            vuln = _synthetic_vuln(
                seed=f"katana:{self._host_id}:{path}",
                description=f"Potentially sensitive endpoint discovered: {path}",
                category=ExploitCategory.CREDENTIAL_ACCESS,
                severity=Severity.HIGH,
                exploitability=0.82,
                cvss_v3=8.1,
            )
            findings.append(
                Finding(
                    tool="katana",
                    finding_type="vulnerability",
                    technical=f"Sensitive endpoint pattern detected at {path}",
                    raw_line=line,
                    vulnerability=vuln,
                    target_host_id=self._host_id,
                    target_port=parsed.port or self._port,
                    metadata={"path": path, "url": url},
                )
            )

        return findings


class HttpxLineParser:
    def __init__(self, target: str) -> None:
        parsed = urlparse(_as_url(target))
        self._default_host = _normalize_host_id(parsed.hostname or target)
        self._default_port = parsed.port or (443 if parsed.scheme == "https" else 80)

    def parse_line(self, line: str) -> list[Finding]:
        if not line:
            return []

        if line.startswith("{"):
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                payload = None
            if isinstance(payload, dict):
                return self._from_json(payload, line)

        return self._from_text(line)

    def _from_json(self, payload: dict[str, Any], raw_line: str) -> list[Finding]:
        value = str(payload.get("url") or payload.get("input") or payload.get("host") or "").strip()
        url = value if value.startswith(("http://", "https://")) else _extract_url(value)
        parsed = urlparse(url) if url else None
        host = (parsed.hostname if parsed else None) or str(payload.get("host") or "").strip()
        host_id = _normalize_host_id(host or self._default_host)
        port = (parsed.port if parsed else None) or _coerce_int(payload.get("port"), default=self._default_port)

        host_finding = Finding(
            tool="httpx",
            finding_type="host",
            technical=f"Live host responded: {host_id}",
            raw_line=raw_line,
            host=_host_from_token(host_id),
            target_host_id=host_id,
            target_port=port,
            metadata={"url": url or value, "status": payload.get("status-code")},
        )

        tech_values = payload.get("tech")
        if isinstance(tech_values, list):
            version = ",".join(str(v) for v in tech_values if str(v).strip())
        else:
            version = str(payload.get("webserver") or "unknown")

        service = Service(
            name="https" if (parsed and parsed.scheme == "https") else "http",
            port=port,
            protocol="tcp",
            version=version or "unknown",
            cve_ids=(),
        )
        service_finding = Finding(
            tool="httpx",
            finding_type="service",
            technical=f"HTTP service fingerprinted on {host_id}:{port}",
            raw_line=raw_line,
            service=service,
            target_host_id=host_id,
            target_port=port,
            metadata={"url": url or value, "status": payload.get("status-code")},
        )

        findings: list[Finding] = [host_finding, service_finding]
        findings.extend(self._extract_vuln_findings(raw_line, host_id, port))
        return findings

    def _from_text(self, line: str) -> list[Finding]:
        url = _extract_url(line)
        if url is None:
            token = line.strip().split()[0] if line.strip() else ""
            if _is_hostname_like(token):
                url = f"http://{token}"
            else:
                return self._extract_vuln_findings(line, self._default_host, self._default_port)

        parsed = urlparse(url)
        host_id = _normalize_host_id(parsed.hostname or self._default_host)
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        service = Service(
            name="https" if parsed.scheme == "https" else "http",
            port=port,
            protocol="tcp",
            version="unknown",
            cve_ids=(),
        )
        findings: list[Finding] = [
            Finding(
                tool="httpx",
                finding_type="service",
                technical=f"HTTP service observed at {parsed.netloc}",
                raw_line=line,
                service=service,
                target_host_id=host_id,
                target_port=port,
                metadata={"url": url},
            )
        ]
        findings.extend(self._extract_vuln_findings(line, host_id, port))
        return findings

    def _extract_vuln_findings(self, line: str, host_id: str, port: int) -> list[Finding]:
        findings: list[Finding] = []
        for cve_id in _extract_cves(line):
            vuln = _vulnerability_from_cve(
                cve_id,
                description=f"httpx output references {cve_id}: {line}",
                category=ExploitCategory.INITIAL_ACCESS,
                severity=Severity.HIGH,
                exploitability=0.74,
                cvss_v3=8.1,
            )
            findings.append(
                Finding(
                    tool="httpx",
                    finding_type="vulnerability",
                    technical=f"Potential vulnerability {cve_id} identified in httpx output",
                    raw_line=line,
                    vulnerability=vuln,
                    target_host_id=host_id,
                    target_port=port,
                )
            )
        return findings


class SecretLeakLineParser:
    def __init__(self, tool: str, target: str) -> None:
        self._tool = tool
        parsed = urlparse(_as_url(target))
        self._host_id = _normalize_host_id(parsed.hostname or target)
        self._port = parsed.port or (443 if parsed.scheme == "https" else 80)

    def parse_line(self, line: str) -> list[Finding]:
        if not line:
            return []

        findings: list[Finding] = []
        url = _extract_url(line)
        if url is not None:
            parsed = urlparse(url)
            path = _normalize_path(parsed.path or "/")
            findings.append(
                Finding(
                    tool=self._tool,
                    finding_type="directory",
                    technical=f"{self._tool} discovered endpoint {path}",
                    raw_line=line,
                    target_host_id=self._host_id,
                    target_port=parsed.port or self._port,
                    metadata={"path": path, "url": url},
                )
            )

        if _looks_secret_text(line):
            vuln = _synthetic_vuln(
                seed=f"{self._tool}:{self._host_id}:{line.strip()}",
                description=f"Potential secret leakage identified by {self._tool}: {line[:200]}",
                category=ExploitCategory.CREDENTIAL_ACCESS,
                severity=Severity.HIGH,
                exploitability=0.9,
                cvss_v3=8.8,
            )
            findings.append(
                Finding(
                    tool=self._tool,
                    finding_type="vulnerability",
                    technical=f"Potential secret exposure flagged by {self._tool}",
                    raw_line=line,
                    vulnerability=vuln,
                    target_host_id=self._host_id,
                    target_port=self._port,
                )
            )

        return findings


class VisualReconLineParser:
    def __init__(self, tool: str, target: str) -> None:
        self._tool = tool
        parsed = urlparse(_as_url(target))
        self._host_id = _normalize_host_id(parsed.hostname or target)
        self._port = parsed.port or (443 if parsed.scheme == "https" else 80)

    def parse_line(self, line: str) -> list[Finding]:
        if not line:
            return []

        url = _extract_url(line)
        if url is None and not _looks_screenshot_line(line):
            return []

        metadata: dict[str, Any] = {}
        if url is not None:
            parsed = urlparse(url)
            metadata["url"] = url
            path = _normalize_path(parsed.path or "/")
            port = parsed.port or self._port
        else:
            path = "/"
            port = self._port

        if _looks_screenshot_line(line):
            metadata["screenshot_hint"] = line.strip()

        return [
            Finding(
                tool=self._tool,
                finding_type="directory",
                technical=f"Visual recon artifact captured by {self._tool}",
                raw_line=line,
                target_host_id=self._host_id,
                target_port=port,
                metadata={"path": path, **metadata},
            )
        ]


def parser_for_tool(tool: str, target: str) -> LineParser:
    normalized = tool.lower()
    if normalized == "nmap":
        return NmapLineParser(target)
    if normalized == "ffuf":
        return FfufLineParser(target)
    if normalized == "nuclei":
        return NucleiLineParser(target)
    if normalized in {"subfinder", "amass", "bbot"}:
        return ReconDomainLineParser(normalized, target)
    if normalized == "katana":
        return KatanaLineParser(target)
    if normalized == "httpx":
        return HttpxLineParser(target)
    if normalized in {"secretfinder", "linkfinder", "gitleaks"}:
        return SecretLeakLineParser(normalized, target)
    if normalized in {"aquatone", "gowitness"}:
        return VisualReconLineParser(normalized, target)
    raise ValueError(f"unsupported parser tool: {tool}")


def _host_from_target(target: str) -> Host | None:
    token = target
    parsed = urlparse(target)
    if parsed.scheme:
        token = parsed.hostname or ""
    if not token:
        return None
    return _host_from_token(token)


def _host_from_token(token: str, *, ip: str = "") -> Host:
    host_id = _normalize_host_id(token)
    hostname = token.strip() or host_id
    ip_address = ip.strip() or "0.0.0.0"
    return Host(
        id=host_id,
        hostname=hostname,
        ip_address=ip_address,
        segment="DISCOVERED",
        os="unknown",
        is_attacker_entry=False,
        is_crown_jewel=False,
        criticality=5,
        services=(),
        reachable=(),
    )


def _normalize_host_id(value: str) -> str:
    lowered = value.strip().lower()
    if not lowered:
        return "unknown-host"
    sanitized = re.sub(r"[^a-z0-9.-]+", "-", lowered).strip(".-")
    return sanitized or "unknown-host"


def _normalize_path(path: str) -> str:
    if path.startswith(("http://", "https://")):
        parsed = urlparse(path)
        path = parsed.path or "/"
    if not path.startswith("/"):
        path = "/" + path
    return path


def _extract_cves(text: str) -> list[str]:
    return [token.upper() for token in _CVE_RE.findall(text)]


def _extract_url(text: str) -> str | None:
    match = _URL_RE.search(text)
    if not match:
        return None
    return match.group(0).rstrip(",.;")


def _extract_host_token(text: str) -> str | None:
    url = _extract_url(text)
    if url is not None:
        parsed = urlparse(url)
        if parsed.hostname:
            return parsed.hostname

    domain_match = _DOMAIN_RE.search(text)
    if domain_match:
        return domain_match.group("host")

    token = text.strip().split()[0] if text.strip() else ""
    if _is_hostname_like(token):
        return token
    return None


def _extract_host_from_json_line(text: str) -> str | None:
    stripped = text.strip()
    if not stripped.startswith("{"):
        return None

    try:
        payload = json.loads(stripped)
    except json.JSONDecodeError:
        return None

    if not isinstance(payload, dict):
        return None

    candidate_keys = (
        "host",
        "hostname",
        "name",
        "domain",
        "fqdn",
        "url",
        "input",
        "target",
        "data",
    )
    for key in candidate_keys:
        value = payload.get(key)
        if isinstance(value, str):
            token = _extract_host_token(value)
            if token:
                return token

    return None


def _is_hostname_like(value: str) -> bool:
    token = value.strip().lower().rstrip(",.;")
    if not token:
        return False
    if token.startswith(("http://", "https://")):
        parsed = urlparse(token)
        token = parsed.hostname or ""
    if not token:
        return False
    if token.count(".") == 0:
        return False
    return bool(re.match(r"^[a-z0-9.-]+$", token))


def _coerce_int(value: Any, *, default: int) -> int:
    if value is None:
        return default
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _severity_from_text(value: str) -> Severity:
    normalized = value.strip().upper()
    if normalized in Severity.__members__:
        return Severity[normalized]
    return Severity.MEDIUM


def _vulnerability_from_cve(
    cve_id: str,
    *,
    description: str,
    category: ExploitCategory,
    severity: Severity,
    exploitability: float,
    cvss_v3: float,
) -> Vulnerability:
    return Vulnerability(
        cve_id=cve_id,
        cvss_v3=cvss_v3,
        severity=severity,
        description=description,
        exploit_category=category,
        mitre_tactics=("TA0001",),
        mitre_techniques=("T1190",),
        exploitability=min(max(exploitability, 0.05), 0.99),
        weaponized=True,
        epss_score=0.65,
        references=(),
    )


def _synthetic_vuln(
    *,
    seed: str,
    description: str,
    category: ExploitCategory,
    severity: Severity,
    exploitability: float,
    cvss_v3: float,
) -> Vulnerability:
    cve_id = _synthetic_cve_id(seed)
    return _vulnerability_from_cve(
        cve_id,
        description=description,
        category=category,
        severity=severity,
        exploitability=exploitability,
        cvss_v3=cvss_v3,
    )


def _synthetic_cve_id(seed: str) -> str:
    digest = hashlib.sha1(seed.encode("utf-8")).hexdigest()[:10].upper()
    return f"GORDIAN-{digest}"


def _looks_sensitive(path: str) -> bool:
    lowered = path.lower()
    sensitive_keywords = (
        "backup",
        "config",
        ".db",
        ".sql",
        ".env",
        ".bak",
        "secret",
        "credential",
        "passwd",
    )
    return any(word in lowered for word in sensitive_keywords)


def _looks_secret_text(text: str) -> bool:
    lowered = text.lower()
    markers = (
        "apikey",
        "api_key",
        "secret",
        "token",
        "password",
        "passwd",
        "private key",
        "authorization",
        "aws_access_key_id",
        "ghp_",
    )
    return any(marker in lowered for marker in markers)


def _looks_screenshot_line(text: str) -> bool:
    lowered = text.lower()
    return any(ext in lowered for ext in (".png", ".jpg", ".jpeg", "screenshot"))


def _as_url(target: str) -> str:
    if target.startswith(("http://", "https://")):
        return target
    return f"http://{target}"
