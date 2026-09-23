from __future__ import annotations

from dataclasses import dataclass
import asyncio
from datetime import datetime, timezone
from fnmatch import fnmatch
from ipaddress import ip_address, ip_network
import json
from pathlib import Path
import re
import socket
from urllib.parse import urlparse


class ScopePolicyError(ValueError):
    """Raised when the scope policy file is malformed."""


@dataclass(frozen=True)
class ScopePolicy:
    allow_hosts: tuple[str, ...] = ()
    deny_hosts: tuple[str, ...] = ()
    allow_cidrs: tuple[str, ...] = ()
    deny_cidrs: tuple[str, ...] = ()
    allow_schemes: tuple[str, ...] = ("http", "https")
    hard_stop_hosts: tuple[str, ...] = ()
    max_nmap_rate: int | None = None
    max_ffuf_threads: int | None = None
    max_nuclei_rate: int | None = None
    max_total_targets: int | None = None
    max_total_commands: int | None = None
    max_findings: int | None = None
    max_run_seconds: int | None = None
    max_followup_targets: int | None = None
    allowed_time_windows: tuple[str, ...] = ()

    def has_allow_rules(self) -> bool:
        return bool(self.allow_hosts or self.allow_cidrs)


def load_scope_policy(path: Path) -> ScopePolicy:
    if not path.exists():
        raise ScopePolicyError(f"scope policy file does not exist: {path}")

    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ScopePolicyError(f"{path.name} is not valid JSON: {exc}") from exc

    if not isinstance(payload, dict):
        raise ScopePolicyError("scope policy must be a JSON object")

    allow_hosts = _normalize_strings(payload.get("allow_hosts", []), field="allow_hosts")
    deny_hosts = _normalize_strings(payload.get("deny_hosts", []), field="deny_hosts")
    allow_cidrs = _normalize_cidrs(payload.get("allow_cidrs", []), field="allow_cidrs")
    deny_cidrs = _normalize_cidrs(payload.get("deny_cidrs", []), field="deny_cidrs")
    schemes = _normalize_strings(payload.get("allow_schemes", ["http", "https"]), field="allow_schemes")
    hard_stop_hosts = _normalize_strings(payload.get("hard_stop_hosts", []), field="hard_stop_hosts")

    max_nmap_rate = _normalize_optional_positive_int(payload.get("max_nmap_rate"), field="max_nmap_rate")
    max_ffuf_threads = _normalize_optional_positive_int(payload.get("max_ffuf_threads"), field="max_ffuf_threads")
    max_nuclei_rate = _normalize_optional_positive_int(payload.get("max_nuclei_rate"), field="max_nuclei_rate")
    max_total_targets = _normalize_optional_positive_int(payload.get("max_total_targets"), field="max_total_targets")
    max_total_commands = _normalize_optional_positive_int(payload.get("max_total_commands"), field="max_total_commands")
    max_findings = _normalize_optional_positive_int(payload.get("max_findings"), field="max_findings")
    max_run_seconds = _normalize_optional_positive_int(payload.get("max_run_seconds"), field="max_run_seconds")
    max_followup_targets = _normalize_optional_positive_int(
        payload.get("max_followup_targets"),
        field="max_followup_targets",
    )
    allowed_time_windows = _normalize_time_windows(payload.get("allowed_time_windows", []))

    return ScopePolicy(
        allow_hosts=allow_hosts,
        deny_hosts=deny_hosts,
        allow_cidrs=allow_cidrs,
        deny_cidrs=deny_cidrs,
        allow_schemes=schemes,
        hard_stop_hosts=hard_stop_hosts,
        max_nmap_rate=max_nmap_rate,
        max_ffuf_threads=max_ffuf_threads,
        max_nuclei_rate=max_nuclei_rate,
        max_total_targets=max_total_targets,
        max_total_commands=max_total_commands,
        max_findings=max_findings,
        max_run_seconds=max_run_seconds,
        max_followup_targets=max_followup_targets,
        allowed_time_windows=allowed_time_windows,
    )


def evaluate_target_scope(target: str, policy: ScopePolicy) -> tuple[bool, str]:
    host, scheme = _extract_host_and_scheme(target)
    if not host:
        return False, "target host is empty"

    if scheme and policy.allow_schemes and scheme not in policy.allow_schemes:
        return False, f"scheme '{scheme}' is not allowed"

    if _matches_any_host(host, policy.deny_hosts):
        return False, f"host '{host}' matches deny_hosts"

    if _matches_any_host(host, policy.hard_stop_hosts):
        return False, f"host '{host}' matches hard_stop_hosts"

    network = None
    try:
        network = ip_network(host, strict=False)
    except ValueError:
        pass

    if network is not None:
        for denied in policy.deny_cidrs:
            deny_net = ip_network(denied, strict=False)
            if network.version == deny_net.version and network.overlaps(deny_net):
                return False, "target range overlaps deny_cidrs"

    if not policy.has_allow_rules():
        return False, "scope allow-list is empty; target rejected"

    allowed_by_host = _matches_any_host(host, policy.allow_hosts)
    allowed_by_cidr = network is not None and any(
        network.version == allowed.version and network.subnet_of(allowed)
        for allowed in (ip_network(cidr, strict=False) for cidr in policy.allow_cidrs)
    )
    # Host patterns cannot broaden an explicitly supplied network range.
    if network is not None:
        allowed_by_host = False
    if allowed_by_host or allowed_by_cidr:
        return True, "target matched allow scope"
    return False, f"target '{host}' is outside allow scope"


async def evaluate_resolved_target_scope(target: str, policy: ScopePolicy) -> tuple[bool, str]:
    """Check hostname rules and every resolved address before dispatch.

Tools may resolve again: deployments still need an egress boundary to constrain
DNS rebinding, redirects and tool-native crawling.
"""
    allowed, reason = evaluate_target_scope(target, policy)
    host, _scheme = _extract_host_and_scheme(target)
    try:
        ip_network(host, strict=False)
        return allowed, reason
    except ValueError:
        pass
    if not allowed:
        return False, reason
    try:
        rows = await asyncio.wait_for(asyncio.get_running_loop().getaddrinfo(
            host, None, type=socket.SOCK_STREAM), timeout=5)
        addresses = {str(row[4][0]) for row in rows}
    except (OSError, asyncio.TimeoutError):
        return False, "target DNS resolution failed"
    if not addresses:
        return False, "target DNS resolution returned no addresses"
    for address in addresses:
        if _matches_any_cidr(address, policy.deny_cidrs):
            return False, "resolved target address matches deny_cidrs"
    return True, "hostname and resolved addresses passed scope checks"


def is_current_time_allowed(policy: ScopePolicy, *, now: datetime | None = None) -> tuple[bool, str]:
    windows = policy.allowed_time_windows
    if not windows:
        return True, "no time window restrictions configured"

    now_utc = now or datetime.now(timezone.utc)
    minute_of_day = (now_utc.hour * 60) + now_utc.minute

    for window in windows:
        start_min, end_min = _window_to_minutes(window)
        if start_min <= end_min:
            if start_min <= minute_of_day <= end_min:
                return True, f"current UTC time matches allowed window {window}"
        else:
            # Window wraps midnight (for example 23:00-02:00).
            if minute_of_day >= start_min or minute_of_day <= end_min:
                return True, f"current UTC time matches allowed window {window}"

    return False, "current UTC time is outside allowed_time_windows"


def _extract_host_and_scheme(target: str) -> tuple[str, str | None]:
    text = target.strip()
    if not text:
        return "", None

    if "://" in text:
        parsed = urlparse(text)
        host = (parsed.hostname or "").strip().lower().rstrip(".")
        scheme = (parsed.scheme or "").strip().lower() or None
        return host, scheme

    return text.lower().rstrip("."), None


def _matches_any_host(host: str, patterns: tuple[str, ...]) -> bool:
    for pattern in patterns:
        if fnmatch(host, pattern):
            return True
        if host == pattern:
            return True
    return False


def _matches_any_cidr(ip_text: str, cidrs: tuple[str, ...]) -> bool:
    ip_obj = ip_address(ip_text)
    for cidr in cidrs:
        network = ip_network(cidr, strict=False)
        if ip_obj in network:
            return True
    return False


def _normalize_strings(raw: object, *, field: str) -> tuple[str, ...]:
    if isinstance(raw, str):
        values = [part.strip().lower() for part in raw.split(",")]
    elif isinstance(raw, list):
        values = [str(item).strip().lower() for item in raw]
    else:
        raise ScopePolicyError(f"'{field}' must be a list or comma-separated string")

    cleaned = tuple(value for value in values if value)
    return tuple(dict.fromkeys(cleaned))


def _normalize_cidrs(raw: object, *, field: str) -> tuple[str, ...]:
    cidrs = _normalize_strings(raw, field=field)
    normalized: list[str] = []
    for cidr in cidrs:
        try:
            network = ip_network(cidr, strict=False)
        except ValueError as exc:
            raise ScopePolicyError(f"invalid CIDR in '{field}': {cidr}") from exc
        normalized.append(str(network))
    return tuple(dict.fromkeys(normalized))


def _normalize_optional_positive_int(raw: object, *, field: str) -> int | None:
    if raw is None:
        return None
    try:
        value = int(raw)
    except (TypeError, ValueError) as exc:
        raise ScopePolicyError(f"'{field}' must be a positive integer") from exc
    if value <= 0:
        raise ScopePolicyError(f"'{field}' must be a positive integer")
    return value


_WINDOW_RE = re.compile(r"^(\d{2}):(\d{2})-(\d{2}):(\d{2})$")


def _normalize_time_windows(raw: object) -> tuple[str, ...]:
    if isinstance(raw, str):
        windows = [part.strip() for part in raw.split(",")]
    elif isinstance(raw, list):
        windows = [str(item).strip() for item in raw]
    else:
        raise ScopePolicyError("'allowed_time_windows' must be a list or comma-separated string")

    normalized: list[str] = []
    for window in windows:
        if not window:
            continue
        _window_to_minutes(window)
        normalized.append(window)
    return tuple(dict.fromkeys(normalized))


def _window_to_minutes(window: str) -> tuple[int, int]:
    match = _WINDOW_RE.match(window)
    if not match:
        raise ScopePolicyError(
            "invalid time window format in 'allowed_time_windows'; expected HH:MM-HH:MM"
        )

    start_h, start_m, end_h, end_m = (int(value) for value in match.groups())
    if start_h > 23 or end_h > 23 or start_m > 59 or end_m > 59:
        raise ScopePolicyError("invalid time value in 'allowed_time_windows'")

    return (start_h * 60 + start_m, end_h * 60 + end_m)
