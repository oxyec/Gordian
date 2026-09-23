"""Pydantic v2 request / response models for the Gordian API."""

from __future__ import annotations

from enum import Enum
from pathlib import PurePosixPath, PureWindowsPath
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


# ── Enums ────────────────────────────────────────────────────────────

class ScanStatusEnum(str, Enum):
    IDLE = "idle"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class StorageBackend(str, Enum):
    RAM = "ram"
    SQLITE = "sqlite"


# ── Scan Start ───────────────────────────────────────────────────────

class ScanStartRequest(BaseModel):
    """JSON body for POST /api/v1/scan/start."""
    model_config = ConfigDict(extra="forbid", allow_inf_nan=False)

    target: str | None = Field(None, max_length=2048, description="Offensive target (host, IP, CIDR, or URL).")
    network_file: str | None = Field(None, description="Override network topology JSON path.")
    cve_file: str | None = Field(None, description="Override CVE feed JSON path.")
    output_dir: str | None = Field(None, description="Override reports output directory.")

    # Offensive knobs
    offensive_mode: Literal["auto", "dry-run", "disabled"] | None = None
    offensive_speed: Literal["stealth", "balanced", "aggressive"] | None = None
    offensive_intensity: Literal["low", "medium", "high"] | None = None
    offensive_tools: list[str] | None = Field(None, description="Tool allowlist, e.g. ['nmap','ffuf','nuclei'].")

    # CVE knobs
    cve_profile: str | None = Field(None, description="CVE source profile key.")
    cve_auto_download: bool | None = None
    cve_sync_policy: str | None = None

    # Advanced Tool Overrides
    tool_bin: dict[str, str] | None = None
    tool_extra_args: dict[str, list[str]] | None = None
    tool_command: dict[str, list[str]] | None = None
    max_nmap_rate: int | None = Field(None, ge=1, le=1000)
    max_ffuf_threads: int | None = Field(None, ge=1, le=80)
    max_nuclei_rate: int | None = Field(None, ge=1, le=250)

    # Wordlist
    wordlist_profile: str | None = None
    ffuf_wordlist: str | None = None

    # Feature toggles
    run_remediation: bool = True
    top_patches: int = Field(5, ge=1, le=100)
    asset_aware_cves: bool = False
    asset_cve_min_score: int = Field(2, ge=1, le=10)
    asset_cve_keep_top: int = Field(120, ge=0, le=5000)

    # Budget
    max_run_seconds: int | None = Field(None, ge=1, le=3600)
    max_total_targets: int | None = Field(None, ge=1, le=100)
    max_total_commands: int | None = Field(None, ge=1, le=200)
    max_findings: int | None = Field(None, ge=1, le=5000)
    bugbounty_mode: bool | None = None
    full_control: bool | None = None

    @field_validator("target")
    @classmethod
    def _validate_target(cls, value: str | None) -> str | None:
        if value is None:
            return value
        target = value.strip()
        if not target:
            raise ValueError("target cannot be empty")
        from src.offensive.command_factory import _sanitize_target
        return _sanitize_target(target)

    @field_validator("network_file", "cve_file", "output_dir", "ffuf_wordlist")
    @classmethod
    def _validate_path_field(cls, value: str | None, info) -> str | None:
        if value is None:
            return value

        cleaned = value.strip()
        if not cleaned:
            raise ValueError(f"{info.field_name} cannot be empty")
        if any(ord(ch) < 32 for ch in cleaned):
            raise ValueError(f"{info.field_name} contains control characters")

        paths = (PurePosixPath(cleaned), PureWindowsPath(cleaned))
        if any(part == ".." for path in paths for part in path.parts):
            raise ValueError(
                f"{info.field_name} cannot contain parent traversal segments ('..')"
            )
        if any(path.is_absolute() or path.drive for path in paths) or "\\" in cleaned:
            raise ValueError(f"{info.field_name} must use a server-relative path")
        if info.field_name == "output_dir" and cleaned != "reports":
            raise ValueError("output_dir is server-managed; omit it or use 'reports'")
        return cleaned

    @field_validator("offensive_tools")
    @classmethod
    def _normalise_tools(cls, value: list[str] | None) -> list[str] | None:
        if value is None:
            return value

        cleaned: list[str] = []
        for item in value:
            tool = str(item).strip().lower()
            if tool:
                cleaned.append(tool)
        from src.offensive.config import VALID_TOOLS
        if set(cleaned) - VALID_TOOLS:
            raise ValueError("unsupported offensive tool")

        return list(dict.fromkeys(cleaned)) or None

    @field_validator("tool_bin", "tool_extra_args", "tool_command")
    @classmethod
    def _validate_tool_maps(cls, value: dict[str, Any] | None, info) -> dict[str, Any] | None:
        if value:
            raise ValueError(f"{info.field_name} is a server-owned setting; API command overrides are disabled")
        return None

    @field_validator("full_control")
    @classmethod
    def _no_interactive_commands(cls, value: bool | None) -> bool | None:
        if value:
            raise ValueError("full_control terminal approval is not available through the API")
        return value

    @field_validator("cve_profile", "cve_auto_download", "cve_sync_policy")
    @classmethod
    def _local_cve_only(cls, value: Any, info) -> Any:
        # Remote feed syncing is not implemented by the API. Never silently accept it.
        supported = {"cve_profile": (None, "local"), "cve_auto_download": (None, False),
                     "cve_sync_policy": (None, "never")}
        if value not in supported[info.field_name]:
            raise ValueError("API scans use a server-managed local CVE feed; sync it before starting the server")
        return value


class ScanStartResponse(BaseModel):
    scan_id: str
    status: ScanStatusEnum
    message: str


# ── Scan Status ──────────────────────────────────────────────────────

class ScanProgress(BaseModel):
    stage: str = "idle"
    percent: float = 0.0
    message: str = ""


class ScanStatsSnapshot(BaseModel):
    hosts: int = 0
    edges: int = 0
    kill_chains: int = 0
    findings: int = 0
    patches: int = 0


class ScanStatusResponse(BaseModel):
    scan_id: str | None = None
    status: ScanStatusEnum = ScanStatusEnum.IDLE
    progress: ScanProgress = Field(default_factory=ScanProgress)
    stats: ScanStatsSnapshot = Field(default_factory=ScanStatsSnapshot)
    elapsed_seconds: float = 0.0
    error: str | None = None


# ── Graph ────────────────────────────────────────────────────────────

class ServiceNode(BaseModel):
    name: str
    port: int
    protocol: str
    version: str
    cve_ids: list[str] = Field(default_factory=list)


class HostNode(BaseModel):
    id: str
    hostname: str
    ip_address: str
    segment: str
    os: str
    is_attacker_entry: bool = False
    is_crown_jewel: bool = False
    criticality: int = 0
    services: list[ServiceNode] = Field(default_factory=list)


class GraphEdge(BaseModel):
    source: str
    target: str
    port: int
    cve_id: str
    cost: float
    cvss: float
    category: str
    technique: str


class GraphResponse(BaseModel):
    hosts: list[HostNode] = Field(default_factory=list)
    edges: list[GraphEdge] = Field(default_factory=list)
    entry_points: list[str] = Field(default_factory=list)
    crown_jewels: list[str] = Field(default_factory=list)
    node_count: int = 0
    edge_count: int = 0


# ── Kill Chains ──────────────────────────────────────────────────────

class AttackStepResponse(BaseModel):
    source_host_id: str
    target_host_id: str
    source_hostname: str = ""
    target_hostname: str = ""
    target_port: int = 0
    cve_id: str = ""
    technique: str = ""
    category: str = ""
    cost: float = 0.0


class KillChainResponse(BaseModel):
    entry_host: str
    target_host: str
    target_hostname: str = ""
    hops: int = 0
    total_cost: float = 0.0
    max_cvss: float = 0.0
    risk_score: float = 0.0
    exploit_chain: list[str] = Field(default_factory=list)
    steps: list[AttackStepResponse] = Field(default_factory=list)


# ── Findings ─────────────────────────────────────────────────────────

class FindingItem(BaseModel):
    tool: str = ""
    type: str = ""
    technical: str = ""
    narrative: str = ""
    confidence: float = 0.0
    severity: str = ""
    target: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)


class FindingsResponse(BaseModel):
    total: int = 0
    deduplicated: int = 0
    findings: list[FindingItem] = Field(default_factory=list)


# ── Live Event (WebSocket) ───────────────────────────────────────────

class LiveEvent(BaseModel):
    type: str
    timestamp: str = ""
    tool: str = "hub"
    level: str = "INFO"
    message: str = ""
    payload: dict[str, Any] = Field(default_factory=dict)


# ── Error Response ───────────────────────────────────────────────────

class ErrorResponse(BaseModel):
    """Uniform error payload for all non-2xx API responses."""
    error: str = Field(..., description="Short error code, e.g. 'not_found', 'rate_limited'.")
    message: str = Field(..., description="Human-readable explanation.")
    status_code: int = Field(..., description="HTTP status code, mirrored for clients that hide it.")
    detail: Any | None = Field(None, description="Optional structured details (validation errors, etc).")


# ── Server Info ──────────────────────────────────────────────────────

class ServerInfoResponse(BaseModel):
    name: str = "Gordian"
    version: str = "2.0.0-api"
    status: str = "online"
    storage_backend: str = "ram"
    max_concurrent_scans: int = 1
    active_scans: int = 0
    api_version: str = "v1"
