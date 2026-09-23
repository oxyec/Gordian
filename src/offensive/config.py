"""Configuration and override handling for the Offensive Integration Hub."""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from enum import Enum
import json
from pathlib import Path
import re
import shlex
from typing import Any


class OffensiveMode(str, Enum):
    AUTO = "auto"
    MANUAL = "manual"
    DRY_RUN = "dry-run"
    DISABLED = "disabled"


class SpeedProfile(str, Enum):
    STEALTH = "stealth"
    BALANCED = "balanced"
    AGGRESSIVE = "aggressive"


class Intensity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


VALID_TOOLS = {
    "nmap",
    "ffuf",
    "nuclei",
    "subfinder",
    "amass",
    "bbot",
    "katana",
    "httpx",
    "secretfinder",
    "linkfinder",
    "gitleaks",
    "aquatone",
    "gowitness",
}


def _default_tool_dependencies() -> dict[str, tuple[str, ...]]:
    return {
        "httpx": ("subfinder", "amass", "bbot"),
        "katana": ("httpx",),
        "ffuf": ("httpx", "katana"),
        "nuclei": ("httpx",),
        "secretfinder": ("httpx", "katana"),
        "linkfinder": ("httpx", "katana"),
        "aquatone": ("httpx",),
        "gowitness": ("httpx",),
    }


def _default_tool_command_templates() -> dict[str, str]:
    return {
        "nmap": "{binary} {default_args} {target} {extra_args}",
        "ffuf": "{binary} -u {fuzz_url} -w {wordlist} {default_args} {extra_args}",
        "nuclei": "{binary} -u {url} {default_args} {extra_args}",
    }


@dataclass(frozen=True)
class OffensiveConfig:
    enabled: bool = True
    mode: OffensiveMode = OffensiveMode.AUTO
    target: str | None = None
    speed: SpeedProfile = SpeedProfile.BALANCED
    intensity: Intensity = Intensity.MEDIUM
    max_concurrency: int = 3
    timeout_seconds: int = 900
    directory_injection: bool = True
    tools: tuple[str, ...] = ("nmap", "ffuf", "nuclei")
    ffuf_wordlist_profile: str | None = None
    ffuf_wordlist: str = "/usr/share/seclists/Discovery/Web-Content/common.txt"
    wordlist_auto_download: bool = True
    wordlist_store_dir: str = "data/wordlists"
    bugbounty_mode: bool = False
    scope_policy_file: str | None = None
    require_scope_match: bool = False
    tech_hints: tuple[str, ...] = ()
    request_headers: tuple[str, ...] = ()
    full_control: bool = False
    max_nmap_rate: int | None = None
    max_ffuf_threads: int | None = None
    max_nuclei_rate: int | None = None
    max_total_targets: int | None = None
    max_total_commands: int | None = None
    max_findings: int | None = None
    max_run_seconds: int | None = None
    max_followup_targets: int = 40
    allowed_time_windows: tuple[str, ...] = ()
    ffuf_extensions: tuple[str, ...] = ("php", "txt", "bak", "db", "env")
    nuclei_templates: str | None = None
    tool_dependencies: dict[str, tuple[str, ...]] = field(default_factory=_default_tool_dependencies)
    tool_command_templates: dict[str, str] = field(default_factory=_default_tool_command_templates)
    tool_binaries: dict[str, str] = field(default_factory=dict)
    tool_extra_args: dict[str, tuple[str, ...]] = field(default_factory=dict)
    tool_command_overrides: dict[str, tuple[str, ...]] = field(default_factory=dict)

    def enabled_tools(self) -> tuple[str, ...]:
        return tuple(dict.fromkeys(tool for tool in self.tools if tool in VALID_TOOLS))

    def binary_for(self, tool: str) -> str:
        return self.tool_binaries.get(tool.lower(), tool)

    def extra_args_for(self, tool: str) -> tuple[str, ...]:
        return self.tool_extra_args.get(tool.lower(), ())

    def command_override_for(self, tool: str) -> tuple[str, ...] | None:
        return self.tool_command_overrides.get(tool.lower())

    def command_template_for(self, tool: str) -> str | None:
        return self.tool_command_templates.get(tool.lower())


class OffensiveConfigError(ValueError):
    """Raised when offensive config JSON is malformed."""


DEFAULT_CONFIG = OffensiveConfig()


def load_offensive_config(path: Path | None) -> OffensiveConfig:
    if path is None or not path.exists():
        return DEFAULT_CONFIG

    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise OffensiveConfigError(f"{path.name} is not valid JSON: {exc}") from exc

    if not isinstance(raw, dict):
        raise OffensiveConfigError(f"{path.name} must contain a JSON object")

    return _parse_config(raw, base=DEFAULT_CONFIG)


def _parse_config(raw: dict[str, Any], *, base: OffensiveConfig) -> OffensiveConfig:
    config = base
    if "enabled" in raw:
        config = replace(config, enabled=bool(raw["enabled"]))
    if "mode" in raw:
        config = replace(config, mode=OffensiveMode(str(raw["mode"]).lower()))
    if "target" in raw:
        value = str(raw["target"]).strip()
        config = replace(config, target=value or None)
    if "speed" in raw:
        config = replace(config, speed=SpeedProfile(str(raw["speed"]).lower()))
    if "intensity" in raw:
        config = replace(config, intensity=Intensity(str(raw["intensity"]).lower()))
    if "max_concurrency" in raw:
        config = replace(config, max_concurrency=max(1, int(raw["max_concurrency"])))
    if "timeout_seconds" in raw:
        config = replace(config, timeout_seconds=max(10, int(raw["timeout_seconds"])))
    if "directory_injection" in raw:
        config = replace(config, directory_injection=bool(raw["directory_injection"]))

    if "tools" in raw:
        if not isinstance(raw["tools"], list):
            raise OffensiveConfigError("'tools' must be a JSON list")
        tools = tuple(str(tool).lower().strip() for tool in raw["tools"] if str(tool).strip())
        bad = sorted(set(tools) - VALID_TOOLS)
        if bad:
            raise OffensiveConfigError(f"unsupported offensive tools: {', '.join(bad)}")
        config = replace(config, tools=tools or config.tools)

    if "tool_binaries" in raw:
        config = replace(config, tool_binaries=_parse_tool_binaries(raw["tool_binaries"]))

    if "tool_extra_args" in raw:
        config = replace(config, tool_extra_args=_parse_tool_argv_map(raw["tool_extra_args"], field_name="tool_extra_args"))

    if "tool_command_overrides" in raw:
        config = replace(
            config,
            tool_command_overrides=_parse_tool_argv_map(raw["tool_command_overrides"], field_name="tool_command_overrides"),
        )

    if "ffuf_wordlist" in raw:
        value = str(raw["ffuf_wordlist"]).strip()
        config = replace(config, ffuf_wordlist=value or config.ffuf_wordlist)

    if "ffuf_wordlist_profile" in raw:
        value = str(raw["ffuf_wordlist_profile"]).strip().lower()
        config = replace(config, ffuf_wordlist_profile=value or None)

    if "wordlist_auto_download" in raw:
        config = replace(config, wordlist_auto_download=bool(raw["wordlist_auto_download"]))

    if "wordlist_store_dir" in raw:
        value = str(raw["wordlist_store_dir"]).strip()
        config = replace(config, wordlist_store_dir=value or config.wordlist_store_dir)

    if "bugbounty_mode" in raw:
        config = replace(config, bugbounty_mode=bool(raw["bugbounty_mode"]))

    if "scope_policy_file" in raw:
        value = str(raw["scope_policy_file"]).strip()
        config = replace(config, scope_policy_file=value or None)

    if "require_scope_match" in raw:
        config = replace(config, require_scope_match=bool(raw["require_scope_match"]))

    if "full_control" in raw:
        config = replace(config, full_control=bool(raw["full_control"]))

    if "tech_hints" in raw:
        config = replace(config, tech_hints=_parse_tech_hints(raw["tech_hints"]))

    if "request_headers" in raw:
        config = replace(config, request_headers=_parse_request_headers(raw["request_headers"]))

    if "max_nmap_rate" in raw:
        value = int(raw["max_nmap_rate"])
        config = replace(config, max_nmap_rate=value if value > 0 else None)

    if "max_ffuf_threads" in raw:
        value = int(raw["max_ffuf_threads"])
        config = replace(config, max_ffuf_threads=value if value > 0 else None)

    if "max_nuclei_rate" in raw:
        value = int(raw["max_nuclei_rate"])
        config = replace(config, max_nuclei_rate=value if value > 0 else None)

    if "max_total_targets" in raw:
        value = int(raw["max_total_targets"])
        config = replace(config, max_total_targets=value if value > 0 else None)

    if "max_total_commands" in raw:
        value = int(raw["max_total_commands"])
        config = replace(config, max_total_commands=value if value > 0 else None)

    if "max_findings" in raw:
        value = int(raw["max_findings"])
        config = replace(config, max_findings=value if value > 0 else None)

    if "max_run_seconds" in raw:
        value = int(raw["max_run_seconds"])
        config = replace(config, max_run_seconds=value if value > 0 else None)

    if "max_followup_targets" in raw:
        config = replace(config, max_followup_targets=max(1, int(raw["max_followup_targets"])))

    if "allowed_time_windows" in raw:
        config = replace(config, allowed_time_windows=_parse_time_windows(raw["allowed_time_windows"]))

    if "ffuf_extensions" in raw:
        if not isinstance(raw["ffuf_extensions"], list):
            raise OffensiveConfigError("'ffuf_extensions' must be a JSON list")
        exts = tuple(str(ext).strip(" .").lower() for ext in raw["ffuf_extensions"] if str(ext).strip())
        config = replace(config, ffuf_extensions=exts)

    if "nuclei_templates" in raw:
        value = str(raw["nuclei_templates"]).strip()
        config = replace(config, nuclei_templates=value or None)

    if "tool_dependencies" in raw:
        config = replace(config, tool_dependencies=_parse_tool_dependency_map(raw["tool_dependencies"]))

    if "tool_command_templates" in raw:
        config = replace(config, tool_command_templates=_parse_tool_template_map(raw["tool_command_templates"]))

    return config


def merge_cli_overrides(
    base: OffensiveConfig,
    *,
    enabled: bool | None = None,
    mode: str | None = None,
    target: str | None = None,
    speed: str | None = None,
    intensity: str | None = None,
    tools: tuple[str, ...] | None = None,
    dry_run: bool = False,
    directory_injection: bool | None = None,
    ffuf_wordlist_profile: str | None = None,
    wordlist_auto_download: bool | None = None,
    wordlist_store_dir: str | None = None,
    ffuf_wordlist: str | None = None,
    bugbounty_mode: bool | None = None,
    scope_policy_file: str | None = None,
    require_scope_match: bool | None = None,
    full_control: bool | None = None,
    tech_hints: tuple[str, ...] | None = None,
    request_headers: tuple[str, ...] | None = None,
    max_nmap_rate: int | None = None,
    max_ffuf_threads: int | None = None,
    max_nuclei_rate: int | None = None,
    max_total_targets: int | None = None,
    max_total_commands: int | None = None,
    max_findings: int | None = None,
    max_run_seconds: int | None = None,
    max_followup_targets: int | None = None,
    allowed_time_windows: tuple[str, ...] | None = None,
    tool_dependencies: dict[str, tuple[str, ...]] | None = None,
    tool_command_templates: dict[str, str] | None = None,
    tool_binaries: dict[str, str] | None = None,
    tool_extra_args: dict[str, tuple[str, ...]] | None = None,
    tool_command_overrides: dict[str, tuple[str, ...]] | None = None,
) -> OffensiveConfig:
    config = base
    if enabled is not None:
        config = replace(config, enabled=enabled)
    if mode is not None:
        config = replace(config, mode=OffensiveMode(mode.lower()))
    if dry_run:
        config = replace(config, mode=OffensiveMode.DRY_RUN)
    if target is not None:
        value = target.strip()
        config = replace(config, target=value or None)
    if speed is not None:
        config = replace(config, speed=SpeedProfile(speed.lower()))
    if intensity is not None:
        config = replace(config, intensity=Intensity(intensity.lower()))
    if tools is not None:
        normalized = tuple(tool.lower().strip() for tool in tools if tool.strip())
        bad = sorted(set(normalized) - VALID_TOOLS)
        if bad:
            raise OffensiveConfigError(f"unsupported offensive tools: {', '.join(bad)}")
        config = replace(config, tools=normalized)
    if directory_injection is not None:
        config = replace(config, directory_injection=directory_injection)
    if ffuf_wordlist_profile is not None:
        value = ffuf_wordlist_profile.strip().lower()
        config = replace(config, ffuf_wordlist_profile=value or None)
    if wordlist_auto_download is not None:
        config = replace(config, wordlist_auto_download=wordlist_auto_download)
    if wordlist_store_dir is not None:
        value = wordlist_store_dir.strip()
        config = replace(config, wordlist_store_dir=value or config.wordlist_store_dir)
    if ffuf_wordlist is not None:
        value = ffuf_wordlist.strip()
        config = replace(config, ffuf_wordlist=value or config.ffuf_wordlist)

    if bugbounty_mode is not None:
        config = replace(config, bugbounty_mode=bugbounty_mode)
    if scope_policy_file is not None:
        value = scope_policy_file.strip()
        config = replace(config, scope_policy_file=value or None)
    if require_scope_match is not None:
        config = replace(config, require_scope_match=require_scope_match)
    if full_control is not None:
        config = replace(config, full_control=full_control)
    if tech_hints is not None:
        config = replace(config, tech_hints=_parse_tech_hints(tech_hints))
    if request_headers is not None:
        config = replace(config, request_headers=_parse_request_headers(request_headers))
    if max_nmap_rate is not None:
        config = replace(config, max_nmap_rate=max(max_nmap_rate, 1))
    if max_ffuf_threads is not None:
        config = replace(config, max_ffuf_threads=max(max_ffuf_threads, 1))
    if max_nuclei_rate is not None:
        config = replace(config, max_nuclei_rate=max(max_nuclei_rate, 1))
    if max_total_targets is not None:
        config = replace(config, max_total_targets=max(max_total_targets, 1))
    if max_total_commands is not None:
        config = replace(config, max_total_commands=max(max_total_commands, 1))
    if max_findings is not None:
        config = replace(config, max_findings=max(max_findings, 1))
    if max_run_seconds is not None:
        config = replace(config, max_run_seconds=max(max_run_seconds, 1))
    if max_followup_targets is not None:
        config = replace(config, max_followup_targets=max(max_followup_targets, 1))
    if allowed_time_windows is not None:
        config = replace(config, allowed_time_windows=_parse_time_windows(allowed_time_windows))
    if tool_dependencies is not None:
        merged = dict(config.tool_dependencies)
        merged.update(_normalize_tool_dependency_map(tool_dependencies))
        config = replace(config, tool_dependencies=merged)
    if tool_command_templates is not None:
        merged = dict(config.tool_command_templates)
        merged.update(_normalize_tool_template_map(tool_command_templates))
        config = replace(config, tool_command_templates=merged)
    if tool_binaries is not None:
        merged = dict(config.tool_binaries)
        merged.update(_normalize_tool_binaries(tool_binaries))
        config = replace(config, tool_binaries=merged)
    if tool_extra_args is not None:
        merged = dict(config.tool_extra_args)
        merged.update(_normalize_tool_argv_map(tool_extra_args, field_name="tool_extra_args"))
        config = replace(config, tool_extra_args=merged)
    if tool_command_overrides is not None:
        merged = dict(config.tool_command_overrides)
        merged.update(_normalize_tool_argv_map(tool_command_overrides, field_name="tool_command_overrides"))
        config = replace(config, tool_command_overrides=merged)

    # Bug bounty mode defaults to strict scoping and lower process fan-out.
    if config.bugbounty_mode:
        if require_scope_match is None:
            config = replace(config, require_scope_match=True)
        if config.max_concurrency > 2:
            config = replace(config, max_concurrency=2)
        if config.max_nmap_rate is None:
            config = replace(config, max_nmap_rate=40)
        if config.max_ffuf_threads is None:
            config = replace(config, max_ffuf_threads=25)
        if config.max_nuclei_rate is None:
            config = replace(config, max_nuclei_rate=80)
    return config


def should_attempt_offensive(config: OffensiveConfig) -> bool:
    return bool(config.enabled and config.mode is not OffensiveMode.DISABLED and config.target)


def _parse_tech_hints(raw: Any) -> tuple[str, ...]:
    values: list[str] = []
    if isinstance(raw, (tuple, list)):
        candidates = raw
    else:
        candidates = str(raw).split(",")

    for item in candidates:
        text = str(item).strip().lower()
        if text:
            values.append(text)
    return tuple(dict.fromkeys(values))


def _parse_request_headers(raw: Any) -> tuple[str, ...]:
    if isinstance(raw, (tuple, list)):
        candidates = raw
    else:
        candidates = str(raw).split(",")

    headers: list[str] = []
    for item in candidates:
        value = str(item).strip()
        if not value:
            continue
        if "\n" in value or "\r" in value:
            raise OffensiveConfigError("request headers must not contain newlines")
        if ":" not in value:
            raise OffensiveConfigError(f"invalid request header format: {value}")
        key, header_value = value.split(":", 1)
        if not key.strip() or not header_value.strip():
            raise OffensiveConfigError(f"invalid request header format: {value}")
        headers.append(f"{key.strip()}: {header_value.strip()}")

    return tuple(dict.fromkeys(headers))


def _parse_tool_binaries(raw: Any) -> dict[str, str]:
    if not isinstance(raw, dict):
        raise OffensiveConfigError("'tool_binaries' must be a JSON object")

    output: dict[str, str] = {}
    for tool, binary in raw.items():
        normalized_tool = _normalize_tool_name(tool)
        value = str(binary).strip()
        if not value:
            continue
        if "\n" in value or "\r" in value:
            raise OffensiveConfigError(f"tool binary override for {normalized_tool} must not contain newlines")
        output[normalized_tool] = value
    return output


def _parse_tool_argv_map(raw: Any, *, field_name: str) -> dict[str, tuple[str, ...]]:
    if not isinstance(raw, dict):
        raise OffensiveConfigError(f"'{field_name}' must be a JSON object")

    output: dict[str, tuple[str, ...]] = {}
    for tool, argv in raw.items():
        normalized_tool = _normalize_tool_name(tool)
        output[normalized_tool] = _coerce_argv(argv, field_name=field_name, tool=normalized_tool)
    return output


def _normalize_tool_binaries(raw: dict[str, str]) -> dict[str, str]:
    output: dict[str, str] = {}
    for tool, binary in raw.items():
        normalized_tool = _normalize_tool_name(tool)
        value = str(binary).strip()
        if not value:
            continue
        if "\n" in value or "\r" in value:
            raise OffensiveConfigError(f"tool binary override for {normalized_tool} must not contain newlines")
        output[normalized_tool] = value
    return output


def _normalize_tool_argv_map(
    raw: dict[str, tuple[str, ...]],
    *,
    field_name: str,
) -> dict[str, tuple[str, ...]]:
    output: dict[str, tuple[str, ...]] = {}
    for tool, argv in raw.items():
        normalized_tool = _normalize_tool_name(tool)
        output[normalized_tool] = _coerce_argv(argv, field_name=field_name, tool=normalized_tool)
    return output


def _normalize_tool_name(raw: Any) -> str:
    normalized = str(raw).strip().lower()
    if not normalized:
        raise OffensiveConfigError("tool name cannot be empty")
    if normalized not in VALID_TOOLS:
        raise OffensiveConfigError(f"unsupported offensive tool: {normalized}")
    return normalized


def _coerce_argv(raw: Any, *, field_name: str, tool: str) -> tuple[str, ...]:
    sentinels = {"(none)", "none", "null"}

    if isinstance(raw, str):
        tokens = tuple(
            token
            for token in shlex.split(raw.strip())
            if token and str(token).strip().lower() not in sentinels
        )
    elif isinstance(raw, (tuple, list)):
        tokens = tuple(
            cleaned
            for token in raw
            if (cleaned := str(token).strip()) and cleaned.lower() not in sentinels
        )
    else:
        raise OffensiveConfigError(f"{field_name}.{tool} must be a string or list of args")

    for token in tokens:
        if "\n" in token or "\r" in token:
            raise OffensiveConfigError(f"{field_name}.{tool} contains invalid newline characters")

    return tokens


_TIME_WINDOW_RE = re.compile(r"^(\d{2}):(\d{2})-(\d{2}):(\d{2})$")


def _parse_time_windows(raw: Any) -> tuple[str, ...]:
    if isinstance(raw, str):
        tokens = [part.strip() for part in raw.split(",")]
    elif isinstance(raw, (tuple, list)):
        tokens = [str(part).strip() for part in raw]
    else:
        raise OffensiveConfigError("allowed_time_windows must be a string or list")

    output: list[str] = []
    for token in tokens:
        if not token:
            continue
        match = _TIME_WINDOW_RE.match(token)
        if not match:
            raise OffensiveConfigError(
                "allowed_time_windows entries must use HH:MM-HH:MM format"
            )
        values = [int(value) for value in match.groups()]
        sh, sm, eh, em = values
        if sh > 23 or eh > 23 or sm > 59 or em > 59:
            raise OffensiveConfigError("allowed_time_windows contains invalid hour/minute values")
        output.append(token)

    return tuple(dict.fromkeys(output))


def _parse_tool_dependency_map(raw: Any) -> dict[str, tuple[str, ...]]:
    if not isinstance(raw, dict):
        raise OffensiveConfigError("'tool_dependencies' must be a JSON object")
    return _normalize_tool_dependency_map(raw)


def _normalize_tool_dependency_map(raw: dict[str, Any]) -> dict[str, tuple[str, ...]]:
    output: dict[str, tuple[str, ...]] = {}
    for tool, dependencies in raw.items():
        normalized_tool = _normalize_tool_name(tool)
        if isinstance(dependencies, str):
            raw_items = [item.strip() for item in dependencies.split(",")]
        elif isinstance(dependencies, (tuple, list)):
            raw_items = [str(item).strip() for item in dependencies]
        else:
            raise OffensiveConfigError(
                f"tool_dependencies.{normalized_tool} must be a string or list"
            )

        deps: list[str] = []
        for item in raw_items:
            if not item:
                continue
            dep = _normalize_tool_name(item)
            if dep == normalized_tool:
                raise OffensiveConfigError(
                    f"tool_dependencies.{normalized_tool} cannot depend on itself"
                )
            deps.append(dep)
        output[normalized_tool] = tuple(dict.fromkeys(deps))
    return output


def _parse_tool_template_map(raw: Any) -> dict[str, str]:
    if not isinstance(raw, dict):
        raise OffensiveConfigError("'tool_command_templates' must be a JSON object")
    return _normalize_tool_template_map(raw)


def _normalize_tool_template_map(raw: dict[str, Any]) -> dict[str, str]:
    output: dict[str, str] = {}
    for tool, template in raw.items():
        normalized_tool = _normalize_tool_name(tool)
        rendered = str(template).strip()
        if not rendered:
            continue
        if "\n" in rendered or "\r" in rendered:
            raise OffensiveConfigError(
                f"tool_command_templates.{normalized_tool} must be single-line"
            )
        output[normalized_tool] = rendered
    return output
