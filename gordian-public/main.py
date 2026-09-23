"""Gordian — API-First Entry Point.

Launch modes:
    python main.py                           # start API server (default port 8000)
    python main.py --api-port 9000           # custom port
    python main.py --storage sqlite          # persistent scan storage
    python main.py --max-concurrent-scans 3  # allow parallel scans
    python main.py --headless                # suppress boot animation
    python main.py --no-intro                # suppress boot animation (alias)
"""

from __future__ import annotations

import argparse
import asyncio
import importlib
import ipaddress
import json
import logging
import os
import re
import shlex
import shutil
import socket
import subprocess
import sys
import time
from urllib.parse import urlsplit
from urllib.request import urlopen
from pathlib import Path
from typing import TYPE_CHECKING, Any

from src.cve_sources import (
    CVE_FEED_CATALOG,
    describe_cve_profiles_for_cli,
)
from src.offensive import (
    CommandFactory,
    CommandFactoryError,
    OffensiveConfigError,
    describe_profiles_for_cli,
    load_offensive_config,
    merge_cli_overrides,
)


EXIT_OK = 0
EXIT_ERROR = 1


# ── ASCII Art & Boot Animation ───────────────────────────────────────

README_ASCII_ART = r"""         
         /\
        /  \
       |    |
       |    |
     __|____|__        ____               _ _
    [==========]      / ___| ___  _ __ __| (_) __ _ _ __
        |  |         | |  _ / _ \| '__/ _` | |/ _` | '_ \
     o--|--|--o      | |_| | (_) | | | (_| | | (_| | | | |
    / \ |  | / \      \____|\___/|_|  \__,_|_|\__,_|_| |_|
   o---o|--|o---o
  / \ / |  | \ / \
 o---o  |  |  o---o
  \ / \ |  | / \ /
   o---o|--|o---o
    \ / |  | \ /
     o--|--|--o
        |  |
        \  /
         \/"""

BOOT_LINES = (
    "bootloader online",
    "loading topology parser",
    "binding CVE source connectors",
    "warming graph transform engine",
    "validating scope and policy guards",
    "loading remediation simulation core",
    "preparing offensive command planner",
    "attaching FastAPI event bus",
    "syncing WebSocket broadcast layer",
    "initialising storage backend",
    "API engine ready",
)


def _render_terminal_intro(args: argparse.Namespace) -> None:
    """Display the Gordian ASCII art + boot sequence on startup."""
    if not _should_render_intro(args):
        return

    speed = max(0.01, min(getattr(args, "intro_speed", 0.065), 0.5))

    # VS Code + WSL terminals render streaming output more reliably than Rich Live.
    if _is_vscode_terminal() or _is_wsl_runtime():
        _render_terminal_intro_vscode_safe(
            args=args,
            boot_lines=_build_intro_boot_lines(args),
            speed=speed,
        )
        return

    # Try Rich for beautiful rendering
    Console, Group, Live, Panel, Text = _load_rich_components()
    if Console is not None and Live is not None and Panel is not None and Text is not None:
        _render_intro_rich(args, speed=speed, Console=Console, Group=Group,
                           Live=Live, Panel=Panel, Text=Text)
        return

    # Fallback: plain ANSI
    _render_intro_plain(args, speed=speed)


def _render_intro_rich(args, *, speed, Console, Group, Live, Panel, Text):
    console = Console()
    art_lines = README_ASCII_ART.splitlines()
    shown_lines: list[str] = []
    shown_boot_lines: list[str] = []
    boot_lines = _build_intro_boot_lines(args)

    def _panel():
        art_block = Text("\n".join(shown_lines), style="bold cyan")
        status_lines = shown_boot_lines[-12:] if shown_boot_lines else ["[boot] preparing API engine"]
        status_block = Text("\n".join(status_lines), style="green")

        info_lines = [
            f"  api_port       : {getattr(args, 'api_port', 8000)}",
            f"  storage        : {getattr(args, 'storage', 'ram')}",
            f"  max_scans      : {getattr(args, 'max_concurrent_scans', 1)}",
            f"  offensive_mode : {getattr(args, 'offensive_mode', 'auto') or 'auto'}",
            f"  offensive_target: {getattr(args, 'offensive_target', None) or 'none'}",
            f"  cve_profile    : {getattr(args, 'cve_profile', 'local')}",
        ]
        info_block = Text("\n".join(info_lines), style="bold bright_green")

        return Panel(
            Group(art_block, Text(""), status_block, Text(""), info_block),
            title="Gordian :: API Engine",
            border_style="cyan",
            expand=False,
            padding=(1, 2),
        )

    with Live(_panel(), console=console, refresh_per_second=30, transient=False) as live:
        for line in art_lines:
            shown_lines.append(line)
            live.update(_panel())
            time.sleep(speed)

        for idx, line in enumerate(boot_lines, start=1):
            pct = int(idx * 100 / max(1, len(boot_lines)))
            fill = min(20, pct // 5)
            bar = ("#" * fill) + ("-" * (20 - fill))
            rendered = f"[{pct:03}%] [{bar}] {line}"
            shown_boot_lines.append(rendered)
            live.update(_panel())
            time.sleep(max(speed * 1.6, 0.08))

    console.print()


def _render_intro_plain(args, *, speed):
    """ANSI-coloured fallback for terminals without Rich."""
    for line in README_ASCII_ART.splitlines():
        print(f"\x1b[96m{line}\x1b[0m", flush=True)
        time.sleep(max(speed * 0.55, 0.01))

    print("", flush=True)
    boot_lines = _build_intro_boot_lines(args)
    total = max(1, len(boot_lines))
    for idx, line in enumerate(boot_lines, start=1):
        pct = int(idx * 100 / total)
        fill = min(20, pct // 5)
        bar = ("#" * fill) + ("-" * (20 - fill))
        color = "93" if pct < 40 else ("92" if pct < 85 else "96")
        rendered = f"[{pct:03}%] [{bar}] {line}"
        print(f"\x1b[{color}m{rendered}\x1b[0m", flush=True)
        time.sleep(max(speed * 0.95, 0.04))

    print("", flush=True)
    print(f"\x1b[95mGordian API Engine :: port={getattr(args, 'api_port', 8000)} "
          f"storage={getattr(args, 'storage', 'ram')}\x1b[0m", flush=True)
    print("", flush=True)


def _build_intro_boot_lines(args: argparse.Namespace) -> tuple[str, ...]:
    dynamic = (
        f"[cfg] api_port={getattr(args, 'api_port', 8000)}",
        f"[cfg] storage={getattr(args, 'storage', 'ram')}",
        f"[cfg] max_concurrent_scans={getattr(args, 'max_concurrent_scans', 1)}",
        f"[cfg] offensive_mode={getattr(args, 'offensive_mode', 'auto') or 'auto'}",
        f"[cfg] offensive_target={getattr(args, 'offensive_target', None) or 'none'}",
        f"[cfg] cve_profile={getattr(args, 'cve_profile', 'local')}",
        f"[path] network={getattr(args, 'network', 'data/sample_network.json')}",
        f"[path] cve_feed={getattr(args, 'cves', 'data/cve_feed.json')}",
        "[sync] WebSocket broadcast layer linked",
    )
    return (*BOOT_LINES, *dynamic)


def _load_rich_components():
    try:
        console_mod = importlib.import_module("rich.console")
        live_mod = importlib.import_module("rich.live")
        panel_mod = importlib.import_module("rich.panel")
        text_mod = importlib.import_module("rich.text")
    except ImportError:
        return None, None, None, None, None

    return (
        getattr(console_mod, "Console", None),
        getattr(console_mod, "Group", None),
        getattr(live_mod, "Live", None),
        getattr(panel_mod, "Panel", None),
        getattr(text_mod, "Text", None),
    )


# ── Logging ──────────────────────────────────────────────────────────

def _configure_logging(verbose: bool) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s  %(levelname)-7s  %(name)s :: %(message)s",
        datefmt="%H:%M:%S",
    )


# ── CLI Arg Parsing ──────────────────────────────────────────────────

def _parse_args(argv: list[str]) -> argparse.Namespace:
    root = Path(__file__).parent
    parser = argparse.ArgumentParser(
        prog="gordian",
        description=(
            "Gordian — API-first attack-path analysis engine. "
            "Starts a FastAPI server that exposes REST endpoints and a "
            "WebSocket stream for real-time scan intelligence."
        ),
    )

    # ── API Server ──
    parser.add_argument(
        "--api-port",
        type=int,
        default=8000,
        help="Port to run the FastAPI server on (default: 8000).",
    )
    parser.add_argument(
        "--api-host",
        default="127.0.0.1",
        help=(
            "Host to bind the API server to (default: 127.0.0.1, loopback only). "
            "Use 0.0.0.0 to expose on all interfaces — only do this if you have "
            "set GORDIAN_API_KEY for authentication."
        ),
    )
    parser.add_argument(
        "--headless",
        action="store_true",
        help="Suppress boot animation (pure headless mode).",
    )

    # ── Storage ──
    parser.add_argument(
        "--storage",
        choices=("ram", "sqlite"),
        default="ram",
        help="Storage backend: 'ram' for speed, 'sqlite' for persistence (default: ram).",
    )
    parser.add_argument(
        "--db-path",
        default="gordian_scans.db",
        help="SQLite database file path when --storage sqlite (default: gordian_scans.db).",
    )

    # ── Concurrency ──
    parser.add_argument(
        "--max-concurrent-scans",
        type=int,
        default=1,
        help="Maximum number of scans that can run in parallel (default: 1).",
    )

    # ── Data Paths ──
    parser.add_argument(
        "--network",
        type=Path,
        default=root / "data" / "sample_network.json",
        help="Path to network topology JSON (default: bundled sample).",
    )
    parser.add_argument(
        "--cves",
        type=Path,
        default=root / "data" / "cve_feed.json",
        help="Path to enriched CVE feed JSON (default: bundled sample).",
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=root / "reports",
        help="Directory to write JSON + Markdown reports into.",
    )

    # ── CVE ──
    parser.add_argument("--list-cve-profiles", action="store_true")
    parser.add_argument("--cve-profile", choices=tuple(CVE_FEED_CATALOG.keys()), default="local")
    parser.add_argument("--cve-cache-dir", type=Path, default=root / "data" / "cve_cache")
    parser.add_argument("--cve-auto-download", action=argparse.BooleanOptionalAction, default=True)
    parser.add_argument("--cve-max-items", type=int, default=2000)
    parser.add_argument("--cve-sync-policy", choices=("always", "if-stale", "never"), default="if-stale")
    parser.add_argument("--cve-sync-schedule", choices=("off", "daily", "weekly"), default="off")
    parser.add_argument("--cve-stale-hours", type=float, default=24.0)
    parser.add_argument("--cve-osv-lookup-limit", type=int, default=80)
    parser.add_argument("--cve-source-priority", default=None)
    parser.add_argument("--cve-disable-sources", default=None)

    # ── Offensive ──
    parser.add_argument("--offensive-config", type=Path, default=root / "data" / "offensive_config.json")
    parser.add_argument("--offensive-mode", choices=("auto", "manual", "dry-run", "disabled"), default=None)
    parser.add_argument("--offensive-target", default=None)
    parser.add_argument("--offensive-speed", choices=("stealth", "balanced", "aggressive"), default=None)
    parser.add_argument("--offensive-intensity", choices=("low", "medium", "high"), default=None)
    parser.add_argument("--offensive-tools", default=None)
    parser.add_argument("--tool-bin", action="append", default=None)
    parser.add_argument("--tool-extra-args", action="append", default=None)
    parser.add_argument("--tool-command", action="append", default=None)
    parser.add_argument("--request-header", action="append", default=None)
    parser.add_argument("--max-nmap-rate", type=int, default=None)
    parser.add_argument("--max-ffuf-threads", type=int, default=None)
    parser.add_argument("--max-nuclei-rate", type=int, default=None)
    parser.add_argument("--max-total-targets", type=int, default=None)
    parser.add_argument("--max-total-commands", type=int, default=None)
    parser.add_argument("--max-findings", type=int, default=None)
    parser.add_argument("--max-run-seconds", type=int, default=None)
    parser.add_argument("--max-followup-targets", type=int, default=None)
    parser.add_argument("--allowed-time-window", action="append", default=None)
    parser.add_argument("--list-wordlists", action="store_true")
    parser.add_argument("--wordlist-profile", default=None)
    parser.add_argument("--ffuf-wordlist", default=None)
    parser.add_argument("--wordlist-store-dir", default=None)
    parser.add_argument("--wordlist-auto-download", action=argparse.BooleanOptionalAction, default=None)
    parser.add_argument("--target-tech", default=None)
    parser.add_argument("--bugbounty-mode", action=argparse.BooleanOptionalAction, default=None)
    parser.add_argument("--scope-file", default=None)
    parser.add_argument("--require-scope-match", action=argparse.BooleanOptionalAction, default=None)
    parser.add_argument("--asset-aware-cves", action=argparse.BooleanOptionalAction, default=False)
    parser.add_argument("--asset-cve-min-score", type=int, default=2)
    parser.add_argument("--asset-cve-keep-top", type=int, default=120)
    parser.add_argument("--offensive-dry-run", action="store_true")
    parser.add_argument("--offensive-disable", action="store_true")
    parser.add_argument("--offensive-no-dir-inject", action="store_true")
    parser.add_argument("--auto-arm-tools", action=argparse.BooleanOptionalAction, default=True)
    parser.add_argument("--full-control", action=argparse.BooleanOptionalAction, default=None)
    parser.add_argument("--no-remediation", action="store_true")
    parser.add_argument("--top-patches", type=int, default=5)
    parser.add_argument("--fail-on-findings", action="store_true")
    parser.add_argument("--quiet", action="store_true")
    parser.add_argument("--live-log", action="store_true")

    # ── UI ──
    parser.add_argument("--no-intro", action="store_true", help="Disable boot animation.")
    parser.add_argument("--intro-speed", type=float, default=0.065)
    parser.add_argument("-v", "--verbose", action="store_true")

    return parser.parse_args(argv)


# ── Utility Functions (kept from original) ───────────────────────────

def _parse_tool_override(raw: str | None) -> tuple[str, ...] | None:
    if raw is None:
        return None
    tokens = [token.strip().lower() for token in raw.split(",") if token.strip()]
    return tuple(tokens)


def _parse_csv_list(raw: str | None) -> tuple[str, ...] | None:
    if raw is None:
        return None
    tokens = [token.strip().lower() for token in raw.split(",") if token.strip()]
    return tuple(tokens)


def _parse_time_windows(raw_values: list[str] | None) -> tuple[str, ...] | None:
    if not raw_values:
        return None
    windows = [value.strip() for value in raw_values if value.strip()]
    return tuple(dict.fromkeys(windows)) or None


def _parse_tool_binary_overrides(raw_values: list[str] | None) -> dict[str, str] | None:
    if not raw_values:
        return None
    overrides: dict[str, str] = {}
    for raw in raw_values:
        if "=" not in raw:
            raise OffensiveConfigError(f"invalid --tool-bin value: {raw}")
        tool, command = raw.split("=", 1)
        tool_name = tool.strip().lower()
        binary = command.strip()
        if not tool_name or not binary:
            raise OffensiveConfigError(f"invalid --tool-bin value: {raw}")
        overrides[tool_name] = binary
    return overrides or None


def _parse_tool_argv_overrides(
    raw_values: list[str] | None,
    *,
    option: str,
) -> dict[str, tuple[str, ...]] | None:
    if not raw_values:
        return None
    overrides: dict[str, tuple[str, ...]] = {}
    for raw in raw_values:
        if "=" not in raw:
            raise OffensiveConfigError(f"invalid {option} value: {raw}")
        tool, arg_text = raw.split("=", 1)
        tool_name = tool.strip().lower()
        if not tool_name:
            raise OffensiveConfigError(f"invalid {option} value: {raw}")
        try:
            argv = tuple(token for token in shlex.split(arg_text.strip()) if token)
        except ValueError as exc:
            raise OffensiveConfigError(f"invalid {option} value: {raw} ({exc})") from exc
        if option == "--tool-command" and not argv:
            raise OffensiveConfigError(f"{option} requires at least one command token for tool '{tool_name}'")
        overrides[tool_name] = argv
    return overrides or None


def _enforce_full_control(args: argparse.Namespace, offensive_config):
    if not offensive_config.full_control:
        return offensive_config
    if args.offensive_disable:
        raise OffensiveConfigError("--full-control cannot be combined with --offensive-disable")
    mode = offensive_config.mode.value
    if mode in {"dry-run", "disabled"}:
        raise OffensiveConfigError("--full-control requires live offensive mode (auto/manual), not dry-run/disabled")
    if not offensive_config.target:
        raise OffensiveConfigError("--full-control requires --offensive-target")
    if mode == "auto":
        offensive_config = merge_cli_overrides(offensive_config, mode="manual")
    return offensive_config


async def _prepare_offensive_toolchain(args: argparse.Namespace, offensive_config):
    if not offensive_config.enabled:
        return offensive_config
    if offensive_config.mode.value != "manual":
        return offensive_config
    _ensure_go_bin_on_path()
    missing = await asyncio.to_thread(_detect_missing_core_tools, offensive_config)
    if not missing:
        return offensive_config

    logging.warning("manual offensive preflight missing tools: %s", ", ".join(missing))
    if args.auto_arm_tools:
        await asyncio.to_thread(_auto_arm_tools, missing)
        _ensure_go_bin_on_path()
        missing = await asyncio.to_thread(_detect_missing_core_tools, offensive_config)
    if not missing:
        return offensive_config
    if _running_in_windows_host():
        logging.warning(
            "Windows host detected; install tools via Scoop/Choco or run in WSL. Missing: %s",
            ", ".join(missing),
        )
    if offensive_config.full_control:
        raise OffensiveConfigError(
            "full-control manual mode requires installed tools, "
            f"missing: {', '.join(missing)}. {_build_missing_tools_guidance(missing)}"
        )
    logging.warning(
        "downgrading offensive mode to dry-run because required tools are missing: %s",
        ", ".join(missing),
    )
    return merge_cli_overrides(offensive_config, mode="dry-run")


def _detect_missing_core_tools(offensive_config) -> list[str]:
    required = [tool for tool in ("nmap", "ffuf", "nuclei") if tool in offensive_config.enabled_tools()]
    if not required:
        return []
    probe_target = offensive_config.target
    if not probe_target:
        probe_target = "https://example.com" if any(tool in {"ffuf", "nuclei"} for tool in required) else "example.com"
    try:
        probe_config = merge_cli_overrides(offensive_config, target=probe_target, tools=tuple(required))
        probe_factory = CommandFactory(probe_config)
        commands = probe_factory.build()
        if commands:
            missing = probe_factory.missing_tools(commands)
            if missing:
                return missing
    except (CommandFactoryError, OffensiveConfigError, ValueError):
        pass
    missing: list[str] = []
    for tool in required:
        binary_spec = offensive_config.binary_for(tool)
        if not _binary_exists(binary_spec):
            missing.append(tool)
    return sorted(set(missing))


def _build_missing_tools_guidance(missing_tools: list[str]) -> str:
    suggestions: list[str] = []
    missing = {tool.lower() for tool in missing_tools}
    if "nmap" in missing:
        suggestions.append("install: sudo apt-get install -y nmap")
    if "ffuf" in missing:
        suggestions.append("install: sudo apt-get install -y ffuf")
    if "nuclei" in missing:
        suggestions.append(
            "install: go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
        )
    suggestions.append("or disable --full-control to allow dry-run fallback")
    return " | ".join(suggestions)


def _binary_exists(binary_spec: str) -> bool:
    rendered = str(binary_spec).strip()
    if not rendered:
        return False
    try:
        first_token = shlex.split(rendered)[0]
    except ValueError:
        first_token = rendered.split()[0]
    path_candidate = Path(first_token)
    if path_candidate.exists():
        return True
    go_bin_candidate = _go_bin_candidate(first_token)
    if go_bin_candidate is not None and go_bin_candidate.exists():
        return True
    return shutil.which(first_token) is not None


def _go_bin_candidate(binary_name: str) -> Path | None:
    token = str(binary_name or "").strip()
    if not token:
        return None
    if "/" in token or "\\" in token:
        return None
    gobin_env = str(os.environ.get("GOBIN", "")).strip()
    base_dir = Path(gobin_env) if gobin_env else (Path.home() / "go" / "bin")
    candidate = base_dir / token
    if os.name == "nt" and not candidate.suffix:
        candidate_exe = candidate.with_suffix(".exe")
        if candidate_exe.exists():
            return candidate_exe
    return candidate


def _ensure_go_bin_on_path() -> None:
    candidate = _go_bin_candidate("nuclei")
    if candidate is None:
        return
    go_bin = str(candidate.parent)
    current_path = str(os.environ.get("PATH", ""))
    path_parts = [part for part in current_path.split(os.pathsep) if part]
    if go_bin in path_parts:
        return
    os.environ["PATH"] = f"{go_bin}{os.pathsep}{current_path}" if current_path else go_bin


def _auto_arm_tools(missing_tools: list[str]) -> None:
    if not missing_tools:
        return
    if not _running_in_linux_or_wsl():
        return
    missing = {tool.lower() for tool in missing_tools}
    has_go = shutil.which("go") is not None
    apt_installs = [tool for tool in ("nmap", "ffuf") if tool in missing]
    if "nuclei" in missing and not has_go:
        apt_installs.append("nuclei")
    if apt_installs and shutil.which("apt-get"):
        subprocess.run(["sudo", "-n", "apt-get", "update"],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False, timeout=60)
        for tool in apt_installs:
            subprocess.run(["sudo", "-n", "apt-get", "install", "-y", tool],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False, timeout=120)
    if "nuclei" in missing and has_go:
        subprocess.run(["go", "install", "-v",
                        "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"],
                       check=False, timeout=240)
        _ensure_go_bin_on_path()


def _running_in_linux_or_wsl() -> bool:
    if os.name != "nt":
        return True
    return bool(os.environ.get("WSL_DISTRO_NAME") or os.environ.get("WSL_INTEROP"))


def _running_in_windows_host() -> bool:
    return os.name == "nt" and not _running_in_linux_or_wsl()


def _force_utf8_stdout() -> None:
    """Windows consoles default to cp1252/cp1254. Force UTF-8."""
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            reconfigure(encoding="utf-8", errors="replace")


# ── Compatibility Helpers For Legacy Tests ─────────────────────────

WORLD_MAP_TEMPLATE = (
    ".|--------------------------------------------------|'.",
    " |....######...........#####.........#######........| ",
    " |..##########......#########......###########......| ",
    " |....######..........#####...........#####.........| ",
    " |......###.............###.............###.........| ",
    " |....#####..........######.........########........| ",
    " '|--------------------------------------------------|' ",
)

_GEO_LOOKUP_CACHE: dict[str, dict[str, Any]] = {}
_DNS_LOOKUP_CACHE: dict[str, str] = {}
_TARGET_GEO_CACHE: dict[str, dict[str, Any]] = {}
_NMAP_REPORT_IP_CACHE: dict[tuple[str, str, bool, int], str] = {}
_NMAP_GEO_CONTEXT_CACHE: dict[tuple[str, str, bool, int], dict[str, Any]] = {}


def _is_vscode_terminal() -> bool:
    term_program = str(os.environ.get("TERM_PROGRAM", "")).lower()
    if "vscode" in term_program:
        return True
    return "vscode" in str(os.environ.get("TERM", "")).lower()


def _is_wsl_runtime() -> bool:
    return bool(os.environ.get("WSL_DISTRO_NAME") or os.environ.get("WSL_INTEROP"))


def _should_render_intro(args: argparse.Namespace) -> bool:
    if getattr(args, "headless", False) or getattr(args, "no_intro", False):
        return False
    if getattr(args, "quiet", False):
        return False
    if getattr(args, "list_cve_profiles", False) or getattr(args, "list_wordlists", False):
        return False
    return bool(getattr(sys.stdout, "isatty", lambda: False)())


def _style_text_ansi(text: str, *, code: str) -> str:
    return f"\x1b[{code}m{text}\x1b[0m"


def _format_intro_progress_line(index: int, total: int, message: str) -> tuple[int, str]:
    pct = int(index * 100 / max(1, total))
    cleaned = re.sub(r"^\s*\[\d{1,3}%\]\s*", "", str(message or "").strip())
    return pct, f"[{pct:03}%] {cleaned}"


def _print_status(level: str, message: str) -> None:
    print(f"[{level}] {message}")


def _short_geo_location(text: str | None) -> str:
    value = str(text or "").strip()
    if not value or value.lower() == "n/a":
        return "n/a"
    if "(" in value:
        value = value.split("(", 1)[0].strip()
    return value


def _build_intro_panel_title(*, geo_location: str | None, nmap_geo_location: str | None) -> str:
    preferred = _short_geo_location(geo_location)
    if preferred == "n/a":
        preferred = _short_geo_location(nmap_geo_location)
    if preferred == "n/a":
        preferred = "Global"
    return f"Gordian :: {preferred}"


def _normalize_target_for_match(target: str | None) -> str:
    raw = str(target or "").strip()
    if not raw:
        return ""
    host = _extract_target_host(raw)
    if host:
        return host.strip().lower()
    return raw.strip().lower()


def _extract_target_host(target: str | None) -> str | None:
    raw = str(target or "").strip()
    if not raw:
        return None

    candidate = raw
    if "://" in raw:
        try:
            parsed = urlsplit(raw)
            try:
                hostname = parsed.hostname
            except ValueError:
                hostname = None
            if hostname:
                return hostname
            candidate = parsed.netloc or parsed.path
        except ValueError:
            candidate = raw.split("://", 1)[-1]

    candidate = candidate.split("/", 1)[0]
    if "@" in candidate:
        candidate = candidate.rsplit("@", 1)[-1]

    if candidate.startswith("["):
        candidate = candidate[1:]
    if "]" in candidate:
        candidate = candidate.split("]", 1)[0]
    elif candidate.count(":") == 1:
        candidate = candidate.split(":", 1)[0]

    candidate = candidate.strip()
    return candidate or None


def _resolve_host_to_ip(host: str | None) -> str:
    token = str(host or "").strip()
    if not token:
        return "n/a"
    if token in _DNS_LOOKUP_CACHE:
        return _DNS_LOOKUP_CACHE[token]

    try:
        ipaddress.ip_address(token)
        _DNS_LOOKUP_CACHE[token] = token
        return token
    except ValueError:
        pass

    try:
        resolved = socket.gethostbyname(token)
    except OSError:
        resolved = "n/a"

    _DNS_LOOKUP_CACHE[token] = resolved
    return resolved


def _lookup_ip_geolocation(ip: str | None) -> dict[str, Any]:
    token = str(ip or "").strip()
    if not token or token == "n/a":
        return {}
    if token in _GEO_LOOKUP_CACHE:
        return _GEO_LOOKUP_CACHE[token]

    try:
        with urlopen(f"https://ipwho.is/{token}", timeout=2.0) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except Exception:
        payload = {}

    if not isinstance(payload, dict) or payload.get("success") is False:
        payload = {}

    _GEO_LOOKUP_CACHE[token] = payload
    return payload


def _project_geo_to_map(*, lat: float, lon: float) -> tuple[int, int]:
    rows = len(WORLD_MAP_TEMPLATE)
    cols = len(WORLD_MAP_TEMPLATE[0]) if rows else 1
    r = round((90.0 - float(lat)) / 180.0 * (rows - 1))
    c = round((float(lon) + 180.0) / 360.0 * (cols - 1))
    r = max(0, min(rows - 1, r))
    c = max(0, min(cols - 1, c))
    return r, c


def _continent_to_region(continent_code: str | None) -> str:
    table = {
        "AF": "AFRICA",
        "AN": "ANTARCTICA",
        "AS": "ASIA",
        "EU": "EUROPE",
        "NA": "NORTH-AMERICA",
        "OC": "OCEANIA",
        "SA": "SOUTH-AMERICA",
    }
    return table.get(str(continent_code or "").upper(), "UNKNOWN")


def _is_private_ip(ip: str | None) -> bool:
    try:
        return ipaddress.ip_address(str(ip or "").strip()).is_private
    except ValueError:
        return False


def _format_geo_location(geo: dict[str, Any]) -> str:
    city = str(geo.get("city") or "n/a").strip()
    country = str(geo.get("country_code") or geo.get("country") or "n/a").strip()
    lat = geo.get("latitude")
    lon = geo.get("longitude")
    if isinstance(lat, (int, float)) and isinstance(lon, (int, float)):
        return f"{city}, {country} ({lat:.2f}, {lon:.2f})"
    return f"{city}, {country}"


def _resolve_target_geo_context(target: str | None) -> dict[str, Any]:
    key = _normalize_target_for_match(target)
    if key in _TARGET_GEO_CACHE:
        return dict(_TARGET_GEO_CACHE[key])

    host = _extract_target_host(target) or key
    resolved_ip = _resolve_host_to_ip(host)

    if _is_private_ip(resolved_ip):
        marker_row, marker_col = _project_geo_to_map(lat=0.0, lon=0.0)
        context = {
            "region_label": "INTERNAL-LAB",
            "resolved_ip": resolved_ip,
            "geo_location": "internal/private address",
            "marker_row": marker_row,
            "marker_col": marker_col,
        }
        _TARGET_GEO_CACHE[key] = context
        return dict(context)

    geo = _lookup_ip_geolocation(resolved_ip)
    if geo:
        lat = float(geo.get("latitude") or 0.0)
        lon = float(geo.get("longitude") or 0.0)
        marker_row, marker_col = _project_geo_to_map(lat=lat, lon=lon)
        context = {
            "region_label": _continent_to_region(geo.get("continent_code")),
            "resolved_ip": resolved_ip,
            "geo_location": _format_geo_location(geo),
            "marker_row": marker_row,
            "marker_col": marker_col,
        }
    else:
        marker_row, marker_col = _project_geo_to_map(lat=0.0, lon=0.0)
        context = {
            "region_label": "UNKNOWN",
            "resolved_ip": resolved_ip,
            "geo_location": "n/a",
            "marker_row": marker_row,
            "marker_col": marker_col,
        }

    _TARGET_GEO_CACHE[key] = context
    return dict(context)


def _report_cache_key(target: str | None, report_path: Path) -> tuple[str, str, bool, int]:
    exists = report_path.exists()
    mtime = report_path.stat().st_mtime_ns if exists else 0
    return (_normalize_target_for_match(target), str(report_path), exists, mtime)


def _extract_nmap_resolved_ip_from_report(*, target: str | None, report_path: Path) -> str:
    key = _report_cache_key(target, report_path)
    cached = _NMAP_REPORT_IP_CACHE.get(key)
    if cached is not None:
        return cached

    if not report_path.exists():
        _NMAP_REPORT_IP_CACHE[key] = "n/a"
        return "n/a"

    try:
        payload = json.loads(report_path.read_text(encoding="utf-8"))
    except Exception:
        _NMAP_REPORT_IP_CACHE[key] = "n/a"
        return "n/a"

    offensive = payload.get("offensive_integration") if isinstance(payload, dict) else None
    if not isinstance(offensive, dict):
        _NMAP_REPORT_IP_CACHE[key] = "n/a"
        return "n/a"

    report_target = _normalize_target_for_match(offensive.get("target"))
    requested_target = _normalize_target_for_match(target)
    if report_target and requested_target and report_target != requested_target:
        _NMAP_REPORT_IP_CACHE[key] = "n/a"
        return "n/a"

    findings = offensive.get("findings")
    if not isinstance(findings, list):
        _NMAP_REPORT_IP_CACHE[key] = "n/a"
        return "n/a"

    for finding in findings:
        if not isinstance(finding, dict):
            continue
        if str(finding.get("tool", "")).lower() != "nmap":
            continue
        metadata = finding.get("metadata")
        if not isinstance(metadata, dict):
            continue
        ip = str(metadata.get("ip_address") or "").strip()
        if ip:
            _NMAP_REPORT_IP_CACHE[key] = ip
            return ip

    _NMAP_REPORT_IP_CACHE[key] = "n/a"
    return "n/a"


def _resolve_nmap_report_geo_context(*, target: str | None, report_path: Path) -> dict[str, Any]:
    key = _report_cache_key(target, report_path)
    cached = _NMAP_GEO_CONTEXT_CACHE.get(key)
    if cached is not None:
        return dict(cached)

    resolved_ip = _extract_nmap_resolved_ip_from_report(target=target, report_path=report_path)
    if resolved_ip == "n/a":
        context = {
            "resolved_ip": "n/a",
            "geo_location": "n/a",
            "marker_row": None,
            "marker_col": None,
        }
        _NMAP_GEO_CONTEXT_CACHE[key] = context
        return dict(context)

    if _is_private_ip(resolved_ip):
        marker_row, marker_col = _project_geo_to_map(lat=0.0, lon=0.0)
        context = {
            "resolved_ip": resolved_ip,
            "geo_location": "internal/private address",
            "marker_row": marker_row,
            "marker_col": marker_col,
        }
        _NMAP_GEO_CONTEXT_CACHE[key] = context
        return dict(context)

    geo = _lookup_ip_geolocation(resolved_ip)
    if geo:
        lat = float(geo.get("latitude") or 0.0)
        lon = float(geo.get("longitude") or 0.0)
        marker_row, marker_col = _project_geo_to_map(lat=lat, lon=lon)
        context = {
            "resolved_ip": resolved_ip,
            "geo_location": _format_geo_location(geo),
            "marker_row": marker_row,
            "marker_col": marker_col,
        }
    else:
        context = {
            "resolved_ip": resolved_ip,
            "geo_location": "n/a",
            "marker_row": None,
            "marker_col": None,
        }

    _NMAP_GEO_CONTEXT_CACHE[key] = context
    return dict(context)


def _render_target_world_map(
    target: str | None,
    *,
    report_path: Path,
    pulse_on: bool,
) -> tuple[list[str], dict[str, Any]]:
    grid = [list(row) for row in WORLD_MAP_TEMPLATE]

    context = _resolve_target_geo_context(target)
    row = int(context.get("marker_row") or 0)
    col = int(context.get("marker_col") or 0)
    if 0 <= row < len(grid) and 0 <= col < len(grid[row]):
        grid[row][col] = "*" if pulse_on else "o"

    nmap_context = _resolve_nmap_report_geo_context(target=target, report_path=report_path)
    nmap_row = nmap_context.get("marker_row")
    nmap_col = nmap_context.get("marker_col")
    if nmap_context.get("resolved_ip") != "n/a" and isinstance(nmap_row, int) and isinstance(nmap_col, int):
        if 0 <= nmap_row < len(grid) and 0 <= nmap_col < len(grid[nmap_row]):
            if nmap_row == row and nmap_col == col:
                grid[nmap_row][nmap_col] = "@" if pulse_on else "0"
            else:
                grid[nmap_row][nmap_col] = "x" if pulse_on else "+"

    merged = dict(context)
    merged["nmap_resolved_ip"] = nmap_context.get("resolved_ip", "n/a")
    merged["nmap_geo_location"] = nmap_context.get("geo_location", "n/a")

    return ["".join(line) for line in grid], merged


def _resolve_intro_geo_context(args: argparse.Namespace) -> dict[str, Any]:
    target = getattr(args, "offensive_target", None)
    if not target:
        return {
            "region_label": "UNKNOWN",
            "resolved_ip": "n/a",
            "geo_location": "n/a",
            "nmap_resolved_ip": "n/a",
            "nmap_geo_location": "n/a",
        }

    context = _resolve_target_geo_context(target)
    report_path = Path("reports") / "attack_paths.json"
    nmap_context = _resolve_nmap_report_geo_context(target=target, report_path=report_path)
    merged = dict(context)
    merged["nmap_resolved_ip"] = nmap_context.get("resolved_ip", "n/a")
    merged["nmap_geo_location"] = nmap_context.get("geo_location", "n/a")
    return merged


def _render_terminal_intro_vscode_safe(
    *,
    args: argparse.Namespace,
    boot_lines: tuple[str, ...],
    speed: float,
) -> None:
    for line in README_ASCII_ART.splitlines():
        print(_style_text_ansi(line, code="96"), flush=True)
        time.sleep(max(speed * 0.45, 0.005))

    print("", flush=True)
    geo_context = _resolve_intro_geo_context(args)
    panel_title = _build_intro_panel_title(
        geo_location=geo_context.get("geo_location"),
        nmap_geo_location=geo_context.get("nmap_geo_location"),
    )
    print(_style_text_ansi(panel_title, code="95"), flush=True)
    print(
        _style_text_ansi(
            f"target_ip={geo_context.get('resolved_ip', 'n/a')}  nmap_ip={geo_context.get('nmap_resolved_ip', 'n/a')}",
            code="90",
        ),
        flush=True,
    )

    total = max(1, len(boot_lines))
    for idx, message in enumerate(boot_lines, start=1):
        _pct, line = _format_intro_progress_line(index=idx, total=total, message=message)
        print(_style_text_ansi(line, code="92"), flush=True)
        time.sleep(max(speed * 0.8, 0.01))
    print("", flush=True)


def _tool_args_as_text(args: tuple[str, ...] | list[str] | str | None) -> str:
    if args is None:
        return ""
    if isinstance(args, str):
        return args
    return " ".join(str(part) for part in args)


def _should_use_ansi_dashboard(args: argparse.Namespace) -> bool:
    if bool(getattr(args, "_force_ansi_dashboard", False)):
        return True
    if bool(getattr(args, "_disable_ansi_dashboard", False)):
        return False
    if bool(getattr(args, "terminal_app", False)):
        return False
    if bool(getattr(args, "list_cve_profiles", False) or getattr(args, "list_wordlists", False)):
        return False
    if not (getattr(sys.stdout, "isatty", lambda: False)() and getattr(sys.stdin, "isatty", lambda: False)()):
        return False
    if _is_vscode_terminal():
        return False
    return True


def _normalize_menu_selection(raw: str | None) -> str | None:
    value = str(raw or "").strip()
    if not value:
        return None
    if "\x1b[" in value or "^[[" in value:
        return None
    return value


class TerminalInputClosedError(RuntimeError):
    """Raised when interactive terminal input is interrupted."""


def _initialize_terminal_customization_state(_args: argparse.Namespace) -> None:
    return None


def _render_terminal_menu(_args: argparse.Namespace) -> None:
    _print_status("menu", "terminal app menu")


def _prompt_text(prompt: str, *, default: str) -> str:
    try:
        value = input(prompt)
    except (EOFError, KeyboardInterrupt) as exc:
        raise TerminalInputClosedError("input interrupted") from exc
    value = value.strip()
    return value or default


async def _run_terminal_app(args: argparse.Namespace) -> int:
    args._disable_ansi_dashboard = False
    args._force_ansi_dashboard = True

    _initialize_terminal_customization_state(args)
    _render_terminal_menu(args)
    _print_status("info", "terminal app ready")

    try:
        _prompt_text("Select action: ", default="q")
    except TerminalInputClosedError:
        return EXIT_OK
    return EXIT_OK


class AnsiTacticalDashboard:
    def __init__(self, _args: argparse.Namespace) -> None:
        self.width = 110
        self.body_height = 10
        self.command_zone_height = 4
        self._started = False
        self._last_map_context: dict[str, Any] = {}

        self.feed_lines: list[str] = []
        self.paused_feed_lines: list[str] = []
        self.intercept_active = False
        self.intercept_tool = ""
        self.intercept_command = ""

        self._recompute_layout()

    def _strip_ansi(self, text: str) -> str:
        return re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", str(text or ""))

    def _sanitize_text(self, text: str) -> str:
        clean = self._strip_ansi(text)
        clean = clean.replace("\r", " ").replace("\n", " ").replace("\t", " ")
        return re.sub(r"\s+", " ", clean).strip()

    def _format_event_line(self, event: dict[str, Any]) -> str:
        timestamp = str(event.get("timestamp") or "")
        if len(timestamp) >= 19 and "T" in timestamp:
            timestamp = timestamp[11:19]
        elif len(timestamp) > 8:
            timestamp = timestamp[-8:]
        timestamp = timestamp or "--:--:--"

        tool = self._sanitize_text(str(event.get("tool") or "hub"))[:10]
        event_type = self._sanitize_text(str(event.get("type") or "event"))[:28]
        message = self._sanitize_text(str(event.get("message") or ""))
        return f"[{timestamp}] {tool:<10} {event_type:<28} {message}".rstrip()

    def consume_event(self, event: dict[str, Any]) -> None:
        event_type = str(event.get("type") or "")
        payload = event.get("payload") if isinstance(event.get("payload"), dict) else {}

        if event_type == "offensive.command_intercept":
            command = payload.get("command", [])
            if isinstance(command, (list, tuple)):
                self.intercept_command = " ".join(str(part) for part in command)
            else:
                self.intercept_command = self._sanitize_text(str(command))
            self.intercept_tool = self._sanitize_text(str(event.get("tool") or "hub"))
            self.intercept_active = True
            return

        if event_type == "offensive.command_intercept_done":
            decision = self._sanitize_text(str(payload.get("decision") or "unknown"))
            self.intercept_active = False
            self.feed_lines.append(f"[intercept] tool={self.intercept_tool or 'hub'} decision={decision}")
            if self.paused_feed_lines:
                self.feed_lines.extend(self.paused_feed_lines)
                self.paused_feed_lines.clear()
            self.feed_lines = self.feed_lines[-300:]
            return

        formatted = self._format_event_line(event)
        if self.intercept_active:
            self.paused_feed_lines.append(formatted)
        else:
            self.feed_lines.append(formatted)
            self.feed_lines = self.feed_lines[-300:]

    def _recompute_layout(self) -> None:
        self.inner_width = max(20, self.width - 2)
        self.left_width = max(8, self.inner_width // 2 - 1)
        self.right_width = max(8, self.inner_width - self.left_width - 1)

    def _compose_left_panel_lines(self) -> list[str]:
        lines = self.feed_lines[-self.body_height:]
        padded = [line[: self.left_width].ljust(self.left_width) for line in lines]
        while len(padded) < self.body_height:
            padded.append(" " * self.left_width)
        return padded

    def _compose_right_panel_lines(self) -> list[str]:
        location = _short_geo_location(
            self._last_map_context.get("nmap_geo_location") or self._last_map_context.get("geo_location")
        )
        seed = [
            f"Location: {location}",
            f"Intercept: {'ON' if self.intercept_active else 'OFF'}",
            f"Tool: {self.intercept_tool or '-'}",
        ]
        seed.extend([""] * self.body_height)
        return [line[: self.right_width].ljust(self.right_width) for line in seed[: self.body_height]]

    def _compose_command_zone_lines(self) -> list[str]:
        lines = [
            f"Command: {self.intercept_command or '-'}",
            "Actions: [ENTER] accept  [E] edit  [S] skip",
        ]
        lines.extend([""] * self.command_zone_height)
        return [line[: self.inner_width].ljust(self.inner_width) for line in lines[: self.command_zone_height]]

    def _compose_frame(self) -> list[str]:
        self._recompute_layout()
        top = "╔" + ("═" * self.inner_width) + "╗"

        location = _short_geo_location(
            self._last_map_context.get("nmap_geo_location") or self._last_map_context.get("geo_location")
        )
        clock = time.strftime("%H:%M:%S", time.localtime())
        title = f" GORDIAN TACTICAL DASHBOARD :: {location} :: {clock} "
        title_line = "║" + title[: self.inner_width].ljust(self.inner_width) + "║"

        sep = "╠" + ("═" * self.left_width) + "╤" + ("═" * self.right_width) + "╣"
        frame = [top, title_line, sep]

        left_lines = self._compose_left_panel_lines()
        right_lines = self._compose_right_panel_lines()
        for idx in range(self.body_height):
            left = left_lines[idx][: self.left_width].ljust(self.left_width)
            right = right_lines[idx][: self.right_width].ljust(self.right_width)
            frame.append(f"║{left}│{right}║")

        cmd_sep = "╠" + ("═" * self.inner_width) + "╣"
        frame.append(cmd_sep)
        for line in self._compose_command_zone_lines():
            frame.append("║" + line[: self.inner_width].ljust(self.inner_width) + "║")

        bottom = "╚" + ("═" * self.inner_width) + "╝"
        frame.append(bottom)
        return frame

    def render(self) -> None:
        print("\n".join(self._compose_frame()))


async def _ansi_dashboard_heartbeat(dashboard: Any) -> None:
    while bool(getattr(dashboard, "_started", False)):
        dashboard.render()
        await asyncio.sleep(0.05)


def _is_root_user() -> bool:
    geteuid = getattr(os, "geteuid", None)
    if geteuid is None:
        return False
    try:
        return geteuid() == 0
    except Exception:
        return False


def _can_passwordless_sudo() -> bool:
    if shutil.which("sudo") is None:
        return False
    try:
        result = subprocess.run(
            ["sudo", "-n", "true"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=2,
        )
        return result.returncode == 0
    except Exception:
        return False


def _resolve_apt_command_prefix() -> tuple[list[str] | None, bool]:
    if _is_root_user():
        return [], False

    if shutil.which("sudo") is None:
        return None, False

    if _can_passwordless_sudo():
        return ["sudo", "-n"], False

    interactive = bool(getattr(sys.stdin, "isatty", lambda: False)() and getattr(sys.stdout, "isatty", lambda: False)())
    if interactive:
        return ["sudo"], True
    return None, False


_CVE_PROFILE_ORDER = (
    "nvd_recent",
    "cisa_kev",
    "all_latest",
    "ghsa_recent",
    "all_plus",
    "local",
)


def _ordered_cve_profile_keys() -> tuple[str, ...]:
    existing = [key for key in _CVE_PROFILE_ORDER if key in CVE_FEED_CATALOG]
    return tuple(existing)


def _resolve_cve_profile_choice(raw_value: str | None, *, current: str) -> str | None:
    value = str(raw_value or "").strip().lower()
    if not value:
        return current

    ordered = _ordered_cve_profile_keys()
    if value.isdigit():
        idx = int(value)
        if 1 <= idx <= len(ordered):
            return ordered[idx - 1]
        return None

    if value in CVE_FEED_CATALOG:
        return value
    return None


def _cycle_cve_sync_policy(policy: str | None) -> str:
    order = ("if-stale", "always", "never")
    token = str(policy or "if-stale").strip().lower()
    if token not in order:
        token = "if-stale"
    return order[(order.index(token) + 1) % len(order)]


def _parse_csv_tokens(raw: str | None) -> tuple[str, ...]:
    if raw is None:
        return ()
    return tuple(dict.fromkeys(part.strip().lower() for part in str(raw).split(",") if part.strip()))


def _resolve_cve_profile_selection(
    raw_selection: str | None,
    *,
    current_profile: str,
    current_priority: str | None,
    current_disabled: str | None,
) -> tuple[str, str | None, str | None] | None:
    tokens = _parse_csv_tokens(raw_selection)
    if not tokens:
        return None

    if len(tokens) == 1:
        choice = _resolve_cve_profile_choice(tokens[0], current=current_profile)
        if choice is None:
            return None
        return choice, current_priority, current_disabled

    if "local" in tokens:
        return None

    profile = "all_plus"
    priority = ",".join(tokens)
    known_merge_sources = ("cisa_kev", "nvd_recent", "ghsa_recent")
    disabled_list = [source for source in known_merge_sources if source not in tokens]
    disabled = ",".join(disabled_list) if disabled_list else None
    return profile, priority, disabled


def _active_cve_sources(args: argparse.Namespace) -> tuple[str, ...]:
    profile = str(getattr(args, "cve_profile", "local") or "local").strip().lower()
    if profile == "all_plus":
        base = ("nvd_recent", "cisa_kev", "ghsa_recent", "osv_enriched")
    elif profile == "all_latest":
        base = ("nvd_recent", "cisa_kev")
    else:
        return (profile,)

    disabled = set(_parse_csv_tokens(getattr(args, "cve_disable_sources", None)))
    return tuple(source for source in base if source not in disabled)


def _should_autosync_selected_profile(args: argparse.Namespace, profile: str) -> bool:
    key = str(profile or "").strip().lower()
    if key == "local" or not key:
        return False

    cache_dir = Path(getattr(args, "cve_cache_dir", Path("data") / "cve_cache"))
    cache_file = cache_dir / f"{key}.json"
    auto_download = bool(getattr(args, "cve_auto_download", True))
    sync_policy = str(getattr(args, "cve_sync_policy", "if-stale") or "if-stale").strip().lower()

    if sync_policy == "never" and not auto_download:
        return not cache_file.exists()
    if not auto_download:
        return False
    return True


def _sync_selected_cve_profile_now(_args: argparse.Namespace) -> None:
    _print_status("sync", "triggering one-shot CVE profile sync")


def _apply_cve_profile_selection(args: argparse.Namespace, raw_selection: str | None) -> bool:
    selection = _normalize_menu_selection(raw_selection)
    if selection is None:
        return False

    resolved = _resolve_cve_profile_selection(
        selection,
        current_profile=getattr(args, "cve_profile", "local"),
        current_priority=getattr(args, "cve_source_priority", None),
        current_disabled=getattr(args, "cve_disable_sources", None),
    )
    if resolved is None:
        return False

    profile, priority, disabled = resolved
    args.cve_profile = profile
    args.cve_source_priority = priority
    args.cve_disable_sources = disabled

    if _should_autosync_selected_profile(args, profile):
        _sync_selected_cve_profile_now(args)
    return True


def _looks_like_cve_profile_input(raw_value: str | None) -> bool:
    value = str(raw_value or "").strip().lower()
    if not value:
        return False
    if "," in value:
        return True
    if value.isdigit():
        return int(value) >= 5
    return True


# ── Main Entry Point ─────────────────────────────────────────────────

def main(argv: list[str] | None = None) -> int:
    _force_utf8_stdout()
    raw_argv = sys.argv[1:] if argv is None else argv
    args = _parse_args(raw_argv)
    _configure_logging(args.verbose)

    # Handle info-only commands
    if args.list_cve_profiles:
        print("Available CVE profiles:")
        for line in describe_cve_profiles_for_cli():
            print(line)
        return EXIT_OK

    if args.list_wordlists:
        print("Available wordlist profiles:")
        for line in describe_profiles_for_cli():
            print(line)
        return EXIT_OK

    # Boot animation
    _render_terminal_intro(args)

    # Start FastAPI server
    try:
        import uvicorn
        from api.app import create_app

        app = create_app(args)

        print(f"\n\x1b[1;36m{'═' * 60}\x1b[0m")
        print(f"\x1b[1;36m  Gordian API Server\x1b[0m")
        print(f"\x1b[1;36m{'═' * 60}\x1b[0m")
        print(f"  REST API  : http://{args.api_host}:{args.api_port}/docs")
        print(f"  WebSocket : ws://{args.api_host}:{args.api_port}/api/v1/live")
        print(f"  Storage   : {args.storage}")
        print(f"  Max Scans : {args.max_concurrent_scans}")
        print(f"\x1b[1;36m{'═' * 60}\x1b[0m\n")

        uvicorn.run(
            app,
            host=args.api_host,
            port=args.api_port,
            log_level="info" if not args.verbose else "debug",
        )
    except KeyboardInterrupt:
        logging.info("Gordian API server stopped by user")
    except ImportError as exc:
        logging.error(
            "Missing dependency: %s. Run: pip install fastapi uvicorn[standard]", exc
        )
        return EXIT_ERROR
    except ValueError as exc:
        logging.error("Server configuration rejected: %s", exc)
        return EXIT_ERROR

    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
    
    
    
