"""Gordian entry point.

Two modes:

    python main.py [server options]          # authenticated FastAPI server (default)
    python main.py --once [analysis options] # one-shot analysis, then exit (CI gate)

Server mode needs GORDIAN_API_KEY; scans are started through the Go TUI or
the REST API. One-shot mode runs the core pipeline (topology + CVE feed ->
kill chains -> patch simulation -> reports) without the offensive hub.

Exit codes: 0 ok, 1 runtime/config error, 2 usage error (argparse),
3 kill chains found with --fail-on-findings.
"""

from __future__ import annotations

import argparse
import asyncio
import importlib
import json
import logging
import os
import sys
import time
from pathlib import Path
from typing import Any

from src.cve_sources import (
    CVE_FEED_CATALOG,
    CVEFeedSyncError,
    describe_cve_profiles_for_cli,
    sync_cve_feed_profile,
)
from src.offensive import describe_profiles_for_cli


EXIT_OK = 0
EXIT_ERROR = 1
EXIT_FINDINGS = 3

# One-shot flags default to None so "not given" is distinguishable from
# "given"; _parse_args applies these effective defaults under --once.
ONCE_DEFAULTS: dict[str, Any] = {
    "fail_on_findings": False,
    "quiet": False,
    "no_remediation": False,
    "top_patches": 5,
    "live_log": False,
    "cve_profile": "local",
    "cve_cache_dir": None,
    "cve_auto_download": True,
    "cve_max_items": 2000,
    "cve_sync_policy": "if-stale",
    "cve_sync_schedule": "off",
    "cve_stale_hours": 24.0,
    "cve_osv_lookup_limit": 80,
    "cve_source_priority": None,
    "cve_disable_sources": None,
    "asset_aware_cves": False,
    "asset_cve_min_score": 2,
    "asset_cve_keep_top": 120,
}

# Offensive tooling is server-owned and scope-checked by the API; the
# one-shot mode never runs it.
SERVER_ONLY_OFFENSIVE = (
    "offensive_mode", "offensive_target", "offensive_speed", "offensive_intensity",
    "scope_file", "max_nmap_rate", "max_ffuf_threads", "max_nuclei_rate",
    "max_total_targets", "max_total_commands", "max_findings", "max_run_seconds",
)


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
        _render_intro_plain(args, speed=speed)
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

def _build_parser() -> argparse.ArgumentParser:
    root = Path(__file__).parent
    parser = argparse.ArgumentParser(
        prog="gordian",
        description=(
            "Gordian — attack-path analysis engine. By default starts the "
            "authenticated FastAPI server; --once runs a single analysis and exits."
        ),
        epilog="Exit codes: 0 ok, 1 error, 2 usage error, 3 kill chains found (--fail-on-findings).",
    )

    shared = parser.add_argument_group("inputs and output (both modes)")
    shared.add_argument("--network", type=Path, default=root / "data" / "sample_network.json",
                        help="Network topology JSON (default: bundled sample).")
    shared.add_argument("--cves", type=Path, default=root / "data" / "cve_feed.json",
                        help="Enriched CVE feed JSON (default: bundled sample).")
    shared.add_argument("--out", type=Path, default=root / "reports",
                        help="Report directory. The server writes per-scan reports to <out>/<scan-id>/.")
    shared.add_argument("--list-cve-profiles", action="store_true",
                        help="List CVE feed profiles usable with --once --cve-profile and exit.")
    shared.add_argument("--list-wordlists", action="store_true",
                        help="List ffuf wordlist profiles accepted by the scan API and exit.")
    shared.add_argument("-v", "--verbose", action="store_true")

    server = parser.add_argument_group("API server (default mode)")
    server.add_argument("--api-port", type=int, default=8000,
                        help="Port to run the FastAPI server on (default: 8000).")
    server.add_argument("--api-host", default="127.0.0.1",
                        help="Bind address (default: 127.0.0.1). Keep loopback; "
                             "use a TLS reverse proxy for remote access.")
    server.add_argument("--headless", action="store_true", help="Suppress boot animation.")
    server.add_argument("--no-intro", action="store_true", help="Suppress boot animation (alias).")
    server.add_argument("--intro-speed", type=float, default=0.065)
    server.add_argument("--storage", choices=("ram", "sqlite"), default="ram",
                        help="Scan storage backend (default: ram).")
    server.add_argument("--db-path", default="gordian_scans.db",
                        help="SQLite file when --storage sqlite (default: gordian_scans.db).")
    server.add_argument("--max-concurrent-scans", type=int, default=1,
                        help="Maximum number of scans that can run in parallel (default: 1).")

    offensive = parser.add_argument_group(
        "offensive hub (server mode only; API clients cannot exceed these)")
    offensive.add_argument("--offensive-config", type=Path,
                           default=root / "data" / "offensive_config.json")
    offensive.add_argument("--offensive-mode", choices=("auto", "manual", "dry-run", "disabled"),
                           default=None)
    offensive.add_argument("--offensive-target", default=None)
    offensive.add_argument("--offensive-speed", choices=("stealth", "balanced", "aggressive"),
                           default=None)
    offensive.add_argument("--offensive-intensity", choices=("low", "medium", "high"), default=None)
    offensive.add_argument("--offensive-dry-run", action="store_true")
    offensive.add_argument("--offensive-disable", action="store_true")
    offensive.add_argument("--scope-file", default=None,
                           help="Scope policy JSON; required for live (non dry-run) scans.")
    offensive.add_argument("--max-nmap-rate", type=int, default=None)
    offensive.add_argument("--max-ffuf-threads", type=int, default=None)
    offensive.add_argument("--max-nuclei-rate", type=int, default=None)
    offensive.add_argument("--max-total-targets", type=int, default=None)
    offensive.add_argument("--max-total-commands", type=int, default=None)
    offensive.add_argument("--max-findings", type=int, default=None)
    offensive.add_argument("--max-run-seconds", type=int, default=None)

    once = parser.add_argument_group("one-shot analysis (--once)")
    once.add_argument("--once", action="store_true",
                      help="Run one analysis on --network/--cves, write reports and exit. "
                           "No API server, no offensive tools.")
    once.add_argument("--fail-on-findings", action="store_true", default=None,
                      help="Exit with code 3 if any kill chain is found.")
    once.add_argument("--quiet", action="store_true", default=None,
                      help="Write reports without the console summary.")
    once.add_argument("--no-remediation", action="store_true", default=None,
                      help="Skip patch-priority simulation.")
    once.add_argument("--top-patches", type=int, default=None,
                      help="Number of patch recommendations (default: 5).")
    once.add_argument("--live-log", action="store_true", default=None,
                      help="Write pipeline events to stderr as JSON lines.")
    once.add_argument("--cve-profile", choices=tuple(CVE_FEED_CATALOG.keys()), default=None,
                      help="Sync and use a remote CVE feed instead of --cves (default: local).")
    once.add_argument("--cve-cache-dir", type=Path, default=None,
                      help="Cache directory for synced feeds (default: data/cve_cache).")
    once.add_argument("--cve-auto-download", action=argparse.BooleanOptionalAction, default=None,
                      help="Allow network downloads; --no-cve-auto-download uses the cache only.")
    once.add_argument("--cve-max-items", type=int, default=None)
    once.add_argument("--cve-sync-policy", choices=("always", "if-stale", "never"), default=None)
    once.add_argument("--cve-sync-schedule", choices=("off", "daily", "weekly"), default=None)
    once.add_argument("--cve-stale-hours", type=float, default=None)
    once.add_argument("--cve-osv-lookup-limit", type=int, default=None)
    once.add_argument("--cve-source-priority", default=None,
                      help="Comma-separated merge priority for all_latest/all_plus.")
    once.add_argument("--cve-disable-sources", default=None,
                      help="Comma-separated sources to drop from merged profiles.")
    once.add_argument("--asset-aware-cves", action=argparse.BooleanOptionalAction, default=None,
                      help="Drop CVEs unrelated to the hosts/services in the topology.")
    once.add_argument("--asset-cve-min-score", type=int, default=None)
    once.add_argument("--asset-cve-keep-top", type=int, default=None)
    return parser


def _flag_names(names: list[str]) -> str:
    return ", ".join("--" + name.replace("_", "-") for name in names)


def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.once:
        clashing = [name for name in SERVER_ONLY_OFFENSIVE if getattr(args, name) is not None]
        clashing += [name for name in ("offensive_dry_run", "offensive_disable") if getattr(args, name)]
        if clashing:
            parser.error(f"{_flag_names(clashing)}: offensive options are server-managed "
                         "and cannot be used with --once")
        for name, default in ONCE_DEFAULTS.items():
            if getattr(args, name) is None:
                setattr(args, name, default)
        if args.cve_cache_dir is None:
            args.cve_cache_dir = Path(__file__).parent / "data" / "cve_cache"
    else:
        given = [name for name in ONCE_DEFAULTS if getattr(args, name) is not None]
        if given:
            parser.error(f"{_flag_names(given)}: requires --once")
    return args


def _force_utf8_stdout() -> None:
    """Windows consoles default to cp1252/cp1254. Force UTF-8."""
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            reconfigure(encoding="utf-8", errors="replace")


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
    if getattr(args, "once", False):
        return False
    if getattr(args, "list_cve_profiles", False) or getattr(args, "list_wordlists", False):
        return False
    return bool(getattr(sys.stdout, "isatty", lambda: False)())


def _csv_tuple(raw: str | None) -> tuple[str, ...] | None:
    if not raw:
        return None
    return tuple(token.strip() for token in raw.split(",") if token.strip())


# ── One-shot mode ────────────────────────────────────────────────────

async def _run_once(args: argparse.Namespace) -> int:
    from src.extractors import ExtractError
    from src.orchestrator import AttackGraphETL

    cve_path = args.cves
    if args.cve_profile != "local":
        try:
            cve_path, state, count = await asyncio.to_thread(
                sync_cve_feed_profile,
                args.cve_profile,
                cache_dir=args.cve_cache_dir,
                auto_download=args.cve_auto_download,
                max_items=args.cve_max_items,
                sync_policy=args.cve_sync_policy,
                sync_schedule=args.cve_sync_schedule,
                stale_after_hours=args.cve_stale_hours,
                osv_lookup_limit=args.cve_osv_lookup_limit,
                source_priority=_csv_tuple(args.cve_source_priority),
                disabled_sources=_csv_tuple(args.cve_disable_sources),
            )
        except CVEFeedSyncError as exc:
            logging.error("CVE feed sync failed: %s", exc)
            return EXIT_ERROR
        logging.info("CVE profile %s: %s (%d CVEs) -> %s", args.cve_profile, state, count, cve_path)

    def _live_hook(event: dict[str, Any]) -> None:
        print(json.dumps(event, default=str), file=sys.stderr, flush=True)

    etl = AttackGraphETL(
        network_source=args.network,
        cve_source=cve_path,
        output_dir=args.out,
        run_remediation=not args.no_remediation,
        top_patches=args.top_patches,
        quiet=args.quiet,
        offensive_config=None,
        asset_aware_cves=args.asset_aware_cves,
        asset_cve_min_score=max(1, args.asset_cve_min_score),
        asset_cve_keep_top=max(0, args.asset_cve_keep_top),
    )
    try:
        result = await etl.run(live_log_hook=_live_hook if args.live_log else None)
    except (ExtractError, OSError) as exc:
        logging.error("analysis failed: %s", exc)
        return EXIT_ERROR

    if args.fail_on_findings and result.kill_chains > 0:
        logging.error("%d kill chain(s) found; failing (--fail-on-findings)", result.kill_chains)
        return EXIT_FINDINGS
    return EXIT_OK


# ── Server mode ──────────────────────────────────────────────────────

def _run_server(args: argparse.Namespace) -> int:
    _render_terminal_intro(args)
    try:
        import uvicorn
        from api.app import create_app

        app = create_app(args)

        print(f"\n\x1b[1;36m{'═' * 60}\x1b[0m")
        print("\x1b[1;36m  Gordian API Server\x1b[0m")
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


def main(argv: list[str] | None = None) -> int:
    _force_utf8_stdout()
    raw_argv = sys.argv[1:] if argv is None else argv
    args = _parse_args(raw_argv)
    _configure_logging(args.verbose)

    if args.list_cve_profiles:
        print("Available CVE profiles (use with --once --cve-profile):")
        for line in describe_cve_profiles_for_cli():
            print(line)
        return EXIT_OK

    if args.list_wordlists:
        print("Available wordlist profiles:")
        for line in describe_profiles_for_cli():
            print(line)
        return EXIT_OK

    if args.once:
        return asyncio.run(_run_once(args))
    return _run_server(args)


if __name__ == "__main__":
    sys.exit(main())
