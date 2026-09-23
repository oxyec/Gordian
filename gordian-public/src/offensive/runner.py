"""Async subprocess orchestration for offensive tools."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
import importlib
import os
from pathlib import Path
import signal
import shlex
import subprocess
import sys
import time
from typing import Any, Callable

from .command_factory import CommandSpec
from .events import LiveLogHook, build_event, emit_event
from .parsers import Finding, LineParser

# Per-stream cap on raw output events forwarded to the live log. A noisy tool
# like `nmap -sV -p-` can emit thousands of lines; without a cap they flood
# the WebSocket buffer and the TUI live-log scrollback. The parser still sees
# every line — only the DEBUG event mirror is throttled.
_MAX_OUTPUT_EVENTS_PER_STREAM = 200

# Hard cap on a single output line. Anything longer is truncated before
# decoding so a runaway tool can't OOM the parser via one giant line.
_MAX_LINE_BYTES = 64 * 1024


async def _kill_process_tree(proc: asyncio.subprocess.Process) -> None:
    try:
        if os.name == "posix":
            # Also kill descendants after the group leader has exited.
            os.killpg(proc.pid, signal.SIGKILL)
        elif proc.returncode is None:
            proc.kill()  # Supervisor exit closes its kill-on-close Windows Job.
    except (ProcessLookupError, OSError):
        pass
    try:
        await asyncio.wait_for(proc.wait(), timeout=3)
    except (asyncio.TimeoutError, ProcessLookupError):
        # The process tree was signalled; pipe tasks are independently cancelled.
        pass


@dataclass
class ToolRunResult:
    tool: str
    argv: tuple[str, ...]
    exit_code: int
    findings_seen: int
    duration_seconds: float
    timed_out: bool = False


class AsyncToolRunner:
    def __init__(
        self,
        *,
        max_concurrency: int,
        timeout_seconds: int,
        live_log_hook: LiveLogHook | None = None,
        review_mode: bool = False,
        command_reviewer: Callable[[CommandSpec], CommandSpec | None] | None = None,
        command_validator: Callable[[CommandSpec], Any] | None = None,
    ) -> None:
        self.max_concurrency = max(1, max_concurrency)
        self.timeout_seconds = max(0.01, timeout_seconds)
        self.live_log_hook = live_log_hook
        self.review_mode = review_mode
        self.command_reviewer = command_reviewer
        self.command_validator = command_validator
        self._review_lock = asyncio.Lock()

    async def run(
        self,
        commands: list[CommandSpec],
        *,
        parser_factory: Callable[[CommandSpec], LineParser],
        on_finding: Callable[[Finding], None],
        dry_run: bool = False,
    ) -> list[ToolRunResult]:
        if dry_run:
            results: list[ToolRunResult] = []
            for spec in commands:
                emit_event(
                    self.live_log_hook,
                    build_event(
                        "offensive.dry_run_command",
                        tool=spec.tool,
                        message="Dry-run mode: command prepared but not executed",
                        command=list(spec.argv),
                    ),
                )
                results.append(
                    ToolRunResult(
                        tool=spec.tool,
                        argv=spec.argv,
                        exit_code=0,
                        findings_seen=0,
                        duration_seconds=0.0,
                        timed_out=False,
                    )
                )
            return results

        semaphore = asyncio.Semaphore(self.max_concurrency)

        async def _bounded(spec: CommandSpec) -> ToolRunResult:
            async with semaphore:
                parser = parser_factory(spec)
                return await self._run_single(spec, parser=parser, on_finding=on_finding)

        tasks = [asyncio.create_task(_bounded(spec)) for spec in commands]
        try:
            return await asyncio.gather(*tasks)
        finally:
            for task in tasks:
                if not task.done():
                    task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)

    async def _run_single(
        self,
        spec: CommandSpec,
        *,
        parser: LineParser,
        on_finding: Callable[[Finding], None],
    ) -> ToolRunResult:
        run_spec = spec
        if self.review_mode:
            async with self._review_lock:
                reviewed = await self._review_command(run_spec)
            if reviewed is None:
                emit_event(
                    self.live_log_hook,
                    build_event(
                        "offensive.tool_skipped",
                        tool=spec.tool,
                        level="WARNING",
                        message=f"{spec.tool} command skipped in review mode",
                        command=list(spec.argv),
                    ),
                )
                return ToolRunResult(
                    tool=spec.tool,
                    argv=spec.argv,
                    exit_code=130,
                    findings_seen=0,
                    duration_seconds=0.0,
                    timed_out=False,
                )
            run_spec = reviewed

        if self.command_validator is not None:
            await self.command_validator(run_spec)
        run_spec = await _stabilize_command_for_noninteractive_runtime(run_spec)

        t0 = time.perf_counter()
        emit_event(
            self.live_log_hook,
            build_event(
                "offensive.tool_start",
                tool=run_spec.tool,
                message=f"Starting {run_spec.tool}",
                command=list(run_spec.argv),
            ),
        )

        argv = run_spec.argv
        if os.name == "nt":
            argv = (sys.executable, str(Path(__file__).with_name("process_tree.py")), *argv)
        proc = await asyncio.create_subprocess_exec(
            *argv,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            start_new_session=True,
        )

        findings_seen = 0
        timed_out = False

        async def _stream(
            stream: asyncio.StreamReader | None,
            *,
            stream_name: str,
        ) -> int:
            if stream is None:
                return 0

            local_seen = 0
            events_emitted = 0
            cap_notified = False
            while True:
                try:
                    raw = await stream.readline()
                except (asyncio.LimitOverrunError, ValueError):
                    # asyncio.StreamReader.readline raises ValueError (wrapping
                    # LimitOverrunError) when a line exceeds the internal
                    # buffer with no separator in sight. Drain a bounded chunk
                    # and continue — better than aborting the scan.
                    raw = await stream.read(_MAX_LINE_BYTES) + b"...<truncated>"
                if not raw:
                    break
                if len(raw) > _MAX_LINE_BYTES:
                    raw = raw[:_MAX_LINE_BYTES] + b"...<truncated>"
                line = raw.decode("utf-8", errors="replace").rstrip()
                if not line:
                    continue

                if events_emitted < _MAX_OUTPUT_EVENTS_PER_STREAM:
                    emit_event(
                        self.live_log_hook,
                        build_event(
                            "offensive.tool_output",
                            tool=run_spec.tool,
                            level="DEBUG",
                            message="Tool output received; raw evidence withheld" + (" (truncated)" if "<truncated>" in line else ""),
                            stream=stream_name,
                        ),
                    )
                    events_emitted += 1
                elif not cap_notified:
                    emit_event(
                        self.live_log_hook,
                        build_event(
                            "offensive.tool_output_truncated",
                            tool=run_spec.tool,
                            level="INFO",
                            message=(
                                f"{run_spec.tool} {stream_name} mirror capped at "
                                f"{_MAX_OUTPUT_EVENTS_PER_STREAM} lines — "
                                "parser still receives every line"
                            ),
                            stream=stream_name,
                        ),
                    )
                    cap_notified = True

                findings = parser.parse_line(line)
                for finding in findings:
                    on_finding(finding)
                    local_seen += 1
            return local_seen

        stdout_task = asyncio.create_task(_stream(proc.stdout, stream_name="stdout"))
        stderr_task = asyncio.create_task(_stream(proc.stderr, stream_name="stderr"))

        wait_task = asyncio.create_task(proc.wait())
        tasks = (wait_task, stdout_task, stderr_task)
        try:
            # Covers pipe draining as well as process lifetime; parser failures
            # immediately enter cleanup rather than waiting for the child timeout.
            results = await asyncio.wait_for(asyncio.gather(*tasks), self.timeout_seconds)
            findings_seen = results[1] + results[2]
        except asyncio.TimeoutError:
            timed_out = True
        finally:
            await _kill_process_tree(proc)
            for task in tasks:
                if not task.done():
                    task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)

        duration = round(time.perf_counter() - t0, 3)
        exit_code = proc.returncode if proc.returncode is not None else 1
        level = "INFO" if exit_code == 0 and not timed_out else "WARNING"

        emit_event(
            self.live_log_hook,
            build_event(
                "offensive.tool_done",
                tool=run_spec.tool,
                level=level,
                message=f"{run_spec.tool} finished with code {exit_code}",
                duration_seconds=duration,
                findings_seen=findings_seen,
                timed_out=timed_out,
            ),
        )

        return ToolRunResult(
            tool=run_spec.tool,
            argv=run_spec.argv,
            exit_code=exit_code,
            findings_seen=findings_seen,
            duration_seconds=duration,
            timed_out=timed_out,
        )

    async def _review_command(self, spec: CommandSpec) -> CommandSpec | None:
        if self.command_reviewer is not None:
            return self.command_reviewer(spec)

        if not sys.stdin.isatty() or not sys.stdout.isatty():
            return None

        emit_event(
            self.live_log_hook,
            build_event(
                "offensive.command_intercept",
                tool=spec.tool,
                level="WARNING",
                message=f"{spec.tool} command intercepted for operator approval",
                command=list(spec.argv),
            ),
        )

        reviewed = await intercept_and_edit(
            tool_name=spec.tool,
            cmd_list=list(spec.argv),
            full_control=self.review_mode,
            silent=_ansi_dashboard_mode_enabled(),
        )

        if reviewed is None:
            decision = "skip"
        elif tuple(reviewed) == spec.argv:
            decision = "approve"
        else:
            decision = "edit"

        emit_event(
            self.live_log_hook,
            build_event(
                "offensive.command_intercept_done",
                tool=spec.tool,
                level="INFO",
                message=f"{spec.tool} interceptor decision: {decision}",
                decision=decision,
                command=list(reviewed) if reviewed is not None else list(spec.argv),
            ),
        )

        if reviewed is None:
            return None
        argv = tuple(reviewed)
        if argv == spec.argv:
            return spec
        return CommandSpec(tool=spec.tool, argv=argv)

    def _interactive_review(self, spec: CommandSpec) -> CommandSpec | None:
        command_text = shlex.join(spec.argv)
        while True:
            _render_war_room_alert(tool=spec.tool, command_text=command_text)
            try:
                answer = input("> ").strip().lower()
            except (EOFError, KeyboardInterrupt):
                print("War Room input closed. Komut atlandi.")
                return None

            if answer == "":
                return spec

            if answer == "e":
                try:
                    edited = input("War Room overwrite > ").strip()
                except (EOFError, KeyboardInterrupt):
                    print("War Room input closed. Komut atlandi.")
                    return None
                if not edited:
                    continue
                try:
                    argv = tuple(token for token in shlex.split(edited) if token)
                except ValueError as exc:
                    print(f"Gecersiz komut: {exc}")
                    continue
                if not argv:
                    print("Bos komut verilemez")
                    continue
                spec = CommandSpec(tool=spec.tool, argv=argv)
                command_text = shlex.join(spec.argv)
                print("Komut guncellendi. Calistirmak icin Enter ile onay ver.")
                continue

            if answer in {"s", "skip", "q", "quit"}:
                return None

            print("War Room secimi gecersiz. Enter(onay), e(overwrite), s(skip).")


def _load_rich_war_room_components() -> tuple[Any, Any, Any]:
    try:
        console_mod = importlib.import_module("rich.console")
        panel_mod = importlib.import_module("rich.panel")
        text_mod = importlib.import_module("rich.text")
    except ImportError:
        return None, None, None
    return (
        getattr(console_mod, "Console", None),
        getattr(panel_mod, "Panel", None),
        getattr(text_mod, "Text", None),
    )


def _render_war_room_alert(*, tool: str, command_text: str) -> None:
    Console, Panel, Text = _load_rich_war_room_components()
    if Console is None or Panel is None or Text is None or not sys.stdout.isatty() or _is_vscode_terminal():
        print("\n" + "=" * 80)
        print("!!! WAR ROOM INTERCEPTOR !!!")
        print(f"Tool: {tool}")
        print(f"Command: {command_text}")
        print("Enter => approve and execute | e => overwrite full command | s => skip")
        print("=" * 80)
        return

    console = Console()
    console.clear()
    body = Text()
    body.append("WAR ROOM INTERCEPTOR\n", style="bold white")
    body.append("Manual approval required before subprocess launch.\n\n", style="bold yellow")
    body.append("Tool: ", style="bold bright_white")
    body.append(f"{tool}\n", style="bold bright_yellow")
    body.append("Live Command:\n", style="bold bright_white")
    body.append(command_text + "\n\n", style="bold bright_white")
    body.append("Enter = approve and execute\n", style="bold bright_green")
    body.append("e = overwrite full command string\n", style="bold bright_yellow")
    body.append("s = skip command\n", style="bold bright_red")
    panel = Panel(
        body,
        title="[bold white]WARNING :: OPERATOR CONTROL ZONE[/bold white]",
        border_style="bright_red",
        padding=(1, 2),
        expand=False,
    )
    console.print(panel)


def _is_vscode_terminal() -> bool:
    term_program = str(os.environ.get("TERM_PROGRAM", "")).lower()
    if term_program == "vscode":
        return True
    return "VSCODE_PID" in os.environ or "VSCODE_IPC_HOOK_CLI" in os.environ


async def intercept_and_edit(tool_name: str, cmd_list: list[str], full_control: bool, silent: bool = False):
    """Komut ateşlenmeden hemen önce operatörün araya girmesini sağlar."""
    return await asyncio.to_thread(_intercept_and_edit_sync, tool_name, cmd_list, full_control, silent)


def _intercept_and_edit_sync(tool_name: str, cmd_list: list[str], full_control: bool, silent: bool):
    current_cmd = shlex.join(cmd_list)

    if not full_control:
        return cmd_list

    while True:
        if not silent:
            _render_war_room_alert(tool=tool_name, command_text=current_cmd)
            print("\n\033[93m[!] INTERCEPTED: command is about to launch.\033[0m")
            print(f"\033[96mCurrent Command:\033[0m {current_cmd}")

        try:
            prompt = "\n[Enter] Confirm | [E] Edit | [S] Skip: "
            if silent:
                prompt = "[Enter]=confirm  E=edit  S=skip: "
            choice = input(prompt).strip().lower()
        except (EOFError, KeyboardInterrupt):
            if not silent:
                print("War Room input closed. Komut atlandi.")
            return None

        if choice == "":
            return cmd_list

        if choice == "e":
            try:
                edited_cmd = input(f"Edit command for {tool_name} [{current_cmd}]: ").strip()
            except (EOFError, KeyboardInterrupt):
                if not silent:
                    print("War Room input closed. Komut atlandi.")
                return None

            if edited_cmd:
                try:
                    cmd_list = shlex.split(edited_cmd)
                except ValueError as exc:
                    if not silent:
                        print(f"Gecersiz komut: {exc}")
                    continue
                if not cmd_list:
                    if not silent:
                        print("Bos komut verilemez")
                    continue
                current_cmd = shlex.join(cmd_list)
                continue
            return cmd_list

        if choice == "s":
            if not silent:
                print(f"[-] Skipping {tool_name} execution.")
            return None

        if not silent:
            print("Gecersiz secim. Enter, E veya S kullan.")


def _ansi_dashboard_mode_enabled() -> bool:
    return os.environ.get("GORDIAN_ANSI_TUI") == "1"


async def _stabilize_command_for_noninteractive_runtime(spec: CommandSpec) -> CommandSpec:
    if spec.tool != "ffuf":
        return spec
    if not spec.argv:
        return spec
    if "-noninteractive" in spec.argv or "--noninteractive" in spec.argv:
        return spec

    ffuf_binary = spec.argv[0]
    supports_flag = await asyncio.to_thread(_ffuf_supports_noninteractive, ffuf_binary)
    if not supports_flag:
        return spec

    return CommandSpec(tool=spec.tool, argv=tuple([*spec.argv, "-noninteractive"]))


_FFUF_NONINTERACTIVE_CACHE: dict[str, bool] = {}


def _ffuf_supports_noninteractive(binary: str) -> bool:
    # Memoise per resolved binary path. Previously every ffuf invocation
    # paid a ~50–500ms probe; in a multi-target run that was the slowest
    # part of preflight. Cache is process-local, which is fine because
    # the binary won't change versions mid-run.
    if binary in _FFUF_NONINTERACTIVE_CACHE:
        return _FFUF_NONINTERACTIVE_CACHE[binary]

    try:
        probe = subprocess.run(
            [binary, "-h"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except OSError:
        _FFUF_NONINTERACTIVE_CACHE[binary] = False
        return False
    except subprocess.SubprocessError:
        _FFUF_NONINTERACTIVE_CACHE[binary] = False
        return False

    help_text = f"{probe.stdout}\n{probe.stderr}".lower()
    supports = "-noninteractive" in help_text or "--noninteractive" in help_text
    _FFUF_NONINTERACTIVE_CACHE[binary] = supports
    return supports
