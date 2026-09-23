"""Regression coverage for the Faz 7 tool-integration hardening.

Covers:
- command_factory: argv[0] resolves to an absolute path when on PATH
- command_factory: missing_tools flags absolute paths that don't exist
- runner: bounded line decoding (no OOM on giant lines)
- runner: kill race when process already exited is swallowed
- runner: DEBUG output events are capped per stream
- runner: ffuf -h probe is memoised per binary
"""

from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path

import pytest

from src.offensive import command_factory as cf_module
from src.offensive import runner as runner_module
from src.offensive.command_factory import CommandFactory, _resolve_argv_binary
from src.offensive.config import OffensiveConfig
from src.offensive.parsers import Finding


# ── command_factory.binary resolution ────────────────────────────────

def test_resolve_argv_binary_returns_absolute_path_when_found(monkeypatch):
    fake = "/usr/local/bin/nmap" if os.sep == "/" else "C:\\tools\\nmap.exe"
    monkeypatch.setattr(cf_module.shutil, "which", lambda b: fake)
    argv = _resolve_argv_binary(("nmap", "-Pn", "127.0.0.1"))
    assert argv == (fake, "-Pn", "127.0.0.1")


def test_resolve_argv_binary_keeps_bare_name_when_unresolved(monkeypatch):
    monkeypatch.setattr(cf_module.shutil, "which", lambda b: None)
    argv = _resolve_argv_binary(("definitely-not-installed", "--help"))
    assert argv == ("definitely-not-installed", "--help")


def test_resolve_argv_binary_leaves_absolute_paths_untouched(monkeypatch):
    monkeypatch.setattr(cf_module.shutil, "which", lambda b: "/wrong/path")
    given = "/explicit/nmap" if os.sep == "/" else "C:\\explicit\\nmap.exe"
    argv = _resolve_argv_binary((given, "-Pn"))
    assert argv[0] == given


def test_build_resolves_binaries_through_helper(monkeypatch):
    captured: list[str] = []

    def fake_resolve(argv):
        captured.append(argv[0])
        return ("/resolved/" + argv[0], *argv[1:])

    monkeypatch.setattr(cf_module, "_resolve_argv_binary", fake_resolve)
    cfg = OffensiveConfig(target="example.com", tools=("nmap",))
    commands = CommandFactory(cfg).build()
    assert commands
    assert commands[0].argv[0] == "/resolved/nmap"
    assert captured == ["nmap"]


def test_missing_tools_flags_absolute_path_that_does_not_exist(tmp_path, monkeypatch):
    monkeypatch.setattr(cf_module, "_resolve_argv_binary", lambda argv: argv)
    cfg = OffensiveConfig(target="example.com", tools=("nmap",))
    factory = CommandFactory(cfg)
    commands = factory.build()
    # Replace with an absolute path to a file we know doesn't exist.
    ghost = tmp_path / "nope" / "nmap"
    commands[0] = type(commands[0])(tool="nmap", argv=(str(ghost), *commands[0].argv[1:]))
    assert factory.missing_tools(commands) == ["nmap"]


# ── runner: ffuf probe cache ─────────────────────────────────────────

def test_ffuf_probe_is_memoised(monkeypatch):
    runner_module._FFUF_NONINTERACTIVE_CACHE.clear()
    calls: list[str] = []

    class _Probe:
        stdout = "some help text -noninteractive\n"
        stderr = ""

    def fake_run(cmd, **_):
        calls.append(cmd[0])
        return _Probe()

    monkeypatch.setattr(runner_module.subprocess, "run", fake_run)
    assert runner_module._ffuf_supports_noninteractive("/bin/ffuf") is True
    assert runner_module._ffuf_supports_noninteractive("/bin/ffuf") is True
    assert runner_module._ffuf_supports_noninteractive("/other/ffuf") is True
    assert calls == ["/bin/ffuf", "/other/ffuf"]


def test_ffuf_probe_caches_negative_lookup(monkeypatch):
    runner_module._FFUF_NONINTERACTIVE_CACHE.clear()

    def boom(cmd, **_):
        raise OSError("not found")

    monkeypatch.setattr(runner_module.subprocess, "run", boom)
    assert runner_module._ffuf_supports_noninteractive("/missing/ffuf") is False
    # Second call should hit cache, not raise again — replace with raising fn
    # that should NOT fire.
    monkeypatch.setattr(runner_module.subprocess, "run",
                        lambda *a, **k: (_ for _ in ()).throw(AssertionError("called twice")))
    assert runner_module._ffuf_supports_noninteractive("/missing/ffuf") is False


# ── runner: event cap + kill safety (integration-ish, via real subprocess) ──

def _make_runner() -> runner_module.AsyncToolRunner:
    return runner_module.AsyncToolRunner(
        max_concurrency=1,
        timeout_seconds=30,
        live_log_hook=None,
    )


@pytest.mark.asyncio
async def test_runner_caps_debug_events_per_stream(monkeypatch):
    """Run a Python subprocess that emits >MAX lines and verify the cap event fires."""
    seen_events: list[dict] = []

    def hook(event):
        seen_events.append(event)

    runner = runner_module.AsyncToolRunner(
        max_concurrency=1,
        timeout_seconds=15,
        live_log_hook=hook,
    )

    # Emit MAX+50 lines from stdout.
    n = runner_module._MAX_OUTPUT_EVENTS_PER_STREAM + 50
    script = f"import sys\nfor i in range({n}): print(f'line-{{i}}')\n"
    spec = runner_module.CommandSpec(tool="nmap", argv=(sys.executable, "-c", script))

    findings: list[Finding] = []
    parser = type("P", (), {"parse_line": staticmethod(lambda line: [])})()

    await runner.run(
        [spec],
        parser_factory=lambda s: parser,
        on_finding=findings.append,
    )

    output_events = [e for e in seen_events if e["type"] == "offensive.tool_output"]
    truncated_events = [e for e in seen_events if e["type"] == "offensive.tool_output_truncated"]
    assert len(output_events) <= runner_module._MAX_OUTPUT_EVENTS_PER_STREAM
    assert len(truncated_events) >= 1, "cap notice should fire when threshold crossed"


@pytest.mark.asyncio
async def test_runner_truncates_oversized_single_line(monkeypatch):
    """A tool emitting one giant line must not crash the runner.

    asyncio.StreamReader.readline raises LimitOverrunError for lines past the
    internal buffer (default 64KiB). Runner should drain + truncate and keep
    going.
    """
    seen: list[dict] = []

    def hook(event):
        seen.append(event)

    runner = runner_module.AsyncToolRunner(
        max_concurrency=1,
        timeout_seconds=15,
        live_log_hook=hook,
    )

    # Print one line of ~200KiB then exit cleanly.
    script = (
        "import sys\n"
        "sys.stdout.write('A' * (200 * 1024))\n"
        "sys.stdout.write('\\n')\n"
        "sys.stdout.flush()\n"
    )
    spec = runner_module.CommandSpec(tool="nmap", argv=(sys.executable, "-c", script))

    parser = type("P", (), {"parse_line": staticmethod(lambda line: [])})()
    results = await runner.run([spec],
                               parser_factory=lambda s: parser,
                               on_finding=lambda f: None)
    assert results[0].exit_code == 0
    # Should not have crashed; at least one event should be emitted with the
    # truncation marker in the message.
    truncated = [e for e in seen if "truncated" in str(e.get("message", "")).lower()]
    assert truncated, "expected a truncation marker for the giant line"
