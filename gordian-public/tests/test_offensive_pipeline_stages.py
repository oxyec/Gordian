"""Verify the recon → exploit pipeline really stages tools correctly.

The default tool_dependencies map declares subfinder/amass/bbot must run
before httpx, which must run before katana/ffuf/nuclei/etc. We don't want
a regression to flatten everything into one parallel stage — that breaks
the whole "tools feed each other" promise.

Also covers _build_followup_commands routing discovered hosts/URLs to the
right tool buckets.
"""

from __future__ import annotations

from src.offensive.command_factory import CommandSpec
from src.offensive.config import OffensiveConfig, _default_tool_dependencies
from src.offensive.hub import _build_command_stages, _build_followup_commands


def _spec(tool: str) -> CommandSpec:
    return CommandSpec(tool=tool, argv=(tool, "--placeholder"))


def test_default_dependencies_enforce_recon_first_pipeline():
    deps = _default_tool_dependencies()
    # subfinder → httpx → katana → ffuf  is the canonical chain.
    assert "subfinder" in deps["httpx"]
    assert deps["katana"] == ("httpx",)
    assert "httpx" in deps["ffuf"] and "katana" in deps["ffuf"]
    assert deps["nuclei"] == ("httpx",)


def test_build_command_stages_layers_recon_before_exploit():
    deps = _default_tool_dependencies()
    commands = [_spec(t) for t in ("nuclei", "ffuf", "katana", "httpx", "subfinder", "nmap")]
    stages = _build_command_stages(commands, dependencies=deps)

    # Flatten into per-stage tool-set lists to assert ordering.
    stage_tools = [{c.tool for c in stage} for stage in stages]
    flat_position = {tool: idx for idx, stools in enumerate(stage_tools) for tool in stools}

    assert flat_position["subfinder"] < flat_position["httpx"]
    assert flat_position["httpx"] < flat_position["katana"]
    assert flat_position["katana"] < flat_position["ffuf"]
    assert flat_position["httpx"] < flat_position["nuclei"]
    # nmap has no deps → can go in the first stage alongside subfinder.
    assert flat_position["nmap"] == flat_position["subfinder"]


def test_build_command_stages_breaks_dependency_cycle_safely():
    # Pathological cycle: a needs b, b needs a. Should not loop forever —
    # the hub flushes remaining tools as one stage when nothing is unblocked.
    commands = [_spec("a"), _spec("b")]
    deps = {"a": ("b",), "b": ("a",)}
    stages = _build_command_stages(commands, dependencies=deps)
    assert len(stages) == 1
    assert {c.tool for c in stages[0]} == {"a", "b"}


def test_followup_routes_discovered_hosts_to_host_tools_only():
    cfg = OffensiveConfig(
        target="example.com",
        tools=("nmap", "httpx", "katana", "ffuf", "nuclei"),
    )
    followups = _build_followup_commands(
        config=cfg,
        host_candidates=["new-host.example.com"],
        url_candidates=[],
        seen_targets={"example.com"},
        executed_signatures=set(),
        max_followup_targets=10,
    )
    tools = {spec.tool for spec in followups}
    # Hosts should fan out to httpx + nmap, not ffuf/katana/nuclei (URL-only).
    assert "httpx" in tools
    assert "nmap" in tools
    assert "ffuf" not in tools and "katana" not in tools and "nuclei" not in tools


def test_followup_routes_discovered_urls_to_web_tools():
    cfg = OffensiveConfig(
        target="https://example.com",
        tools=("httpx", "katana", "ffuf", "nuclei", "gowitness"),
    )
    followups = _build_followup_commands(
        config=cfg,
        host_candidates=[],
        url_candidates=["https://api.example.com"],
        seen_targets={"https://example.com"},
        executed_signatures=set(),
        max_followup_targets=10,
    )
    tools = {spec.tool for spec in followups}
    # URLs fan out to web tools; nmap should be absent.
    assert "httpx" in tools
    assert "katana" in tools or "ffuf" in tools or "nuclei" in tools or "gowitness" in tools
    assert "nmap" not in tools


def test_followup_respects_seen_targets_idempotency():
    cfg = OffensiveConfig(target="example.com", tools=("httpx",))
    seen = {"example.com", "already.example.com"}
    followups = _build_followup_commands(
        config=cfg,
        host_candidates=["already.example.com", "fresh.example.com"],
        url_candidates=[],
        seen_targets=seen,
        executed_signatures=set(),
        max_followup_targets=10,
    )
    # only fresh.example.com should produce commands; already-seen is skipped.
    targets_in_commands = [spec.argv for spec in followups]
    assert any("fresh.example.com" in arg for argv in targets_in_commands for arg in argv)
    assert not any("already.example.com" in arg for argv in targets_in_commands for arg in argv)
