from __future__ import annotations

import pytest

from src.offensive import command_factory as cf_module
from src.offensive.command_factory import CommandFactory, CommandFactoryError
from src.offensive.config import Intensity, OffensiveConfig, OffensiveMode, SpeedProfile, merge_cli_overrides


@pytest.fixture(autouse=True)
def _skip_binary_resolution(monkeypatch):
    """These tests assert on bare argv[0] names. Real binary resolution is
    covered by test_command_factory_resolves_binary_to_absolute_path below."""
    monkeypatch.setattr(cf_module, "_resolve_argv_binary", lambda argv: argv)


def test_command_factory_builds_safe_commands_for_url_target():
    cfg = OffensiveConfig(
        mode=OffensiveMode.AUTO,
        target="https://app.example.com",
        tools=("nmap", "ffuf", "nuclei"),
    )
    factory = CommandFactory(cfg)

    commands = factory.build()

    assert len(commands) == 3
    by_tool = {spec.tool: spec for spec in commands}
    assert by_tool["nmap"].argv[0] == "nmap"
    assert by_tool["ffuf"].argv[0] == "ffuf"
    assert by_tool["nuclei"].argv[0] == "nuclei"
    assert all(";" not in token for spec in commands for token in spec.argv)


def test_command_factory_rejects_shell_control_characters():
    cfg = OffensiveConfig(target="example.com;rm -rf /")
    factory = CommandFactory(cfg)

    with pytest.raises(CommandFactoryError, match="unsupported characters"):
        factory.build()


def test_command_factory_skips_web_tools_for_cidr_target():
    cfg = OffensiveConfig(target="10.0.0.0/24", tools=("nmap", "ffuf", "nuclei"))
    commands = CommandFactory(cfg).build()

    assert [spec.tool for spec in commands] == ["nmap"]


def test_merge_cli_overrides_supports_dry_run_and_tool_filter():
    base = OffensiveConfig(target="example.com")
    merged = merge_cli_overrides(
        base,
        dry_run=True,
        tools=("nmap",),
        speed="aggressive",
        intensity="high",
        ffuf_wordlist_profile="ffuf_common",
        wordlist_auto_download=False,
        wordlist_store_dir="data/custom-wordlists",
    )

    assert merged.mode is OffensiveMode.DRY_RUN
    assert merged.tools == ("nmap",)
    assert merged.speed.value == "aggressive"
    assert merged.intensity.value == "high"
    assert merged.ffuf_wordlist_profile == "ffuf_common"
    assert merged.wordlist_auto_download is False
    assert merged.wordlist_store_dir == "data/custom-wordlists"


def test_command_factory_bugbounty_mode_uses_safer_limits():
    cfg = OffensiveConfig(
        mode=OffensiveMode.AUTO,
        target="https://app.example.com",
        tools=("nmap", "ffuf", "nuclei"),
        speed=SpeedProfile.AGGRESSIVE,
        intensity=Intensity.HIGH,
        bugbounty_mode=True,
    )

    by_tool = {spec.tool: spec.argv for spec in CommandFactory(cfg).build()}

    nmap_argv = by_tool["nmap"]
    assert "--max-rate" in nmap_argv
    assert "--script" not in nmap_argv

    ffuf_argv = by_tool["ffuf"]
    ffuf_threads = int(ffuf_argv[ffuf_argv.index("-t") + 1])
    assert ffuf_threads <= 25
    assert "-p" in ffuf_argv
    assert ffuf_argv[ffuf_argv.index("-p") + 1] == "0.05"

    nuclei_argv = by_tool["nuclei"]
    nuclei_rate = int(nuclei_argv[nuclei_argv.index("-rl") + 1])
    assert nuclei_rate <= 80
    assert "-timeout" in nuclei_argv


def test_merge_cli_overrides_bugbounty_mode_enables_scope_and_caps_concurrency():
    base = OffensiveConfig(target="example.com", max_concurrency=6)

    merged = merge_cli_overrides(base, bugbounty_mode=True)

    assert merged.bugbounty_mode is True
    assert merged.require_scope_match is True
    assert merged.max_concurrency == 2


def test_command_factory_applies_custom_headers_and_rate_caps():
    cfg = OffensiveConfig(
        target="https://api.example.com",
        tools=("ffuf", "nuclei", "nmap"),
        request_headers=("Authorization: Bearer token", "X-Bounty: true"),
        max_nmap_rate=15,
        max_ffuf_threads=7,
        max_nuclei_rate=22,
    )

    commands = {spec.tool: spec.argv for spec in CommandFactory(cfg).build()}

    nmap = commands["nmap"]
    assert "--max-rate" in nmap
    assert nmap[nmap.index("--max-rate") + 1] == "15"

    ffuf = commands["ffuf"]
    assert ffuf[ffuf.index("-t") + 1] == "7"
    assert ffuf.count("-H") == 2
    assert "Authorization: Bearer token" in ffuf

    nuclei = commands["nuclei"]
    assert nuclei[nuclei.index("-rl") + 1] == "22"
    assert nuclei.count("-H") == 2


def test_command_factory_supports_extended_toolset_with_defaults():
    cfg = OffensiveConfig(
        target="https://app.example.com",
        tools=(
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
        ),
    )

    commands = {spec.tool: spec.argv for spec in CommandFactory(cfg).build()}

    assert set(commands) == {
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
    assert commands["subfinder"][:3] == ("subfinder", "-silent", "-d")
    assert commands["amass"][:2] == ("amass", "enum")
    assert commands["katana"][:3] == ("katana", "-u", "https://app.example.com")
    assert commands["httpx"][0] == "httpx"
    assert commands["gitleaks"][:2] == ("gitleaks", "detect")


def test_command_factory_applies_binary_and_command_overrides_with_placeholders():
    cfg = OffensiveConfig(
        target="https://api.example.com",
        tools=("katana", "httpx"),
        tool_binaries={"katana": "katana-custom"},
        tool_extra_args={"katana": ("-jc", "-kf")},
        tool_command_overrides={
            "httpx": ("httpx-custom", "-u", "{url}", "-H", "Host: {host}")
        },
    )

    commands = {spec.tool: spec.argv for spec in CommandFactory(cfg).build()}

    katana = commands["katana"]
    assert katana[0] == "katana-custom"
    assert "-jc" in katana
    assert "-kf" in katana

    httpx = commands["httpx"]
    assert httpx[0] == "httpx-custom"
    assert "https://api.example.com" in httpx
    assert "Host: api.example.com" in httpx


def test_command_factory_skips_domain_only_tools_for_cidr_targets():
    cfg = OffensiveConfig(
        target="10.10.0.0/24",
        tools=("subfinder", "amass", "katana", "httpx"),
    )

    commands = [spec.tool for spec in CommandFactory(cfg).build()]

    assert commands == ["httpx"]


def test_offensive_config_exposes_default_core_tool_templates():
    cfg = OffensiveConfig()

    assert "nmap" in cfg.tool_command_templates
    assert "ffuf" in cfg.tool_command_templates
    assert "nuclei" in cfg.tool_command_templates


def test_command_factory_respects_template_override_for_nmap():
    cfg = OffensiveConfig(
        target="example.com",
        tools=("nmap",),
        tool_command_templates={"nmap": "{binary} -Pn {target} {extra_args}"},
        tool_extra_args={"nmap": ("--open",)},
    )

    command = CommandFactory(cfg).build()[0]

    assert command.tool == "nmap"
    assert command.argv[:3] == ("nmap", "-Pn", "example.com")
    assert "--open" in command.argv


def test_merge_cli_overrides_supports_ffuf_wordlist_and_full_control():
    base = OffensiveConfig(target="https://app.example.com")

    merged = merge_cli_overrides(
        base,
        ffuf_wordlist="data/wordlists/custom.txt",
        full_control=True,
    )

    assert merged.ffuf_wordlist == "data/wordlists/custom.txt"
    assert merged.full_control is True


def test_command_factory_nmap_uses_host_for_url_targets():
    cfg = OffensiveConfig(
        target="https://demo.testfire.net",
        tools=("nmap",),
    )

    command = CommandFactory(cfg).build()[0]

    assert command.tool == "nmap"
    assert "demo.testfire.net" in command.argv
    assert "https://demo.testfire.net" not in command.argv


def test_command_factory_strips_sentinel_tokens_from_templates():
    cfg = OffensiveConfig(
        target="example.com",
        tools=("nmap",),
        tool_command_templates={"nmap": "{binary} -Pn (none) {target} {extra_args}"},
        tool_extra_args={"nmap": ("none", "--open", "null")},
    )

    command = CommandFactory(cfg).build()[0]

    assert "(none)" not in command.argv
    assert "none" not in command.argv
    assert "null" not in command.argv
    assert "--open" in command.argv


def test_merge_cli_overrides_drops_sentinel_tool_extra_args():
    base = OffensiveConfig(target="example.com")

    merged = merge_cli_overrides(
        base,
        tool_extra_args={"nmap": ("(none)", "--open", "null")},
    )

    assert merged.extra_args_for("nmap") == ("--open",)


def test_nmap_template_target_uses_hostname_for_url_target():
    cfg = OffensiveConfig(
        target="https://demo.testfire.net",
        tools=("nmap",),
        tool_command_templates={"nmap": "{binary} -Pn {target} {extra_args}"},
    )

    command = CommandFactory(cfg).build()[0]

    assert "demo.testfire.net" in command.argv
    assert "https://demo.testfire.net" not in command.argv
