from __future__ import annotations

import argparse
import asyncio
import builtins
import json
import re
import types

import pytest

import main
from src.offensive.config import OffensiveConfig, OffensiveMode


def _reset_geo_caches() -> None:
    main._GEO_LOOKUP_CACHE.clear()
    main._DNS_LOOKUP_CACHE.clear()
    main._TARGET_GEO_CACHE.clear()
    main._NMAP_REPORT_IP_CACHE.clear()
    main._NMAP_GEO_CONTEXT_CACHE.clear()


def test_project_geo_to_map_stays_within_world_map_bounds():
    row, col = main._project_geo_to_map(lat=41.01, lon=28.97)

    assert 0 <= row < len(main.WORLD_MAP_TEMPLATE)
    assert 0 <= col < len(main.WORLD_MAP_TEMPLATE[row])


def test_resolve_target_geo_context_uses_ip_geolocation(monkeypatch):
    _reset_geo_caches()

    monkeypatch.setattr(main, "_resolve_host_to_ip", lambda _host: "8.8.8.8")
    monkeypatch.setattr(
        main,
        "_lookup_ip_geolocation",
        lambda _ip: {
            "ip": "8.8.8.8",
            "city": "Frankfurt",
            "country": "Germany",
            "country_code": "DE",
            "continent_code": "EU",
            "latitude": 50.11,
            "longitude": 8.68,
        },
    )

    context = main._resolve_target_geo_context("https://demo.testfire.net")

    assert context["resolved_ip"] == "8.8.8.8"
    assert context["region_label"] == "EUROPE"
    assert "Frankfurt" in context["geo_location"]


def test_resolve_target_geo_context_internal_ip_maps_to_internal_region(monkeypatch):
    _reset_geo_caches()

    monkeypatch.setattr(main, "_resolve_host_to_ip", lambda _host: "10.0.0.9")

    context = main._resolve_target_geo_context("http://10.0.0.9")

    assert context["region_label"] == "INTERNAL-LAB"
    assert context["resolved_ip"] == "10.0.0.9"
    assert context["geo_location"] == "internal/private address"


def test_extract_nmap_resolved_ip_from_report(tmp_path):
    _reset_geo_caches()

    report_path = tmp_path / "attack_paths.json"
    report_path.write_text(
        json.dumps(
            {
                "offensive_integration": {
                    "target": "https://demo.testfire.net",
                    "findings": [
                        {
                            "tool": "nmap",
                            "type": "host",
                            "metadata": {"ip_address": "65.61.137.117"},
                        }
                    ],
                }
            }
        ),
        encoding="utf-8",
    )

    resolved_ip = main._extract_nmap_resolved_ip_from_report(
        target="https://demo.testfire.net",
        report_path=report_path,
    )

    assert resolved_ip == "65.61.137.117"


def test_render_target_world_map_supports_dual_markers(monkeypatch, tmp_path):
    _reset_geo_caches()

    monkeypatch.setattr(
        main,
        "_resolve_target_geo_context",
        lambda _target: {
            "region_label": "NORTH-AMERICA",
            "resolved_ip": "1.1.1.1",
            "geo_location": "Dallas, US (32.78, -96.80)",
            "marker_row": 2,
            "marker_col": 14,
        },
    )
    monkeypatch.setattr(
        main,
        "_resolve_nmap_report_geo_context",
        lambda *, target, report_path: {
            "resolved_ip": "8.8.8.8",
            "geo_location": "Frankfurt, DE (50.11, 8.68)",
            "marker_row": 2,
            "marker_col": 43,
        },
    )

    world_map, context = main._render_target_world_map(
        "https://demo.testfire.net",
        report_path=tmp_path / "attack_paths.json",
        pulse_on=True,
    )

    assert world_map[2][14] == "*"
    assert world_map[2][43] == "x"
    assert context["resolved_ip"] == "1.1.1.1"
    assert context["nmap_resolved_ip"] == "8.8.8.8"


def test_build_intro_panel_title_prefers_geo_location():
    title = main._build_intro_panel_title(
        geo_location="Dallas, US (32.78, -96.80)",
        nmap_geo_location="Frankfurt, DE (50.11, 8.68)",
    )

    assert title == "Gordian :: Dallas, US"


def test_tool_args_as_text_returns_empty_string_for_none():
    assert main._tool_args_as_text(None) == ""


def test_should_use_ansi_dashboard_returns_false_for_terminal_app(monkeypatch):
    class _TtyStream:
        def isatty(self) -> bool:
            return True

    monkeypatch.setattr(main.sys, "stdout", _TtyStream())
    monkeypatch.setattr(main.sys, "stdin", _TtyStream())
    monkeypatch.setattr(main, "_is_vscode_terminal", lambda: False)

    args = argparse.Namespace(
        list_cve_profiles=False,
        list_wordlists=False,
        terminal_app=True,
    )

    assert main._should_use_ansi_dashboard(args) is False


def test_should_use_ansi_dashboard_returns_false_when_disabled(monkeypatch):
    class _TtyStream:
        def isatty(self) -> bool:
            return True

    monkeypatch.setattr(main.sys, "stdout", _TtyStream())
    monkeypatch.setattr(main.sys, "stdin", _TtyStream())
    monkeypatch.setattr(main, "_is_vscode_terminal", lambda: False)

    args = argparse.Namespace(
        list_cve_profiles=False,
        list_wordlists=False,
        terminal_app=False,
        _disable_ansi_dashboard=True,
    )

    assert main._should_use_ansi_dashboard(args) is False


def test_should_use_ansi_dashboard_force_override_allows_terminal_and_vscode(monkeypatch):
    class _TtyStream:
        def isatty(self) -> bool:
            return True

    monkeypatch.setattr(main.sys, "stdout", _TtyStream())
    monkeypatch.setattr(main.sys, "stdin", _TtyStream())
    monkeypatch.setattr(main, "_is_vscode_terminal", lambda: True)

    args = argparse.Namespace(
        list_cve_profiles=False,
        list_wordlists=False,
        terminal_app=True,
        _disable_ansi_dashboard=False,
        _force_ansi_dashboard=True,
    )

    assert main._should_use_ansi_dashboard(args) is True


def test_run_terminal_app_keeps_ansi_dashboard_enabled(monkeypatch):
    captured: dict[str, bool | None] = {"disabled": None, "forced": None}

    monkeypatch.setattr(main, "_initialize_terminal_customization_state", lambda _args: None)
    monkeypatch.setattr(main, "_print_status", lambda *_args, **_kwargs: None)

    def _capture_menu(menu_args):
        captured["disabled"] = bool(getattr(menu_args, "_disable_ansi_dashboard", True))
        captured["forced"] = bool(getattr(menu_args, "_force_ansi_dashboard", False))

    monkeypatch.setattr(main, "_render_terminal_menu", _capture_menu)

    def _abort_prompt(_prompt: str, *, default: str):  # noqa: ARG001
        raise main.TerminalInputClosedError("closed")

    monkeypatch.setattr(main, "_prompt_text", _abort_prompt)

    args = argparse.Namespace(terminal_app=True)

    code = asyncio.run(main._run_terminal_app(args))

    assert code == main.EXIT_OK
    assert captured["disabled"] is False
    assert captured["forced"] is True


def test_ansi_dashboard_intercept_reads_command_from_event_payload(monkeypatch):
    dashboard = main.AnsiTacticalDashboard(argparse.Namespace())
    monkeypatch.setattr(dashboard, "render", lambda *args, **kwargs: None)

    dashboard.consume_event(
        {
            "type": "offensive.command_intercept",
            "tool": "nmap",
            "payload": {"command": ["nmap", "-Pn", "demo.testfire.net"]},
        }
    )

    assert dashboard.intercept_active is True
    assert dashboard.intercept_tool == "nmap"
    assert dashboard.intercept_command == "nmap -Pn demo.testfire.net"


def test_ansi_dashboard_intercept_done_reads_decision_from_event_payload(monkeypatch):
    dashboard = main.AnsiTacticalDashboard(argparse.Namespace())
    monkeypatch.setattr(dashboard, "render", lambda *args, **kwargs: None)

    dashboard.intercept_active = True
    dashboard.paused_feed_lines.append("queued-event")

    dashboard.consume_event(
        {
            "type": "offensive.command_intercept_done",
            "tool": "nmap",
            "payload": {"decision": "skip"},
        }
    )

    assert dashboard.intercept_active is False
    plain_feed = [dashboard._strip_ansi(line) for line in dashboard.feed_lines]
    assert any("decision=skip" in line for line in plain_feed)


def test_ansi_dashboard_event_line_sanitizes_control_chars_and_external_ansi():
    dashboard = main.AnsiTacticalDashboard(argparse.Namespace())

    rendered = dashboard._format_event_line(
        {
            "timestamp": "2026-04-18T13:00:00+00:00",
            "tool": "ffuf",
            "type": "offensive.tool_output",
            "message": "entering interactive mode\r\ntype \x1b[31mhelp\x1b[0m\tok",
        }
    )

    plain = dashboard._strip_ansi(rendered)
    assert "\r" not in plain
    assert "\n" not in plain
    assert "\x1b" not in plain
    assert "entering interactive mode type help ok" in plain.lower()


def test_ansi_dashboard_compose_frame_uses_box_layout_and_clock(monkeypatch):
    dashboard = main.AnsiTacticalDashboard(argparse.Namespace())
    dashboard._started = True
    monkeypatch.setattr(
        dashboard,
        "_compose_left_panel_lines",
        lambda: ["LEFT"] * dashboard.body_height,
    )
    monkeypatch.setattr(
        dashboard,
        "_compose_right_panel_lines",
        lambda: ["RIGHT"] * dashboard.body_height,
    )
    monkeypatch.setattr(
        dashboard,
        "_compose_command_zone_lines",
        lambda: ["ZONE"] * dashboard.command_zone_height,
    )

    dashboard._recompute_layout()
    frame = dashboard._compose_frame()

    top_plain = dashboard._strip_ansi(frame[0])
    title_plain = dashboard._strip_ansi(frame[1])
    assert top_plain.startswith("╔") and top_plain.endswith("╗")
    assert "GORDIAN TACTICAL DASHBOARD" in title_plain
    assert re.search(r"\b\d{2}:\d{2}:\d{2}\b", title_plain)


def test_ansi_dashboard_header_prefers_nmap_geo_location(monkeypatch):
    dashboard = main.AnsiTacticalDashboard(argparse.Namespace())
    dashboard._started = True
    dashboard._last_map_context = {
        "geo_location": "Dallas, US (32.78, -96.80)",
        "nmap_geo_location": "Frankfurt, DE (50.11, 8.68)",
    }

    monkeypatch.setattr(
        dashboard,
        "_compose_left_panel_lines",
        lambda: ["LEFT"] * dashboard.body_height,
    )
    monkeypatch.setattr(
        dashboard,
        "_compose_right_panel_lines",
        lambda: ["RIGHT"] * dashboard.body_height,
    )
    monkeypatch.setattr(
        dashboard,
        "_compose_command_zone_lines",
        lambda: ["ZONE"] * dashboard.command_zone_height,
    )

    dashboard._recompute_layout()
    frame = dashboard._compose_frame()
    title_plain = dashboard._strip_ansi(frame[1])

    assert "Frankfurt, DE" in title_plain
    assert "Dallas, US" not in title_plain


def test_resolve_nmap_geo_context_refreshes_when_report_file_changes(monkeypatch, tmp_path):
    _reset_geo_caches()

    report_path = tmp_path / "attack_paths.json"
    target = "https://demo.testfire.net"

    initial = main._resolve_nmap_report_geo_context(target=target, report_path=report_path)
    assert initial["resolved_ip"] == "n/a"

    report_path.write_text(
        json.dumps(
            {
                "offensive_integration": {
                    "target": target,
                    "findings": [
                        {
                            "tool": "nmap",
                            "type": "host",
                            "metadata": {"ip_address": "65.61.137.117"},
                        }
                    ],
                }
            }
        ),
        encoding="utf-8",
    )

    monkeypatch.setattr(
        main,
        "_lookup_ip_geolocation",
        lambda _ip: {
            "ip": "65.61.137.117",
            "city": "Dallas",
            "country": "United States",
            "country_code": "US",
            "continent_code": "NA",
            "latitude": 32.78,
            "longitude": -96.80,
        },
    )

    refreshed = main._resolve_nmap_report_geo_context(target=target, report_path=report_path)

    assert refreshed["resolved_ip"] == "65.61.137.117"
    assert "Dallas" in refreshed["geo_location"]


def test_ansi_dashboard_heartbeat_triggers_periodic_render():
    calls = {"count": 0}

    class _FakeDashboard:
        def __init__(self):
            self._started = True

        def render(self):
            calls["count"] += 1
            self._started = False

    asyncio.run(main._ansi_dashboard_heartbeat(_FakeDashboard()))

    assert calls["count"] == 1


def test_vscode_safe_intro_does_not_render_world_map_block(monkeypatch):
    printed: list[str] = []

    monkeypatch.setattr(main.time, "sleep", lambda _seconds: None)
    monkeypatch.setattr(main, "_style_text_ansi", lambda text, *, code: text)
    monkeypatch.setattr(
        main,
        "_resolve_intro_geo_context",
        lambda _args: {
            "region_label": "EUROPE",
            "resolved_ip": "8.8.8.8",
            "geo_location": "Frankfurt, DE (50.11, 8.68)",
            "nmap_resolved_ip": "8.8.4.4",
            "nmap_geo_location": "Frankfurt, DE (50.11, 8.68)",
        },
    )

    def _fake_print(*args, **kwargs):
        printed.append(" ".join(str(part) for part in args))

    monkeypatch.setattr(builtins, "print", _fake_print)

    args = argparse.Namespace(
        offensive_mode="manual",
        offensive_target="https://demo.testfire.net",
        full_control=True,
        dashboard_enable=False,
        live_log=False,
        asset_aware_cves=False,
        wordlist_profile=None,
        ffuf_wordlist=None,
        cve_profile="local",
        offensive_config="data/offensive_config.json",
    )

    main._render_terminal_intro_vscode_safe(args=args, boot_lines=("boot",), speed=0.01)

    assert not any("GLOBAL TARGET MAP :: LIVE FEED" in line for line in printed)


def test_format_intro_progress_line_strips_embedded_percent_prefix():
    pct, line = main._format_intro_progress_line(index=1, total=2, message="[03%] bootloader online")

    assert pct == 50
    assert "[050%]" in line
    assert "bootloader online" in line
    assert "[03%]" not in line


def test_vscode_safe_intro_prints_progress_percent_lines(monkeypatch):
    printed: list[str] = []

    monkeypatch.setattr(main.time, "sleep", lambda _seconds: None)
    monkeypatch.setattr(main, "_style_text_ansi", lambda text, *, code: text)
    monkeypatch.setattr(
        main,
        "_resolve_intro_geo_context",
        lambda _args: {
            "region_label": "EUROPE",
            "resolved_ip": "8.8.8.8",
            "geo_location": "Frankfurt, DE (50.11, 8.68)",
            "nmap_resolved_ip": "8.8.4.4",
            "nmap_geo_location": "Frankfurt, DE (50.11, 8.68)",
        },
    )

    def _fake_print(*args, **kwargs):
        printed.append(" ".join(str(part) for part in args))

    monkeypatch.setattr(builtins, "print", _fake_print)

    args = argparse.Namespace(
        offensive_mode="manual",
        offensive_target="https://demo.testfire.net",
        full_control=True,
        dashboard_enable=False,
        live_log=False,
        asset_aware_cves=False,
        wordlist_profile=None,
        ffuf_wordlist=None,
        cve_profile="local",
        offensive_config="data/offensive_config.json",
    )

    main._render_terminal_intro_vscode_safe(
        args=args,
        boot_lines=("step one", "step two"),
        speed=0.01,
    )

    assert any("[050%]" in line for line in printed)
    assert any("[100%]" in line for line in printed)


def test_normalize_menu_selection_ignores_arrow_escape_sequences():
    assert main._normalize_menu_selection("^[[A^[[A") is None
    assert main._normalize_menu_selection("\x1b[A\x1b[B") is None
    assert main._normalize_menu_selection("9") == "9"


def test_build_missing_tools_guidance_contains_install_hints():
    text = main._build_missing_tools_guidance(["nuclei", "nmap"])

    assert "apt-get install -y nmap" in text
    assert "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest" in text
    assert "disable --full-control" in text


def test_binary_exists_detects_gobin_candidate(monkeypatch, tmp_path):
    gobin = tmp_path / "go-bin"
    gobin.mkdir()
    (gobin / "nuclei").write_text("", encoding="utf-8")

    monkeypatch.setenv("GOBIN", str(gobin))
    monkeypatch.setattr(main.shutil, "which", lambda _name: None)

    assert main._binary_exists("nuclei") is True


def test_detect_missing_core_tools_prefers_command_factory_result(monkeypatch):
    cfg = OffensiveConfig(
        enabled=True,
        mode=OffensiveMode.MANUAL,
        target="https://demo.testfire.net",
        tools=("nmap", "ffuf", "nuclei"),
    )

    class _FakeFactory:
        def __init__(self, _config):  # noqa: D401, ANN001
            pass

        def build(self):
            return [types.SimpleNamespace(tool="nuclei", argv=("nuclei", "-u", "https://demo.testfire.net"))]

        def missing_tools(self, _commands):  # noqa: ANN001
            return ["nuclei"]

    monkeypatch.setattr(main, "CommandFactory", _FakeFactory)
    monkeypatch.setattr(main, "_binary_exists", lambda _binary: True)

    missing = main._detect_missing_core_tools(cfg)

    assert missing == ["nuclei"]


def test_prepare_offensive_toolchain_raises_for_full_control_when_missing_tools(monkeypatch):
    args = argparse.Namespace(auto_arm_tools=False)
    cfg = OffensiveConfig(
        enabled=True,
        mode=OffensiveMode.MANUAL,
        target="https://demo.testfire.net",
        full_control=True,
        tools=("nmap", "ffuf", "nuclei"),
    )

    monkeypatch.setattr(main, "_detect_missing_core_tools", lambda _cfg: ["nuclei"])
    monkeypatch.setattr(main, "_ensure_go_bin_on_path", lambda: None)

    with pytest.raises(main.OffensiveConfigError, match="missing: nuclei"):
        asyncio.run(main._prepare_offensive_toolchain(args, cfg))


def test_resolve_apt_command_prefix_prefers_interactive_sudo_when_needed(monkeypatch):
    class _TtyStream:
        def isatty(self) -> bool:
            return True

    monkeypatch.setattr(main, "_is_root_user", lambda: False)
    monkeypatch.setattr(main, "_can_passwordless_sudo", lambda: False)
    monkeypatch.setattr(main.shutil, "which", lambda name: "/usr/bin/sudo" if name == "sudo" else None)
    monkeypatch.setattr(main.sys, "stdin", _TtyStream())
    monkeypatch.setattr(main.sys, "stdout", _TtyStream())

    prefix, interactive = main._resolve_apt_command_prefix()

    assert prefix == ["sudo"]
    assert interactive is True


def test_resolve_apt_command_prefix_returns_none_without_interactive_or_passwordless(monkeypatch):
    class _NoTtyStream:
        def isatty(self) -> bool:
            return False

    monkeypatch.setattr(main, "_is_root_user", lambda: False)
    monkeypatch.setattr(main, "_can_passwordless_sudo", lambda: False)
    monkeypatch.setattr(main.shutil, "which", lambda name: "/usr/bin/sudo" if name == "sudo" else None)
    monkeypatch.setattr(main.sys, "stdin", _NoTtyStream())
    monkeypatch.setattr(main.sys, "stdout", _NoTtyStream())

    prefix, interactive = main._resolve_apt_command_prefix()

    assert prefix is None
    assert interactive is False


def test_resolve_cve_profile_choice_supports_index_and_key():
    assert main._resolve_cve_profile_choice("1", current="local") == main._ordered_cve_profile_keys()[0]
    assert main._resolve_cve_profile_choice("local", current="nvd_recent") == "local"


def test_resolve_cve_profile_choice_returns_none_for_invalid_value():
    assert main._resolve_cve_profile_choice("unknown-profile", current="local") is None


def test_cycle_cve_sync_policy_rotates_known_values():
    assert main._cycle_cve_sync_policy("if-stale") == "always"
    assert main._cycle_cve_sync_policy("always") == "never"
    assert main._cycle_cve_sync_policy("never") == "if-stale"


def test_resolve_cve_profile_selection_supports_multi_source_merge():
    profile, priority, disabled = main._resolve_cve_profile_selection(
        "nvd_recent,ghsa_recent",
        current_profile="local",
        current_priority=None,
        current_disabled=None,
    )

    assert profile == "all_plus"
    assert priority == "nvd_recent,ghsa_recent"
    assert disabled == "cisa_kev"


def test_resolve_cve_profile_selection_rejects_local_with_multiple():
    resolved = main._resolve_cve_profile_selection(
        "local,nvd_recent",
        current_profile="local",
        current_priority=None,
        current_disabled=None,
    )

    assert resolved is None


def test_active_cve_sources_for_all_plus_respects_disabled_list():
    args = argparse.Namespace(
        cve_profile="all_plus",
        cve_disable_sources="ghsa_recent,osv_enriched",
    )

    assert main._active_cve_sources(args) == ("nvd_recent", "cisa_kev")


def test_should_autosync_selected_profile_requires_cache_when_policy_never(tmp_path):
    args = argparse.Namespace(
        cve_auto_download=False,
        cve_sync_policy="never",
        cve_cache_dir=tmp_path,
    )

    assert main._should_autosync_selected_profile(args, "all_plus") is True

    (tmp_path / "all_plus.json").write_text("{}", encoding="utf-8")
    assert main._should_autosync_selected_profile(args, "all_plus") is False


def test_apply_cve_profile_selection_by_index_triggers_one_shot_sync(monkeypatch, tmp_path):
    calls = {"sync": 0}

    monkeypatch.setattr(main, "_print_status", lambda *args, **kwargs: None)
    monkeypatch.setattr(main, "_sync_selected_cve_profile_now", lambda _args: calls.__setitem__("sync", calls["sync"] + 1))

    args = argparse.Namespace(
        cve_profile="local",
        cve_source_priority=None,
        cve_disable_sources=None,
        cve_auto_download=False,
        cve_sync_policy="never",
        cve_cache_dir=tmp_path,
    )

    ok = main._apply_cve_profile_selection(args, "5")

    assert ok is True
    assert args.cve_profile == "all_plus"
    assert calls["sync"] == 1


def test_looks_like_cve_profile_input_respects_menu_action_digits():
    assert main._looks_like_cve_profile_input("0") is False
    assert main._looks_like_cve_profile_input("1") is False
    assert main._looks_like_cve_profile_input("4") is False
    assert main._looks_like_cve_profile_input("5") is True
    assert main._looks_like_cve_profile_input("all_plus") is True
    assert main._looks_like_cve_profile_input("1,2") is True


def test_normalize_target_for_match_handles_invalid_ipv6_url():
    normalized = main._normalize_target_for_match("http://[2001:db8::1")

    assert normalized
    assert "2001:db8::1" in normalized


def test_extract_target_host_handles_invalid_ipv6_url():
    host = main._extract_target_host("http://[2001:db8::1")

    assert host is not None
    assert "2001:db8::1" in host


def test_render_terminal_intro_uses_streaming_path_in_wsl(monkeypatch):
    called = {"streaming": False}

    monkeypatch.setattr(main, "_should_render_intro", lambda _args: True)
    monkeypatch.setattr(main, "_build_intro_boot_lines", lambda _args: ("boot",))
    monkeypatch.setattr(main, "_is_vscode_terminal", lambda: False)
    monkeypatch.setattr(main, "_is_wsl_runtime", lambda: True)

    def _fake_streaming(*, args, boot_lines, speed):
        called["streaming"] = True

    monkeypatch.setattr(main, "_render_terminal_intro_vscode_safe", _fake_streaming)

    args = argparse.Namespace(
        no_intro=False,
        quiet=False,
        list_cve_profiles=False,
        list_wordlists=False,
        intro_speed=0.05,
    )

    main._render_terminal_intro(args)

    assert called["streaming"] is True
