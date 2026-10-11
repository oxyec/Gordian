"""CLI contract: one-shot mode, exit codes and flag validation."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

import main

ROOT = Path(main.__file__).parent


def test_once_writes_reports_and_exits_ok(tmp_path: Path):
    code = main.main(["--once", "--quiet", "--out", str(tmp_path)])

    assert code == main.EXIT_OK
    report = json.loads((tmp_path / "attack_paths.json").read_text(encoding="utf-8"))
    assert report["total_paths"] > 0
    assert (tmp_path / "attack_paths.md").exists()


def test_once_fail_on_findings_exits_with_findings_code(tmp_path: Path):
    code = main.main(["--once", "--quiet", "--fail-on-findings", "--out", str(tmp_path)])

    # Distinct from argparse's usage-error code so CI can tell them apart.
    assert code == main.EXIT_FINDINGS == 3


def test_once_missing_input_exits_with_error(tmp_path: Path):
    code = main.main(["--once", "--quiet", "--network", str(tmp_path / "missing.json"),
                      "--out", str(tmp_path)])

    assert code == main.EXIT_ERROR


@pytest.mark.parametrize("flag", ["--fail-on-findings", "--quiet", "--no-remediation",
                                  "--live-log", "--cve-profile=cisa_kev", "--top-patches=3"])
def test_one_shot_flags_require_once(flag: str, capsys):
    with pytest.raises(SystemExit) as exc:
        main._parse_args([flag])

    assert exc.value.code == 2
    assert "requires --once" in capsys.readouterr().err


def test_server_mode_defaults_do_not_trip_once_check():
    args = main._parse_args(["--headless"])

    assert args.once is False
    assert args.top_patches is None


@pytest.mark.parametrize("flags", [["--offensive-target", "10.0.0.1"],
                                   ["--scope-file", "data/scope_policy.example.json"],
                                   ["--offensive-dry-run"]])
def test_offensive_flags_rejected_with_once(flags: list[str], capsys):
    with pytest.raises(SystemExit) as exc:
        main._parse_args(["--once", *flags])

    assert exc.value.code == 2
    assert "server-managed" in capsys.readouterr().err


def test_once_applies_effective_defaults():
    args = main._parse_args(["--once"])

    assert args.top_patches == 5
    assert args.cve_profile == "local"
    assert args.fail_on_findings is False
    assert args.cve_cache_dir == ROOT / "data" / "cve_cache"


def test_once_uses_cached_cve_profile_without_network(tmp_path: Path):
    cache = tmp_path / "cache"
    cache.mkdir()
    shutil.copy(ROOT / "data" / "cve_feed.json", cache / "cisa_kev.json")

    code = main.main([
        "--once", "--quiet", "--fail-on-findings",
        "--cve-profile", "cisa_kev", "--no-cve-auto-download", "--cve-sync-policy", "never",
        "--cve-cache-dir", str(cache), "--out", str(tmp_path / "out"),
    ])

    assert code == main.EXIT_FINDINGS


def test_once_cve_sync_failure_exits_with_error(tmp_path: Path):
    code = main.main([
        "--once", "--quiet", "--cve-profile", "cisa_kev", "--no-cve-auto-download",
        "--cve-cache-dir", str(tmp_path / "empty"), "--out", str(tmp_path / "out"),
    ])

    assert code == main.EXIT_ERROR


def test_once_live_log_writes_json_events_to_stderr(tmp_path: Path, capsys):
    main.main(["--once", "--quiet", "--no-remediation", "--live-log", "--out", str(tmp_path)])

    events = [json.loads(line) for line in capsys.readouterr().err.splitlines()
              if line.startswith("{")]
    assert events[0]["type"] == "pipeline.start"
    assert events[-1]["type"] == "pipeline.done"


def test_intro_skipped_in_once_mode():
    args = main._parse_args(["--once"])

    assert main._should_render_intro(args) is False


def test_intro_uses_plain_renderer_in_wsl(monkeypatch):
    called: dict[str, bool] = {}
    monkeypatch.setenv("WSL_DISTRO_NAME", "Ubuntu")
    monkeypatch.setattr(main, "_should_render_intro", lambda _args: True)
    monkeypatch.setattr(main, "_render_intro_plain",
                        lambda _args, *, speed: called.setdefault("plain", True))

    main._render_terminal_intro(main._parse_args(["--intro-speed", "0.01"]))

    assert called == {"plain": True}
