from __future__ import annotations

import io

from src.offensive.config import Intensity, SpeedProfile
from src.offensive.wordlists import (
    ensure_wordlist,
    recommended_wordlist_profiles,
    resolve_wordlist_store_dir,
)


def test_recommended_wordlists_prioritize_api_targets():
    picks = recommended_wordlist_profiles(
        target="https://api.example.com",
        speed=SpeedProfile.BALANCED,
        intensity=Intensity.MEDIUM,
    )

    assert picks
    assert picks[0] == "ffuf_parameters"


def test_recommended_wordlists_use_tech_hints_for_wordpress():
    picks = recommended_wordlist_profiles(
        target="https://portal.example.com",
        speed=SpeedProfile.BALANCED,
        intensity=Intensity.MEDIUM,
        tech_hints=("wordpress", "php"),
    )

    assert "seclists_quickhits" in picks


def test_recommended_wordlists_bugbounty_mode_avoids_raft_large():
    picks = recommended_wordlist_profiles(
        target="https://shop.example.com",
        speed=SpeedProfile.AGGRESSIVE,
        intensity=Intensity.HIGH,
        bugbounty_mode=True,
    )

    assert "seclists_raft_large" not in picks
    assert "seclists_raft_medium" in picks


def test_resolve_wordlist_store_dir_supports_relative_paths(tmp_path):
    resolved = resolve_wordlist_store_dir("data/wordlists", root_dir=tmp_path)

    assert resolved == tmp_path / "data" / "wordlists"


def test_ensure_wordlist_downloads_when_missing(monkeypatch, tmp_path):
    class _FakeResponse(io.BytesIO):
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

    def _fake_urlopen(_request, timeout=30):  # noqa: ARG001
        return _FakeResponse(b"admin\nlogin\nbackup\n")

    monkeypatch.setattr("urllib.request.urlopen", _fake_urlopen)
    destination, state = ensure_wordlist(
        "ffuf_common",
        store_dir=tmp_path / "wordlists",
        auto_download=True,
    )

    assert state == "downloaded"
    assert destination.exists()
    assert "admin" in destination.read_text(encoding="utf-8")


def test_ensure_wordlist_returns_missing_without_autodownload(tmp_path):
    destination, state = ensure_wordlist(
        "ffuf_common",
        store_dir=tmp_path / "wordlists",
        auto_download=False,
    )

    assert state == "missing"
    assert not destination.exists()
