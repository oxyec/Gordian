"""Wordlist catalog, recommendation, and download helpers for ffuf integration."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable
import urllib.error
import urllib.request

from .config import Intensity, SpeedProfile


@dataclass(frozen=True)
class WordlistProfile:
    key: str
    title: str
    description: str
    source_repo: str
    raw_url: str
    filename: str


WORDLIST_CATALOG: dict[str, WordlistProfile] = {
    "seclists_common": WordlistProfile(
        key="seclists_common",
        title="SecLists Common",
        description="Balanced default for directory/file discovery.",
        source_repo="danielmiessler/SecLists",
        raw_url="https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt",
        filename="seclists_common.txt",
    ),
    "seclists_raft_medium": WordlistProfile(
        key="seclists_raft_medium",
        title="SecLists RAFT Medium Directories",
        description="Medium-sized directory coverage with good signal/noise ratio.",
        source_repo="danielmiessler/SecLists",
        raw_url="https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-medium-directories.txt",
        filename="seclists_raft_medium_directories.txt",
    ),
    "seclists_raft_large": WordlistProfile(
        key="seclists_raft_large",
        title="SecLists RAFT Large Directories",
        description="High coverage and aggressive fuzzing profile.",
        source_repo="danielmiessler/SecLists",
        raw_url="https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-large-directories.txt",
        filename="seclists_raft_large_directories.txt",
    ),
    "seclists_raft_small": WordlistProfile(
        key="seclists_raft_small",
        title="SecLists RAFT Small Directories",
        description="Low-noise directory discovery profile for constrained scans.",
        source_repo="danielmiessler/SecLists",
        raw_url="https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-small-directories.txt",
        filename="seclists_raft_small_directories.txt",
    ),
    "seclists_quickhits": WordlistProfile(
        key="seclists_quickhits",
        title="SecLists QuickHits",
        description="High-value endpoints list commonly useful in bug bounty recon.",
        source_repo="danielmiessler/SecLists",
        raw_url="https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/quickhits.txt",
        filename="seclists_quickhits.txt",
    ),
    "ffuf_common": WordlistProfile(
        key="ffuf_common",
        title="ffuf Common",
        description="Compact ffuf-maintained starter list for quick probes.",
        source_repo="ffuf/ffuf",
        raw_url="https://raw.githubusercontent.com/ffuf/ffuf/master/wordlists/common.txt",
        filename="ffuf_common.txt",
    ),
    "ffuf_parameters": WordlistProfile(
        key="ffuf_parameters",
        title="ffuf Parameters",
        description="Useful for API/web parameter discovery.",
        source_repo="ffuf/ffuf",
        raw_url="https://raw.githubusercontent.com/ffuf/ffuf/master/wordlists/parameters.txt",
        filename="ffuf_parameters.txt",
    ),
}


class WordlistDownloadError(RuntimeError):
    """Raised when a selected wordlist cannot be downloaded."""


def list_wordlist_profiles() -> tuple[WordlistProfile, ...]:
    return tuple(WORDLIST_CATALOG.values())


def get_wordlist_profile(profile_key: str | None) -> WordlistProfile | None:
    if profile_key is None:
        return None
    return WORDLIST_CATALOG.get(profile_key.strip().lower())


def recommended_wordlist_profiles(
    *,
    target: str | None,
    speed: SpeedProfile,
    intensity: Intensity,
    tech_hints: tuple[str, ...] = (),
    bugbounty_mode: bool = False,
) -> list[str]:
    picks: list[str] = []
    lowered_target = (target or "").lower()
    hints = {hint.strip().lower() for hint in tech_hints if hint.strip()}

    # URL/host string is still useful as an implicit hint source.
    if lowered_target:
        hints.add(lowered_target)

    if _contains_any(hints, ("api", "graphql", "openapi", "swagger", "rest")):
        picks.append("ffuf_parameters")

    if _contains_any(hints, ("wordpress", "wp-", "wpadmin", "plugin", "cms")):
        picks.extend(["seclists_quickhits", "seclists_raft_medium"])

    if _contains_any(hints, ("react", "nextjs", "angular", "vue", "spa", "js")):
        picks.extend(["ffuf_common", "seclists_quickhits"])

    if _contains_any(hints, ("mobile", "android", "ios")):
        picks.extend(["seclists_quickhits", "ffuf_parameters"])

    if bugbounty_mode:
        if speed is SpeedProfile.STEALTH or intensity is Intensity.LOW:
            picks.extend(["ffuf_common", "seclists_raft_small"])
        else:
            picks.extend(["seclists_common", "seclists_raft_medium"])
    else:
        if speed is SpeedProfile.STEALTH or intensity is Intensity.LOW:
            picks.append("ffuf_common")
        elif speed is SpeedProfile.AGGRESSIVE or intensity is Intensity.HIGH:
            picks.append("seclists_raft_large")
        else:
            picks.extend(["seclists_common", "seclists_raft_medium"])

    picks.append("seclists_common")
    return _dedupe_existing(picks)


def resolve_wordlist_store_dir(store_dir: str, *, root_dir: Path | None = None) -> Path:
    path = Path(store_dir)
    if path.is_absolute() or root_dir is None:
        return path
    return root_dir / path


def ensure_wordlist(
    profile_key: str,
    *,
    store_dir: Path,
    auto_download: bool,
    timeout_seconds: int = 30,
) -> tuple[Path, str]:
    profile = get_wordlist_profile(profile_key)
    if profile is None:
        raise WordlistDownloadError(f"unknown wordlist profile: {profile_key}")

    store_dir.mkdir(parents=True, exist_ok=True)
    destination = store_dir / profile.filename

    if destination.exists() and destination.stat().st_size > 0:
        return destination, "existing"

    if not auto_download:
        return destination, "missing"

    data = _download_bytes(profile.raw_url, timeout_seconds=timeout_seconds)
    destination.write_bytes(data)
    return destination, "downloaded"


def describe_profiles_for_cli() -> list[str]:
    lines: list[str] = []
    for profile in list_wordlist_profiles():
        lines.append(
            f"- {profile.key}: {profile.title} | {profile.source_repo} | {profile.description}"
        )
    return lines


def _download_bytes(url: str, *, timeout_seconds: int) -> bytes:
    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": "gordian-offensive-hub/1.0",
            "Accept": "text/plain,application/octet-stream;q=0.9,*/*;q=0.1",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
            payload = response.read()
    except urllib.error.URLError as exc:
        raise WordlistDownloadError(f"download failed for {url}: {exc}") from exc

    if not payload or not payload.strip():
        raise WordlistDownloadError(f"downloaded wordlist is empty: {url}")
    return payload


def _dedupe_existing(keys: Iterable[str]) -> list[str]:
    ordered: list[str] = []
    seen: set[str] = set()
    for key in keys:
        if key not in WORDLIST_CATALOG:
            continue
        if key in seen:
            continue
        seen.add(key)
        ordered.append(key)
    return ordered


def _contains_any(hints: set[str], terms: tuple[str, ...]) -> bool:
    for hint in hints:
        for term in terms:
            if term in hint:
                return True
    return False
