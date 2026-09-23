from __future__ import annotations

from datetime import datetime, timedelta, timezone
import gzip
import io
import json
from pathlib import Path
import urllib.error

import pytest

from src.cve_sources import (
    CISA_KEV_URL,
    NVD_RECENT_URL,
    CVEFeedSyncError,
    describe_cve_profiles_for_cli,
    get_cve_feed_age_hours,
    get_cve_feed_last_updated,
    sync_cve_feed_profile,
)


class _FakeResponse(io.BytesIO):
    def __init__(self, payload: bytes, headers: dict[str, str] | None = None):
        super().__init__(payload)
        self.headers = headers or {}

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False


def _make_nvd_doc() -> dict:
    return {
        "CVE_Items": [
            {
                "cve": {
                    "CVE_data_meta": {"ID": "CVE-2024-1111"},
                    "description": {
                        "description_data": [
                            {"lang": "en", "value": "Remote code execution in web component."}
                        ]
                    },
                    "references": {
                        "reference_data": [
                            {"url": "https://nvd.nist.gov/vuln/detail/CVE-2024-1111"}
                        ]
                    },
                },
                "impact": {
                    "baseMetricV3": {
                        "cvssV3": {"baseScore": 9.8, "baseSeverity": "CRITICAL"},
                        "exploitabilityScore": 8.6,
                    }
                },
            }
        ]
    }


def _make_kev_doc() -> dict:
    return {
        "vulnerabilities": [
            {
                "cveID": "CVE-2024-1111",
                "vendorProject": "Acme",
                "product": "Portal",
                "vulnerabilityName": "RCE in portal",
                "shortDescription": "Actively exploited remote code execution.",
                "knownRansomwareCampaignUse": "Known",
            },
            {
                "cveID": "CVE-2024-2222",
                "vendorProject": "Acme",
                "product": "Gateway",
                "vulnerabilityName": "Auth bypass",
                "shortDescription": "Known exploited vulnerability.",
                "knownRansomwareCampaignUse": "Unknown",
            },
        ]
    }


def test_describe_cve_profiles_includes_local_and_all_latest():
    lines = describe_cve_profiles_for_cli()

    assert any("local" in line for line in lines)
    assert any("all_latest" in line for line in lines)


def test_sync_cisa_profile_downloads_and_normalizes(monkeypatch, tmp_path: Path):
    kev_bytes = json.dumps(_make_kev_doc()).encode("utf-8")

    def _fake_urlopen(request, timeout=45):  # noqa: ARG001
        assert request.full_url == CISA_KEV_URL
        return _FakeResponse(kev_bytes, headers={"ETag": '"kev-v1"'})

    monkeypatch.setattr("urllib.request.urlopen", _fake_urlopen)

    out, state, count = sync_cve_feed_profile(
        "cisa_kev",
        cache_dir=tmp_path,
        auto_download=True,
        max_items=50,
    )

    assert state == "downloaded"
    assert count == 2
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert payload["cves"][0]["cve_id"].startswith("CVE-")
    assert payload["cves"][0]["severity"] in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}


def test_sync_nvd_recent_downloads_and_normalizes(monkeypatch, tmp_path: Path):
    nvd_gz = gzip.compress(json.dumps(_make_nvd_doc()).encode("utf-8"))

    def _fake_urlopen(request, timeout=45):  # noqa: ARG001
        assert request.full_url == NVD_RECENT_URL
        return _FakeResponse(nvd_gz, headers={"ETag": '"nvd-v1"'})

    monkeypatch.setattr("urllib.request.urlopen", _fake_urlopen)

    out, state, count = sync_cve_feed_profile(
        "nvd_recent",
        cache_dir=tmp_path,
        auto_download=True,
        max_items=10,
    )

    assert state == "downloaded"
    assert count == 1
    payload = json.loads(out.read_text(encoding="utf-8"))
    cve = payload["cves"][0]
    assert cve["cve_id"] == "CVE-2024-1111"
    assert cve["cvss_v3"] == 9.8
    assert cve["severity"] == "CRITICAL"


def test_sync_nvd_recent_uses_source_cache_when_remote_forbidden(monkeypatch, tmp_path: Path):
    source_cache = tmp_path / "_sources" / "nvd_recent.json"
    source_cache.parent.mkdir(parents=True, exist_ok=True)
    source_cache.write_text(
        json.dumps(
            {
                "generated_at": "2026-01-01T00:00:00Z",
                "source": "nvd_recent",
                "cves": [
                    {
                        "cve_id": "CVE-2024-9999",
                        "description": "Cached fallback row",
                        "severity": "HIGH",
                        "cvss_v3": 8.0,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    def _fake_urlopen(request, timeout=45):  # noqa: ARG001
        raise urllib.error.HTTPError(request.full_url, 403, "Forbidden", hdrs=None, fp=None)

    monkeypatch.setattr("urllib.request.urlopen", _fake_urlopen)

    out, state, count = sync_cve_feed_profile(
        "nvd_recent",
        cache_dir=tmp_path,
        auto_download=True,
        max_items=10,
        sync_policy="always",
    )

    assert state == "existing"
    assert count == 1
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert payload["cves"][0]["cve_id"] == "CVE-2024-9999"


def test_sync_all_latest_merges_and_marks_weaponized(monkeypatch, tmp_path: Path):
    nvd_gz = gzip.compress(json.dumps(_make_nvd_doc()).encode("utf-8"))
    kev_bytes = json.dumps(_make_kev_doc()).encode("utf-8")

    def _fake_urlopen(request, timeout=45):  # noqa: ARG001
        if request.full_url == NVD_RECENT_URL:
            return _FakeResponse(nvd_gz)
        if request.full_url == CISA_KEV_URL:
            return _FakeResponse(kev_bytes)
        raise AssertionError(f"unexpected URL: {request.full_url}")

    monkeypatch.setattr("urllib.request.urlopen", _fake_urlopen)

    out, state, count = sync_cve_feed_profile(
        "all_latest",
        cache_dir=tmp_path,
        auto_download=True,
        max_items=10,
    )

    assert state == "downloaded"
    assert count >= 2
    payload = json.loads(out.read_text(encoding="utf-8"))
    by_id = {row["cve_id"]: row for row in payload["cves"]}
    assert by_id["CVE-2024-1111"]["weaponized"] is True


def test_sync_without_download_uses_existing_cache(tmp_path: Path):
    cached = tmp_path / "cisa_kev.json"
    cached.write_text(
        json.dumps(
            {
                "feed_version": "dynamic-1.0",
                "source": "cached",
                "generated_at": "2026-01-01T00:00:00Z",
                "cves": [{"cve_id": "CVE-1"}],
            }
        ),
        encoding="utf-8",
    )

    out, state, count = sync_cve_feed_profile(
        "cisa_kev",
        cache_dir=tmp_path,
        auto_download=False,
        max_items=10,
    )

    assert out == cached
    assert state in {"existing", "existing-stale"}
    assert count == 1


def test_sync_without_download_and_without_cache_raises(tmp_path: Path):
    with pytest.raises(CVEFeedSyncError, match="cached CVE feed not found"):
        sync_cve_feed_profile(
            "nvd_recent",
            cache_dir=tmp_path,
            auto_download=False,
            max_items=10,
        )


def test_sync_policy_if_stale_uses_fresh_cache_without_download(monkeypatch, tmp_path: Path):
    cached = tmp_path / "cisa_kev.json"
    cached.write_text(
        json.dumps(
            {
                "feed_version": "dynamic-1.0",
                "source": "cached",
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "cves": [{"cve_id": "CVE-1"}],
            }
        ),
        encoding="utf-8",
    )

    def _should_not_download(*_args, **_kwargs):
        raise AssertionError("download should not be called for fresh cache")

    monkeypatch.setattr("urllib.request.urlopen", _should_not_download)

    out, state, count = sync_cve_feed_profile(
        "cisa_kev",
        cache_dir=tmp_path,
        auto_download=True,
        max_items=10,
        sync_policy="if-stale",
        stale_after_hours=24,
    )

    assert out == cached
    assert state == "existing"
    assert count == 1


def test_sync_policy_if_stale_redownloads_stale_cache(monkeypatch, tmp_path: Path):
    cached = tmp_path / "cisa_kev.json"
    cached.write_text(
        json.dumps(
            {
                "feed_version": "dynamic-1.0",
                "source": "cached",
                "generated_at": "2000-01-01T00:00:00Z",
                "cves": [{"cve_id": "CVE-OLD"}],
            }
        ),
        encoding="utf-8",
    )

    kev_bytes = json.dumps(_make_kev_doc()).encode("utf-8")

    def _fake_urlopen(request, timeout=45):  # noqa: ARG001
        assert request.full_url == CISA_KEV_URL
        return _FakeResponse(kev_bytes, headers={"ETag": '"kev-v2"'})

    monkeypatch.setattr("urllib.request.urlopen", _fake_urlopen)

    out, state, count = sync_cve_feed_profile(
        "cisa_kev",
        cache_dir=tmp_path,
        auto_download=True,
        max_items=10,
        sync_policy="if-stale",
        stale_after_hours=1,
    )

    assert out == cached
    assert state == "downloaded"
    assert count == 2


def test_sync_policy_never_requires_existing_cache(tmp_path: Path):
    with pytest.raises(CVEFeedSyncError, match="blocks downloads"):
        sync_cve_feed_profile(
            "nvd_recent",
            cache_dir=tmp_path,
            auto_download=True,
            max_items=10,
            sync_policy="never",
        )


def test_get_cve_feed_age_prefers_generated_at(tmp_path: Path):
    cached = tmp_path / "nvd_recent.json"
    generated_at = datetime.now(timezone.utc) - timedelta(hours=2)
    cached.write_text(
        json.dumps(
            {
                "feed_version": "dynamic-1.0",
                "source": "cached",
                "generated_at": generated_at.isoformat(),
                "cves": [{"cve_id": "CVE-1"}],
            }
        ),
        encoding="utf-8",
    )

    age = get_cve_feed_age_hours(cached)
    updated_at = get_cve_feed_last_updated(cached)

    assert age is not None
    assert 1.5 <= age <= 2.5
    assert updated_at is not None


def test_sync_schedule_daily_defers_download_when_cache_is_recent(monkeypatch, tmp_path: Path):
    cached = tmp_path / "nvd_recent.json"
    cached.write_text(
        json.dumps(
            {
                "feed_version": "dynamic-1.0",
                "source": "cached",
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "cves": [{"cve_id": "CVE-1"}],
            }
        ),
        encoding="utf-8",
    )

    def _should_not_download(*_args, **_kwargs):
        raise AssertionError("download should not happen due to daily schedule")

    monkeypatch.setattr("urllib.request.urlopen", _should_not_download)

    out, state, count = sync_cve_feed_profile(
        "nvd_recent",
        cache_dir=tmp_path,
        auto_download=True,
        max_items=10,
        sync_policy="always",
        sync_schedule="daily",
    )

    assert out == cached
    assert state == "existing-scheduled"
    assert count == 1


def test_sync_uses_conditional_headers_and_not_modified(monkeypatch, tmp_path: Path):
    nvd_gz = gzip.compress(json.dumps(_make_nvd_doc()).encode("utf-8"))
    calls = {"count": 0}

    def _fake_urlopen(request, timeout=45):  # noqa: ARG001
        calls["count"] += 1
        if calls["count"] == 1:
            return _FakeResponse(nvd_gz, headers={"ETag": '"nvd-v1"', "Last-Modified": "Tue, 10 Jan 2026 10:00:00 GMT"})

        normalized_headers = {key.lower(): value for key, value in request.headers.items()}
        assert normalized_headers.get("if-none-match") == '"nvd-v1"'
        raise urllib.error.HTTPError(request.full_url, 304, "Not Modified", hdrs=None, fp=None)

    monkeypatch.setattr("urllib.request.urlopen", _fake_urlopen)

    first_out, first_state, first_count = sync_cve_feed_profile(
        "nvd_recent",
        cache_dir=tmp_path,
        auto_download=True,
        max_items=10,
        sync_policy="always",
    )
    second_out, second_state, second_count = sync_cve_feed_profile(
        "nvd_recent",
        cache_dir=tmp_path,
        auto_download=True,
        max_items=10,
        sync_policy="always",
    )

    assert first_out == second_out
    assert first_state == "downloaded"
    assert second_state == "existing-not-modified"
    assert first_count == second_count == 1


def test_sync_all_plus_merges_ghsa_and_osv(monkeypatch, tmp_path: Path):
    nvd_gz = gzip.compress(json.dumps(_make_nvd_doc()).encode("utf-8"))
    kev_bytes = json.dumps(_make_kev_doc()).encode("utf-8")
    ghsa_doc = [
        {
            "ghsa_id": "GHSA-xxxx-yyyy-zzzz",
            "summary": "Portal RCE",
            "description": "Affects portal component CVE-2024-1111",
            "severity": "high",
            "identifiers": [
                {"type": "GHSA", "value": "GHSA-xxxx-yyyy-zzzz"},
                {"type": "CVE", "value": "CVE-2024-1111"},
            ],
            "references": [{"url": "https://github.com/advisories/GHSA-xxxx-yyyy-zzzz"}],
        }
    ]
    osv_doc = {
        "id": "CVE-2024-1111",
        "aliases": ["CVE-2024-1111"],
        "summary": "OSV summary",
        "details": "OSV details for CVE-2024-1111",
        "references": [{"type": "WEB", "url": "https://osv.dev/vulnerability/CVE-2024-1111"}],
    }

    def _fake_urlopen(request, timeout=45):  # noqa: ARG001
        url = request.full_url
        if url == NVD_RECENT_URL:
            return _FakeResponse(nvd_gz)
        if url == CISA_KEV_URL:
            return _FakeResponse(kev_bytes)
        if url.startswith("https://api.github.com/advisories"):
            return _FakeResponse(json.dumps(ghsa_doc).encode("utf-8"))
        if url.startswith("https://api.osv.dev/v1/vulns/"):
            return _FakeResponse(json.dumps(osv_doc).encode("utf-8"))
        raise AssertionError(f"unexpected URL: {url}")

    monkeypatch.setattr("urllib.request.urlopen", _fake_urlopen)

    out, state, count = sync_cve_feed_profile(
        "all_plus",
        cache_dir=tmp_path,
        auto_download=True,
        max_items=20,
        osv_lookup_limit=10,
    )

    assert state == "downloaded"
    assert count >= 2
    payload = json.loads(out.read_text(encoding="utf-8"))
    by_id = {row["cve_id"]: row for row in payload["cves"]}
    assert "CVE-2024-1111" in by_id
    assert by_id["CVE-2024-1111"].get("source_confidence") is not None


def test_sync_all_plus_continues_when_nvd_forbidden(monkeypatch, tmp_path: Path):
    kev_bytes = json.dumps(_make_kev_doc()).encode("utf-8")
    ghsa_doc = [
        {
            "ghsa_id": "GHSA-403-test",
            "summary": "Fallback advisory",
            "description": "Used when NVD is unavailable",
            "severity": "medium",
            "identifiers": [
                {"type": "GHSA", "value": "GHSA-403-test"},
                {"type": "CVE", "value": "CVE-2024-2222"},
            ],
            "references": [{"url": "https://github.com/advisories/GHSA-403-test"}],
        }
    ]

    def _fake_urlopen(request, timeout=45):  # noqa: ARG001
        url = request.full_url
        if url == NVD_RECENT_URL:
            raise urllib.error.HTTPError(url, 403, "Forbidden", hdrs=None, fp=None)
        if url == CISA_KEV_URL:
            return _FakeResponse(kev_bytes)
        if url.startswith("https://api.github.com/advisories"):
            return _FakeResponse(json.dumps(ghsa_doc).encode("utf-8"))
        raise AssertionError(f"unexpected URL: {url}")

    monkeypatch.setattr("urllib.request.urlopen", _fake_urlopen)

    out, state, count = sync_cve_feed_profile(
        "all_plus",
        cache_dir=tmp_path,
        auto_download=True,
        max_items=20,
        osv_lookup_limit=0,
    )

    assert state == "downloaded"
    assert count >= 1
    payload = json.loads(out.read_text(encoding="utf-8"))
    by_id = {row["cve_id"]: row for row in payload["cves"]}
    assert "CVE-2024-2222" in by_id
    warnings = payload.get("source_warnings") or []
    assert any("nvd_recent sync failed" in message for message in warnings)


def test_sync_all_plus_allows_disabling_sources(monkeypatch, tmp_path: Path):
    nvd_gz = gzip.compress(json.dumps(_make_nvd_doc()).encode("utf-8"))
    kev_bytes = json.dumps(_make_kev_doc()).encode("utf-8")
    seen_urls: list[str] = []

    def _fake_urlopen(request, timeout=45):  # noqa: ARG001
        url = request.full_url
        seen_urls.append(url)
        if url == NVD_RECENT_URL:
            return _FakeResponse(nvd_gz)
        if url == CISA_KEV_URL:
            return _FakeResponse(kev_bytes)
        raise AssertionError(f"unexpected URL: {url}")

    monkeypatch.setattr("urllib.request.urlopen", _fake_urlopen)

    out, state, count = sync_cve_feed_profile(
        "all_plus",
        cache_dir=tmp_path,
        auto_download=True,
        max_items=20,
        osv_lookup_limit=50,
        disabled_sources=("ghsa_recent", "osv_enriched"),
    )

    assert state == "downloaded"
    assert count >= 1
    assert all("api.github.com/advisories" not in url for url in seen_urls)
    assert all("api.osv.dev/v1/vulns/" not in url for url in seen_urls)
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert payload.get("disabled_sources") == ["ghsa_recent", "osv_enriched"]


def test_sync_all_plus_respects_custom_source_priority(monkeypatch, tmp_path: Path):
    nvd_gz = gzip.compress(json.dumps(_make_nvd_doc()).encode("utf-8"))
    kev_bytes = json.dumps(_make_kev_doc()).encode("utf-8")
    ghsa_doc = [
        {
            "ghsa_id": "GHSA-priority-test",
            "summary": "Priority override advisory",
            "description": "Priority-selected source for CVE-2024-1111",
            "severity": "critical",
            "identifiers": [
                {"type": "GHSA", "value": "GHSA-priority-test"},
                {"type": "CVE", "value": "CVE-2024-1111"},
            ],
            "references": [{"url": "https://github.com/advisories/GHSA-priority-test"}],
        }
    ]

    def _fake_urlopen(request, timeout=45):  # noqa: ARG001
        url = request.full_url
        if url == NVD_RECENT_URL:
            return _FakeResponse(nvd_gz)
        if url == CISA_KEV_URL:
            return _FakeResponse(kev_bytes)
        if url.startswith("https://api.github.com/advisories"):
            return _FakeResponse(json.dumps(ghsa_doc).encode("utf-8"))
        raise AssertionError(f"unexpected URL: {url}")

    monkeypatch.setattr("urllib.request.urlopen", _fake_urlopen)

    out, state, count = sync_cve_feed_profile(
        "all_plus",
        cache_dir=tmp_path,
        auto_download=True,
        max_items=20,
        osv_lookup_limit=0,
        source_priority=("ghsa_recent", "cisa_kev", "nvd_recent", "osv_enriched"),
    )

    assert state == "downloaded"
    assert count >= 1
    payload = json.loads(out.read_text(encoding="utf-8"))
    by_id = {row["cve_id"]: row for row in payload["cves"]}
    assert by_id["CVE-2024-1111"]["source"] == "ghsa_recent"


def test_sync_all_latest_raises_when_all_sources_disabled(tmp_path: Path):
    with pytest.raises(CVEFeedSyncError, match="no enabled sources"):
        sync_cve_feed_profile(
            "all_latest",
            cache_dir=tmp_path,
            auto_download=True,
            max_items=10,
            disabled_sources=("nvd_recent", "cisa_kev"),
        )
