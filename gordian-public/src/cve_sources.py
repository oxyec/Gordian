"""CVE source catalog and auto-sync helpers.

Provides:
- built-in CVE feed profiles (NVD recent, CISA KEV, merged all_latest)
- optional auto-download to a local cache file
- normalization into Gordian's expected CVE feed schema
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import gzip
import json
from pathlib import Path
from typing import Any
from urllib.parse import quote
import urllib.error
import urllib.request

from .json_utils import try_load_json_file


@dataclass(frozen=True)
class CVEFeedProfile:
    key: str
    title: str 
    description: str


CVE_FEED_CATALOG: dict[str, CVEFeedProfile] = {
    "nvd_recent": CVEFeedProfile(
        key="nvd_recent",
        title="NVD Recent",
        description="Latest published CVEs from NVD recent feed.",
    ),
    "cisa_kev": CVEFeedProfile(
        key="cisa_kev",
        title="CISA KEV",
        description="Known exploited vulnerabilities from CISA KEV catalog.",
    ),
    "all_latest": CVEFeedProfile(
        key="all_latest",
        title="All Latest",
        description="Merged NVD recent + CISA KEV (weaponized priority).",
    ),
    "ghsa_recent": CVEFeedProfile(
        key="ghsa_recent",
        title="GHSA Recent",
        description="Recent GitHub reviewed advisories normalized into CVE rows.",
    ),
    "all_plus": CVEFeedProfile(
        key="all_plus",
        title="All Plus",
        description="Merged NVD + CISA KEV + GHSA plus OSV CVE enrichment.",
    ),
    "local": CVEFeedProfile(
        key="local",
        title="Local File",
        description="Use the --cves JSON file provided by the user.",
    ),
}


NVD_RECENT_URL = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-recent.json.gz"
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
GHSA_RECENT_URL = "https://api.github.com/advisories?type=reviewed&per_page=100"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/{}"
VALID_SYNC_POLICIES = {"always", "if-stale", "never"}
VALID_SYNC_SCHEDULES = {"off", "daily", "weekly"}
MERGE_SOURCE_KEYS = ("cisa_kev", "nvd_recent", "ghsa_recent", "osv_enriched")
DEFAULT_MERGE_SOURCE_PRIORITY = MERGE_SOURCE_KEYS


class CVEFeedSyncError(RuntimeError):
    """Raised when CVE profile sync fails."""


def list_cve_profiles() -> tuple[CVEFeedProfile, ...]:
    return tuple(CVE_FEED_CATALOG.values())


def describe_cve_profiles_for_cli() -> list[str]:
    lines: list[str] = []
    for profile in list_cve_profiles():
        lines.append(f"- {profile.key}: {profile.title} | {profile.description}")
    return lines


def sync_cve_feed_profile(
    profile_key: str,
    *,
    cache_dir: Path,
    auto_download: bool,
    max_items: int,
    sync_policy: str = "if-stale",
    sync_schedule: str = "off",
    stale_after_hours: float = 24.0,
    osv_lookup_limit: int = 80,
    source_priority: tuple[str, ...] | None = None,
    disabled_sources: tuple[str, ...] | None = None,
    timeout_seconds: int = 45,
) -> tuple[Path, str, int]:
    key = profile_key.strip().lower()
    if key not in CVE_FEED_CATALOG:
        raise CVEFeedSyncError(f"unknown CVE profile: {profile_key}")
    if key == "local":
        raise CVEFeedSyncError("'local' profile does not require sync; use --cves directly")

    policy = _normalize_sync_policy(sync_policy)
    stale_threshold = max(float(stale_after_hours), 0.5)
    schedule = _normalize_sync_schedule(sync_schedule)
    disabled = _normalize_merge_source_names(disabled_sources, field_name="disabled_sources")
    priority = _build_merge_source_priority(
        _normalize_merge_source_names(source_priority, field_name="source_priority"),
        disabled_sources=disabled,
    )

    if key in MERGE_SOURCE_KEYS and key in disabled:
        raise CVEFeedSyncError(f"profile source '{key}' is disabled by configuration")

    cache_dir.mkdir(parents=True, exist_ok=True)
    destination = cache_dir / f"{key}.json"
    cached_count = _count_cves_in_file(destination)
    cache_age_hours = get_cve_feed_age_hours(destination)
    cache_is_stale = cache_age_hours is None or cache_age_hours > stale_threshold
    schedule_due = _is_schedule_due(cache_age_hours, schedule)

    if destination.exists():
        if policy == "never":
            return destination, "existing", cached_count
        if schedule != "off" and not schedule_due:
            return destination, "existing-scheduled", cached_count
        if schedule == "off" and policy == "if-stale" and not cache_is_stale:
            return destination, "existing", cached_count
        if not auto_download:
            state = "existing-stale" if cache_is_stale else "existing"
            return destination, state, cached_count

    if policy == "never" and not destination.exists():
        raise CVEFeedSyncError(
            f"sync policy '{policy}' blocks downloads and cached feed is missing for '{key}'"
        )

    if not auto_download and not destination.exists():
        raise CVEFeedSyncError(
            f"cached CVE feed not found for profile '{key}' and auto-download is disabled"
        )

    state = "downloaded"
    source_warnings: list[str] = []
    if key == "nvd_recent":
        cves, fetch_state, warning = _fetch_source_with_cache_fallback(
            source_key="nvd_recent",
            cache_dir=cache_dir,
            max_items=max_items,
            fetcher=lambda: _fetch_nvd_recent(
                timeout_seconds=timeout_seconds,
                max_items=max_items,
                cache_dir=cache_dir,
                source_key="nvd_recent",
            ),
        )
        if warning and fetch_state == "failed":
            raise CVEFeedSyncError(warning)
        if warning:
            source_warnings.append(warning)
        if fetch_state == "not-modified" and destination.exists():
            return destination, "existing-not-modified", cached_count
        state = "downloaded" if fetch_state == "downloaded" else "existing"
    elif key == "cisa_kev":
        cves, fetch_state, warning = _fetch_source_with_cache_fallback(
            source_key="cisa_kev",
            cache_dir=cache_dir,
            max_items=max_items,
            fetcher=lambda: _fetch_cisa_kev(
                timeout_seconds=timeout_seconds,
                max_items=max_items,
                cache_dir=cache_dir,
                source_key="cisa_kev",
            ),
        )
        if warning and fetch_state == "failed":
            raise CVEFeedSyncError(warning)
        if warning:
            source_warnings.append(warning)
        if fetch_state == "not-modified" and destination.exists():
            return destination, "existing-not-modified", cached_count
        state = "downloaded" if fetch_state == "downloaded" else "existing"
    elif key == "ghsa_recent":
        cves, fetch_state, warning = _fetch_source_with_cache_fallback(
            source_key="ghsa_recent",
            cache_dir=cache_dir,
            max_items=max_items,
            fetcher=lambda: _fetch_ghsa_recent(
                timeout_seconds=timeout_seconds,
                max_items=max_items,
                cache_dir=cache_dir,
                source_key="ghsa_recent",
            ),
        )
        if warning and fetch_state == "failed":
            raise CVEFeedSyncError(warning)
        if warning:
            source_warnings.append(warning)
        if fetch_state == "not-modified" and destination.exists():
            return destination, "existing-not-modified", cached_count
        state = "downloaded" if fetch_state == "downloaded" else "existing"
    elif key == "all_latest":
        selected_sources: list[tuple[str, list[dict[str, Any]]]] = []
        source_states: list[str] = []
        source_errors: list[str] = []

        if "nvd_recent" not in disabled:
            nvd, nvd_state, warning = _fetch_source_with_cache_fallback(
                source_key="nvd_recent",
                cache_dir=cache_dir,
                max_items=max_items,
                fetcher=lambda: _fetch_nvd_recent(
                    timeout_seconds=timeout_seconds,
                    max_items=max_items,
                    cache_dir=cache_dir,
                    source_key="nvd_recent",
                ),
            )
            if warning:
                source_errors.append(warning)
                source_warnings.append(warning)
            if nvd:
                selected_sources.append(("nvd_recent", nvd))
                source_states.append(nvd_state)

        if "cisa_kev" not in disabled:
            kev, kev_state, warning = _fetch_source_with_cache_fallback(
                source_key="cisa_kev",
                cache_dir=cache_dir,
                max_items=max_items,
                fetcher=lambda: _fetch_cisa_kev(
                    timeout_seconds=timeout_seconds,
                    max_items=max_items,
                    cache_dir=cache_dir,
                    source_key="cisa_kev",
                ),
            )
            if warning:
                source_errors.append(warning)
                source_warnings.append(warning)
            if kev:
                selected_sources.append(("cisa_kev", kev))
                source_states.append(kev_state)

        if not selected_sources:
            if source_errors:
                detail = "; ".join(source_errors)
                raise CVEFeedSyncError(f"all_latest has no usable sources: {detail}")
            raise CVEFeedSyncError("all_latest has no enabled sources after disabled_sources filters")

        cves = _merge_cve_sources(
            sources=selected_sources,
            max_items=max_items,
            source_priority=priority,
        )
        if source_states and all(state == "not-modified" for state in source_states) and destination.exists():
            return destination, "existing-not-modified", cached_count
        state = "downloaded"
    else:
        selected_sources: list[tuple[str, list[dict[str, Any]]]] = []
        source_errors: list[str] = []

        if "nvd_recent" not in disabled:
            nvd, _, warning = _fetch_source_with_cache_fallback(
                source_key="nvd_recent",
                cache_dir=cache_dir,
                max_items=max_items,
                fetcher=lambda: _fetch_nvd_recent(
                    timeout_seconds=timeout_seconds,
                    max_items=max_items,
                    cache_dir=cache_dir,
                    source_key="nvd_recent",
                ),
            )
            if warning:
                source_errors.append(warning)
                source_warnings.append(warning)
            if nvd:
                selected_sources.append(("nvd_recent", nvd))

        if "cisa_kev" not in disabled:
            kev, _, warning = _fetch_source_with_cache_fallback(
                source_key="cisa_kev",
                cache_dir=cache_dir,
                max_items=max_items,
                fetcher=lambda: _fetch_cisa_kev(
                    timeout_seconds=timeout_seconds,
                    max_items=max_items,
                    cache_dir=cache_dir,
                    source_key="cisa_kev",
                ),
            )
            if warning:
                source_errors.append(warning)
                source_warnings.append(warning)
            if kev:
                selected_sources.append(("cisa_kev", kev))

        if "ghsa_recent" not in disabled:
            ghsa, _, warning = _fetch_source_with_cache_fallback(
                source_key="ghsa_recent",
                cache_dir=cache_dir,
                max_items=max_items,
                fetcher=lambda: _fetch_ghsa_recent(
                    timeout_seconds=timeout_seconds,
                    max_items=max_items,
                    cache_dir=cache_dir,
                    source_key="ghsa_recent",
                ),
            )
            if warning:
                source_errors.append(warning)
                source_warnings.append(warning)
            if ghsa:
                selected_sources.append(("ghsa_recent", ghsa))

        if not selected_sources:
            if source_errors:
                detail = "; ".join(source_errors)
                raise CVEFeedSyncError(f"all_plus has no usable sources: {detail}")
            raise CVEFeedSyncError("all_plus has no enabled sources after disabled_sources filters")

        cves = _merge_cve_sources(
            sources=selected_sources,
            max_items=max_items,
            source_priority=priority,
        )
        if "osv_enriched" not in disabled:
            osv, _ = _fetch_osv_enrichment(
                cve_ids=[row["cve_id"] for row in cves],
                timeout_seconds=timeout_seconds,
                lookup_limit=max(0, int(osv_lookup_limit)),
                cache_dir=cache_dir,
                source_key="osv_enriched",
            )
            if osv:
                cves = _merge_cve_sources(
                    sources=[("merged", cves), ("osv_enriched", osv)],
                    max_items=max_items,
                    source_priority=priority,
                )
        state = "downloaded"

    payload = {
        "feed_version": "dynamic-1.0",
        "source": CVE_FEED_CATALOG[key].title,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "sync_policy": policy,
        "sync_schedule": schedule,
        "cves": cves,
    }
    if key in {"all_latest", "all_plus"}:
        payload["source_priority"] = list(priority)
        payload["disabled_sources"] = list(disabled)
    if source_warnings:
        payload["source_warnings"] = source_warnings
    destination.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return destination, state, len(cves)


def _fetch_source_with_cache_fallback(
    *,
    source_key: str,
    cache_dir: Path,
    max_items: int,
    fetcher: Any,
) -> tuple[list[dict[str, Any]], str, str | None]:
    try:
        rows, state = fetcher()
        return rows, state, None
    except CVEFeedSyncError as exc:
        cached = _read_source_cache(_source_cache_path(cache_dir, source_key))
        if cached:
            warning = f"{source_key} sync failed ({exc}); using cached source rows"
            return cached[:max_items], "existing", warning
        warning = f"{source_key} sync failed ({exc})"
        return [], "failed", warning


def _fetch_nvd_recent(
    *,
    timeout_seconds: int,
    max_items: int,
    cache_dir: Path,
    source_key: str,
) -> tuple[list[dict[str, Any]], str]:
    cache_path = _source_cache_path(cache_dir, source_key)
    raw_bytes, fetch_state = _download_bytes(
        NVD_RECENT_URL,
        timeout_seconds=timeout_seconds,
        validator_path=_validator_path(cache_dir, source_key),
    )
    if fetch_state == "not-modified":
        cached = _read_source_cache(cache_path)
        if cached:
            return cached[:max_items], "not-modified"
        raise CVEFeedSyncError("nvd source reported not-modified but no local source cache exists")

    assert raw_bytes is not None
    try:
        unzipped = gzip.decompress(raw_bytes)
    except OSError as exc:
        raise CVEFeedSyncError(f"NVD recent feed is not valid gzip: {exc}") from exc

    try:
        doc = json.loads(unzipped.decode("utf-8"))
    except json.JSONDecodeError as exc:
        raise CVEFeedSyncError(f"NVD recent feed is not valid JSON: {exc}") from exc

    items = doc.get("CVE_Items", []) if isinstance(doc, dict) else []
    out: list[dict[str, Any]] = []
    for item in items:
        cve = _normalize_nvd_item(item)
        if cve is None:
            continue
        cve["source"] = "nvd_recent"
        cve["source_priority"] = 2
        cve["source_confidence"] = 0.95
        out.append(cve)
        if len(out) >= max_items:
            break

    _write_source_cache(cache_path, out)
    return out, "downloaded"


def _fetch_cisa_kev(
    *,
    timeout_seconds: int,
    max_items: int,
    cache_dir: Path,
    source_key: str,
) -> tuple[list[dict[str, Any]], str]:
    cache_path = _source_cache_path(cache_dir, source_key)
    raw_bytes, fetch_state = _download_bytes(
        CISA_KEV_URL,
        timeout_seconds=timeout_seconds,
        validator_path=_validator_path(cache_dir, source_key),
    )
    if fetch_state == "not-modified":
        cached = _read_source_cache(cache_path)
        if cached:
            return cached[:max_items], "not-modified"
        raise CVEFeedSyncError("cisa source reported not-modified but no local source cache exists")

    assert raw_bytes is not None
    try:
        doc = json.loads(raw_bytes.decode("utf-8"))
    except json.JSONDecodeError as exc:
        raise CVEFeedSyncError(f"CISA KEV feed is not valid JSON: {exc}") from exc

    rows = doc.get("vulnerabilities", []) if isinstance(doc, dict) else []
    out: list[dict[str, Any]] = []
    for row in rows:
        cve = _normalize_kev_item(row)
        if cve is None:
            continue
        cve["source"] = "cisa_kev"
        cve["source_priority"] = 1
        cve["source_confidence"] = 0.98
        out.append(cve)
        if len(out) >= max_items:
            break

    _write_source_cache(cache_path, out)
    return out, "downloaded"


def _fetch_ghsa_recent(
    *,
    timeout_seconds: int,
    max_items: int,
    cache_dir: Path,
    source_key: str,
) -> tuple[list[dict[str, Any]], str]:
    cache_path = _source_cache_path(cache_dir, source_key)
    raw_bytes, fetch_state = _download_bytes(
        GHSA_RECENT_URL,
        timeout_seconds=timeout_seconds,
        validator_path=_validator_path(cache_dir, source_key),
    )
    if fetch_state == "not-modified":
        cached = _read_source_cache(cache_path)
        if cached:
            return cached[:max_items], "not-modified"
        raise CVEFeedSyncError("ghsa source reported not-modified but no local source cache exists")

    assert raw_bytes is not None
    try:
        rows = json.loads(raw_bytes.decode("utf-8"))
    except json.JSONDecodeError as exc:
        raise CVEFeedSyncError(f"GHSA feed is not valid JSON: {exc}") from exc

    if not isinstance(rows, list):
        raise CVEFeedSyncError("GHSA feed response is not a list")

    out: list[dict[str, Any]] = []
    for row in rows:
        cve = _normalize_ghsa_item(row)
        if cve is None:
            continue
        out.append(cve)
        if len(out) >= max_items:
            break

    _write_source_cache(cache_path, out)
    return out, "downloaded"


def _fetch_osv_enrichment(
    *,
    cve_ids: list[str],
    timeout_seconds: int,
    lookup_limit: int,
    cache_dir: Path,
    source_key: str,
) -> tuple[list[dict[str, Any]], str]:
    if lookup_limit <= 0:
        return [], "skipped"

    cache_path = _source_cache_path(cache_dir, source_key)
    targets = list(dict.fromkeys(cve_ids))[:lookup_limit]
    out: list[dict[str, Any]] = []

    for cve_id in targets:
        url = OSV_VULN_URL.format(quote(cve_id, safe=""))
        request = urllib.request.Request(
            url,
            headers={
                "User-Agent": "gordian-cve-sync/1.0",
                "Accept": "application/json,*/*;q=0.1",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
                raw = response.read()
        except urllib.error.HTTPError as exc:
            if exc.code in {404, 429}:
                continue
            raise CVEFeedSyncError(f"failed to query OSV for {cve_id}: {exc}") from exc
        except urllib.error.URLError as exc:
            raise CVEFeedSyncError(f"failed to query OSV for {cve_id}: {exc}") from exc

        if not raw or not raw.strip():
            continue
        try:
            doc = json.loads(raw.decode("utf-8"))
        except json.JSONDecodeError:
            continue

        normalized = _normalize_osv_item(doc, cve_id=cve_id)
        if normalized is not None:
            out.append(normalized)

    if out:
        _write_source_cache(cache_path, out)
        return out, "downloaded"

    cached = _read_source_cache(cache_path)
    if cached:
        return cached[:lookup_limit], "existing"
    return [], "empty"


def _merge_cve_sources(
    *,
    sources: list[tuple[str, list[dict[str, Any]]]],
    max_items: int,
    source_priority: tuple[str, ...] | None = None,
) -> list[dict[str, Any]]:
    source_rank = _build_source_rank_map(source_priority)
    source_conf = {
        "cisa_kev": 0.98,
        "nvd_recent": 0.95,
        "ghsa_recent": 0.78,
        "osv_enriched": 0.72,
        "merged": 0.9,
    }

    merged: dict[str, dict[str, Any]] = {}
    rank_tracker: dict[str, int] = {}

    for source_name, rows in sources:
        rank = source_rank.get(source_name, 99)
        default_conf = source_conf.get(source_name, 0.7)
        for row in rows:
            cve_id = str(row.get("cve_id", "")).strip().upper()
            if not cve_id:
                continue

            candidate = dict(row)
            candidate.setdefault("source", source_name)
            # Caller-provided source priority must override embedded defaults.
            if source_priority is not None and source_name in source_rank:
                candidate_rank = rank
            else:
                candidate_rank = int(candidate.get("source_priority", rank))
            candidate["source_priority"] = candidate_rank
            candidate.setdefault("source_confidence", default_conf)

            if cve_id not in merged:
                candidate["sources"] = [source_name]
                merged[cve_id] = candidate
                rank_tracker[cve_id] = candidate_rank
                continue

            current = merged[cve_id]
            current_sources = list(current.get("sources", []))
            if source_name not in current_sources:
                current_sources.append(source_name)
            current["sources"] = current_sources

            current["weaponized"] = bool(current.get("weaponized", False) or candidate.get("weaponized", False))
            current["epss_score"] = max(float(current.get("epss_score", 0.0)), float(candidate.get("epss_score", 0.0)))
            current["exploitability"] = max(
                float(current.get("exploitability", 0.0)),
                float(candidate.get("exploitability", 0.0)),
            )
            refs = list(current.get("references", [])) + list(candidate.get("references", []))
            current["references"] = _dedupe_keep_order(refs)

            if candidate_rank < rank_tracker[cve_id]:
                for key in (
                    "cvss_v3",
                    "severity",
                    "description",
                    "exploit_category",
                    "mitre_tactics",
                    "mitre_techniques",
                    "source",
                    "source_priority",
                ):
                    if key in candidate:
                        current[key] = candidate[key]
                rank_tracker[cve_id] = candidate_rank
            else:
                current["cvss_v3"] = max(float(current.get("cvss_v3", 0.0)), float(candidate.get("cvss_v3", 0.0)))
                if candidate.get("severity") == "CRITICAL" and current.get("severity") != "CRITICAL":
                    current["severity"] = "CRITICAL"
                if len(str(candidate.get("description", ""))) > len(str(current.get("description", ""))):
                    current["description"] = candidate.get("description", current.get("description", ""))

            conf_now = float(current.get("source_confidence", default_conf))
            conf_new = float(candidate.get("source_confidence", default_conf))
            current["source_confidence"] = round(min(0.99, max(conf_now, conf_new) + 0.02), 3)

    values = list(merged.values())
    values.sort(
        key=lambda row: (
            bool(row.get("weaponized", False)),
            float(row.get("cvss_v3", 0.0)),
            float(row.get("exploitability", 0.0)),
            float(row.get("source_confidence", 0.0)),
        ),
        reverse=True,
    )
    return values[:max_items]


def _normalize_nvd_item(item: dict[str, Any]) -> dict[str, Any] | None:
    try:
        cve_id = str(item["cve"]["CVE_data_meta"]["ID"])
    except (KeyError, TypeError):
        return None

    description = _extract_nvd_description(item)
    cvss, severity, exploitability = _extract_nvd_impact(item)
    category = _infer_category(description)
    tactic, technique = _category_to_mitre(category)
    refs = _extract_nvd_references(item)

    return {
        "cve_id": cve_id,
        "cvss_v3": cvss,
        "severity": severity,
        "description": description,
        "exploit_category": category,
        "mitre_tactics": [tactic],
        "mitre_techniques": [technique],
        "exploitability": exploitability,
        "weaponized": False,
        "epss_score": 0.0,
        "references": refs,
    }


def _normalize_kev_item(item: dict[str, Any]) -> dict[str, Any] | None:
    cve_id = str(item.get("cveID", "")).strip().upper()
    if not cve_id.startswith("CVE-"):
        return None

    vendor = str(item.get("vendorProject", "")).strip()
    product = str(item.get("product", "")).strip()
    vuln_name = str(item.get("vulnerabilityName", "")).strip()
    short_desc = str(item.get("shortDescription", "")).strip()
    description = " ".join(part for part in [vuln_name, short_desc] if part).strip() or "Known exploited vulnerability"

    category = _infer_category(description)
    tactic, technique = _category_to_mitre(category)

    ransomware_flag = str(item.get("knownRansomwareCampaignUse", "")).strip().lower()
    is_ransomware = ransomware_flag in {"known", "yes", "true"}

    cvss = 9.3 if is_ransomware else 8.6
    severity = "CRITICAL" if is_ransomware else "HIGH"

    references = []
    if cve_id:
        references.append(f"https://nvd.nist.gov/vuln/detail/{cve_id}")
    references.append("https://www.cisa.gov/known-exploited-vulnerabilities-catalog")

    if vendor or product:
        vendor_product = " ".join(part for part in [vendor, product] if part)
        if vendor_product and vendor_product.lower() not in description.lower():
            description = f"{vendor_product}: {description}"

    return {
        "cve_id": cve_id,
        "cvss_v3": cvss,
        "severity": severity,
        "description": description,
        "exploit_category": category,
        "mitre_tactics": [tactic],
        "mitre_techniques": [technique],
        "exploitability": 0.92 if is_ransomware else 0.86,
        "weaponized": True,
        "epss_score": 0.85 if is_ransomware else 0.75,
        "references": _dedupe_keep_order(references),
    }


def _normalize_ghsa_item(item: dict[str, Any]) -> dict[str, Any] | None:
    if not isinstance(item, dict):
        return None

    identifiers = item.get("identifiers", [])
    cve_id = ""
    if isinstance(identifiers, list):
        for ident in identifiers:
            if not isinstance(ident, dict):
                continue
            value = str(ident.get("value", "")).strip().upper()
            if value.startswith("CVE-"):
                cve_id = value
                break
    if not cve_id:
        return None

    summary = str(item.get("summary", "")).strip()
    description = str(item.get("description", "")).strip()
    joined_description = " ".join(part for part in [summary, description] if part) or "GitHub advisory"

    severity_text = str(item.get("severity", "MEDIUM"))
    severity = _to_severity(severity_text)
    cvss_info = item.get("cvss") if isinstance(item.get("cvss"), dict) else {}
    cvss_score = _to_float(cvss_info.get("score"), default=_severity_default_cvss(severity))

    category = _infer_category(joined_description)
    tactic, technique = _category_to_mitre(category)

    refs = []
    html_url = str(item.get("html_url", "")).strip()
    if html_url:
        refs.append(html_url)
    references = item.get("references", [])
    if isinstance(references, list):
        for ref in references:
            if isinstance(ref, dict):
                url = str(ref.get("url", "")).strip()
                if url:
                    refs.append(url)

    exploitability = min(max(cvss_score / 10.0, 0.2), 0.95)
    return {
        "cve_id": cve_id,
        "cvss_v3": round(cvss_score, 1),
        "severity": severity,
        "description": joined_description,
        "exploit_category": category,
        "mitre_tactics": [tactic],
        "mitre_techniques": [technique],
        "exploitability": round(exploitability, 3),
        "weaponized": False,
        "epss_score": 0.4,
        "references": _dedupe_keep_order(refs),
        "source": "ghsa_recent",
        "source_priority": 3,
        "source_confidence": 0.78,
    }


def _normalize_osv_item(item: dict[str, Any], *, cve_id: str) -> dict[str, Any] | None:
    if not isinstance(item, dict):
        return None

    aliases = item.get("aliases", []) if isinstance(item.get("aliases"), list) else []
    normalized_id = cve_id
    for alias in aliases:
        value = str(alias).strip().upper()
        if value.startswith("CVE-"):
            normalized_id = value
            break

    summary = str(item.get("summary", "")).strip()
    details = str(item.get("details", "")).strip()
    description = " ".join(part for part in [summary, details] if part) or "OSV advisory"

    cvss = 6.5
    severities = item.get("severity", []) if isinstance(item.get("severity"), list) else []
    for severity_obj in severities:
        if not isinstance(severity_obj, dict):
            continue
        score = str(severity_obj.get("score", "")).strip()
        if score.startswith("CVSS"):
            tail = score.rsplit("/", 1)[-1]
            if tail.startswith("AV"):
                continue
        numeric_match = [chunk for chunk in score.replace("/", " ").split() if chunk.replace(".", "", 1).isdigit()]
        if numeric_match:
            cvss = _to_float(numeric_match[-1], default=cvss)

    severity = _to_severity(_cvss_to_severity(cvss))
    category = _infer_category(description)
    tactic, technique = _category_to_mitre(category)

    refs = []
    references = item.get("references", []) if isinstance(item.get("references"), list) else []
    for ref in references:
        if isinstance(ref, dict):
            url = str(ref.get("url", "")).strip()
            if url:
                refs.append(url)

    return {
        "cve_id": normalized_id,
        "cvss_v3": round(cvss, 1),
        "severity": severity,
        "description": description,
        "exploit_category": category,
        "mitre_tactics": [tactic],
        "mitre_techniques": [technique],
        "exploitability": round(min(max(cvss / 10.0, 0.2), 0.9), 3),
        "weaponized": False,
        "epss_score": 0.35,
        "references": _dedupe_keep_order(refs),
        "source": "osv_enriched",
        "source_priority": 4,
        "source_confidence": 0.72,
    }


def _extract_nvd_description(item: dict[str, Any]) -> str:
    nodes = item.get("cve", {}).get("description", {}).get("description_data", [])
    if not isinstance(nodes, list):
        return "No description provided"

    english = [n for n in nodes if isinstance(n, dict) and str(n.get("lang", "")).lower() == "en"]
    chosen = english[0] if english else (nodes[0] if nodes else None)
    if isinstance(chosen, dict):
        text = str(chosen.get("value", "")).strip()
        if text:
            return text
    return "No description provided"


def _extract_nvd_impact(item: dict[str, Any]) -> tuple[float, str, float]:
    impact = item.get("impact", {}) if isinstance(item.get("impact", {}), dict) else {}

    base_metric_v3 = impact.get("baseMetricV3", {}) if isinstance(impact.get("baseMetricV3", {}), dict) else {}
    cvss_v3 = base_metric_v3.get("cvssV3", {}) if isinstance(base_metric_v3.get("cvssV3", {}), dict) else {}

    if cvss_v3:
        base = _to_float(cvss_v3.get("baseScore"), default=6.0)
        severity = _to_severity(str(cvss_v3.get("baseSeverity", "MEDIUM")))
        exploit = _to_float(base_metric_v3.get("exploitabilityScore"), default=base) / 10.0
        return round(base, 1), severity, _clamp_prob(exploit)

    base_metric_v2 = impact.get("baseMetricV2", {}) if isinstance(impact.get("baseMetricV2", {}), dict) else {}
    cvss_v2 = base_metric_v2.get("cvssV2", {}) if isinstance(base_metric_v2.get("cvssV2", {}), dict) else {}

    if cvss_v2:
        base = _to_float(cvss_v2.get("baseScore"), default=5.5)
        severity = _to_severity(str(base_metric_v2.get("severity", "MEDIUM")))
        exploit = _to_float(base_metric_v2.get("exploitabilityScore"), default=base) / 10.0
        return round(base, 1), severity, _clamp_prob(exploit)

    return 5.5, "MEDIUM", 0.5


def _extract_nvd_references(item: dict[str, Any]) -> list[str]:
    refs = item.get("cve", {}).get("references", {}).get("reference_data", [])
    if not isinstance(refs, list):
        return []

    urls = []
    for ref in refs:
        if not isinstance(ref, dict):
            continue
        url = str(ref.get("url", "")).strip()
        if url:
            urls.append(url)
    return _dedupe_keep_order(urls)


def _infer_category(description: str) -> str:
    lowered = description.lower()

    credential_words = ("credential", "password", "token", "secret", "hash", "account takeover")
    priv_words = ("privilege escalation", "elevation of privilege", "local privilege", "sudo")
    lateral_words = ("lateral", "smb", "rpc", "netlogon", "domain controller", "wormable")

    if any(word in lowered for word in credential_words):
        return "CREDENTIAL_ACCESS"
    if any(word in lowered for word in priv_words):
        return "PRIVILEGE_ESCALATION"
    if any(word in lowered for word in lateral_words):
        return "LATERAL_MOVEMENT"
    return "INITIAL_ACCESS"


def _category_to_mitre(category: str) -> tuple[str, str]:
    mapping: dict[str, tuple[str, str]] = {
        "INITIAL_ACCESS": ("TA0001", "T1190"),
        "LATERAL_MOVEMENT": ("TA0008", "T1210"),
        "PRIVILEGE_ESCALATION": ("TA0004", "T1068"),
        "CREDENTIAL_ACCESS": ("TA0006", "T1003"),
    }
    return mapping.get(category, ("TA0001", "T1190"))


def _download_bytes(
    url: str,
    *,
    timeout_seconds: int,
    validator_path: Path | None = None,
) -> tuple[bytes | None, str]:
    headers = {
        "User-Agent": (
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Gordian-CVE-Sync/1.0 Safari/537.36"
        ),
        "Accept": "application/json,application/gzip;q=0.9,*/*;q=0.1",
        "Accept-Language": "en-US,en;q=0.9",
        "Connection": "close",
    }
    validators = _read_validators(validator_path)
    etag = str(validators.get("etag", "")).strip()
    last_modified = str(validators.get("last_modified", "")).strip()
    if etag:
        headers["If-None-Match"] = etag
    if last_modified:
        headers["If-Modified-Since"] = last_modified

    request = urllib.request.Request(url, headers=headers)

    try:
        with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
            data = response.read()
            if validator_path is not None:
                _write_validators(
                    validator_path,
                    etag=str(response.headers.get("ETag", "")).strip() or None,
                    last_modified=str(response.headers.get("Last-Modified", "")).strip() or None,
                )
    except urllib.error.HTTPError as exc:
        if exc.code == 304:
            return None, "not-modified"
        raise CVEFeedSyncError(f"failed to download CVE feed from {url}: {exc}") from exc
    except urllib.error.URLError as exc:
        raise CVEFeedSyncError(f"failed to download CVE feed from {url}: {exc}") from exc

    if not data or not data.strip():
        raise CVEFeedSyncError(f"downloaded CVE feed is empty: {url}")
    return data, "downloaded"


def _to_float(value: Any, *, default: float) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _to_severity(value: str) -> str:
    normalized = value.strip().upper()
    if normalized in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}:
        return normalized
    return "MEDIUM"


def _cvss_to_severity(score: float) -> str:
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    return "LOW"


def _severity_default_cvss(severity: str) -> float:
    mapping = {
        "LOW": 3.2,
        "MEDIUM": 5.9,
        "HIGH": 8.1,
        "CRITICAL": 9.4,
    }
    return mapping.get(_to_severity(severity), 5.9)


def _clamp_prob(value: float) -> float:
    return round(min(max(value, 0.05), 0.99), 3)


def _dedupe_keep_order(items: list[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for item in items:
        if item in seen:
            continue
        seen.add(item)
        out.append(item)
    return out


def _count_cves_in_file(path: Path) -> int:
    payload = try_load_json_file(path, default=None)

    if not isinstance(payload, dict):
        return 0
    cves = payload.get("cves", [])
    if not isinstance(cves, list):
        return 0
    return len(cves)


def _source_cache_path(cache_dir: Path, source_key: str) -> Path:
    return cache_dir / "_sources" / f"{source_key}.json"


def _validator_path(cache_dir: Path, source_key: str) -> Path:
    return cache_dir / "_http_validators" / f"{source_key}.json"


def _write_source_cache(path: Path, rows: list[dict[str, Any]]) -> None:
    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "cves": rows,
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def _read_source_cache(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    payload = try_load_json_file(path, default=None)
    if not isinstance(payload, dict):
        return []
    rows = payload.get("cves", [])
    if not isinstance(rows, list):
        return []
    out: list[dict[str, Any]] = []
    for row in rows:
        if isinstance(row, dict):
            out.append(row)
    return out


def _read_validators(path: Path | None) -> dict[str, Any]:
    if path is None or not path.exists():
        return {}
    payload = try_load_json_file(path, default=None)
    if not isinstance(payload, dict):
        return {}
    return payload


def _write_validators(path: Path, *, etag: str | None, last_modified: str | None) -> None:
    payload = {
        "etag": etag,
        "last_modified": last_modified,
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def get_cve_feed_age_hours(path: Path) -> float | None:
    if not path.exists():
        return None

    generated_at = _read_generated_at(path)
    now = datetime.now(timezone.utc)

    if generated_at is not None:
        age_seconds = (now - generated_at).total_seconds()
        return max(age_seconds / 3600.0, 0.0)

    mtime = datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc)
    age_seconds = (now - mtime).total_seconds()
    return max(age_seconds / 3600.0, 0.0)


def get_cve_feed_last_updated(path: Path) -> str | None:
    if not path.exists():
        return None
    generated_at = _read_generated_at(path)
    if generated_at is not None:
        return generated_at.isoformat()
    mtime = datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc)
    return mtime.isoformat()


def _read_generated_at(path: Path) -> datetime | None:
    payload = try_load_json_file(path, default=None)

    if not isinstance(payload, dict):
        return None

    value = payload.get("generated_at")
    if value is None:
        return None

    text = str(value).strip()
    if not text:
        return None

    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _normalize_sync_policy(policy: str) -> str:
    normalized = str(policy).strip().lower()
    if normalized not in VALID_SYNC_POLICIES:
        supported = ", ".join(sorted(VALID_SYNC_POLICIES))
        raise CVEFeedSyncError(f"unsupported cve sync policy '{policy}', expected one of: {supported}")
    return normalized


def _normalize_sync_schedule(schedule: str) -> str:
    normalized = str(schedule).strip().lower()
    if normalized not in VALID_SYNC_SCHEDULES:
        supported = ", ".join(sorted(VALID_SYNC_SCHEDULES))
        raise CVEFeedSyncError(f"unsupported cve sync schedule '{schedule}', expected one of: {supported}")
    return normalized


def _normalize_merge_source_names(
    raw: tuple[str, ...] | None,
    *,
    field_name: str,
) -> tuple[str, ...]:
    if raw is None:
        return ()

    out: list[str] = []
    seen: set[str] = set()
    for item in raw:
        key = str(item).strip().lower()
        if not key:
            continue
        if key not in MERGE_SOURCE_KEYS:
            supported = ", ".join(MERGE_SOURCE_KEYS)
            raise CVEFeedSyncError(
                f"unsupported source in '{field_name}': {key}; expected one of: {supported}"
            )
        if key in seen:
            continue
        seen.add(key)
        out.append(key)
    return tuple(out)


def _build_merge_source_priority(
    source_priority: tuple[str, ...],
    *,
    disabled_sources: tuple[str, ...],
) -> tuple[str, ...]:
    disabled = set(disabled_sources)
    ordered: list[str] = [key for key in source_priority if key not in disabled]
    for key in DEFAULT_MERGE_SOURCE_PRIORITY:
        if key in disabled or key in ordered:
            continue
        ordered.append(key)
    return tuple(ordered)


def _build_source_rank_map(source_priority: tuple[str, ...] | None) -> dict[str, int]:
    ordered = list(source_priority) if source_priority else list(DEFAULT_MERGE_SOURCE_PRIORITY)
    if "merged" not in ordered:
        ordered.append("merged")
    return {name: idx + 1 for idx, name in enumerate(ordered)}


def _is_schedule_due(age_hours: float | None, schedule: str) -> bool:
    if schedule == "off":
        return True
    if age_hours is None:
        return True
    threshold = 24.0 if schedule == "daily" else 24.0 * 7.0
    return age_hours >= threshold
