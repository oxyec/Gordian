"""Load stage: serialise results to JSON, Markdown, and stdout.

Split from the transform stage so that swapping the sink (say, to push
into Elastic or a SIEM) doesn't touch graph logic.
"""

from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any

from .json_utils import try_load_json_file
from .models import AttackPath, PatchRecommendation, Vulnerability
from .scoring import path_risk_score
from .transformers import AttackGraph
from .security import redact, safe_text

if TYPE_CHECKING:
    from .offensive.hub import OffensiveRunSummary

log = logging.getLogger(__name__)


def _serialize_path(path: AttackPath, graph: AttackGraph,
                    cve_db: dict[str, Vulnerability]) -> dict:
    jewel = graph.hosts[path.target_host_id]
    return {
        "entry_host": path.entry_host_id,
        "target_host": path.target_host_id,
        "target_hostname": jewel.hostname,
        "target_segment": jewel.segment,
        "hops": path.hops,
        "total_cost": path.total_cost,
        "max_cvss": path.max_cvss,
        "risk_score": path_risk_score(path, jewel, cve_db),
        "exploit_chain": path.exploit_chain,
        "mitre_techniques": [step.technique for step in path.steps],
        "steps": [
            {
                **asdict(step),
                "source_hostname": graph.hosts[step.source_host_id].hostname,
                "target_hostname": graph.hosts[step.target_host_id].hostname,
                "category": step.category.value,
            }
            for step in path.steps
        ],
    }


async def write_json_report(
    paths: list[AttackPath],
    graph: AttackGraph,
    cve_db: dict[str, Vulnerability],
    patches: list[PatchRecommendation],
    out_dir: Path,
    offensive: "OffensiveRunSummary | None" = None,
    previous_report: dict[str, Any] | None = None,
) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "attack_paths.json"
    chain_rows = [_serialize_path(p, graph, cve_db) for p in paths]
    offensive_payload = _serialize_offensive(offensive)
    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_paths": len(paths),
        "graph_stats": {
            "nodes": len(graph.hosts),
            "edges": graph.edge_count(),
        },
        "kill_chains": chain_rows,
        "patch_recommendations": [asdict(p) for p in patches],
        "offensive_integration": offensive_payload,
        "trend": _build_trend_report(chain_rows, previous_report, offensive_payload),
    }
    await asyncio.to_thread(_write_sync, out_path, json.dumps(redact(payload), indent=2, allow_nan=False))
    log.info("wrote JSON report -> %s", out_path)
    return out_path


async def write_markdown_report(
    paths: list[AttackPath],
    graph: AttackGraph,
    cve_db: dict[str, Vulnerability],
    patches: list[PatchRecommendation],
    out_dir: Path,
    offensive: "OffensiveRunSummary | None" = None,
    previous_report: dict[str, Any] | None = None,
) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "attack_paths.md"
    chain_rows = [_serialize_path(p, graph, cve_db) for p in paths]
    trend = _build_trend_report(chain_rows, previous_report, _serialize_offensive(offensive))
    body = _render_markdown(paths, graph, cve_db, patches, offensive, trend)
    # Preserve document length while removing terminal controls and common credentials.
    body = "\n".join(safe_text(line) for line in body.splitlines())
    await asyncio.to_thread(_write_sync, out_path, body)
    log.info("wrote Markdown report -> %s", out_path)
    return out_path


def _write_sync(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")


def _render_markdown(
    paths: list[AttackPath],
    graph: AttackGraph,
    cve_db: dict[str, Vulnerability],
    patches: list[PatchRecommendation],
    offensive: "OffensiveRunSummary | None" = None,
    trend: dict[str, Any] | None = None,
) -> str:
    ts = datetime.now(timezone.utc).isoformat()
    lines: list[str] = [
        "# Attack Path Report",
        "",
        f"_Generated: {ts}_",
        "",
        f"- Hosts analysed: **{len(graph.hosts)}**",
        f"- Exploit edges: **{graph.edge_count()}**",
        f"- Kill chains to crown jewels: **{len(paths)}**",
        "",
        "---",
        "",
    ]
    if not paths:
        lines.append("_No viable attack paths. Crown jewels are isolated from the attacker's entry point._")
        return "\n".join(lines)

    for idx, path in enumerate(paths, start=1):
        jewel = graph.hosts[path.target_host_id]
        risk = path_risk_score(path, jewel, cve_db)
        lines.extend(
            [
                f"## Kill Chain #{idx} — {jewel.hostname}",
                "",
                f"- **Risk score:** {risk} / 100",
                f"- **Hops:** {path.hops}",
                f"- **Peak CVSS in chain:** {path.max_cvss}",
                f"- **Exploit chain:** {' → '.join(path.exploit_chain)}",
                "",
                "| # | Source | Target:Port | CVE | ATT&CK | Category | Edge cost |",
                "|---|--------|-------------|-----|--------|----------|-----------|",
            ]
        )
        for i, step in enumerate(path.steps, start=1):
            src = graph.hosts[step.source_host_id].hostname
            dst = graph.hosts[step.target_host_id].hostname
            lines.append(
                f"| {i} | {src} | {dst}:{step.target_port} | {step.cve_id} | "
                f"{step.technique} | {step.category.value} | {step.cost} |"
            )
        lines.append("")

    if patches:
        lines.extend([
            "---",
            "",
            "## Recommended Patches",
            "",
            "Ranked by how much aggregate kill-chain risk each patch removes.",
            "",
            "| # | CVE | CVSS | Chains broken | Chains remaining | Risk reduction |",
            "|---|-----|------|---------------|------------------|----------------|",
        ])
        for i, p in enumerate(patches, start=1):
            lines.append(
                f"| {i} | {p.cve_id} | {p.cvss} | {p.chains_broken} | "
                f"{p.chains_remaining} | {p.risk_reduction} |"
            )
        lines.append("")

    if trend is not None and trend.get("baseline_available"):
        lines.extend(
            [
                "---",
                "",
                "## Trend Report",
                "",
                f"- Baseline report date: **{trend.get('baseline_generated_at', 'unknown')}**",
                f"- New CVEs in current kill chains: **{trend.get('new_cves_count', 0)}**",
                f"- Closed risk since previous run: **{trend.get('closed_risk', 0.0)}**",
                f"- Increased kill-chain risk: **{trend.get('increased_kill_chain_risk', 0.0)}**",
                f"- New kill chains: **{trend.get('new_kill_chains', 0)}**",
                f"- Resolved kill chains: **{trend.get('resolved_kill_chains', 0)}**",
                f"- Risk delta: **{trend.get('risk_delta', 0.0)}**",
                f"- Risk change %: **{trend.get('risk_change_percent', 0.0)}%**",
                f"- Offensive findings delta: **{trend.get('offensive_findings_delta', 0)}**",
                f"- Offensive unique targets delta: **{trend.get('offensive_unique_targets_delta', 0)}**",
                f"- Tool success rate: **{trend.get('tool_success_rate_percent', 0.0)}%**",
                f"- Tool success rate delta: **{trend.get('tool_success_rate_delta', 0.0)}%**",
                f"- Tool timeout delta: **{trend.get('tool_timeout_delta', 0)}**",
                f"- Estimated false-positive delta: **{trend.get('estimated_false_positive_delta', 0)}**",
                f"- Estimated false-positive rate delta: **{trend.get('estimated_false_positive_rate_delta', 0.0)}%**",
                "",
            ]
        )

    if offensive is not None:
        lines.extend(
            [
                "---",
                "",
                "## Offensive Integration Hub",
                "",
                f"- Mode: **{offensive.mode}**",
                f"- Target: **{offensive.target or 'n/a'}**",
                f"- Wordlist profile: **{offensive.wordlist_profile or 'n/a'}**",
                f"- Wordlist path: **{offensive.wordlist_path or 'n/a'}**",
                f"- Findings streamed: **{len(offensive.findings)}**",
                f"- Deduplicated findings: **{offensive.deduplicated_findings}**",
                f"- Duplicate findings dropped: **{offensive.duplicate_findings_dropped}**",
                f"- Mean confidence: **{offensive.mean_confidence}**",
                f"- Unique targets seen: **{offensive.unique_targets_seen}**",
                f"- Narratives generated: **{len(offensive.narratives)}**",
                f"- Graph updates: **{offensive.graph_updates}**",
                "",
            ]
        )

        if offensive.wordlist_recommendations:
            lines.append(f"- Recommended wordlists: **{', '.join(offensive.wordlist_recommendations)}**")
            lines.append("")

        if offensive.findings:
            lines.extend(
                [
                    "| # | Tool | Technical finding | Narrative |",
                    "|---|------|-------------------|-----------|",
                ]
            )
            for i, finding in enumerate(offensive.findings[:20], start=1):
                technical = str(finding.get("technical", "")).replace("|", "\\|")
                narrative = str(finding.get("narrative", "")).replace("|", "\\|")
                tool = str(finding.get("tool", ""))
                lines.append(f"| {i} | {tool} | {technical} | {narrative} |")
            if len(offensive.findings) > 20:
                lines.append("")
                lines.append(f"_Showing first 20 of {len(offensive.findings)} offensive findings._")
                lines.append("")

    return "\n".join(lines)


def render_console(
    paths: list[AttackPath],
    graph: AttackGraph,
    cve_db: dict[str, Vulnerability],
    patches: list[PatchRecommendation],
    offensive: "OffensiveRunSummary | None" = None,
) -> None:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[31m"
    YEL = "\033[33m"
    CYN = "\033[36m"
    GRN = "\033[32m"

    print(f"\n{BOLD}{CYN}== killchain-etl :: attack path analysis =={RESET}\n")
    print(f"  graph: {len(graph.hosts)} hosts, {graph.edge_count()} exploit edges")
    print(f"  kill chains found: {len(paths)}\n")

    if not paths:
        print(f"  {GRN}no viable attack paths — crown jewels are isolated from the attacker{RESET}\n")
        return

    for idx, path in enumerate(paths, start=1):
        jewel = graph.hosts[path.target_host_id]
        risk = path_risk_score(path, jewel, cve_db)
        colour = RED if risk >= 70 else YEL if risk >= 40 else CYN
        print(
            f"  {BOLD}#{idx}{RESET} -> {jewel.hostname}  "
            f"[{colour}risk {risk}/100{RESET}, {path.hops} hops, "
            f"max CVSS {path.max_cvss}]"
        )
        for step in path.steps:
            src = graph.hosts[step.source_host_id].hostname
            dst = graph.hosts[step.target_host_id].hostname
            print(
                f"     {DIM}>{RESET} {src} -> {dst}:{step.target_port}  "
                f"{YEL}{step.cve_id}{RESET} "
                f"{DIM}({step.category.value}, {step.technique}){RESET}"
            )
        print()

    if patches:
        print(f"  {BOLD}recommended patches{RESET} (ranked by aggregate risk reduction):")
        for i, p in enumerate(patches, start=1):
            total = p.chains_broken + p.chains_remaining
            print(
                f"     {i}. {YEL}{p.cve_id}{RESET} "
                f"CVSS {p.cvss}  "
                f"breaks {p.chains_broken}/{total} chain(s), "
                f"risk -{p.risk_reduction:.1f}"
            )
        print()

    if offensive is not None:
        print(f"  {BOLD}offensive integration hub{RESET}")
        print(f"     mode: {offensive.mode}")
        print(f"     target: {offensive.target or 'n/a'}")
        print(f"     wordlist profile: {offensive.wordlist_profile or 'n/a'}")
        print(f"     wordlist path: {offensive.wordlist_path or 'n/a'}")
        if offensive.wordlist_recommendations:
            print(f"     recommended wordlists: {', '.join(offensive.wordlist_recommendations)}")
        print(f"     findings: {len(offensive.findings)}")
        print(f"     deduplicated findings: {offensive.deduplicated_findings}")
        print(f"     duplicates dropped: {offensive.duplicate_findings_dropped}")
        print(f"     mean confidence: {offensive.mean_confidence}")
        print(f"     unique targets seen: {offensive.unique_targets_seen}")
        print(
            "     graph updates: "
            f"hosts+{offensive.graph_updates.get('hosts_added', 0)}, "
            f"services+{offensive.graph_updates.get('services_added', 0)}, "
            f"vulns+{offensive.graph_updates.get('vulnerabilities_added', 0)}, "
            f"edges+{offensive.graph_updates.get('edges_added', 0)}"
        )
        print()


def _serialize_offensive(offensive: "OffensiveRunSummary | None") -> dict:
    if offensive is None:
        return {
            "enabled": False,
            "mode": "disabled",
            "target": None,
            "wordlist_profile": None,
            "wordlist_path": None,
            "wordlist_recommendations": [],
            "commands": [],
            "tool_results": [],
            "findings": [],
            "narratives": [],
            "graph_updates": {
                "hosts_added": 0,
                "services_added": 0,
                "vulnerabilities_added": 0,
                "edges_added": 0,
            },
            "deduplicated_findings": 0,
            "duplicate_findings_dropped": 0,
            "mean_confidence": 0.0,
            "unique_targets_seen": 0,
            "budget_stop_reason": None,
            "skipped_reason": "offensive integration not configured",
        }

    return {
        "enabled": offensive.enabled,
        "mode": offensive.mode,
        "target": offensive.target,
        "wordlist_profile": offensive.wordlist_profile,
        "wordlist_path": offensive.wordlist_path,
        "wordlist_recommendations": offensive.wordlist_recommendations,
        "commands": offensive.commands,
        "tool_results": offensive.tool_results,
        "findings": offensive.findings,
        "narratives": offensive.narratives,
        "graph_updates": offensive.graph_updates,
        "deduplicated_findings": offensive.deduplicated_findings,
        "duplicate_findings_dropped": offensive.duplicate_findings_dropped,
        "mean_confidence": offensive.mean_confidence,
        "unique_targets_seen": offensive.unique_targets_seen,
        "budget_stop_reason": offensive.budget_stop_reason,
        "skipped_reason": offensive.skipped_reason,
    }


def load_previous_report(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    payload = try_load_json_file(path, default=None)
    if not isinstance(payload, dict):
        return None
    return payload


def _build_trend_report(
    current_chains: list[dict[str, Any]],
    previous_report: dict[str, Any] | None,
    current_offensive: dict[str, Any],
) -> dict[str, Any]:
    current_total_risk = round(sum(float(row.get("risk_score", 0.0)) for row in current_chains), 3)
    current_cves = _collect_chain_cves(current_chains)
    current_high_risk = sum(1 for row in current_chains if float(row.get("risk_score", 0.0)) >= 70)
    current_findings = _offensive_findings_count(current_offensive)
    current_unique_targets = _offensive_unique_targets_count(current_offensive)
    current_tool_stats = _offensive_tool_success_stats(current_offensive)
    current_fp_stats = _offensive_false_positive_stats(current_offensive)

    if previous_report is None:
        return {
            "baseline_available": False,
            "new_cves_count": 0,
            "closed_risk": 0.0,
            "increased_kill_chain_risk": 0.0,
            "new_kill_chains": len(current_chains),
            "resolved_kill_chains": 0,
            "risk_delta": current_total_risk,
            "risk_change_percent": 0.0,
            "high_risk_kill_chain_delta": current_high_risk,
            "offensive_findings_delta": current_findings,
            "offensive_unique_targets_delta": current_unique_targets,
            "tool_success_rate_percent": current_tool_stats["success_rate_percent"],
            "tool_success_rate_delta": 0.0,
            "tool_timeout_delta": current_tool_stats["timed_out"],
            "tool_results_summary": current_tool_stats,
            "estimated_false_positive_count": current_fp_stats["count"],
            "estimated_false_positive_rate_percent": current_fp_stats["rate_percent"],
            "estimated_false_positive_delta": current_fp_stats["count"],
            "estimated_false_positive_rate_delta": current_fp_stats["rate_percent"],
            "baseline_generated_at": None,
        }

    previous_chains_raw = previous_report.get("kill_chains", [])
    previous_chains: list[dict[str, Any]] = [
        row for row in previous_chains_raw if isinstance(row, dict)
    ]

    previous_total_risk = round(sum(float(row.get("risk_score", 0.0)) for row in previous_chains), 3)
    previous_cves = _collect_chain_cves(previous_chains)
    previous_high_risk = sum(1 for row in previous_chains if float(row.get("risk_score", 0.0)) >= 70)

    previous_offensive_raw = previous_report.get("offensive_integration", {})
    previous_offensive = previous_offensive_raw if isinstance(previous_offensive_raw, dict) else {}
    previous_findings = _offensive_findings_count(previous_offensive)
    previous_unique_targets = _offensive_unique_targets_count(previous_offensive)
    previous_tool_stats = _offensive_tool_success_stats(previous_offensive)
    previous_fp_stats = _offensive_false_positive_stats(previous_offensive)

    current_by_key = {_chain_key(row): float(row.get("risk_score", 0.0)) for row in current_chains}
    previous_by_key = {_chain_key(row): float(row.get("risk_score", 0.0)) for row in previous_chains}

    increased = 0.0
    for key, risk in current_by_key.items():
        previous_risk = previous_by_key.get(key, 0.0)
        if risk > previous_risk:
            increased += risk - previous_risk

    new_chain_count = sum(1 for key in current_by_key if key not in previous_by_key)
    resolved_chain_count = sum(1 for key in previous_by_key if key not in current_by_key)
    risk_delta = round(current_total_risk - previous_total_risk, 3)
    risk_change_percent = round((risk_delta / previous_total_risk) * 100, 3) if previous_total_risk else 0.0

    return {
        "baseline_available": True,
        "baseline_generated_at": previous_report.get("generated_at"),
        "new_cves_count": len(current_cves - previous_cves),
        "closed_risk": round(max(previous_total_risk - current_total_risk, 0.0), 3),
        "increased_kill_chain_risk": round(increased, 3),
        "new_kill_chains": new_chain_count,
        "resolved_kill_chains": resolved_chain_count,
        "risk_delta": risk_delta,
        "risk_change_percent": risk_change_percent,
        "high_risk_kill_chain_delta": current_high_risk - previous_high_risk,
        "offensive_findings_delta": current_findings - previous_findings,
        "offensive_unique_targets_delta": current_unique_targets - previous_unique_targets,
        "tool_success_rate_percent": current_tool_stats["success_rate_percent"],
        "tool_success_rate_delta": round(
            current_tool_stats["success_rate_percent"] - previous_tool_stats["success_rate_percent"],
            3,
        ),
        "tool_timeout_delta": current_tool_stats["timed_out"] - previous_tool_stats["timed_out"],
        "tool_results_summary": current_tool_stats,
        "estimated_false_positive_count": current_fp_stats["count"],
        "estimated_false_positive_rate_percent": current_fp_stats["rate_percent"],
        "estimated_false_positive_delta": current_fp_stats["count"] - previous_fp_stats["count"],
        "estimated_false_positive_rate_delta": round(
            current_fp_stats["rate_percent"] - previous_fp_stats["rate_percent"],
            3,
        ),
    }


def _offensive_findings_count(offensive: dict[str, Any]) -> int:
    findings = offensive.get("findings", [])
    if not isinstance(findings, list):
        return 0
    return len(findings)


def _offensive_unique_targets_count(offensive: dict[str, Any]) -> int:
    value = offensive.get("unique_targets_seen")
    if isinstance(value, int):
        return value

    findings = offensive.get("findings", [])
    if not isinstance(findings, list):
        return 0

    targets: set[str] = set()
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        host = str(finding.get("target_host_id", "")).strip()
        if host:
            targets.add(host)
    return len(targets)


def _offensive_tool_success_stats(offensive: dict[str, Any]) -> dict[str, Any]:
    rows = offensive.get("tool_results", [])
    if not isinstance(rows, list):
        rows = []

    attempted = 0
    succeeded = 0
    timed_out = 0
    by_tool: dict[str, dict[str, int | float]] = {}

    for row in rows:
        if not isinstance(row, dict):
            continue
        attempted += 1
        tool = str(row.get("tool", "unknown")).strip().lower() or "unknown"
        exit_code = row.get("exit_code")
        timeout = bool(row.get("timed_out", False))
        ok = (exit_code == 0) and not timeout

        if ok:
            succeeded += 1
        if timeout:
            timed_out += 1

        bucket = by_tool.setdefault(tool, {"attempted": 0, "succeeded": 0, "timed_out": 0})
        bucket["attempted"] = int(bucket["attempted"]) + 1
        if ok:
            bucket["succeeded"] = int(bucket["succeeded"]) + 1
        if timeout:
            bucket["timed_out"] = int(bucket["timed_out"]) + 1

    success_rate = round((succeeded / attempted) * 100, 3) if attempted else 0.0
    for stats in by_tool.values():
        local_attempted = int(stats["attempted"])
        local_succeeded = int(stats["succeeded"])
        stats["success_rate_percent"] = round((local_succeeded / local_attempted) * 100, 3) if local_attempted else 0.0

    return {
        "attempted": attempted,
        "succeeded": succeeded,
        "failed": max(attempted - succeeded, 0),
        "timed_out": timed_out,
        "success_rate_percent": success_rate,
        "by_tool": by_tool,
    }


def _offensive_false_positive_stats(offensive: dict[str, Any]) -> dict[str, float | int]:
    findings = offensive.get("findings", [])
    if not isinstance(findings, list):
        findings = []

    estimated_fp = 0
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        confidence = finding.get("confidence")
        try:
            score = float(confidence)
        except (TypeError, ValueError):
            score = 0.5
        if score < 0.55:
            estimated_fp += 1

    total = len(findings)
    rate = round((estimated_fp / total) * 100, 3) if total else 0.0
    return {"count": estimated_fp, "rate_percent": rate}


def _collect_chain_cves(chains: list[dict[str, Any]]) -> set[str]:
    out: set[str] = set()
    for row in chains:
        chain = row.get("exploit_chain", [])
        if not isinstance(chain, list):
            continue
        for cve in chain:
            text = str(cve).strip()
            if text:
                out.add(text)
    return out


def _chain_key(chain: dict[str, Any]) -> str:
    target = str(chain.get("target_host", ""))
    exploit_chain = chain.get("exploit_chain", [])
    if not isinstance(exploit_chain, list):
        exploit_chain = []
    parts = [str(item) for item in exploit_chain]
    return f"{target}|{'>'.join(parts)}"
