"""Pipeline wiring.

Extract runs under asyncio.gather because topology and CVE feed are
independent. Transform is CPU-bound pure Python; no reason to fake
async there. Load runs under gather again so the two report sinks
(JSON + Markdown) write in parallel.
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from .cve_filtering import filter_cves_for_hosts
from .extractors import extract_cve_feed, extract_network
from .loaders import load_previous_report, render_console, write_json_report, write_markdown_report
from .offensive import LiveLogHook, OffensiveConfig, OffensiveIntegrationHub, build_event, emit_event
from .remediation import suggest_patches
from .transformers import build_graph, find_all_kill_chains

log = logging.getLogger(__name__)


@dataclass
class OffensiveImpact:
    """Before/after view of what offensive integration changed in the graph.

    Computed by re-running Dijkstra against the pre-offensive snapshot and
    diffing against the post-offensive result. Lets the operator see whether
    runtime recon actually opened up new attack paths or just enriched
    existing ones.
    """
    baseline_chains: int = 0
    post_chains: int = 0
    new_chains: int = 0
    new_target_hosts: tuple[str, ...] = ()
    edges_added: int = 0
    hosts_added: int = 0


@dataclass
class PipelineResult:
    kill_chains: int
    patches_suggested: int
    offensive_findings: int
    json_report: Path
    markdown_report: Path
    elapsed_seconds: float
    offensive_impact: OffensiveImpact | None = None


class AttackGraphETL:
    def __init__(
        self,
        network_source: Path,
        cve_source: Path,
        output_dir: Path,
        *,
        run_remediation: bool = True,
        top_patches: int = 5,
        quiet: bool = False,
        offensive_config: OffensiveConfig | None = None,
        asset_aware_cves: bool = False,
        asset_cve_min_score: int = 2,
        asset_cve_keep_top: int = 120,
    ) -> None:
        self.network_source = network_source
        self.cve_source = cve_source
        self.output_dir = output_dir
        self.run_remediation = run_remediation
        self.top_patches = top_patches
        self.quiet = quiet
        self.offensive_config = offensive_config
        self.asset_aware_cves = asset_aware_cves
        self.asset_cve_min_score = asset_cve_min_score
        self.asset_cve_keep_top = asset_cve_keep_top

    async def run(
        self,
        live_log_hook: LiveLogHook | None = None,
        progress_callback: "Callable[[str, float, str], None] | None" = None,
    ) -> PipelineResult:
        t0 = time.perf_counter()
        log.info("pipeline start")

        # Expose internal state for API consumers (ScanManager reads these after run)
        self._last_graph = None
        self._last_chains: list = []
        self._last_cve_db: dict = {}
        self._last_offensive = None
        self._last_offensive_impact: OffensiveImpact | None = None

        def _progress(stage: str, pct: float, msg: str) -> None:
            if progress_callback is not None:
                try:
                    progress_callback(stage, pct, msg)
                except Exception:
                    log.exception(
                        "progress callback failed (stage=%s, percent=%.1f)",
                        stage,
                        pct,
                    )

        _progress("extract", 10.0, "Pipeline execution started")
        emit_event(
            live_log_hook,
            build_event("pipeline.start", message="Pipeline execution started", stage="extract"),
        )

        hosts, cve_db = await asyncio.gather(
            extract_network(self.network_source),
            extract_cve_feed(self.cve_source),
        )
        self._last_cve_db = cve_db
        _progress("extract", 25.0, f"Extracted {len(hosts)} hosts, {len(cve_db)} CVEs")
        emit_event(
            live_log_hook,
            build_event(
                "pipeline.extract.done",
                message="Extraction stage completed",
                hosts=len(hosts),
                cves=len(cve_db),
                stage="transform",
            ),
        )

        if self.asset_aware_cves:
            filtered_cve_db, stats = filter_cves_for_hosts(
                hosts,
                cve_db,
                enabled=True,
                min_score=self.asset_cve_min_score,
                keep_top=self.asset_cve_keep_top,
            )
            cve_db = filtered_cve_db
            self._last_cve_db = cve_db
            log.info(
                "asset-aware cve filtering reduced feed from %d to %d entries",
                stats.before_count,
                stats.after_count,
            )
            emit_event(
                live_log_hook,
                build_event(
                    "pipeline.extract.cve_filter",
                    message="Asset-aware CVE filtering applied",
                    cves_before=stats.before_count,
                    cves_after=stats.after_count,
                    direct_matches=stats.direct_matches,
                    inferred_matches=stats.inferred_matches,
                    fallback_matches=stats.fallback_matches,
                ),
            )

        _progress("transform", 35.0, "Building attack graph")
        graph = build_graph(hosts, cve_db)
        self._last_graph = graph
        _progress("transform", 45.0, f"Graph built: {len(graph.hosts)} nodes, {graph.edge_count()} edges")
        emit_event(
            live_log_hook,
            build_event(
                "pipeline.transform.graph_built",
                message="Attack graph constructed",
                nodes=len(graph.hosts),
                edges=graph.edge_count(),
            ),
        )

        offensive_summary = None
        offensive_impact: OffensiveImpact | None = None
        baseline_chains: list = []
        baseline_targets: set[str] = set()
        baseline_hosts = len(graph.hosts)
        baseline_edges = graph.edge_count()

        if self.offensive_config is not None and self.offensive_config.enabled:
            # Snapshot the kill chains BEFORE offensive runs so we can show
            # the operator which chains were already known vs. which were
            # opened up by live recon/exploit findings.
            baseline_chains = find_all_kill_chains(graph)
            baseline_targets = {chain.target_host_id for chain in baseline_chains}
            emit_event(
                live_log_hook,
                build_event(
                    "pipeline.offensive.baseline",
                    message="Captured baseline kill chains before offensive run",
                    baseline_chains=len(baseline_chains),
                    baseline_targets=len(baseline_targets),
                ),
            )

            _progress("offensive", 50.0, "Running offensive integration hub")
            log.info("offensive integration enabled (mode=%s)", self.offensive_config.mode.value)
            hub = OffensiveIntegrationHub(self.offensive_config, live_log_hook=live_log_hook)
            try:
                offensive_summary = await hub.run(graph, cve_db)
            except Exception:
                # Never let optional offensive integrations break the core ETL pipeline.
                log.exception("offensive integration failed; continuing with base graph")
                emit_event(
                    live_log_hook,
                    build_event(
                        "pipeline.offensive.failed",
                        level="ERROR",
                        message="Offensive integration failed; continuing with base graph",
                    ),
                )
        self._last_offensive = offensive_summary

        _progress("dijkstra", 70.0, "Computing kill-chain shortest paths")
        chains = find_all_kill_chains(graph)

        if self.offensive_config is not None and self.offensive_config.enabled:
            post_targets = {chain.target_host_id for chain in chains}
            new_targets = tuple(sorted(post_targets - baseline_targets))
            offensive_impact = OffensiveImpact(
                baseline_chains=len(baseline_chains),
                post_chains=len(chains),
                new_chains=max(0, len(chains) - len(baseline_chains)),
                new_target_hosts=new_targets,
                edges_added=max(0, graph.edge_count() - baseline_edges),
                hosts_added=max(0, len(graph.hosts) - baseline_hosts),
            )
            self._last_offensive_impact = offensive_impact
            emit_event(
                live_log_hook,
                build_event(
                    "pipeline.offensive.impact",
                    message=(
                        f"Offensive run added {offensive_impact.new_chains} new kill chain(s), "
                        f"{offensive_impact.edges_added} new edge(s), "
                        f"{offensive_impact.hosts_added} new host(s)"
                    ),
                    baseline_chains=offensive_impact.baseline_chains,
                    post_chains=offensive_impact.post_chains,
                    new_chains=offensive_impact.new_chains,
                    new_target_hosts=list(offensive_impact.new_target_hosts),
                    edges_added=offensive_impact.edges_added,
                    hosts_added=offensive_impact.hosts_added,
                ),
            )
        self._last_chains = chains
        _progress("dijkstra", 80.0, f"Found {len(chains)} kill chain(s)")
        emit_event(
            live_log_hook,
            build_event(
                "pipeline.transform.paths_built",
                message="Kill-chain enumeration completed",
                kill_chains=len(chains),
            ),
        )

        patches = []
        if self.run_remediation:
            _progress("remediation", 85.0, "Simulating patch recommendations")
            patches = suggest_patches(graph, chains, cve_db, top_n=self.top_patches)
        emit_event(
            live_log_hook,
            build_event(
                "pipeline.remediation.done",
                message="Remediation simulation completed",
                recommendations=len(patches),
                stage="load",
            ),
        )

        _progress("load", 90.0, "Writing reports")
        previous_report = await asyncio.to_thread(load_previous_report, self.output_dir / "attack_paths.json")

        json_path, md_path = await asyncio.gather(
            write_json_report(
                chains,
                graph,
                cve_db,
                patches,
                self.output_dir,
                offensive_summary,
                previous_report,
            ),
            write_markdown_report(
                chains,
                graph,
                cve_db,
                patches,
                self.output_dir,
                offensive_summary,
                previous_report,
            ),
        )

        if not self.quiet:
            render_console(chains, graph, cve_db, patches, offensive_summary)

        elapsed = round(time.perf_counter() - t0, 3)
        log.info("pipeline done in %.3fs", elapsed)
        offensive_findings = len(offensive_summary.findings) if offensive_summary is not None else 0
        _progress("done", 100.0, f"Completed in {elapsed}s — {len(chains)} chains, {offensive_findings} findings")
        emit_event(
            live_log_hook,
            build_event(
                "pipeline.done",
                message="Pipeline execution completed",
                elapsed_seconds=elapsed,
                kill_chains=len(chains),
                patch_recommendations=len(patches),
                offensive_findings=offensive_findings,
                json_report=str(json_path),
                markdown_report=str(md_path),
            ),
        )
        return PipelineResult(
            kill_chains=len(chains),
            patches_suggested=len(patches),
            offensive_findings=offensive_findings,
            json_report=json_path,
            markdown_report=md_path,
            elapsed_seconds=elapsed,
            offensive_impact=offensive_impact,
        )
