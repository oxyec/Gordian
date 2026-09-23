"""ScanManager — central state coordinator for all active/completed scans.

Owns the storage backend, tracks running asyncio tasks, and wires the
``AttackGraphETL`` pipeline into the FastAPI lifecycle.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from dataclasses import replace
from pathlib import Path
from typing import Any, Callable

from .models import (
    ScanProgress,
    ScanStartRequest,
    ScanStatsSnapshot,
    ScanStatusEnum,
    ScanStatusResponse,
)
from .storage import ScanRecord, StorageBackend, create_storage
from src.security import redact, safe_text

log = logging.getLogger(__name__)


class ScanManager:
    """Thread-safe coordinator that manages scan lifecycle.

    * Supports concurrent scans up to ``max_concurrent``.
    * Stores results through a pluggable storage backend (RAM / SQLite).
    * Exposes progress callbacks that pipe into WebSocket broadcast.
    """

    def __init__(
        self,
        storage_backend: str = "ram",
        max_concurrent: int = 1,
        default_args: Any = None,
        db_path: str = "gordian_scans.db",
    ) -> None:
        kwargs: dict[str, Any] = {}
        if storage_backend == "sqlite":
            kwargs["db_path"] = db_path
        self.storage: StorageBackend = create_storage(storage_backend, **kwargs)
        self.storage_backend_name = storage_backend
        self.max_concurrent = max(1, max_concurrent)
        self.default_args = default_args

        # Running task registry: scan_id -> asyncio.Task
        self._tasks: dict[str, asyncio.Task[None]] = {}

        # In-memory graph cache for running/completed scans (fast API reads)
        self._graphs: dict[str, Any] = {}          # scan_id -> AttackGraph
        self._kill_chains: dict[str, list] = {}     # scan_id -> list[AttackPath]
        self._findings: dict[str, list] = {}        # scan_id -> list[dict]
        self._offensive: dict[str, Any] = {}        # scan_id -> OffensiveRunSummary | None
        self._cve_dbs: dict[str, dict] = {}         # scan_id -> dict[str, Vulnerability]
        self._pipeline_results: dict[str, Any] = {} # scan_id -> PipelineResult

        # Event broadcast hook — set by WebSocketManager
        self._event_broadcaster: Callable[[str, dict], Any] | None = None

    # ── Properties ───────────────────────────────────────────────────

    @property
    def active_scan_count(self) -> int:
        return sum(1 for t in self._tasks.values() if not t.done())

    @property
    def can_start_scan(self) -> bool:
        return self.active_scan_count < self.max_concurrent

    # ── Public API ───────────────────────────────────────────────────

    def set_event_broadcaster(self, fn: Callable[[str, dict], Any]) -> None:
        self._event_broadcaster = fn

    async def start_scan(self, request: ScanStartRequest) -> ScanRecord:
        """Kick off a new scan in a background task."""
        if not self.can_start_scan:
            raise RuntimeError(
                f"Maximum concurrent scans reached ({self.max_concurrent}). "
                "Wait for a running scan to complete or increase --max-concurrent-scans."
            )

        from src.offensive import load_offensive_config, merge_cli_overrides
        root = Path(__file__).resolve().parent.parent
        self._resolve_paths(request=request, args=self.default_args, root=root)
        self._build_offensive_config(request=request, args=self.default_args, root=root,
                                     load_offensive_config=load_offensive_config,
                                     merge_cli_overrides=merge_cli_overrides)
        config = request.model_dump(exclude_none=True)
        record = self.storage.create_scan(config)
        record.status = "running"
        record.stage = "initialising"
        record.progress_message = "Scan queued"
        self.storage.update_scan(record)

        task = asyncio.create_task(self._run_scan(record.scan_id, request))
        self._tasks[record.scan_id] = task
        log.info("scan %s started (backend=%s)", record.scan_id, self.storage_backend_name)
        return record

    async def close(self) -> None:
        for scan_id in list(self._tasks):
            await self.cancel_scan(scan_id)
        close = getattr(self.storage, "close", None)
        if close:
            close()

    def get_status(self, scan_id: str | None = None) -> ScanStatusResponse:
        """Return status for a specific scan, or the most recent one."""
        if scan_id:
            record = self.storage.get_scan(scan_id)
        else:
            scans = self.storage.list_scans(limit=1)
            record = scans[0] if scans else None

        if record is None:
            return ScanStatusResponse(status=ScanStatusEnum.IDLE)

        stats_raw = _safe_json(record.stats_json, {})
        return ScanStatusResponse(
            scan_id=record.scan_id,
            status=ScanStatusEnum(record.status),
            progress=ScanProgress(
                stage=record.stage,
                percent=record.progress_percent,
                message=record.progress_message,
            ),
            stats=ScanStatsSnapshot(**{
                k: stats_raw.get(k, 0) for k in ScanStatsSnapshot.model_fields
            }),
            elapsed_seconds=record.elapsed_seconds,
            error=record.error,
        )

    def get_graph_data(self, scan_id: str | None = None) -> dict[str, Any]:
        """Return graph hosts + edges for the requested (or latest) scan."""
        record = self._resolve_record(scan_id)
        if record is None:
            return {"hosts": [], "edges": [], "entry_points": [], "crown_jewels": [],
                    "node_count": 0, "edge_count": 0}

        # Prefer live in-memory graph
        graph = self._graphs.get(record.scan_id)
        cve_db = self._cve_dbs.get(record.scan_id, {})
        if graph is not None:
            return self._serialise_graph(graph, cve_db)

        # Fallback to stored JSON
        return _safe_json(record.graph_json, {
            "hosts": [], "edges": [], "entry_points": [], "crown_jewels": [],
            "node_count": 0, "edge_count": 0,
        })

    def get_findings(self, scan_id: str | None = None) -> dict[str, Any]:
        """Return deduplicated findings for the requested (or latest) scan."""
        record = self._resolve_record(scan_id)
        if record is None:
            return {"total": 0, "deduplicated": 0, "findings": []}

        findings = self._findings.get(record.scan_id)
        if findings is not None:
            return {
                "total": len(findings),
                "deduplicated": len(findings),
                "findings": findings,
            }

        stored = _safe_json(record.findings_json, [])
        return {"total": len(stored), "deduplicated": len(stored), "findings": stored}

    def get_kill_chains(self, scan_id: str | None = None) -> list[dict]:
        """Return kill chain data for the requested (or latest) scan."""
        record = self._resolve_record(scan_id)
        if record is None:
            return []

        chains = self._kill_chains.get(record.scan_id)
        graph = self._graphs.get(record.scan_id)
        cve_db = self._cve_dbs.get(record.scan_id, {})

        if chains is not None and graph is not None:
            from src.loaders import _serialize_path
            result = []
            for path in chains:
                try:
                    row = _serialize_path(path, graph, cve_db)
                    result.append(row)
                except Exception:
                    log.debug(
                        "failed to serialise kill-chain path for scan %s",
                        record.scan_id,
                        exc_info=True,
                    )
                    continue
            return result

        return _safe_json(record.kill_chains_json, [])

    async def cancel_scan(self, scan_id: str) -> bool:
        """Cancel a running scan.

        Returns True if the scan was running and a cancellation was issued,
        False if the scan was unknown or already finished.
        """
        task = self._tasks.get(scan_id)
        if task is None or task.done():
            return False

        task.cancel()
        try:
            await task
        except (asyncio.CancelledError, Exception):
            pass

        record = self.storage.get_scan(scan_id)
        if record is not None and record.status == "running":
            record.status = "failed"
            record.stage = "cancelled"
            record.progress_message = "Cancelled by user"
            record.error = "cancelled"
            self.storage.update_scan(record)

        log.info("scan %s cancelled by user request", scan_id)
        return True

    def list_scans(self, limit: int = 50) -> list[dict]:
        records = self.storage.list_scans(limit=limit)
        return [
            {
                "scan_id": r.scan_id,
                "status": r.status,
                "stage": r.stage,
                "progress_percent": r.progress_percent,
                "elapsed_seconds": r.elapsed_seconds,
                "created_at": r.created_at,
                "error": r.error,
            }
            for r in records
        ]

    # ── Internal: pipeline execution ─────────────────────────────────

    async def _run_scan(self, scan_id: str, request: ScanStartRequest) -> None:
        """Execute the full ETL pipeline inside a background task."""
        record = self.storage.get_scan(scan_id)
        if record is None:
            return

        t0 = time.perf_counter()
        event_buffer: list[dict[str, Any]] = []

        try:
            # Late imports to avoid circular dependencies
            from src.offensive import (
                load_offensive_config,
                merge_cli_overrides,
            )
            from src.orchestrator import AttackGraphETL

            args = self.default_args
            root = Path(__file__).resolve().parent.parent
            network_path, cve_path, output_dir = self._resolve_paths(
                request=request,
                args=args,
                root=root,
                scan_id=scan_id,
            )

            # ── Progress helper ──
            def _update_progress(stage: str, percent: float, message: str) -> None:
                record.stage = stage
                record.progress_percent = min(percent, 100.0)
                record.progress_message = message
                record.elapsed_seconds = round(time.perf_counter() - t0, 3)
                self.storage.update_scan(record)

            # ── Live log hook → WebSocket ──
            def _live_hook(event: dict[str, Any]) -> None:
                event_buffer.append(event)
                if len(event_buffer) >= 20:
                    self.storage.store_events(scan_id, event_buffer[:])
                    event_buffer.clear()
                # Broadcast to WebSocket clients
                if self._event_broadcaster:
                    try:
                        self._event_broadcaster(scan_id, event)
                    except Exception:
                        log.exception(
                            "event broadcast failed for scan %s (event_type=%s)",
                            scan_id,
                            event.get("type", "event"),
                        )

            _update_progress("initialising", 5.0, "Loading offensive configuration")

            offensive_config = self._build_offensive_config(
                request=request,
                args=args,
                root=root,
                load_offensive_config=load_offensive_config,
                merge_cli_overrides=merge_cli_overrides,
            )

            _update_progress("extracting", 15.0, "Loading network topology and CVE feed")

            # Build and run ETL
            etl = AttackGraphETL(
                network_source=network_path,
                cve_source=cve_path,
                output_dir=output_dir,
                run_remediation=request.run_remediation,
                top_patches=request.top_patches,
                quiet=True,
                offensive_config=offensive_config,
                asset_aware_cves=request.asset_aware_cves,
                asset_cve_min_score=max(1, request.asset_cve_min_score),
                asset_cve_keep_top=max(0, request.asset_cve_keep_top),
            )

            _update_progress("running", 25.0, "Pipeline executing")

            # Network stages are async; CPU graph stages still execute synchronously.
            result = await etl.run(
                live_log_hook=_live_hook,
                progress_callback=_update_progress,
            )

            self._cache_pipeline_state(scan_id=scan_id, etl=etl)

            self._pipeline_results[scan_id] = result

            self._flush_event_buffer(scan_id=scan_id, event_buffer=event_buffer)
            self._mark_scan_completed(scan_id=scan_id, record=record, result=result)

            log.info("scan %s completed in %.3fs", scan_id, result.elapsed_seconds)

        except asyncio.CancelledError:
            log.info("scan %s cancelled mid-flight", scan_id)
            record.status = "failed"
            record.stage = "cancelled"
            record.progress_message = "Cancelled by user"
            record.error = "cancelled"
            record.elapsed_seconds = round(time.perf_counter() - t0, 3)
            self.storage.update_scan(record)
            self._flush_event_buffer(scan_id=scan_id, event_buffer=event_buffer)
            raise

        except Exception as exc:
            log.exception("scan %s failed", scan_id)
            record.status = "failed"
            record.stage = "error"
            record.progress_message = safe_text(str(exc))
            record.error = safe_text(str(exc))
            record.elapsed_seconds = round(time.perf_counter() - t0, 3)
            self.storage.update_scan(record)

            self._flush_event_buffer(scan_id=scan_id, event_buffer=event_buffer)

        finally:
            self._tasks.pop(scan_id, None)
            # Keep a small number of completed in-memory graph snapshots.
            completed = [sid for sid in self._graphs if sid not in self._tasks]
            for old_id in completed[:-10]:
                for cache in (self._graphs, self._kill_chains, self._findings,
                              self._offensive, self._cve_dbs, self._pipeline_results):
                    cache.pop(old_id, None)

    # ── Helpers ──────────────────────────────────────────────────────

    @staticmethod
    def _resolve_paths(
        *,
        request: ScanStartRequest,
        args: Any,
        root: Path,
        scan_id: str | None = None,
    ) -> tuple[Path, Path, Path]:
        def dataset(value: str | None, configured: Path) -> Path:
            if value is None:
                return configured
            candidate = (root / value).resolve()
            allowed_root = (root / "data").resolve()
            if not candidate.is_relative_to(allowed_root) or candidate.suffix != ".json" or not candidate.is_file():
                raise ValueError("Input must be an existing JSON dataset inside data/")
            return candidate

        network_path = dataset(request.network_file, Path(getattr(args, "network", root / "data/sample_network.json")))
        cve_path = dataset(request.cve_file, Path(getattr(args, "cves", root / "data/cve_feed.json")))
        output_dir = Path(getattr(args, "out", root / "reports"))
        if scan_id:
            output_dir = output_dir / scan_id
        return network_path, cve_path, output_dir

    def _build_offensive_config(
        self,
        *,
        request: ScanStartRequest,
        args: Any,
        root: Path,
        load_offensive_config: Callable[[Path | None], Any],
        merge_cli_overrides: Callable[..., Any],
    ) -> Any:
        cfg_path = getattr(args, "offensive_config", root / "data" / "offensive_config.json")
        cfg_path = cfg_path if cfg_path and Path(cfg_path).exists() else None
        base_offensive = load_offensive_config(cfg_path)
        from src.offensive.config import OffensiveMode, _default_tool_command_templates
        from src.offensive.scope_policy import load_scope_policy, evaluate_target_scope
        base_offensive = merge_cli_overrides(
            base_offensive,
            target=getattr(args, "offensive_target", None),
            mode=getattr(args, "offensive_mode", None),
            speed=getattr(args, "offensive_speed", None),
            intensity=getattr(args, "offensive_intensity", None),
            scope_policy_file=getattr(args, "scope_file", None),
            dry_run=bool(getattr(args, "offensive_dry_run", False)),
            enabled=False if getattr(args, "offensive_disable", False) else None,
            max_nmap_rate=getattr(args, "max_nmap_rate", None),
            max_ffuf_threads=getattr(args, "max_ffuf_threads", None),
            max_nuclei_rate=getattr(args, "max_nuclei_rate", None),
            max_total_targets=getattr(args, "max_total_targets", None),
            max_total_commands=getattr(args, "max_total_commands", None),
            max_findings=getattr(args, "max_findings", None),
            max_run_seconds=getattr(args, "max_run_seconds", None),
        )
        # Process selection and arbitrary tool programs never come from API clients.
        if base_offensive.tool_command_overrides or base_offensive.tool_extra_args:
            raise ValueError("API server configuration cannot contain arbitrary tool commands or extra args")
        base_offensive = replace(base_offensive, full_control=False, require_scope_match=True,
                                 tool_command_templates=_default_tool_command_templates())
        config = merge_cli_overrides(
            base_offensive,
            target=request.target,
            mode=request.offensive_mode,
            speed=request.offensive_speed,
            intensity=request.offensive_intensity,
            tools=tuple(request.offensive_tools) if request.offensive_tools else None,
            ffuf_wordlist_profile=request.wordlist_profile,
            ffuf_wordlist=request.ffuf_wordlist,
            bugbounty_mode=request.bugbounty_mode,
            full_control=request.full_control,
            max_nmap_rate=request.max_nmap_rate,
            max_ffuf_threads=request.max_ffuf_threads,
            max_nuclei_rate=request.max_nuclei_rate,
            max_total_targets=request.max_total_targets,
            max_total_commands=request.max_total_commands,
            max_findings=request.max_findings,
            max_run_seconds=request.max_run_seconds,
        )
        if base_offensive.mode in {OffensiveMode.DRY_RUN, OffensiveMode.DISABLED}:
            config = replace(config, mode=base_offensive.mode)
        # Server limits are ceilings, even if the client requests more.
        caps = {"max_nmap_rate": 40, "max_ffuf_threads": 20, "max_nuclei_rate": 80,
                "max_total_targets": 40, "max_total_commands": 100,
                "max_findings": 2000, "max_run_seconds": 900}
        config = replace(config, **{
            name: min(getattr(base_offensive, name) or ceiling, getattr(config, name) or ceiling, ceiling)
            for name, ceiling in caps.items()
        })
        if request.ffuf_wordlist:
            wordlist = (root / request.ffuf_wordlist).resolve()
            if not wordlist.is_relative_to((root / "data/wordlists").resolve()) or not wordlist.is_file():
                raise ValueError("Wordlist must be an existing file inside data/wordlists/")
            config = replace(config, ffuf_wordlist=str(wordlist), ffuf_wordlist_profile=None,
                             wordlist_auto_download=False)
        elif not Path(config.ffuf_wordlist).is_absolute():
            config = replace(config, ffuf_wordlist=str(root / config.ffuf_wordlist))
        if config.enabled and config.target and config.mode not in {OffensiveMode.DRY_RUN, OffensiveMode.DISABLED}:
            if not config.scope_policy_file:
                raise ValueError("Live scans require a server-owned scope policy (--scope-file)")
            policy = load_scope_policy(Path(config.scope_policy_file))
            allowed, reason = evaluate_target_scope(config.target, policy)
            if not allowed:
                raise ValueError(reason)
        return config

    def _cache_pipeline_state(self, *, scan_id: str, etl: Any) -> None:
        graph = getattr(etl, "_last_graph", None)
        if graph is not None:
            self._graphs[scan_id] = graph

        chains = getattr(etl, "_last_chains", None)
        if chains is not None:
            self._kill_chains[scan_id] = chains

        cve_db = getattr(etl, "_last_cve_db", None)
        if cve_db is not None:
            self._cve_dbs[scan_id] = cve_db

        offensive = getattr(etl, "_last_offensive", None)
        self._offensive[scan_id] = offensive
        self._findings[scan_id] = redact(list(offensive.findings)) if offensive is not None else []

    def _flush_event_buffer(self, *, scan_id: str, event_buffer: list[dict[str, Any]]) -> None:
        if not event_buffer:
            return
        self.storage.store_events(scan_id, event_buffer)
        event_buffer.clear()

    def _mark_scan_completed(self, *, scan_id: str, record: ScanRecord, result: Any) -> None:
        record.status = "completed"
        record.stage = "done"
        record.progress_percent = 100.0

        impact_blurb = ""
        impact = getattr(result, "offensive_impact", None)
        if impact is not None and impact.new_chains:
            impact_blurb = f" (+{impact.new_chains} new chain(s) from offensive run)"

        record.progress_message = (
            f"Completed: {result.kill_chains} kill chain(s), "
            f"{result.patches_suggested} patches, "
            f"{result.offensive_findings} findings" + impact_blurb
        )
        record.elapsed_seconds = result.elapsed_seconds

        graph = self._graphs.get(scan_id)
        host_count = len(graph.hosts) if graph is not None else 0
        edge_count = graph.edge_count() if graph is not None else 0
        stats: dict[str, Any] = {
            "hosts": host_count,
            "edges": edge_count,
            "kill_chains": result.kill_chains,
            "findings": result.offensive_findings,
            "patches": result.patches_suggested,
        }
        if impact is not None:
            stats["offensive_impact"] = {
                "baseline_chains": impact.baseline_chains,
                "post_chains": impact.post_chains,
                "new_chains": impact.new_chains,
                "new_target_hosts": list(impact.new_target_hosts),
                "edges_added": impact.edges_added,
                "hosts_added": impact.hosts_added,
            }
        record.stats_json = json.dumps(stats, default=str)
        # Persist snapshots before evicting the heavier Python object caches.
        from src.loaders import _serialize_offensive
        record.graph_json = json.dumps(redact(self.get_graph_data(scan_id)), allow_nan=False)
        record.kill_chains_json = json.dumps(redact(self.get_kill_chains(scan_id)), allow_nan=False)
        record.findings_json = json.dumps(redact(self._findings.get(scan_id, [])), allow_nan=False)
        record.offensive_json = json.dumps(redact(_serialize_offensive(self._offensive.get(scan_id))), allow_nan=False)
        self.storage.update_scan(record)

    def _resolve_record(self, scan_id: str | None) -> ScanRecord | None:
        if scan_id:
            return self.storage.get_scan(scan_id)
        scans = self.storage.list_scans(limit=1)
        return scans[0] if scans else None

    @staticmethod
    def _serialise_graph(graph: Any, cve_db: dict) -> dict[str, Any]:
        """Convert an AttackGraph to a JSON-friendly dict."""
        hosts = []
        for h in graph.hosts.values():
            hosts.append({
                "id": h.id,
                "hostname": h.hostname,
                "ip_address": h.ip_address,
                "segment": h.segment,
                "os": h.os,
                "is_attacker_entry": h.is_attacker_entry,
                "is_crown_jewel": h.is_crown_jewel,
                "criticality": h.criticality,
                "services": [
                    {
                        "name": s.name,
                        "port": s.port,
                        "protocol": s.protocol,
                        "version": s.version,
                        "cve_ids": list(s.cve_ids),
                    }
                    for s in h.services
                ],
            })

        edges = []
        for src_id, edge_list in graph._edges.items():
            for dst_id, port, vuln, cost in edge_list:
                edges.append({
                    "source": src_id,
                    "target": dst_id,
                    "port": port,
                    "cve_id": vuln.cve_id,
                    "cost": round(cost, 4),
                    "cvss": vuln.cvss_v3,
                    "category": vuln.exploit_category.value,
                    "technique": vuln.mitre_techniques[0] if vuln.mitre_techniques else "T0000",
                })

        return {
            "hosts": hosts,
            "edges": edges,
            "entry_points": [h.id for h in graph.entry_points()],
            "crown_jewels": [h.id for h in graph.crown_jewels()],
            "node_count": len(graph.hosts),
            "edge_count": graph.edge_count(),
        }


def _safe_json(raw: str, default: Any) -> Any:
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return default
