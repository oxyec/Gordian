"""High-level Offensive Integration Hub orchestration."""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from pathlib import Path
import asyncio
import time
from typing import Any
from urllib.parse import urlparse

from ..models import Vulnerability
from ..security import redact
from ..transformers import AttackGraph
from .command_factory import CommandFactory, CommandFactoryError, CommandSpec
from .config import OffensiveConfig, OffensiveMode, should_attempt_offensive
from .events import LiveLogHook, build_event, emit_event
from .injector import GraphInjector
from .parsers import Finding, parser_for_tool
from .runner import AsyncToolRunner
from .scope_policy import ScopePolicy, ScopePolicyError, evaluate_target_scope, evaluate_resolved_target_scope, is_current_time_allowed, load_scope_policy
from .storyteller import Storyteller
from .wordlists import (
    WordlistDownloadError,
    ensure_wordlist,
    recommended_wordlist_profiles,
    resolve_wordlist_store_dir,
)


@dataclass
class OffensiveRunSummary:
    enabled: bool
    mode: str
    target: str | None
    commands: list[list[str]] = field(default_factory=list)
    tool_results: list[dict[str, Any]] = field(default_factory=list)
    findings: list[dict[str, Any]] = field(default_factory=list)
    narratives: list[str] = field(default_factory=list)
    wordlist_profile: str | None = None
    wordlist_path: str | None = None
    wordlist_recommendations: list[str] = field(default_factory=list)
    graph_updates: dict[str, int] = field(
        default_factory=lambda: {
            "hosts_added": 0,
            "services_added": 0,
            "vulnerabilities_added": 0,
            "edges_added": 0,
        }
    )
    deduplicated_findings: int = 0
    duplicate_findings_dropped: int = 0
    mean_confidence: float = 0.0
    unique_targets_seen: int = 0
    budget_stop_reason: str | None = None
    skipped_reason: str | None = None


class OffensiveIntegrationHub:
    def __init__(
        self,
        config: OffensiveConfig,
        *,
        live_log_hook: LiveLogHook | None = None,
    ) -> None:
        self.config = config
        self.live_log_hook = live_log_hook

    async def run(
        self,
        graph: AttackGraph,
        cve_db: dict[str, Vulnerability],
    ) -> OffensiveRunSummary:
        async with asyncio.timeout(self.config.max_run_seconds or 900):
            return await self._run(graph, cve_db)

    async def _run(self, graph: AttackGraph, cve_db: dict[str, Vulnerability]) -> OffensiveRunSummary:
        started = time.perf_counter()
        summary = OffensiveRunSummary(
            enabled=self.config.enabled,
            mode=self.config.mode.value,
            target=self.config.target,
            wordlist_profile=self.config.ffuf_wordlist_profile,
        )

        if not should_attempt_offensive(self.config):
            summary.skipped_reason = "offensive mode disabled or target missing"
            emit_event(
                self.live_log_hook,
                build_event(
                    "offensive.skipped",
                    level="INFO",
                    message=summary.skipped_reason,
                ),
            )
            return summary

        if self.config.allowed_time_windows:
            allowed, reason = _is_utc_time_allowed(self.config.allowed_time_windows)
            emit_event(
                self.live_log_hook,
                build_event(
                    "offensive.window.evaluated",
                    message="Global UTC time window evaluated",
                    windows=list(self.config.allowed_time_windows),
                    allowed=allowed,
                    reason=reason,
                ),
            )
            if not allowed:
                summary.skipped_reason = reason
                return summary

        if self.config.require_scope_match and not self.config.scope_policy_file:
            summary.skipped_reason = "scope policy is required but no scope file is configured"
            emit_event(
                self.live_log_hook,
                build_event(
                    "offensive.scope.skipped",
                    level="WARNING",
                    message=summary.skipped_reason,
                ),
            )
            return summary

        scope_policy = None

        if self.config.scope_policy_file:
            scope_file = Path(self.config.scope_policy_file)
            try:
                policy = load_scope_policy(scope_file)
                in_scope, reason = evaluate_target_scope(self.config.target or "", policy)
            except ScopePolicyError as exc:
                message = f"scope policy error: {exc}"
                emit_event(
                    self.live_log_hook,
                    build_event(
                        "offensive.scope.error",
                        level="ERROR",
                        message=message,
                        path=str(scope_file),
                    ),
                )
                summary.skipped_reason = message
                return summary
            else:
                allowed_now, window_reason = is_current_time_allowed(policy)
                emit_event(
                    self.live_log_hook,
                    build_event(
                        "offensive.scope.evaluated",
                        message="Target scope evaluated",
                        target=self.config.target,
                        scope_file=str(scope_file),
                        in_scope=in_scope,
                        window_allowed=allowed_now,
                        window_reason=window_reason,
                        reason=reason,
                    ),
                )
                if not allowed_now:
                    summary.skipped_reason = window_reason
                    emit_event(
                        self.live_log_hook,
                        build_event(
                            "offensive.scope.window_blocked",
                            level="WARNING",
                            message=window_reason,
                            scope_file=str(scope_file),
                        ),
                    )
                    return summary
                if not in_scope:
                    summary.skipped_reason = reason
                    emit_event(
                        self.live_log_hook,
                        build_event(
                            "offensive.scope.blocked",
                            level="WARNING",
                            message=reason,
                            target=self.config.target,
                        ),
                    )
                    return summary
                scope_policy = policy

        working_config = self.config
        if scope_policy is not None:
            working_config = _apply_scope_caps(working_config, scope_policy)

        discovered_hints = _derive_tech_hints_from_graph(graph)
        combined_hints = tuple(dict.fromkeys([*self.config.tech_hints, *discovered_hints]))
        recommendations = recommended_wordlist_profiles(
            target=self.config.target,
            speed=self.config.speed,
            intensity=self.config.intensity,
            tech_hints=combined_hints,
            bugbounty_mode=self.config.bugbounty_mode,
        )
        summary.wordlist_recommendations = recommendations
        emit_event(
            self.live_log_hook,
            build_event(
                "offensive.wordlist.recommendation",
                message="Wordlist recommendations generated",
                recommendations=recommendations,
                discovered_hints=list(discovered_hints),
            ),
        )

        selected_profile = self.config.ffuf_wordlist_profile or (recommendations[0] if recommendations else None)
        if selected_profile:
            summary.wordlist_profile = selected_profile
            store_dir = resolve_wordlist_store_dir(self.config.wordlist_store_dir, root_dir=Path.cwd())
            try:
                wordlist_path, state = await asyncio.to_thread(ensure_wordlist,
                    selected_profile,
                    store_dir=store_dir,
                    auto_download=self.config.wordlist_auto_download and self.config.mode is not OffensiveMode.DRY_RUN,
                )
            except WordlistDownloadError as exc:
                emit_event(
                    self.live_log_hook,
                    build_event(
                        "offensive.wordlist.warning",
                        level="WARNING",
                        message=str(exc),
                        profile=selected_profile,
                    ),
                )
            else:
                summary.wordlist_path = str(wordlist_path)
                working_config = replace(
                    working_config,
                    ffuf_wordlist_profile=selected_profile,
                    ffuf_wordlist=str(wordlist_path),
                )
                emit_event(
                    self.live_log_hook,
                    build_event(
                        "offensive.wordlist.selected",
                        message=f"Wordlist profile '{selected_profile}' resolved ({state})",
                        profile=selected_profile,
                        path=str(wordlist_path),
                        state=state,
                    ),
                )

        factory = CommandFactory(working_config)
        try:
            commands = factory.build()
        except CommandFactoryError as exc:
            summary.skipped_reason = str(exc)
            emit_event(
                self.live_log_hook,
                build_event(
                    "offensive.skipped",
                    level="ERROR",
                    message=str(exc),
                ),
            )
            return summary

        if not commands:
            summary.skipped_reason = "no runnable offensive command for target"
            emit_event(
                self.live_log_hook,
                build_event(
                    "offensive.skipped",
                    level="WARNING",
                    message=summary.skipped_reason,
                ),
            )
            return summary

        dry_run = self.config.mode is OffensiveMode.DRY_RUN
        missing = factory.missing_tools(commands) if not dry_run else []
        if missing and self.config.mode is OffensiveMode.MANUAL:
            raise RuntimeError(
                f"offensive mode=manual requires installed tools, missing: {', '.join(missing)}"
            )

        if missing:
            commands = [cmd for cmd in commands if cmd.tool not in missing]
            emit_event(
                self.live_log_hook,
                build_event(
                    "offensive.preflight_missing_tools",
                    level="WARNING",
                    message="Some tools are unavailable and will be skipped",
                    missing=missing,
                ),
            )

        if not commands:
            summary.skipped_reason = "all offensive tools were unavailable"
            return summary

        commands = _filter_ffuf_wordlist(commands, working_config, dry_run=dry_run, live_log_hook=self.live_log_hook)

        if not commands:
            summary.skipped_reason = "no executable offensive commands after wordlist/tool preflight"
            return summary

        injector = GraphInjector(
            graph,
            cve_db,
            directory_injection=self.config.directory_injection,
        )
        storyteller = Storyteller()

        seen_fingerprints: set[str] = set()
        confidence_total = 0.0
        confidence_count = 0
        finding_cap_emitted = False
        discovered_hosts: set[str] = set()
        discovered_urls: set[str] = set()
        scheduled_targets: set[str] = set()
        observed_targets: set[str] = set()
        if self.config.target:
            scheduled_targets.add(self.config.target)
            observed_targets.add(self.config.target)

        def on_finding(finding: Finding) -> None:
            nonlocal confidence_total, confidence_count, finding_cap_emitted

            if working_config.max_findings is not None and len(summary.findings) >= working_config.max_findings:
                if not finding_cap_emitted:
                    finding_cap_emitted = True
                    summary.budget_stop_reason = (
                        f"max_findings limit reached ({working_config.max_findings}); further findings will be dropped"
                    )
                    emit_event(
                        self.live_log_hook,
                        build_event(
                            "offensive.budget.findings_reached",
                            level="WARNING",
                            message=summary.budget_stop_reason,
                        ),
                    )
                return

            fingerprint = _finding_fingerprint(finding)
            if fingerprint in seen_fingerprints:
                summary.duplicate_findings_dropped += 1
                return
            seen_fingerprints.add(fingerprint)

            confidence = _confidence_for_finding(finding)
            confidence_total += confidence
            confidence_count += 1

            narrative = storyteller.narrate(finding)
            delta = injector.inject_finding(finding)

            if narrative:
                summary.narratives.append(narrative)

            discovered_host = _extract_host_candidate(finding)
            if discovered_host is not None:
                discovered_hosts.add(discovered_host)
                observed_targets.add(discovered_host)

            discovered_url = _extract_url_candidate(finding)
            if discovered_url is not None:
                discovered_urls.add(discovered_url)
                observed_targets.add(discovered_url)

            summary.findings.append(
                {
                    "tool": finding.tool,
                    "type": finding.finding_type,
                    "technical": finding.technical,
                    "narrative": narrative,
                    "target_host_id": finding.target_host_id,
                    "target_port": finding.target_port,
                    "cve_id": finding.vulnerability.cve_id if finding.vulnerability else None,
                    "metadata": redact(dict(finding.metadata)),
                    "raw_line": "[REDACTED]",
                    "confidence": confidence,
                }
            )

            summary.graph_updates["hosts_added"] += delta.hosts_added
            summary.graph_updates["services_added"] += delta.services_added
            summary.graph_updates["vulnerabilities_added"] += delta.vulnerabilities_added
            summary.graph_updates["edges_added"] += delta.edges_added

            emit_event(
                self.live_log_hook,
                build_event(
                    "offensive.finding",
                    tool=finding.tool,
                    message=finding.technical,
                    narrative=narrative,
                    target_host_id=finding.target_host_id,
                    target_port=finding.target_port,
                    confidence=confidence,
                    graph_delta={
                        "hosts_added": delta.hosts_added,
                        "services_added": delta.services_added,
                        "vulnerabilities_added": delta.vulnerabilities_added,
                        "edges_added": delta.edges_added,
                    },
                ),
            )

        runner_timeout = working_config.timeout_seconds
        if working_config.max_run_seconds is not None:
            runner_timeout = max(1, min(runner_timeout, working_config.max_run_seconds))

        async def validate_command(spec: CommandSpec) -> None:
            if scope_policy is None:
                if working_config.require_scope_match:
                    raise ScopePolicyError("Live command requires a scope policy")
                return  # Explicit trusted library use; API always requires scope.
            allowed_now, reason = is_current_time_allowed(scope_policy)
            if not allowed_now:
                raise ScopePolicyError(reason)
            target = _infer_target_for_spec(spec, working_config.target or "")
            allowed, reason = await evaluate_resolved_target_scope(target, scope_policy)
            if not allowed:
                raise ScopePolicyError(reason)

        runner = AsyncToolRunner(
            max_concurrency=working_config.max_concurrency,
            timeout_seconds=runner_timeout,
            live_log_hook=self.live_log_hook,
            review_mode=working_config.full_control,
            command_validator=validate_command,
        )

        command_stages = _build_command_stages(commands, dependencies=working_config.tool_dependencies)
        executed_signatures: set[tuple[str, ...]] = set()
        results = []
        stage_index = 0
        followup_cap = max(1, working_config.max_followup_targets)

        while stage_index < len(command_stages):
            if working_config.max_run_seconds is not None:
                elapsed = time.perf_counter() - started
                if elapsed >= working_config.max_run_seconds:
                    summary.budget_stop_reason = (
                        f"max_run_seconds reached ({working_config.max_run_seconds}s); remaining stages skipped"
                    )
                    emit_event(
                        self.live_log_hook,
                        build_event(
                            "offensive.budget.runtime_reached",
                            level="WARNING",
                            message=summary.budget_stop_reason,
                            elapsed_seconds=round(elapsed, 3),
                        ),
                    )
                    break

            stage = _dedupe_unseen_commands(command_stages[stage_index], executed_signatures)
            stage_index += 1

            if working_config.max_total_commands is not None:
                remaining = working_config.max_total_commands - len(summary.commands)
                if remaining <= 0:
                    summary.budget_stop_reason = (
                        f"max_total_commands reached ({working_config.max_total_commands}); remaining stages skipped"
                    )
                    emit_event(
                        self.live_log_hook,
                        build_event(
                            "offensive.budget.commands_reached",
                            level="WARNING",
                            message=summary.budget_stop_reason,
                        ),
                    )
                    break
                if remaining < len(stage):
                    summary.budget_stop_reason = (
                        f"max_total_commands reached ({working_config.max_total_commands}); trailing commands were dropped"
                    )
                    emit_event(
                        self.live_log_hook,
                        build_event(
                            "offensive.budget.commands_reached",
                            level="WARNING",
                            message=summary.budget_stop_reason,
                        ),
                    )
                stage = stage[:remaining]

            if not stage:
                continue

            stage = _filter_ffuf_wordlist(stage, working_config, dry_run=dry_run, live_log_hook=self.live_log_hook)
            if not stage:
                continue

            summary.commands.extend([list(spec.argv) for spec in stage])
            for spec in stage:
                executed_signatures.add(tuple(spec.argv))

            emit_event(
                self.live_log_hook,
                build_event(
                    "offensive.stage.start",
                    message="Executing offensive stage",
                    stage_index=stage_index,
                    command_count=len(stage),
                    tools=[spec.tool for spec in stage],
                ),
            )

            stage_results = await runner.run(
                stage,
                parser_factory=lambda spec: parser_for_tool(
                    spec.tool,
                    _infer_target_for_spec(spec, self.config.target or ""),
                ),
                on_finding=on_finding,
                dry_run=dry_run,
            )
            results.extend(stage_results)

            if dry_run:
                continue

            followup_commands = _build_followup_commands(
                config=working_config,
                host_candidates=sorted(discovered_hosts),
                url_candidates=sorted(discovered_urls),
                seen_targets=scheduled_targets,
                executed_signatures=executed_signatures,
                max_followup_targets=followup_cap,
                scope_policy=scope_policy,
            )

            if (
                working_config.max_total_targets is not None
                and len(scheduled_targets) >= working_config.max_total_targets
            ):
                emit_event(
                    self.live_log_hook,
                    build_event(
                        "offensive.budget.targets_reached",
                        level="WARNING",
                        message=f"max_total_targets reached ({working_config.max_total_targets}); no new follow-up targets",
                    ),
                )
                followup_commands = []

            if followup_commands:
                followup_missing = factory.missing_tools(followup_commands)
                if followup_missing and self.config.mode is OffensiveMode.MANUAL:
                    raise RuntimeError(
                        f"offensive mode=manual requires installed tools, missing: {', '.join(followup_missing)}"
                    )
                if followup_missing:
                    followup_commands = [spec for spec in followup_commands if spec.tool not in followup_missing]

            followup_commands = _filter_ffuf_wordlist(
                followup_commands,
                working_config,
                dry_run=dry_run,
                live_log_hook=self.live_log_hook,
            )

            if followup_commands:
                followup_stages = _build_command_stages(followup_commands, dependencies=working_config.tool_dependencies)
                command_stages.extend(followup_stages)
                emit_event(
                    self.live_log_hook,
                    build_event(
                        "offensive.followup.scheduled",
                        message="Scheduled follow-up commands from staged findings",
                        commands=len(followup_commands),
                        tools=sorted({spec.tool for spec in followup_commands}),
                    ),
                )
                # Per-spawn lineage event: lets the TUI render the
                # recon→exploit feeding loop as discrete arrows in the
                # live log instead of a single opaque "scheduled N" line.
                # Parent tools = whatever just produced findings in the
                # stage we're returning from.
                parent_tools = sorted({r.tool for r in stage_results if r.findings_seen > 0})
                parent_label = "+".join(parent_tools) if parent_tools else "scan"
                for spec in followup_commands:
                    target = _infer_target_for_spec(spec, self.config.target or "")
                    emit_event(
                        self.live_log_hook,
                        build_event(
                            "pipeline.tool_chain.spawned",
                            tool=spec.tool,
                            message=f"{parent_label} ▸ {spec.tool} ({target})",
                            parent_tools=parent_tools,
                            child_tool=spec.tool,
                            target=target,
                        ),
                    )

        summary.tool_results = [
            {
                "tool": result.tool,
                "command": list(result.argv),
                "exit_code": result.exit_code,
                "findings_seen": result.findings_seen,
                "duration_seconds": result.duration_seconds,
                "timed_out": result.timed_out,
            }
            for result in results
        ]

        summary.deduplicated_findings = len(summary.findings)
        summary.mean_confidence = round(confidence_total / confidence_count, 3) if confidence_count else 0.0
        summary.unique_targets_seen = len(observed_targets)

        emit_event(
            self.live_log_hook,
            build_event(
                "offensive.summary",
                message="Offensive integration phase completed",
                mode=summary.mode,
                findings=len(summary.findings),
                deduplicated_findings=summary.deduplicated_findings,
                duplicate_findings_dropped=summary.duplicate_findings_dropped,
                mean_confidence=summary.mean_confidence,
                unique_targets_seen=summary.unique_targets_seen,
                narratives=len(summary.narratives),
                graph_updates=summary.graph_updates,
                budget_stop_reason=summary.budget_stop_reason,
            ),
        )
        return summary


def _derive_tech_hints_from_graph(graph: AttackGraph) -> tuple[str, ...]:
    hints: list[str] = []
    for host in graph.hosts.values():
        host_text = " ".join([host.hostname, host.os]).lower()
        _collect_tech_hints(host_text, hints)
        for service in host.services:
            service_text = " ".join([service.name, service.version]).lower()
            _collect_tech_hints(service_text, hints)
    return tuple(dict.fromkeys(hints))


def _collect_tech_hints(text: str, output: list[str]) -> None:
    mapping = {
        "wordpress": ("wordpress", "wp-", "woocommerce"),
        "laravel": ("laravel",),
        "spring": ("spring", "springboot", "spring-boot"),
        "api": ("graphql", "swagger", "openapi", "rest", "api"),
        "node": ("node", "express", "next.js", "nextjs"),
        "react": ("react",),
        "django": ("django",),
    }
    for label, markers in mapping.items():
        if any(marker in text for marker in markers):
            output.append(label)


def _is_utc_time_allowed(windows: tuple[str, ...]) -> tuple[bool, str]:
    now = datetime.now(timezone.utc)
    minute_of_day = now.hour * 60 + now.minute

    for window in windows:
        start_raw, end_raw = window.split("-", 1)
        start_h, start_m = (int(value) for value in start_raw.split(":"))
        end_h, end_m = (int(value) for value in end_raw.split(":"))
        start = start_h * 60 + start_m
        end = end_h * 60 + end_m

        if start <= end:
            if start <= minute_of_day <= end:
                return True, f"current UTC time matches {window}"
        else:
            if minute_of_day >= start or minute_of_day <= end:
                return True, f"current UTC time matches {window}"

    return False, "current UTC time is outside allowed_time_windows"


def _apply_scope_caps(config: OffensiveConfig, scope_policy: ScopePolicy) -> OffensiveConfig:
    updated = config

    def _cap(current: int | None, limit: int | None) -> int | None:
        if limit is None:
            return current
        if current is None:
            return limit
        return min(current, limit)

    updated = replace(updated, max_nmap_rate=_cap(updated.max_nmap_rate, scope_policy.max_nmap_rate))
    updated = replace(updated, max_ffuf_threads=_cap(updated.max_ffuf_threads, scope_policy.max_ffuf_threads))
    updated = replace(updated, max_nuclei_rate=_cap(updated.max_nuclei_rate, scope_policy.max_nuclei_rate))
    updated = replace(updated, max_total_targets=_cap(updated.max_total_targets, scope_policy.max_total_targets))
    updated = replace(updated, max_total_commands=_cap(updated.max_total_commands, scope_policy.max_total_commands))
    updated = replace(updated, max_findings=_cap(updated.max_findings, scope_policy.max_findings))
    updated = replace(updated, max_run_seconds=_cap(updated.max_run_seconds, scope_policy.max_run_seconds))

    if scope_policy.max_followup_targets is not None:
        if updated.max_followup_targets <= 0:
            updated = replace(updated, max_followup_targets=scope_policy.max_followup_targets)
        else:
            updated = replace(updated, max_followup_targets=min(updated.max_followup_targets, scope_policy.max_followup_targets))

    return updated


def _filter_ffuf_wordlist(
    commands: list[CommandSpec],
    config: OffensiveConfig,
    *,
    dry_run: bool,
    live_log_hook: LiveLogHook | None,
) -> list[CommandSpec]:
    if dry_run:
        return commands
    if not any(spec.tool == "ffuf" for spec in commands):
        return commands

    ffuf_wordlist_path = Path(config.ffuf_wordlist)
    if ffuf_wordlist_path.exists():
        return commands

    emit_event(
        live_log_hook,
        build_event(
            "offensive.wordlist.warning",
            level="WARNING",
            message=(
                "ffuf command skipped because resolved wordlist file does not exist; "
                "choose a different profile or enable auto-download"
            ),
            path=str(ffuf_wordlist_path),
        ),
    )
    return [spec for spec in commands if spec.tool != "ffuf"]


def _build_command_stages(
    commands: list[CommandSpec],
    *,
    dependencies: dict[str, tuple[str, ...]],
) -> list[list[CommandSpec]]:
    if not commands:
        return []

    remaining = list(commands)
    stages: list[list[CommandSpec]] = []
    completed_tools: set[str] = set()

    while remaining:
        stage: list[CommandSpec] = []
        next_remaining: list[CommandSpec] = []

        for spec in remaining:
            deps = dependencies.get(spec.tool, ())
            blocked = False
            for dep in deps:
                if dep in [candidate.tool for candidate in remaining] and dep not in completed_tools:
                    blocked = True
                    break
            if blocked:
                next_remaining.append(spec)
            else:
                stage.append(spec)

        if not stage:
            # Dependency cycle or unresolved mapping; flush remaining in one stage.
            stages.append(remaining)
            break

        stages.append(stage)
        completed_tools.update(spec.tool for spec in stage)
        remaining = next_remaining

    return stages


def _dedupe_unseen_commands(
    stage: list[CommandSpec],
    executed_signatures: set[tuple[str, ...]],
) -> list[CommandSpec]:
    deduped: list[CommandSpec] = []
    for spec in stage:
        signature = tuple(spec.argv)
        if signature in executed_signatures:
            continue
        deduped.append(spec)
    return deduped


def _infer_target_for_spec(spec: CommandSpec, fallback_target: str) -> str:
    argv = list(spec.argv)
    if not argv:
        return fallback_target

    tool = spec.tool
    key_map = {
        "ffuf": "-u",
        "nuclei": "-u",
        "subfinder": "-d",
        "amass": "-d",
        "bbot": "-t",
        "katana": "-u",
        "httpx": "-u",
        "secretfinder": "-i",
        "linkfinder": "-i",
        "aquatone": "-url",
        "gowitness": "-u",
    }

    if tool == "nmap":
        return argv[-1]

    key = key_map.get(tool)
    if key and key in argv:
        idx = argv.index(key) + 1
        if idx < len(argv):
            value = argv[idx]
            if tool == "ffuf":
                return value.replace("/FUZZ", "")
            return value

    return fallback_target


def _build_followup_commands(
    *,
    config: OffensiveConfig,
    host_candidates: list[str],
    url_candidates: list[str],
    seen_targets: set[str],
    executed_signatures: set[tuple[str, ...]],
    max_followup_targets: int,
    scope_policy: ScopePolicy | None = None,
) -> list[CommandSpec]:
    if scope_policy is None and config.scope_policy_file:
        scope_policy = load_scope_policy(Path(config.scope_policy_file))
    if scope_policy is None and config.require_scope_match:
        return []
    enabled_tools = set(config.enabled_tools())
    host_tools = [tool for tool in ("httpx", "nmap") if tool in enabled_tools]
    url_tools = [
        tool
        for tool in ("httpx", "katana", "ffuf", "nuclei", "secretfinder", "linkfinder", "aquatone", "gowitness")
        if tool in enabled_tools
    ]

    accepted_hosts: list[str] = []
    for host in host_candidates:
        if scope_policy and not evaluate_target_scope(host, scope_policy)[0]:
            continue
        if config.max_total_targets is not None and len(seen_targets) >= config.max_total_targets:
            break
        if host in seen_targets:
            continue
        accepted_hosts.append(host)
        seen_targets.add(host)
        if len(accepted_hosts) >= max_followup_targets:
            break

    accepted_urls: list[str] = []
    for url in url_candidates:
        if scope_policy and not evaluate_target_scope(url, scope_policy)[0]:
            continue
        if config.max_total_targets is not None and len(seen_targets) >= config.max_total_targets:
            break
        if url in seen_targets:
            continue
        accepted_urls.append(url)
        seen_targets.add(url)
        if len(accepted_urls) >= max_followup_targets:
            break

    followups: list[CommandSpec] = []
    for target in accepted_hosts:
        for tool in host_tools:
            scoped = replace(config, target=target, tools=(tool,))
            try:
                followups.extend(CommandFactory(scoped).build())
            except CommandFactoryError:
                continue

    for target in accepted_urls:
        for tool in url_tools:
            scoped = replace(config, target=target, tools=(tool,))
            try:
                followups.extend(CommandFactory(scoped).build())
            except CommandFactoryError:
                continue

    output: list[CommandSpec] = []
    for spec in followups:
        signature = tuple(spec.argv)
        if signature in executed_signatures:
            continue
        output.append(spec)
    return output


def _finding_fingerprint(finding: Finding) -> str:
    cve_id = (finding.vulnerability.cve_id if finding.vulnerability else "").upper()
    host = (finding.target_host_id or str(finding.metadata.get("host", ""))).strip().lower()
    port = str(finding.target_port or "")
    path = str(finding.metadata.get("path", "")).strip().lower()

    raw_url = str(finding.metadata.get("url", "")).strip()
    url_norm = ""
    if raw_url.startswith(("http://", "https://")):
        parsed = urlparse(raw_url)
        path = path or (parsed.path or "/").strip().lower()
        if not host and parsed.hostname:
            host = parsed.hostname.strip().lower()
        if not port and parsed.port:
            port = str(parsed.port)
        url_norm = f"{parsed.scheme}://{parsed.netloc}{parsed.path or '/'}".lower()

    if cve_id:
        # Canonical vulnerability identity across multiple tools.
        return "|".join(["vulnerability", host, port, cve_id, path, url_norm])

    if finding.finding_type.lower() == "host":
        return "|".join(["host", host])

    if finding.finding_type.lower() == "service":
        service_name = ""
        if finding.service is not None:
            service_name = finding.service.name.lower().strip()
        return "|".join(["service", host, port, service_name])

    if finding.finding_type.lower() == "directory":
        return "|".join(["directory", host, port, path or url_norm])

    return "|".join([finding.finding_type.lower(), host, port, path, url_norm, finding.technical.strip().lower()])


def _confidence_for_finding(finding: Finding) -> float:
    base_by_tool = {
        "nuclei": 0.92,
        "gitleaks": 0.9,
        "nmap": 0.82,
        "httpx": 0.8,
        "katana": 0.73,
        "ffuf": 0.71,
        "subfinder": 0.77,
        "amass": 0.78,
        "bbot": 0.76,
        "secretfinder": 0.79,
        "linkfinder": 0.74,
        "aquatone": 0.69,
        "gowitness": 0.69,
    }
    score = base_by_tool.get(finding.tool.lower(), 0.7)

    if finding.finding_type == "vulnerability":
        score += 0.08
    elif finding.finding_type == "service":
        score += 0.02
    elif finding.finding_type == "directory":
        score -= 0.03

    cve_id = finding.vulnerability.cve_id if finding.vulnerability else ""
    if cve_id.startswith("CVE-"):
        score += 0.05
    elif cve_id.startswith("GORDIAN-"):
        score -= 0.03

    technical = finding.technical.lower()
    if any(marker in technical for marker in ("sensitive", "secret", "token", "credential")):
        score += 0.03

    return round(min(max(score, 0.05), 0.99), 3)


def _extract_host_candidate(finding: Finding) -> str | None:
    if finding.host is not None and finding.host.hostname:
        return finding.host.hostname.strip().lower()

    host_id = (finding.target_host_id or "").strip().lower()
    if host_id and "." in host_id:
        return host_id

    metadata_host = str(finding.metadata.get("host", "")).strip().lower()
    if metadata_host and "." in metadata_host:
        return metadata_host

    return None


def _extract_url_candidate(finding: Finding) -> str | None:
    raw = finding.metadata.get("url")
    if not isinstance(raw, str):
        return None

    value = raw.strip()
    if not value.startswith(("http://", "https://")):
        return None

    parsed = urlparse(value)
    if not parsed.scheme or not parsed.netloc:
        return None
    return f"{parsed.scheme}://{parsed.netloc}{parsed.path or '/'}"
