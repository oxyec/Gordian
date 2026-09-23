"""Offensive integration package for Gordian."""

from .command_factory import CommandFactory, CommandFactoryError, CommandSpec
from .config import (
    Intensity,
    OffensiveConfig,
    OffensiveConfigError,
    OffensiveMode,
    SpeedProfile,
    load_offensive_config,
    merge_cli_overrides,
    should_attempt_offensive,
)
from .dashboard import DashboardServer, DashboardServerConfig, DashboardUnavailableError
from .events import LiveLogHook, build_event, emit_event
from .hub import OffensiveIntegrationHub, OffensiveRunSummary
from .injector import GraphDelta, GraphInjector
from .parsers import Finding, parser_for_tool
from .runner import AsyncToolRunner, ToolRunResult
from .scope_policy import (
    ScopePolicy,
    ScopePolicyError,
    evaluate_target_scope,
    is_current_time_allowed,
    load_scope_policy,
)
from .storyteller import Storyteller
from .wordlists import (
    WordlistDownloadError,
    WordlistProfile,
    describe_profiles_for_cli,
    ensure_wordlist,
    get_wordlist_profile,
    list_wordlist_profiles,
    recommended_wordlist_profiles,
    resolve_wordlist_store_dir,
)

__all__ = [
    "AsyncToolRunner",
    "CommandFactory",
    "CommandFactoryError",
    "CommandSpec",
    "DashboardServer",
    "DashboardServerConfig",
    "DashboardUnavailableError",
    "Finding",
    "GraphDelta",
    "GraphInjector",
    "Intensity",
    "LiveLogHook",
    "OffensiveConfig",
    "OffensiveConfigError",
    "OffensiveIntegrationHub",
    "OffensiveMode",
    "OffensiveRunSummary",
    "SpeedProfile",
    "ScopePolicy",
    "ScopePolicyError",
    "Storyteller",
    "ToolRunResult",
    "WordlistDownloadError",
    "WordlistProfile",
    "build_event",
    "describe_profiles_for_cli",
    "emit_event",
    "evaluate_target_scope",
    "is_current_time_allowed",
    "ensure_wordlist",
    "get_wordlist_profile",
    "list_wordlist_profiles",
    "load_offensive_config",
    "load_scope_policy",
    "merge_cli_overrides",
    "parser_for_tool",
    "recommended_wordlist_profiles",
    "resolve_wordlist_store_dir",
    "should_attempt_offensive",
]
