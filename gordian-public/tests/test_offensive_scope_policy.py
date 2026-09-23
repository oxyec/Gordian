from __future__ import annotations

from datetime import datetime, timezone
import json

import pytest

from src.offensive.scope_policy import (
    ScopePolicy,
    ScopePolicyError,
    evaluate_target_scope,
    is_current_time_allowed,
    load_scope_policy,
)


def test_load_scope_policy_parses_hosts_and_cidrs(tmp_path):
    scope_file = tmp_path / "scope.json"
    scope_file.write_text(
        json.dumps(
            {
                "allow_hosts": ["*.example.com"],
                "deny_hosts": ["admin.example.com"],
                "allow_cidrs": ["10.0.0.0/24"],
                "deny_cidrs": ["10.0.0.99/32"],
                "allow_schemes": ["https"],
                "hard_stop_hosts": ["payments.example.com"],
                "max_nmap_rate": 20,
                "max_ffuf_threads": 8,
                "max_nuclei_rate": 40,
                "max_total_targets": 12,
                "max_total_commands": 30,
                "max_findings": 50,
                "max_run_seconds": 600,
                "max_followup_targets": 9,
                "allowed_time_windows": ["08:00-11:30", "22:00-23:59"],
            }
        ),
        encoding="utf-8",
    )

    policy = load_scope_policy(scope_file)

    assert policy.allow_hosts == ("*.example.com",)
    assert policy.deny_hosts == ("admin.example.com",)
    assert policy.allow_cidrs == ("10.0.0.0/24",)
    assert policy.deny_cidrs == ("10.0.0.99/32",)
    assert policy.allow_schemes == ("https",)
    assert policy.hard_stop_hosts == ("payments.example.com",)
    assert policy.max_nmap_rate == 20
    assert policy.max_ffuf_threads == 8
    assert policy.max_nuclei_rate == 40
    assert policy.max_total_targets == 12
    assert policy.max_total_commands == 30
    assert policy.max_findings == 50
    assert policy.max_run_seconds == 600
    assert policy.max_followup_targets == 9
    assert policy.allowed_time_windows == ("08:00-11:30", "22:00-23:59")


def test_load_scope_policy_rejects_invalid_cidr(tmp_path):
    scope_file = tmp_path / "scope.json"
    scope_file.write_text(json.dumps({"allow_cidrs": ["10.0.0.0/99"]}), encoding="utf-8")

    with pytest.raises(ScopePolicyError, match="invalid CIDR"):
        load_scope_policy(scope_file)


def test_evaluate_target_scope_honors_allow_and_deny_rules():
    policy = ScopePolicy(
        allow_hosts=("*.example.com",),
        deny_hosts=("admin.example.com",),
    )

    allowed, _ = evaluate_target_scope("https://app.example.com", policy)
    denied, reason = evaluate_target_scope("https://admin.example.com", policy)

    assert allowed is True
    assert denied is False
    assert "deny_hosts" in reason


def test_evaluate_target_scope_rejects_disallowed_scheme():
    policy = ScopePolicy(allow_schemes=("http", "https"))

    allowed, reason = evaluate_target_scope("ftp://files.example.com", policy)

    assert allowed is False
    assert "scheme" in reason


def test_evaluate_target_scope_hard_stop_has_priority_over_allowlist():
    policy = ScopePolicy(
        allow_hosts=("*.example.com",),
        hard_stop_hosts=("payments.example.com",),
    )

    allowed, reason = evaluate_target_scope("https://payments.example.com", policy)

    assert allowed is False
    assert "hard_stop_hosts" in reason


def test_is_current_time_allowed_honors_windows():
    policy = ScopePolicy(allowed_time_windows=("08:00-11:00", "20:00-22:00"))

    allowed, _ = is_current_time_allowed(policy, now=datetime(2026, 1, 1, 8, 30, tzinfo=timezone.utc))
    blocked, reason = is_current_time_allowed(policy, now=datetime(2026, 1, 1, 15, 0, tzinfo=timezone.utc))

    assert allowed is True
    assert blocked is False
    assert "outside" in reason
