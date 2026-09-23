"""Scoring.

Two knobs live here:

1. `edge_cost` — the weight Dijkstra minimises. Lower cost = an attacker
   prefers this exploit. Blends CVSS (impact), EPSS (observed exploitation
   in the wild), weaponisation, and the target's value.

2. `path_risk_score` — the 0-100 number a human reads in the report.
   Deliberately *not* a monotone function of edge cost: a one-hop chain
   against a low-value target should score lower than a multi-hop chain
   that ends in full MITRE coverage and hits a crown jewel, even if the
   single-hop chain has lower total cost.

The formula is a weighted sum of five signals. Weights sum to 100 so the
numbers are easy to reason about:

    target value          -> 30 pts   (how bad is it if they succeed?)
    chain severity (CVSS) -> 20 pts   (how nasty are the individual hops?)
    chain success prob    -> 25 pts   (geometric mean of per-step prob)
    MITRE stage coverage  -> 15 pts   (is this a full kill chain or a stub?)
    weaponisation bonus   -> 10 pts   (are these actually being used today?)

Then a hop penalty (max -10) docks noisy chains. I let the raw score
exceed 100 slightly before clamping; that way tweaking one weight moves
everything up or down cleanly instead of hitting a hard ceiling.
"""

from __future__ import annotations

import logging
import math

from .models import AttackPath, ExploitCategory, Host, Vulnerability

log = logging.getLogger(__name__)
_warned_missing_cve_db = False

_FULL_KILL_CHAIN_STAGES = {
    ExploitCategory.INITIAL_ACCESS,
    ExploitCategory.PRIVILEGE_ESCALATION,
    ExploitCategory.LATERAL_MOVEMENT,
}


def edge_cost(vuln: Vulnerability, target_criticality: int) -> float:
    base = vuln.difficulty
    epss_discount = 1.0 - (vuln.epss_score * 0.4)
    value_bonus = 1.0 - (target_criticality / 20.0)
    return max(base * epss_discount * value_bonus, 0.001)


def _geometric_mean(values: list[float]) -> float:
    if not values:
        return 0.0
    if any(not math.isfinite(value) or value < 0 for value in values):
        raise ValueError("geometric mean requires finite non-negative values")
    if any(value == 0 for value in values):
        return 0.0
    return math.exp(math.fsum(math.log(value) for value in values) / len(values))


def path_risk_score(
    path: AttackPath,
    crown_jewel: Host,
    cve_db: dict[str, Vulnerability] | None = None,
) -> float:
    if not path.steps:
        return 0.0

    # 1. Target value (max 30). Criticality is documented as [0,10]; clamp so
    # bad upstream data can't push a single signal above its weight budget.
    criticality = min(max(crown_jewel.criticality, 0), 10)
    target_value = (criticality / 10.0) * 30.0

    # 2. Chain severity — average CVSS (max 20).
    if not path.cvss_chain:
        severity = 0.0
    else:
        avg_cvss = sum(path.cvss_chain) / len(path.cvss_chain)
        severity = (min(max(avg_cvss, 0.0), 10.0) / 10.0) * 20.0

    # 3. Success probability — geometric mean of per-step confidence (max 25).
    # Confidence is (1 - clamped_cost) floored at 0.05 so one tough hop doesn't
    # collapse the whole product to zero. Clamping cost to [0,1] first prevents
    # the floor from masking a negative confidence (semantic bug).
    confidences = [max(1.0 - min(max(step.cost, 0.0), 1.0), 0.05) for step in path.steps]
    success_prob = _geometric_mean(confidences)
    success_score = success_prob * 25.0

    # 4. MITRE stage coverage (max 15).
    matched_stages = len(path.unique_categories & _FULL_KILL_CHAIN_STAGES)
    coverage = (matched_stages / 3.0) * 15.0

    # 5. Weaponisation bonus (max 10). Requires cve_db to look up weaponized
    # flag — degrade gracefully if caller didn't pass it.
    weapon_bonus = 0.0
    if cve_db is not None:
        weaponised = [
            1 for step in path.steps
            if (v := cve_db.get(step.cve_id)) and v.weaponized
        ]
        if path.steps:
            weapon_bonus = (sum(weaponised) / len(path.steps)) * 10.0
    else:
        global _warned_missing_cve_db
        if not _warned_missing_cve_db:
            log.warning(
                "path_risk_score called without cve_db; weaponisation bonus "
                "disabled — scores may underestimate risk for KEV-listed CVEs"
            )
            _warned_missing_cve_db = True

    # Hop penalty: chains longer than 2 hops cost 2.5 pts each, max -10.
    hop_penalty = min(max(path.hops - 2, 0) * 2.5, 10.0)

    raw = target_value + severity + success_score + coverage + weapon_bonus - hop_penalty
    return round(max(0.0, min(raw, 100.0)), 1)
