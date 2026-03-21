"""
Chain Analyzer — Deterministic postcondition→precondition matching engine.

Links findings together into multi-step exploit chains by matching
what one exploit CREATES (postconditions) with what another exploit NEEDS
(preconditions_missing).

This is a pure deterministic engine — no LLM needed.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import List

from src.models.finding import Finding, FindingVerdict

logger = logging.getLogger(__name__)


# ── Chain Hypothesis dataclass ───────────────────────────────────

@dataclass
class ChainHypothesis:
    """A multi-step exploit chain linking two findings."""
    chain_id: str                   # CH-01, CH-02, ...
    enabler_finding: Finding        # Finding B: creates the precondition
    blocked_finding: Finding        # Finding A: needs the precondition
    match_type: str                 # STATE / ACCESS / TIMING / BALANCE
    match_strength: str             # STRONG / MODERATE / WEAK
    matched_postcondition: str      # What B creates
    matched_precondition: str       # What A needs
    combined_attack_steps: List[str] = field(default_factory=list)
    chain_severity: str = ""        # Upgraded severity


# ── Matching keywords by type ────────────────────────────────────

_STATE_KEYWORDS = [
    "balance", "supply", "totalSupply", "shares", "debt",
    "allowance", "approved", "owner", "admin", "paused",
    "initialized", "locked", "nonce", "rate", "price",
    "reserve", "collateral", "liquidit", "stake", "reward",
]

_ACCESS_KEYWORDS = [
    "owner", "admin", "role", "permission", "auth",
    "access", "privilege", "operator", "minter", "governance",
    "controller", "manager", "guardian",
]

_TIMING_KEYWORDS = [
    "block", "timestamp", "time", "delay", "cooldown",
    "timelock", "deadline", "expir", "epoch", "period",
]

_BALANCE_KEYWORDS = [
    "balance", "fund", "token", "ether", "eth", "amount",
    "value", "deposit", "withdraw", "transfer", "flash",
]


def _classify_match_type(postcondition: str, precondition: str) -> str:
    """Classify the type of match based on keyword analysis."""
    combined = (postcondition + " " + precondition).lower()

    scores = {
        "ACCESS": sum(1 for kw in _ACCESS_KEYWORDS if kw in combined),
        "TIMING": sum(1 for kw in _TIMING_KEYWORDS if kw in combined),
        "BALANCE": sum(1 for kw in _BALANCE_KEYWORDS if kw in combined),
        "STATE": sum(1 for kw in _STATE_KEYWORDS if kw in combined),
    }
    return max(scores, key=scores.get) if max(scores.values()) > 0 else "STATE"


def _compute_match_strength(
    postcondition: str,
    precondition: str,
    enabler: Finding,
    blocked: Finding,
) -> str:
    """Compute how strong the postcondition→precondition match is."""
    post_lower = postcondition.lower()
    pre_lower = precondition.lower()

    # STRONG: same contract or shared variable names
    if enabler.affected_contract == blocked.affected_contract:
        # Same contract — state changes are directly visible
        if any(word in post_lower for word in pre_lower.split() if len(word) > 3):
            return "STRONG"

    # Check for overlapping key terms (3+ character words)
    post_words = set(w for w in post_lower.split() if len(w) > 3)
    pre_words = set(w for w in pre_lower.split() if len(w) > 3)
    overlap = post_words & pre_words

    if len(overlap) >= 3:
        return "STRONG"
    elif len(overlap) >= 1:
        return "MODERATE"
    else:
        # Check category-level match
        post_type = _classify_match_type(postcondition, "")
        pre_type = _classify_match_type("", precondition)
        if post_type == pre_type:
            return "MODERATE"
        return "WEAK"


# ── Severity Upgrade Matrix ──────────────────────────────────────

_SEVERITY_RANK = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
    "INFO": 0,
}

_SEVERITY_FROM_RANK = {v: k for k, v in _SEVERITY_RANK.items()}


def _chain_severity(
    enabler_severity: str,
    blocked_severity: str,
    match_strength: str,
) -> str:
    """
    Compute the chain severity using the upgrade matrix.

    Rules:
    - Chain severity is NEVER lower than the higher of the two.
    - REFUTED + confirmed enabler → re-evaluate as PARTIAL at enabler's severity.
    - Same severity + same severity → upgrade by 1 tier.
    - STRONG match → bonus upgrade chance.
    """
    rank_a = _SEVERITY_RANK.get(enabler_severity.upper(), 1)
    rank_b = _SEVERITY_RANK.get(blocked_severity.upper(), 1)
    base_rank = max(rank_a, rank_b)

    # Same severity → upgrade by 1
    if rank_a == rank_b and rank_a >= 2:
        base_rank = min(base_rank + 1, 4)

    # Strong match → additional upgrade if not already CRITICAL
    if match_strength == "STRONG" and base_rank < 4:
        base_rank = min(base_rank + 1, 4)

    return _SEVERITY_FROM_RANK.get(base_rank, "HIGH")


# ── Main Analysis Engine ─────────────────────────────────────────

def run_chain_analysis(findings: list[Finding]) -> list[ChainHypothesis]:
    """
    Run deterministic chain analysis on all findings.

    For every finding with preconditions_missing, search all other findings
    for matching postconditions. Build ChainHypothesis objects for each match.
    """
    if len(findings) < 2:
        print("[Chain] Need at least 2 findings for chain analysis.")
        return []

    # Collect findings with postconditions (potential enablers)
    enablers = [
        f for f in findings
        if f.postconditions
        and f.verdict not in (FindingVerdict.REFUTED, "REFUTED")
    ]

    # Collect findings with missing preconditions (potentially blocked)
    blocked = [
        f for f in findings
        if f.preconditions_missing
    ]

    if not enablers or not blocked:
        print("[Chain] No enabler/blocked pairs found — skipping chain analysis.")
        return []

    print(f"[Chain] Analyzing {len(enablers)} enabler(s) × {len(blocked)} blocked finding(s)...")

    chains: list[ChainHypothesis] = []
    chain_counter = 0

    for blocked_finding in blocked:
        for missing_pre in blocked_finding.preconditions_missing:
            for enabler_finding in enablers:
                # Don't chain a finding with itself
                if enabler_finding.id == blocked_finding.id:
                    continue

                for postcond in enabler_finding.postconditions:
                    strength = _compute_match_strength(
                        postcond, missing_pre, enabler_finding, blocked_finding
                    )

                    # Only create chains for non-WEAK matches
                    if strength == "WEAK":
                        continue

                    chain_counter += 1
                    chain_id = f"CH-{chain_counter:02d}"
                    match_type = _classify_match_type(postcond, missing_pre)

                    # Build combined attack steps
                    combined_steps = []
                    # Step 1: Execute enabler
                    enabler_path = enabler_finding.attack_path or [
                        f"{enabler_finding.affected_contract}::{enabler_finding.affected_function}"
                    ]
                    for step in enabler_path:
                        combined_steps.append(f"[ENABLER] {step}")
                    combined_steps.append(f"[POSTCONDITION] {postcond}")

                    # Step 2: Execute blocked finding
                    blocked_path = blocked_finding.attack_path or [
                        f"{blocked_finding.affected_contract}::{blocked_finding.affected_function}"
                    ]
                    for step in blocked_path:
                        combined_steps.append(f"[EXPLOIT] {step}")
                    combined_steps.append(
                        f"[IMPACT] {blocked_finding.impact or 'Combined exploit impact'}"
                    )

                    severity = _chain_severity(
                        enabler_finding.severity_estimate,
                        blocked_finding.severity_estimate,
                        strength,
                    )

                    chain = ChainHypothesis(
                        chain_id=chain_id,
                        enabler_finding=enabler_finding,
                        blocked_finding=blocked_finding,
                        match_type=match_type,
                        match_strength=strength,
                        matched_postcondition=postcond,
                        matched_precondition=missing_pre,
                        combined_attack_steps=combined_steps,
                        chain_severity=severity,
                    )
                    chains.append(chain)

                    print(
                        f"  [Chain] {chain_id}: "
                        f"{enabler_finding.affected_contract}::{enabler_finding.affected_function} "
                        f"→ {blocked_finding.affected_contract}::{blocked_finding.affected_function} "
                        f"({strength} {match_type}, severity: {severity})"
                    )

    # Apply chain metadata back to findings
    for chain in chains:
        _apply_chain_to_findings(chain)

    print(f"[Chain] Complete: {len(chains)} chain(s) discovered")
    return chains


def _apply_chain_to_findings(chain: ChainHypothesis) -> None:
    """Apply chain metadata back onto the involved findings."""
    enabler = chain.enabler_finding
    blocked = chain.blocked_finding

    # Add chain ID to both findings
    if chain.chain_id not in enabler.chain_ids:
        enabler.chain_ids.append(chain.chain_id)
    if chain.chain_id not in blocked.chain_ids:
        blocked.chain_ids.append(chain.chain_id)

    # Set roles
    enabler.chain_role = "enabler"
    blocked.chain_role = "blocked"

    # Severity upgrade on the blocked finding
    blocked_rank = _SEVERITY_RANK.get(blocked.severity_estimate.upper(), 1)
    chain_rank = _SEVERITY_RANK.get(chain.chain_severity.upper(), 1)
    if chain_rank > blocked_rank:
        original = blocked.severity_estimate
        blocked.chain_severity_upgrade = f"{original} → {chain.chain_severity}"
        blocked.severity_estimate = chain.chain_severity

    # If the blocked finding was REFUTED/PARTIAL, upgrade to at least PARTIAL/CONTESTED
    if blocked.verdict in (FindingVerdict.REFUTED, "REFUTED"):
        blocked.verdict = FindingVerdict.PARTIAL
    elif blocked.verdict in (FindingVerdict.UNASSESSED, "UNASSESSED"):
        blocked.verdict = FindingVerdict.CONTESTED
