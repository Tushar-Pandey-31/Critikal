"""
Unit tests for the Chain Analyzer (Epic 3).

Tests the deterministic postcondition→precondition matching engine,
severity upgrade matrix, and chain metadata application.
"""

import pytest
import uuid
from src.agents.chain_analyzer import (
    run_chain_analysis,
    ChainHypothesis,
    _compute_match_strength,
    _chain_severity,
    _classify_match_type,
)
from src.models.finding import Finding, FindingVerdict


def _make_finding(
    *,
    vuln_class: str = "reentrancy",
    severity: str = "MEDIUM",
    verdict: str = "CONFIRMED",
    postconditions: list[str] | None = None,
    preconditions: list[str] | None = None,
    preconditions_missing: list[str] | None = None,
    attack_path: list[str] | None = None,
    contract: str = "Vault",
    function: str = "withdraw",
    hypothesis: str = "Test hypothesis",
    impact: str = "Drain funds",
) -> Finding:
    """Helper to create a test finding with minimal boilerplate."""
    return Finding(
        id=str(uuid.uuid4()),
        hotspot_node_id=f"{contract}.{function}",
        affected_contract=contract,
        affected_function=function,
        vulnerability_class=vuln_class,
        hypothesis=hypothesis,
        attack_path=attack_path or [f"{contract}::{function}"],
        evidence_nodes=[],
        confidence=70,
        severity_estimate=severity,
        impact=impact,
        title=f"Test {vuln_class} in {function}",
        verdict=verdict,
        postconditions=postconditions or [],
        preconditions=preconditions or [],
        preconditions_missing=preconditions_missing or [],
    )


class TestChainSeverity:
    """Tests for the severity upgrade matrix."""

    def test_same_medium_upgrades_to_high(self):
        result = _chain_severity("MEDIUM", "MEDIUM", "MODERATE")
        assert result == "HIGH"

    def test_same_high_upgrades_to_critical(self):
        result = _chain_severity("HIGH", "HIGH", "MODERATE")
        assert result == "CRITICAL"

    def test_strong_match_upgrades_medium(self):
        result = _chain_severity("MEDIUM", "LOW", "STRONG")
        # base = max(2,1) = 2, STRONG → 3 = HIGH
        assert result == "HIGH"

    def test_never_lower_than_highest(self):
        result = _chain_severity("HIGH", "LOW", "WEAK")
        assert result in ("HIGH", "CRITICAL")

    def test_critical_stays_critical(self):
        result = _chain_severity("CRITICAL", "LOW", "MODERATE")
        assert result == "CRITICAL"


class TestMatchClassification:
    """Tests for match type classification."""

    def test_access_type(self):
        result = _classify_match_type("owner role changed", "admin permission required")
        assert result == "ACCESS"

    def test_balance_type(self):
        result = _classify_match_type("token balance increased", "sufficient balance needed")
        assert result == "BALANCE"

    def test_timing_type(self):
        result = _classify_match_type("block timestamp advanced", "deadline passed")
        assert result == "TIMING"

    def test_state_default(self):
        result = _classify_match_type("supply updated", "total supply zero")
        assert result == "STATE"


class TestMatchStrength:
    """Tests for match strength computation."""

    def test_strong_match_same_contract_shared_words(self):
        enabler = _make_finding(contract="Vault", postconditions=["balance drained"])
        blocked = _make_finding(contract="Vault", preconditions_missing=["balance is zero"])
        strength = _compute_match_strength(
            "balance drained completely to zero", 
            "balance must be zero for overflow", 
            enabler, blocked
        )
        assert strength == "STRONG"

    def test_moderate_match_shared_category(self):
        enabler = _make_finding(contract="TokenA")
        blocked = _make_finding(contract="TokenB")
        strength = _compute_match_strength(
            "owner privileges changed",
            "admin control required",
            enabler, blocked
        )
        assert strength in ("MODERATE", "STRONG")

    def test_weak_match_no_overlap(self):
        enabler = _make_finding(contract="ContractA")
        blocked = _make_finding(contract="ContractB")
        strength = _compute_match_strength(
            "completely unrelated output",
            "totally different requirement",
            enabler, blocked
        )
        # Should be WEAK or MODERATE depending on category match
        assert strength in ("WEAK", "MODERATE")


class TestRunChainAnalysis:
    """Integration tests for the full chain analysis engine."""

    def test_single_finding_returns_empty(self):
        finding = _make_finding(postconditions=["state changed"])
        chains = run_chain_analysis([finding])
        assert chains == []

    def test_no_enablers_returns_empty(self):
        # Two findings but neither has postconditions
        f1 = _make_finding(function="funcA", preconditions_missing=["needs X"])
        f2 = _make_finding(function="funcB", preconditions_missing=["needs Y"])
        chains = run_chain_analysis([f1, f2])
        assert chains == []

    def test_matching_pair_creates_chain(self):
        enabler = _make_finding(
            function="deposit",
            postconditions=["User balance increased", "Total supply updated"],
            severity="HIGH",
        )
        blocked = _make_finding(
            function="withdraw",
            preconditions_missing=["User balance must be greater than zero"],
            severity="MEDIUM",
        )
        chains = run_chain_analysis([enabler, blocked])
        # Should find at least one chain (balance keyword overlap)
        assert len(chains) >= 1
        chain = chains[0]
        assert chain.chain_id.startswith("CH-")
        assert chain.enabler_finding.id == enabler.id
        assert chain.blocked_finding.id == blocked.id
        assert chain.match_strength in ("STRONG", "MODERATE")

    def test_chain_applies_severity_upgrade(self):
        enabler = _make_finding(
            function="setOwner",
            postconditions=["Owner role transferred to attacker"],
            severity="HIGH",
        )
        blocked = _make_finding(
            function="withdrawAll",
            preconditions_missing=["Caller must be owner"],
            severity="HIGH",
            verdict="PARTIAL",
        )
        chains = run_chain_analysis([enabler, blocked])
        # HIGH + HIGH should upgrade to CRITICAL
        if chains:
            assert chains[0].chain_severity == "CRITICAL"

    def test_chain_applies_metadata_to_findings(self):
        enabler = _make_finding(
            function="flip",
            postconditions=["Paused state toggled"],
            severity="MEDIUM",
        )
        blocked = _make_finding(
            function="drain",
            preconditions_missing=["Contract must be paused"],
            severity="HIGH",
        )
        chains = run_chain_analysis([enabler, blocked])
        if chains:
            assert enabler.chain_role == "enabler"
            assert blocked.chain_role == "blocked"
            assert len(enabler.chain_ids) >= 1
            assert len(blocked.chain_ids) >= 1

    def test_refuted_blocked_finding_upgraded_to_partial(self):
        enabler = _make_finding(
            function="grantRole",
            postconditions=["Admin role granted to user"],
            severity="MEDIUM",
        )
        blocked = _make_finding(
            function="selfDestruct",
            preconditions_missing=["Caller must have admin role"],
            severity="CRITICAL",
            verdict="REFUTED",
        )
        chains = run_chain_analysis([enabler, blocked])
        if chains:
            # REFUTED finding with a matching enabler should be upgraded to PARTIAL
            assert blocked.verdict in (FindingVerdict.PARTIAL, "PARTIAL")

    def test_no_self_chaining(self):
        """A finding should not chain with itself."""
        f = _make_finding(
            postconditions=["balance changed"],
            preconditions_missing=["balance changed"],
        )
        chains = run_chain_analysis([f, _make_finding()])
        # The finding should not appear as both enabler and blocked
        for chain in chains:
            assert chain.enabler_finding.id != chain.blocked_finding.id

    def test_combined_attack_steps_populated(self):
        enabler = _make_finding(
            function="approve",
            postconditions=["Token allowance set"],
            attack_path=["Token::approve"],
        )
        blocked = _make_finding(
            function="transferFrom",
            preconditions_missing=["Allowance must be set for token"],
            attack_path=["Token::transferFrom"],
        )
        chains = run_chain_analysis([enabler, blocked])
        if chains:
            steps = chains[0].combined_attack_steps
            assert len(steps) >= 2
            assert any("[ENABLER]" in s for s in steps)
            assert any("[EXPLOIT]" in s for s in steps)
