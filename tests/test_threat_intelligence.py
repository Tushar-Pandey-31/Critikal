"""
Tests for P0: Threat Intelligence Layer

Tests:
1. ThreatProfiler protocol classification
2. ThreatProfiler threat profile loading
3. ThreatProfiler agent routing
4. AttackVectorDB loading and matching
5. AttackVectorDB bundle generation
"""

import pytest
import networkx as nx
from src.intelligence.threat_profiler import ThreatProfiler
from src.intelligence.attack_vector_db import AttackVectorDB


# ═══════════════════════════════════════════════════════════
#  Fixtures
# ═══════════════════════════════════════════════════════════

def _build_vault_graph() -> nx.DiGraph:
    """Build a minimal vault-like knowledge graph for testing."""
    g = nx.DiGraph()
    # Contract node
    g.add_node("Vault", type="contract", name="Vault")
    # Vault-specific functions
    for fn in ["deposit", "withdraw", "redeem", "convertToShares",
                "convertToAssets", "totalAssets", "previewDeposit",
                "previewRedeem", "maxDeposit", "maxWithdraw"]:
        node_id = f"Vault::{fn}"
        g.add_node(node_id, type="function", name=fn, contract="Vault",
                   source_code=f"function {fn}() public {{ }}")
        g.add_edge("Vault", node_id, type="DEFINES")
    # State vars
    g.add_node("Vault::totalShares", type="state_variable", name="totalShares", contract="Vault")
    g.add_node("Vault::asset", type="state_variable", name="asset", contract="Vault")
    return g


def _build_lending_graph() -> nx.DiGraph:
    """Build a minimal lending-like knowledge graph for testing."""
    g = nx.DiGraph()
    g.add_node("LendingPool", type="contract", name="LendingPool")
    for fn in ["borrow", "repay", "liquidate", "flashLoan",
                "accrueInterest", "getAccountLiquidity"]:
        node_id = f"LendingPool::{fn}"
        g.add_node(node_id, type="function", name=fn, contract="LendingPool",
                   source_code=f"function {fn}() external {{ }}")
        g.add_edge("LendingPool", node_id, type="DEFINES")
    g.add_node("LendingPool::totalBorrows", type="state_variable",
               name="totalBorrows", contract="LendingPool")
    g.add_node("LendingPool::borrowIndex", type="state_variable",
               name="borrowIndex", contract="LendingPool")
    g.add_node("LendingPool::healthFactor", type="state_variable",
               name="healthFactor", contract="LendingPool")
    return g


def _build_dex_graph() -> nx.DiGraph:
    """Build a minimal DEX-like knowledge graph for testing."""
    g = nx.DiGraph()
    g.add_node("UniswapPool", type="contract", name="UniswapPool")
    for fn in ["swap", "mint", "burn", "getReserves", "sync"]:
        node_id = f"UniswapPool::{fn}"
        g.add_node(node_id, type="function", name=fn, contract="UniswapPool",
                   source_code=f"function {fn}() external {{ }}")
        g.add_edge("UniswapPool", node_id, type="DEFINES")
    g.add_node("UniswapPool::reserve0", type="state_variable",
               name="reserve0", contract="UniswapPool")
    g.add_node("UniswapPool::reserve1", type="state_variable",
               name="reserve1", contract="UniswapPool")
    return g


def _build_empty_graph() -> nx.DiGraph:
    return nx.DiGraph()


# ═══════════════════════════════════════════════════════════
#  ThreatProfiler Tests
# ═══════════════════════════════════════════════════════════

class TestThreatProfiler:
    def test_classify_vault(self):
        profiler = ThreatProfiler()
        result = profiler.classify(_build_vault_graph())
        assert len(result) >= 1
        assert result[0]["type"] == "vault"
        assert result[0]["confidence"] > 0.5

    def test_classify_lending(self):
        profiler = ThreatProfiler()
        result = profiler.classify(_build_lending_graph())
        assert len(result) >= 1
        assert result[0]["type"] == "lending"
        assert result[0]["confidence"] > 0.5

    def test_classify_dex(self):
        profiler = ThreatProfiler()
        result = profiler.classify(_build_dex_graph())
        assert len(result) >= 1
        assert result[0]["type"] == "dex_amm"

    def test_classify_empty_graph(self):
        profiler = ThreatProfiler()
        result = profiler.classify(_build_empty_graph())
        assert result[0]["type"] == "unknown"
        assert result[0]["confidence"] == 0.0

    def test_get_threat_profile_vault(self):
        profiler = ThreatProfiler()
        profile = profiler.get_threat_profile("vault")
        assert profile.protocol_type == "vault"
        assert len(profile.adversaries) > 0
        assert len(profile.invariants) > 0
        assert profile.adversaries[0].name  # has a name
        assert profile.adversaries[0].priority >= 1

    def test_get_threat_profile_unknown(self):
        profiler = ThreatProfiler()
        profile = profiler.get_threat_profile("nonexistent_type")
        assert profile.protocol_type == "nonexistent_type"
        assert len(profile.adversaries) == 0

    def test_format_for_prompt(self):
        profiler = ThreatProfiler()
        profile = profiler.get_threat_profile("lending")
        prompt = profile.format_for_prompt()
        assert "LENDING PROTOCOL" in prompt
        assert "ADVERSARIES" in prompt
        assert "INVARIANTS" in prompt
        assert len(prompt) > 100  # non-trivial content

    def test_agent_routing_basic(self):
        profiler = ThreatProfiler()
        agents = profiler.get_agent_routing("vault", {
            "has_external_calls": False,
            "has_math_operations": True,
            "has_division": True,
            "has_role_checks": False,
            "matched_vector_count": 3,
        })
        assert "attack_hypothesis" in agents
        assert "math_precision" in agents
        assert "vector_scan" in agents

    def test_agent_routing_no_duplicates(self):
        profiler = ThreatProfiler()
        agents = profiler.get_agent_routing("vault", {
            "has_external_calls": True,
            "has_math_operations": True,
            "has_division": True,
            "has_role_checks": True,
            "is_initializer": True,
            "matched_vector_count": 10,
        })
        assert len(agents) == len(set(agents))  # no duplicates

    def test_extract_hotspot_signals(self):
        profiler = ThreatProfiler()
        g = _build_vault_graph()
        # Add some signals to a node
        g.nodes["Vault::deposit"]["source_code"] = "function deposit(uint256 amount) public { uint256 shares = amount / totalSupply; }"
        g.nodes["Vault::deposit"]["is_protected"] = False
        signals = profiler.extract_hotspot_signals(g, "Vault::deposit")
        assert "has_division" in signals
        assert "has_math_operations" in signals
        assert "writes_state" in signals


# ═══════════════════════════════════════════════════════════
#  AttackVectorDB Tests
# ═══════════════════════════════════════════════════════════

class TestAttackVectorDB:
    def test_load_vectors(self):
        db = AttackVectorDB()
        assert db.total_vectors > 0
        print(f"Loaded {db.total_vectors} vectors")

    def test_get_vector_by_id(self):
        db = AttackVectorDB()
        v = db.get_vector("V001")
        assert v is not None
        assert v.title == "ERC4626 Share Inflation"
        assert "vault" in v.applicable_protocols

    def test_match_vectors_vault(self):
        db = AttackVectorDB()
        g = _build_vault_graph()
        matched = db.match_vectors(g, ["vault"])
        assert len(matched) > 0
        # Should include V001 (ERC4626 share inflation)
        matched_ids = {v.id for v in matched}
        assert "V001" in matched_ids

    def test_match_vectors_lending(self):
        db = AttackVectorDB()
        g = _build_lending_graph()
        matched = db.match_vectors(g, ["lending"])
        assert len(matched) > 0

    def test_match_vectors_includes_universal(self):
        db = AttackVectorDB()
        g = _build_vault_graph()
        # "all" protocol vectors should be included
        matched_with = db.match_vectors(g, ["vault"], include_universal=True)
        matched_without = db.match_vectors(g, ["vault"], include_universal=False)
        assert len(matched_with) >= len(matched_without)

    def test_build_agent_bundle(self):
        db = AttackVectorDB()
        matched = db.match_vectors(_build_vault_graph(), ["vault"])
        bundle = db.build_agent_bundle(matched, "function deposit() public { }")
        assert "ATTACK VECTOR DATABASE" in bundle
        assert len(bundle) > 50

    def test_build_agent_bundle_empty(self):
        db = AttackVectorDB()
        bundle = db.build_agent_bundle([], "")
        assert bundle == ""

    def test_build_agent_bundle_token_limit(self):
        db = AttackVectorDB()
        matched = db.match_vectors(_build_vault_graph(), ["vault"])
        bundle = db.build_agent_bundle(matched, max_tokens=500)
        # Should be within approximate token limit (500 tokens ≈ 2000 chars)
        assert len(bundle) < 3000

    def test_get_categories(self):
        db = AttackVectorDB()
        cats = db.get_categories()
        assert len(cats) > 0
        assert "arithmetic" in cats
        assert "reentrancy" in cats

    def test_vectors_by_category(self):
        db = AttackVectorDB()
        reent = db.get_vectors_by_category("reentrancy")
        assert len(reent) >= 3  # at least V020, V021, V022

    def test_vector_fields_complete(self):
        """Every vector must have all required fields."""
        db = AttackVectorDB()
        for vec in db.get_all_vectors():
            assert vec.id, f"Vector missing id"
            assert vec.title, f"{vec.id} missing title"
            assert vec.root_cause, f"{vec.id} missing root_cause"
            assert vec.detection_pattern, f"{vec.id} missing detection_pattern"
            assert vec.false_positive_guard, f"{vec.id} missing false_positive_guard"
            assert vec.applicable_protocols, f"{vec.id} missing applicable_protocols"
            assert vec.severity_range, f"{vec.id} missing severity_range"
