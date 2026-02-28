"""
Tests for Dev Story 3 — Cross-Function State Transition Modeling.

Covers:
  3.1 State Dependency Graph construction
  3.2 Dangerous Sequence Detection
  3.3 Exploit Chain Generation
  Integration: Risk scoring, query layer
"""

import pytest
import networkx as nx

from src.utils.graph_queries import (
    GraphQueries,
    get_state_dependencies,
    get_dangerous_sequences,
    get_exploit_chains,
)


# ═══════════════════════════════════════════════════════════════
#  Helpers
# ═══════════════════════════════════════════════════════════════

def _add_contract(g: nx.DiGraph, name: str, tier: str = "CORE"):
    g.add_node(name, type="contract", name=name, tier=tier)


def _add_func(
    g: nx.DiGraph,
    contract: str,
    name: str,
    visibility: str = "public",
    is_external_entry: bool = True,
    is_protected: bool = False,
    is_payable: bool = False,
    reachable: bool = True,
    **extra,
):
    fid = f"{contract}::{name}"
    g.add_node(fid, **{
        "type": "function",
        "name": name,
        "contract": contract,
        "visibility": visibility,
        "is_external_entry": is_external_entry,
        "is_protected": is_protected,
        "is_payable": is_payable,
        "is_view_or_pure": False,
        "is_constructor": False,
        "reachable_from_external_entry": reachable,
        "propagated_state_variables": [],
        "writes_state": False,
        "modifiers": [],
        "signature": f"{name}()",
        # DS1 / DS2 defaults
        "safe_init_pattern": False,
        "has_initializer_guard": False,
        "has_reentrancy_guard": False,
        "access_control_type": "none",
        "unprotected_risk_level": "NONE",
        "reentrancy_risk": False,
        "can_escalate_privileges": False,
        "is_unprotected_mutator": False,
        "state_write_after_external_call": False,
        "cei_violation_only": False,
        "has_array_length_mutation": False,
        "delegatecall_storage_risk": False,
        "has_taint_risk": False,
        "taint_risk_score": 0,
        "taint_risk_types": [],
        "tainted_state_writes": [],
        **extra,
    })
    return fid


def _add_var(g: nx.DiGraph, contract: str, name: str, sensitivity_tags=None):
    vid = f"{contract}::{name}"
    g.add_node(vid, **{
        "type": "state_variable",
        "node_type": "StateVariable",
        "name": name,
        "contract": contract,
        "sensitivity_tags": sensitivity_tags or [],
        "sensitivity_tag": (sensitivity_tags or [None])[0],
        "is_sensitive": bool(sensitivity_tags),
    })
    return vid


def _link_reads(g, func_id, var_id):
    g.add_edge(func_id, var_id, relationship="READS")


def _link_writes(g, func_id, var_id):
    g.add_edge(func_id, var_id, relationship="WRITES")


def _run_ds3(g: nx.DiGraph):
    from src.graph_builder import GraphBuilder
    gb = GraphBuilder()
    gb.graph = g
    gb._build_state_dependency_graph()
    gb._detect_dangerous_sequences()
    gb._generate_exploit_chains()
    return gb


def _run_ds3_with_scoring(g: nx.DiGraph):
    gb = _run_ds3(g)
    gb._compute_global_risk_scores()
    return gb


# ═══════════════════════════════════════════════════════════════
#  3.1 State Dependency Graph
# ═══════════════════════════════════════════════════════════════

class TestStateDependencyGraph:

    def test_write_read_creates_dependency(self):
        """deposit() writes balance, withdraw() reads balance → dependency."""
        g = nx.DiGraph()
        _add_contract(g, "Vault")
        vid = _add_var(g, "Vault", "balances", ["ACCOUNTING_CRITICAL"])
        f1 = _add_func(g, "Vault", "deposit")
        f2 = _add_func(g, "Vault", "withdraw")
        _link_writes(g, f1, vid)
        _link_reads(g, f2, vid)
        _run_ds3(g)

        deps_out = g.nodes[f1]["state_dependencies_out"]
        assert len(deps_out) == 1
        assert deps_out[0]["target"] == f2
        assert vid in deps_out[0]["shared_variables"]
        assert "ACCOUNTING_CRITICAL" in deps_out[0]["sensitivity_overlap"]

    def test_no_dependency_without_shared_state(self):
        g = nx.DiGraph()
        _add_contract(g, "V")
        v1 = _add_var(g, "V", "a")
        v2 = _add_var(g, "V", "b")
        f1 = _add_func(g, "V", "setA")
        f2 = _add_func(g, "V", "readB")
        _link_writes(g, f1, v1)
        _link_reads(g, f2, v2)
        _run_ds3(g)

        assert g.nodes[f1]["state_dependencies_out"] == []

    def test_write_write_dependency(self):
        """Two functions writing the same variable → INVARIANT potential."""
        g = nx.DiGraph()
        _add_contract(g, "V")
        vid = _add_var(g, "V", "totalSupply", ["ACCOUNTING_CRITICAL"])
        f1 = _add_func(g, "V", "mint")
        f2 = _add_func(g, "V", "burn")
        _link_writes(g, f1, vid)
        _link_writes(g, f2, vid)
        _run_ds3(g)

        deps = g.nodes[f1]["state_dependencies_out"]
        assert any(d["target"] == f2 for d in deps)
        dep = next(d for d in deps if d["target"] == f2)
        assert "write" in dep["dependency_type"]

    def test_cross_contract_no_dependency(self):
        """Functions in different contracts don't create STATE_DEPENDENCY."""
        g = nx.DiGraph()
        _add_contract(g, "A")
        _add_contract(g, "B")
        vid = _add_var(g, "A", "x")
        f1 = _add_func(g, "A", "setX")
        f2 = _add_func(g, "B", "readX")
        _link_writes(g, f1, vid)
        _link_reads(g, f2, vid)
        _run_ds3(g)

        assert g.nodes[f1]["state_dependencies_out"] == []

    def test_bidirectional_dependency(self):
        """
        deposit writes balance (withdraw reads it),
        withdraw writes totalSupply (deposit reads it) → dependency both ways.
        Uses separate variables to avoid DiGraph single-edge-per-pair limit.
        """
        g = nx.DiGraph()
        _add_contract(g, "V")
        v_bal = _add_var(g, "V", "balance", ["ACCOUNTING_CRITICAL"])
        v_supply = _add_var(g, "V", "totalSupply", ["ACCOUNTING_CRITICAL"])
        f1 = _add_func(g, "V", "deposit")
        f2 = _add_func(g, "V", "withdraw")
        _link_writes(g, f1, v_bal)
        _link_reads(g, f2, v_bal)
        _link_writes(g, f2, v_supply)
        _link_reads(g, f1, v_supply)
        _run_ds3(g)

        deps_f1 = g.nodes[f1]["state_dependencies_out"]
        deps_f2 = g.nodes[f2]["state_dependencies_out"]
        assert any(d["target"] == f2 for d in deps_f1)
        assert any(d["target"] == f1 for d in deps_f2)

    def test_propagated_writes_included(self):
        """Propagated writes (through internal calls) count for dependencies."""
        g = nx.DiGraph()
        _add_contract(g, "V")
        vid = _add_var(g, "V", "totalSupply", ["ACCOUNTING_CRITICAL"])
        f1 = _add_func(g, "V", "deposit", propagated_state_variables=[vid])
        f2 = _add_func(g, "V", "getRate")
        _link_reads(g, f2, vid)
        _run_ds3(g)

        deps = g.nodes[f1]["state_dependencies_out"]
        assert any(d["target"] == f2 for d in deps)

    def test_shared_state_variables_attribute(self):
        g = nx.DiGraph()
        _add_contract(g, "V")
        vid = _add_var(g, "V", "reserves", ["ACCOUNTING_CRITICAL"])
        f1 = _add_func(g, "V", "addReserve")
        f2 = _add_func(g, "V", "useReserve")
        _link_writes(g, f1, vid)
        _link_reads(g, f2, vid)
        _run_ds3(g)

        assert vid in g.nodes[f1]["shared_state_variables"]
        assert vid in g.nodes[f2]["shared_state_variables"]


# ═══════════════════════════════════════════════════════════════
#  3.2 Dangerous Sequence Detection
# ═══════════════════════════════════════════════════════════════

class TestDangerousSequences:

    def test_accounting_manipulation_flagged(self):
        """Unprotected deposit writing accounting state → dangerous."""
        g = nx.DiGraph()
        _add_contract(g, "V")
        vid = _add_var(g, "V", "totalSupply", ["ACCOUNTING_CRITICAL"])
        f1 = _add_func(g, "V", "deposit", is_protected=False)
        f2 = _add_func(g, "V", "getExchangeRate")
        _link_writes(g, f1, vid)
        _link_reads(g, f2, vid)
        _run_ds3(g)

        seqs = g.nodes[f1]["dangerous_sequences"]
        assert len(seqs) >= 1
        assert any("ACCOUNTING_MANIPULATION" in s["danger_types"] for s in seqs)

    def test_privilege_chain_flagged(self):
        g = nx.DiGraph()
        _add_contract(g, "V")
        vid = _add_var(g, "V", "admin", ["ACCESS_CRITICAL"])
        f1 = _add_func(g, "V", "setAdmin", is_protected=False)
        f2 = _add_func(g, "V", "withdraw")
        _link_writes(g, f1, vid)
        _link_reads(g, f2, vid)
        _run_ds3(g)

        seqs = g.nodes[f1]["dangerous_sequences"]
        assert any("PRIVILEGE_CHAIN" in s["danger_types"] for s in seqs)

    def test_reward_inflation_flagged(self):
        g = nx.DiGraph()
        _add_contract(g, "Farm")
        vid = _add_var(g, "Farm", "rewardRate", ["REWARD_CRITICAL"])
        f1 = _add_func(g, "Farm", "setRewardRate", is_protected=False)
        f2 = _add_func(g, "Farm", "claimRewards")
        _link_writes(g, f1, vid)
        _link_reads(g, f2, vid)
        _run_ds3(g)

        seqs = g.nodes[f1]["dangerous_sequences"]
        assert any("REWARD_INFLATION" in s["danger_types"] for s in seqs)

    def test_cap_bypass_flagged(self):
        g = nx.DiGraph()
        _add_contract(g, "T")
        vid = _add_var(g, "T", "supplyCap", ["CAP_CRITICAL"])
        f1 = _add_func(g, "T", "updateCap", is_protected=False)
        f2 = _add_func(g, "T", "mint")
        _link_writes(g, f1, vid)
        _link_reads(g, f2, vid)
        _run_ds3(g)

        seqs = g.nodes[f1]["dangerous_sequences"]
        assert any("CAP_BYPASS_SEQUENCE" in s["danger_types"] for s in seqs)

    def test_invariant_break_on_write_write(self):
        g = nx.DiGraph()
        _add_contract(g, "V")
        vid = _add_var(g, "V", "totalSupply", ["ACCOUNTING_CRITICAL"])
        f1 = _add_func(g, "V", "mint", is_protected=False)
        f2 = _add_func(g, "V", "burn", is_protected=False)
        _link_writes(g, f1, vid)
        _link_writes(g, f2, vid)
        _run_ds3(g)

        all_seqs = g.nodes[f1]["dangerous_sequences"] + g.nodes[f2]["dangerous_sequences"]
        assert any("INVARIANT_BREAK" in s["danger_types"] for s in all_seqs)

    def test_protected_writer_no_accounting_manipulation(self):
        """If the writer is protected, ACCOUNTING_MANIPULATION should not fire."""
        g = nx.DiGraph()
        _add_contract(g, "V")
        vid = _add_var(g, "V", "totalSupply", ["ACCOUNTING_CRITICAL"])
        f1 = _add_func(g, "V", "deposit", is_protected=True)
        f2 = _add_func(g, "V", "getRate", is_protected=True)
        _link_writes(g, f1, vid)
        _link_reads(g, f2, vid)
        _run_ds3(g)

        seqs = g.nodes[f1]["dangerous_sequences"]
        assert not any("ACCOUNTING_MANIPULATION" in s.get("danger_types", []) for s in seqs)

    def test_unreachable_functions_excluded(self):
        g = nx.DiGraph()
        _add_contract(g, "V")
        vid = _add_var(g, "V", "balance", ["ACCOUNTING_CRITICAL"])
        f1 = _add_func(g, "V", "deposit", reachable=False)
        f2 = _add_func(g, "V", "withdraw")
        _link_writes(g, f1, vid)
        _link_reads(g, f2, vid)
        _run_ds3(g)

        assert g.nodes[f1]["has_dangerous_sequence"] is False

    def test_sequence_risk_score_set(self):
        g = nx.DiGraph()
        _add_contract(g, "V")
        vid = _add_var(g, "V", "admin", ["ACCESS_CRITICAL"])
        f1 = _add_func(g, "V", "setAdmin", is_protected=False)
        f2 = _add_func(g, "V", "withdraw")
        _link_writes(g, f1, vid)
        _link_reads(g, f2, vid)
        _run_ds3(g)

        assert g.nodes[f1]["sequence_risk_score"] > 0


# ═══════════════════════════════════════════════════════════════
#  3.3 Exploit Chain Generation
# ═══════════════════════════════════════════════════════════════

class TestExploitChains:

    def test_two_step_chain_generated(self):
        g = nx.DiGraph()
        _add_contract(g, "V")
        vid = _add_var(g, "V", "totalSupply", ["ACCOUNTING_CRITICAL"])
        f1 = _add_func(g, "V", "deposit", is_protected=False)
        f2 = _add_func(g, "V", "claimRewards")
        _link_writes(g, f1, vid)
        _link_reads(g, f2, vid)
        _run_ds3(g)

        chains = g.nodes[f1]["exploit_chains"]
        assert len(chains) >= 1
        assert chains[0]["chain_length"] >= 2

    def test_chain_steps_have_correct_structure(self):
        g = nx.DiGraph()
        _add_contract(g, "V")
        vid = _add_var(g, "V", "balance", ["ACCOUNTING_CRITICAL"])
        f1 = _add_func(g, "V", "deposit", is_protected=False)
        f2 = _add_func(g, "V", "withdraw")
        _link_writes(g, f1, vid)
        _link_reads(g, f2, vid)
        _run_ds3(g)

        chains = g.nodes[f1]["exploit_chains"]
        assert len(chains) >= 1
        steps = chains[0]["steps"]
        assert f1 in steps
        assert f2 in steps

    def test_exploit_sequence_format(self):
        g = nx.DiGraph()
        _add_contract(g, "V")
        vid = _add_var(g, "V", "balance", ["ACCOUNTING_CRITICAL"])
        f1 = _add_func(g, "V", "deposit", is_protected=False)
        f2 = _add_func(g, "V", "withdraw")
        _link_writes(g, f1, vid)
        _link_reads(g, f2, vid)
        _run_ds3(g)

        chains = g.nodes[f1]["exploit_chains"]
        seq = chains[0]["exploit_sequence"]
        assert len(seq) >= 2
        assert seq[0]["role"] == "MANIPULATE"
        assert seq[-1]["role"] == "EXTRACT"
        assert "step" in seq[0]
        assert "function_id" in seq[0]
        assert "signature" in seq[0]

    def test_three_step_chain(self):
        """deposit → modifies balance → claimRewards reads balance → writes rewards → exit."""
        g = nx.DiGraph()
        _add_contract(g, "V")
        v_bal = _add_var(g, "V", "balance", ["ACCOUNTING_CRITICAL"])
        v_rew = _add_var(g, "V", "rewards", ["REWARD_CRITICAL"])
        f1 = _add_func(g, "V", "deposit", is_protected=False, writes_state=True)
        f2 = _add_func(g, "V", "claimRewards", is_protected=False, writes_state=True)
        f3 = _add_func(g, "V", "withdrawRewards", writes_state=True)
        _link_writes(g, f1, v_bal)
        _link_reads(g, f2, v_bal)
        _link_writes(g, f2, v_rew)
        _link_reads(g, f3, v_rew)
        _run_ds3(g)

        # f1 should have a chain that extends through f2 to f3
        chains = g.nodes[f1]["exploit_chains"]
        max_len = max((c["chain_length"] for c in chains), default=0)
        assert max_len >= 3

    def test_is_chain_entry_flag(self):
        g = nx.DiGraph()
        _add_contract(g, "V")
        vid = _add_var(g, "V", "balance", ["ACCOUNTING_CRITICAL"])
        f1 = _add_func(g, "V", "deposit", is_protected=False)
        f2 = _add_func(g, "V", "withdraw")
        _link_writes(g, f1, vid)
        _link_reads(g, f2, vid)
        _run_ds3(g)

        assert g.nodes[f1]["is_chain_entry"] is True

    def test_no_chain_for_safe_function(self):
        """Protected functions without dangerous sequences don't generate chains."""
        g = nx.DiGraph()
        _add_contract(g, "V")
        vid = _add_var(g, "V", "x")
        f1 = _add_func(g, "V", "f", is_protected=True)
        f2 = _add_func(g, "V", "g", is_protected=True)
        _link_writes(g, f1, vid)
        _link_reads(g, f2, vid)
        _run_ds3(g)

        assert g.nodes[f1]["exploit_chains"] == []


# ═══════════════════════════════════════════════════════════════
#  Risk Score Integration
# ═══════════════════════════════════════════════════════════════

class TestRiskScoreIntegration:

    def test_sequence_risk_adds_to_structural(self):
        g = nx.DiGraph()
        _add_contract(g, "V")
        vid = _add_var(g, "V", "admin", ["ACCESS_CRITICAL"])
        f1 = _add_func(g, "V", "setAdmin", is_protected=False)
        f2 = _add_func(g, "V", "withdraw")
        _link_writes(g, f1, vid)
        _link_reads(g, f2, vid)
        _run_ds3_with_scoring(g)

        assert g.nodes[f1]["structural_score"] > 0

    def test_danger_type_in_risk_categories(self):
        g = nx.DiGraph()
        _add_contract(g, "V")
        vid = _add_var(g, "V", "admin", ["ACCESS_CRITICAL"])
        f1 = _add_func(g, "V", "setAdmin", is_protected=False)
        f2 = _add_func(g, "V", "withdraw")
        _link_writes(g, f1, vid)
        _link_reads(g, f2, vid)
        _run_ds3_with_scoring(g)

        cats = g.nodes[f1]["risk_categories"]
        assert "privilege_chain" in cats

    def test_chain_entry_boosts_exploitability(self):
        """3-step chains should get exploitability bonus."""
        g = nx.DiGraph()
        _add_contract(g, "V")
        v1 = _add_var(g, "V", "balance", ["ACCOUNTING_CRITICAL"])
        v2 = _add_var(g, "V", "rewards", ["REWARD_CRITICAL"])
        f1 = _add_func(g, "V", "deposit", is_protected=False)
        f2 = _add_func(g, "V", "claim", is_protected=False)
        f3 = _add_func(g, "V", "exit")
        _link_writes(g, f1, v1)
        _link_reads(g, f2, v1)
        _link_writes(g, f2, v2)
        _link_reads(g, f3, v2)
        _run_ds3_with_scoring(g)

        exp = g.nodes[f1]["exploitability_score"]
        assert exp >= 15

    def test_impact_boost_for_privilege_chain(self):
        g = nx.DiGraph()
        _add_contract(g, "V")
        vid = _add_var(g, "V", "owner", ["ACCESS_CRITICAL"])
        f1 = _add_func(g, "V", "setOwner", is_protected=False)
        f2 = _add_func(g, "V", "drain")
        _link_writes(g, f1, vid)
        _link_reads(g, f2, vid)
        _run_ds3_with_scoring(g)

        assert g.nodes[f1]["impact_score"] >= 20

    def test_sequence_score_capped(self):
        """sequence_risk_score contribution to structural is capped at 50."""
        g = nx.DiGraph()
        _add_contract(g, "V")
        vid = _add_var(g, "V", "admin", ["ACCESS_CRITICAL"])
        f1 = _add_func(g, "V", "setAdmin", is_protected=False,
                       sequence_risk_score=200,
                       dangerous_sequences=[{"danger_types": ["PRIVILEGE_CHAIN"]}],
                       has_dangerous_sequence=True)
        _run_ds3_with_scoring(g)

        structural = g.nodes[f1]["structural_score"]
        assert structural <= 50


# ═══════════════════════════════════════════════════════════════
#  Query Layer
# ═══════════════════════════════════════════════════════════════

class TestQueryLayer:

    def test_get_state_dependencies(self):
        g = nx.DiGraph()
        _add_contract(g, "V")
        vid = _add_var(g, "V", "x", ["ACCOUNTING_CRITICAL"])
        f1 = _add_func(g, "V", "write")
        f2 = _add_func(g, "V", "read")
        _link_writes(g, f1, vid)
        _link_reads(g, f2, vid)
        _run_ds3(g)

        result = GraphQueries(g).get_state_dependencies()
        assert len(result) >= 1
        assert result[0]["writer"] == f1
        assert result[0]["reader"] == f2

    def test_get_state_dependencies_contract_filter(self):
        g = nx.DiGraph()
        _add_contract(g, "A")
        _add_contract(g, "B")
        va = _add_var(g, "A", "x", ["ACCOUNTING_CRITICAL"])
        vb = _add_var(g, "B", "y", ["ACCOUNTING_CRITICAL"])
        _add_func(g, "A", "w")
        _add_func(g, "A", "r")
        _add_func(g, "B", "w")
        _add_func(g, "B", "r")
        _link_writes(g, "A::w", va)
        _link_reads(g, "A::r", va)
        _link_writes(g, "B::w", vb)
        _link_reads(g, "B::r", vb)
        _run_ds3(g)

        result = GraphQueries(g).get_state_dependencies(contract_name="A")
        assert all(r["writer"].startswith("A::") for r in result)

    def test_get_dangerous_sequences(self):
        g = nx.DiGraph()
        _add_contract(g, "V")
        vid = _add_var(g, "V", "admin", ["ACCESS_CRITICAL"])
        f1 = _add_func(g, "V", "setAdmin", is_protected=False)
        f2 = _add_func(g, "V", "drain")
        _link_writes(g, f1, vid)
        _link_reads(g, f2, vid)
        _run_ds3(g)

        result = GraphQueries(g).get_dangerous_sequences()
        assert len(result) >= 1
        assert result[0]["sequence_risk_score"] > 0

    def test_get_exploit_chains(self):
        g = nx.DiGraph()
        _add_contract(g, "V")
        vid = _add_var(g, "V", "balance", ["ACCOUNTING_CRITICAL"])
        f1 = _add_func(g, "V", "deposit", is_protected=False)
        f2 = _add_func(g, "V", "withdraw")
        _link_writes(g, f1, vid)
        _link_reads(g, f2, vid)
        _run_ds3(g)

        result = GraphQueries(g).get_exploit_chains()
        assert len(result) >= 1
        chain = result[0]
        assert "exploit_sequence" in chain
        assert chain["chain_length"] >= 2

    def test_get_exploit_chains_min_length(self):
        g = nx.DiGraph()
        _add_contract(g, "V")
        vid = _add_var(g, "V", "x", ["ACCOUNTING_CRITICAL"])
        f1 = _add_func(g, "V", "f", is_protected=False)
        f2 = _add_func(g, "V", "g")
        _link_writes(g, f1, vid)
        _link_reads(g, f2, vid)
        _run_ds3(g)

        result_2 = GraphQueries(g).get_exploit_chains(min_length=2)
        result_5 = GraphQueries(g).get_exploit_chains(min_length=5)
        assert len(result_2) >= 1
        assert len(result_5) == 0

    def test_standalone_wrappers(self):
        g = nx.DiGraph()
        _add_contract(g, "V")
        vid = _add_var(g, "V", "balance", ["ACCOUNTING_CRITICAL"])
        f1 = _add_func(g, "V", "deposit", is_protected=False)
        f2 = _add_func(g, "V", "withdraw")
        _link_writes(g, f1, vid)
        _link_reads(g, f2, vid)
        _run_ds3(g)

        assert len(get_state_dependencies(g)) >= 1
        assert len(get_dangerous_sequences(g)) >= 1
        assert len(get_exploit_chains(g)) >= 1


# ═══════════════════════════════════════════════════════════════
#  End-to-End Scenario Tests
# ═══════════════════════════════════════════════════════════════

class TestEndToEnd:

    def test_defi_deposit_claim_withdraw_flow(self):
        """
        Classic DeFi exploit flow:
          deposit() → manipulates balance
          claimRewards() → uses balance to compute rewards
          withdraw() → drains accounting
        """
        g = nx.DiGraph()
        _add_contract(g, "Vault")
        v_bal = _add_var(g, "Vault", "balances", ["ACCOUNTING_CRITICAL"])
        v_rew = _add_var(g, "Vault", "rewards", ["REWARD_CRITICAL"])
        v_supply = _add_var(g, "Vault", "totalSupply", ["ACCOUNTING_CRITICAL"])

        f_dep = _add_func(g, "Vault", "deposit", is_protected=False)
        f_claim = _add_func(g, "Vault", "claimRewards", is_protected=False)
        f_withdraw = _add_func(g, "Vault", "withdraw", is_protected=False)

        _link_writes(g, f_dep, v_bal)
        _link_writes(g, f_dep, v_supply)
        _link_reads(g, f_claim, v_bal)
        _link_writes(g, f_claim, v_rew)
        _link_reads(g, f_withdraw, v_bal)
        _link_reads(g, f_withdraw, v_supply)
        _link_reads(g, f_withdraw, v_rew)

        _run_ds3_with_scoring(g)

        # deposit should have chains reaching claim and withdraw
        chains = g.nodes[f_dep]["exploit_chains"]
        assert len(chains) >= 1
        max_len = max(c["chain_length"] for c in chains)
        assert max_len >= 2

        # deposit should flag ACCOUNTING_MANIPULATION
        seqs = g.nodes[f_dep]["dangerous_sequences"]
        danger_set = set()
        for s in seqs:
            danger_set.update(s["danger_types"])
        assert "ACCOUNTING_MANIPULATION" in danger_set

    def test_privilege_escalation_chain(self):
        """
        setAdmin() → modifies admin
        withdraw() → checks admin, drains funds
        """
        g = nx.DiGraph()
        _add_contract(g, "V")
        v_admin = _add_var(g, "V", "admin", ["ACCESS_CRITICAL"])

        f_set = _add_func(g, "V", "setAdmin", is_protected=False)
        f_drain = _add_func(g, "V", "withdraw")
        _link_writes(g, f_set, v_admin)
        _link_reads(g, f_drain, v_admin)

        _run_ds3_with_scoring(g)

        seqs = g.nodes[f_set]["dangerous_sequences"]
        assert any("PRIVILEGE_CHAIN" in s["danger_types"] for s in seqs)

        chains = g.nodes[f_set]["exploit_chains"]
        assert len(chains) >= 1
        seq = chains[0]["exploit_sequence"]
        assert seq[0]["function_name"] == "setAdmin"
        assert seq[0]["role"] == "MANIPULATE"
