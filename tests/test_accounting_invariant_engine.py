import networkx as nx

from src.graph_builder import GraphBuilder
from src.utils.graph_queries import (
    GraphQueries,
    get_accounting_invariant_risks,
    get_external_call_risks,
    get_exploit_targets,
)


def _add_contract(g: nx.DiGraph, name: str, tier: str = "CORE"):
    g.add_node(name, type="contract", name=name, tier=tier)


def _add_func(
    g: nx.DiGraph,
    contract: str,
    name: str,
    *,
    source_code: str = "",
    is_external_entry: bool = True,
    is_protected: bool = False,
    is_view_or_pure: bool = False,
    is_payable: bool = False,
    **extra,
):
    fid = f"{contract}::{name}"
    attrs = {
        "type": "function",
        "name": name,
        "contract": contract,
        "visibility": "public",
        "source_code": source_code,
        "signature": f"{name}()",
        "is_external_entry": is_external_entry,
        "is_protected": is_protected,
        "is_view_or_pure": is_view_or_pure,
        "is_payable": is_payable,
        "is_constructor": False,
        "reachable_from_external_entry": True,
        "modifiers": [],
        "writes_state": False,
        "propagated_state_variables": [],
        "safe_init_pattern": False,
        "has_initializer_guard": False,
        "has_reentrancy_guard": False,
        "access_control_type": "none",
        "is_unprotected_mutator": False,
        "unprotected_risk_level": "NONE",
        "reentrancy_risk": False,
        "can_escalate_privileges": False,
        "state_write_after_external_call": False,
        "state_write_after_reentrant_call": False,
        "cei_violation_only": False,
        "has_array_length_mutation": False,
        "delegatecall_storage_risk": False,
        "has_taint_risk": False,
        "taint_risk_score": 0,
        "taint_risk_types": [],
        "tainted_state_writes": [],
        "taint_sources": [],
        "cross_function_taint_paths": [],
        "has_dangerous_sequence": False,
        "sequence_risk_score": 0,
        "dangerous_sequences": [],
        "makes_external_call": False,
        "unchecked_external_return": False,
        "max_chain_length": 0,
    }
    attrs.update(extra)
    g.add_node(fid, **attrs)
    return fid


def _add_var(g: nx.DiGraph, contract: str, name: str, tags=None):
    vid = f"{contract}::{name}"
    g.add_node(
        vid,
        type="state_variable",
        node_type="StateVariable",
        name=name,
        contract=contract,
        sensitivity_tags=tags or [],
        sensitivity_tag=(tags or [None])[0],
        is_sensitive=bool(tags),
    )
    return vid


def _writes(g: nx.DiGraph, fid: str, vid: str):
    g.add_edge(fid, vid, relationship="WRITES")


def _reads(g: nx.DiGraph, fid: str, vid: str):
    g.add_edge(fid, vid, relationship="READS")


def _run_ds4_ds5_ds6(g: nx.DiGraph) -> GraphBuilder:
    gb = GraphBuilder()
    gb.graph = g
    gb._run_accounting_invariant_heuristics()
    gb._analyze_external_call_risks()
    gb._compute_global_risk_scores()
    gb._compute_exploit_target_scores()
    return gb


class TestAccountingInvariantHeuristics:
    def test_supply_mismatch_flagged(self):
        g = nx.DiGraph()
        _add_contract(g, "Vault")
        v_supply = _add_var(g, "Vault", "totalSupply", ["ACCOUNTING_CRITICAL"])
        f = _add_func(g, "Vault", "mint")
        _writes(g, f, v_supply)

        _run_ds4_ds5_ds6(g)
        assert g.nodes[f]["supply_consistency_issue"] is True
        assert "SUPPLY_BALANCE_MISMATCH" in g.nodes[f]["supply_consistency_flags"]

    def test_supply_cap_bypass_flagged(self):
        g = nx.DiGraph()
        _add_contract(g, "Vault")
        v_cap = _add_var(g, "Vault", "supplyCap")
        g.nodes[v_cap]["accounting_role"] = "CAP"
        v_supply = _add_var(g, "Vault", "totalSupply")
        g.nodes[v_supply]["accounting_role"] = "SUPPLY"
        f = _add_func(g, "Vault", "mint", source_code="totalSupply += amount;", is_external_entry=True)
        _reads(g, f, v_cap)
        _writes(g, f, v_supply)

        _run_ds4_ds5_ds6(g)
        assert g.nodes[f]["cap_enforcement_issue"] is True
        assert "MISSING_CAP_ENFORCEMENT" in g.nodes[f]["cap_enforcement_flags"]

    def test_supply_cap_check_not_flagged(self):
        g = nx.DiGraph()
        _add_contract(g, "Vault")
        v_cap = _add_var(g, "Vault", "supplyCap")
        g.nodes[v_cap]["accounting_role"] = "CAP"
        v_supply = _add_var(g, "Vault", "totalSupply")
        g.nodes[v_supply]["accounting_role"] = "SUPPLY"
        src = "require(totalSupply + amount <= supplyCap, 'cap'); totalSupply += amount;"
        f = _add_func(g, "Vault", "mint", source_code=src, is_external_entry=True)
        _reads(g, f, v_cap)
        _writes(g, f, v_supply)

        _run_ds4_ds5_ds6(g)
        assert g.nodes[f]["cap_enforcement_issue"] is False

    def test_reward_reset_flagged(self):
        g = nx.DiGraph()
        _add_contract(g, "Farm")
        v_idx = _add_var(g, "Farm", "rewardIndex", ["REWARD_CRITICAL"])
        f = _add_func(g, "Farm", "syncRewards", source_code="rewardIndex = 0;")
        _writes(g, f, v_idx)

        _run_ds4_ds5_ds6(g)
        assert g.nodes[f]["reward_drift_issue"] is True
        assert "REWARD_INDEX_RESET" in g.nodes[f]["reward_drift_flags"]

    def test_monotonic_decrease_flagged(self):
        g = nx.DiGraph()
        _add_contract(g, "Lending")
        v_idx = _add_var(g, "Lending", "borrowIndex", ["ACCOUNTING_CRITICAL"])
        f = _add_func(g, "Lending", "updateBorrowIndex", source_code="borrowIndex -= delta;")
        _writes(g, f, v_idx)

        _run_ds4_ds5_ds6(g)
        assert g.nodes[f]["monotonicity_issue"] is True
        assert any("NON_MONOTONIC_INDEX" in x for x in g.nodes[f]["monotonicity_flags"])


class TestExternalCallRiskAnalyzer:
    def test_reentrancy_tag(self):
        g = nx.DiGraph()
        _add_contract(g, "A")
        f = _add_func(g, "A", "withdraw", reentrancy_risk=True)
        _run_ds4_ds5_ds6(g)

        assert "REENTRANCY_RISK" in g.nodes[f]["external_risk_tags"]

    def test_unchecked_return_tag(self):
        g = nx.DiGraph()
        _add_contract(g, "A")
        f = _add_func(g, "A", "callOut", unchecked_external_return=True)
        _run_ds4_ds5_ds6(g)

        assert "UNCHECKED_RETURN" in g.nodes[f]["external_risk_tags"]

    def test_external_dependency_tag_cross_contract(self):
        g = nx.DiGraph()
        _add_contract(g, "Caller")
        _add_contract(g, "Callee")
        caller = _add_func(g, "Caller", "execute", makes_external_call=True)
        callee = _add_func(g, "Callee", "doStateChange", writes_state=True)
        g.add_edge(
            caller,
            callee,
            relationship="EXTERNAL_CALL",
            call_type="interface",
            forwards_gas="full",
            return_value_checked=True,
            target_expression="callee.doStateChange",
        )

        _run_ds4_ds5_ds6(g)
        assert "EXTERNAL_DEPENDENCY_RISK" in g.nodes[caller]["external_risk_tags"]


class TestExploitTargetScoring:
    def test_high_probability_target_marked_for_exploit_writer(self):
        g = nx.DiGraph()
        _add_contract(g, "Vault")
        f = _add_func(
            g,
            "Vault",
            "withdraw",
            makes_external_call=True,
            reentrancy_risk=True,
            unchecked_external_return=True,
            is_unprotected_mutator=True, has_taint_risk=True,
            taint_sources=["calldata:param1", "tx.origin"],
            cross_function_taint_paths=[{"from": "a", "to": "b"}],
            tainted_state_writes=[{"sensitivity": ["ACCOUNTING_CRITICAL", "ACCESS_CRITICAL"]}],
            max_chain_length=4,
        )
        _run_ds4_ds5_ds6(g)

        assert g.nodes[f]["exploit_target_score"] >= 75
        assert g.nodes[f]["send_to_exploit_writer"] is True

    def test_low_signal_target_not_marked(self):
        g = nx.DiGraph()
        _add_contract(g, "Vault")
        f = _add_func(g, "Vault", "viewFn", is_external_entry=False, is_view_or_pure=True)
        _run_ds4_ds5_ds6(g)

        assert g.nodes[f]["exploit_target_score"] < 75
        assert g.nodes[f]["send_to_exploit_writer"] is False

    def test_structural_only_signal_cannot_cross_exploit_threshold(self):
        g = nx.DiGraph()
        _add_contract(g, "Vault")
        f = _add_func(
            g,
            "Vault",
            "shapeOnly",
            is_external_entry=True,
            makes_external_call=True,
            reentrancy_risk=True,
            unchecked_external_return=True,
            writes_state=False,
            propagated_state_variables=[],
            taint_sources=[],
            tainted_state_writes=[],
        )
        _run_ds4_ds5_ds6(g)

        assert g.nodes[f]["exploit_target_score"] < 75
        assert g.nodes[f]["send_to_exploit_writer"] is False

    def test_no_feasible_attacker_path_blocks_exploit_writer(self):
        g = nx.DiGraph()
        _add_contract(g, "Vault")
        entry = _add_func(g, "Vault", "entry", is_external_entry=True)
        target = _add_func(
            g,
            "Vault",
            "_internalSink",
            is_external_entry=False,
            writes_state=True,
            is_unprotected_mutator=True, makes_external_call=True, has_taint_risk=True,
            taint_sources=["calldata:a", "calldata:b", "msg.value"],
            cross_function_taint_paths=[{"from": "entry", "to": "_internalSink"}],
            tainted_state_writes=[{"sensitivity": ["ACCOUNTING_CRITICAL", "ACCESS_CRITICAL"]}],
            max_chain_length=4,
            entry_points=[entry],  # Declared reachable, but no CALLS path exists.
        )
        _run_ds4_ds5_ds6(g)

        assert g.nodes[target]["exploit_target_score"] >= 75
        assert g.nodes[target]["has_viable_attacker_path"] is False
        assert g.nodes[target]["send_to_exploit_writer"] is False

    def test_feasible_attacker_path_enables_exploit_writer(self):
        g = nx.DiGraph()
        _add_contract(g, "Vault")
        entry = _add_func(g, "Vault", "entry", is_external_entry=True, writes_state=False)
        target = _add_func(
            g,
            "Vault",
            "_internalSink",
            is_external_entry=False,
            writes_state=True,
            is_unprotected_mutator=True, makes_external_call=True, has_taint_risk=True,
            taint_sources=["calldata:a", "calldata:b", "msg.value"],
            cross_function_taint_paths=[{"from": "entry", "to": "_internalSink"}],
            tainted_state_writes=[{"sensitivity": ["ACCOUNTING_CRITICAL", "ACCESS_CRITICAL"]}],
            max_chain_length=4,
            entry_points=[entry],
        )
        g.add_edge(entry, target, relationship="CALLS", call_type="internal")
        _run_ds4_ds5_ds6(g)

        assert g.nodes[target]["exploit_target_score"] >= 75
        assert g.nodes[target]["has_viable_attacker_path"] is True
        assert g.nodes[target]["send_to_exploit_writer"] is True

    def test_dev_story_5_boosts_applied_correctly(self):
        g = nx.DiGraph()
        _add_contract(g, "Vault")
        f = _add_func(
            g,
            "Vault",
            "exploitCandidate",
            is_external_entry=True,
            is_unprotected_mutator=True,
            has_taint_risk=True,
            taint_sources=["calldata:amount"],
            uses_tainted_math=True,
            cap_enforcement_flags=["MISSING_CAP_ENFORCEMENT"],
            can_escalate_privileges=True,
            tainted_state_writes=[{"sensitivity": ["ACCOUNTING_CRITICAL"]}],
            max_chain_length=3,
        )
        _run_ds4_ds5_ds6(g)
        score = g.nodes[f]["exploit_target_score"]
        assert score >= 75
        assert g.nodes[f]["send_to_exploit_writer"] is True

    def test_dev_story_5_penalties_applied_correctly(self):
        g = nx.DiGraph()
        _add_contract(g, "Vault")
        f = _add_func(
            g,
            "Vault",
            "viewPrice",
            is_external_entry=True,
            is_view_or_pure=True,  # Heavy penalty
            is_protected=True,     # Heavy penalty
            has_taint_risk=False,  # Heavy penalty
        )
        _run_ds4_ds5_ds6(g)
        score = g.nodes[f]["exploit_target_score"]
        assert score < 75
        assert g.nodes[f]["send_to_exploit_writer"] is False


class TestQueries:
    def test_accounting_query(self):
        g = nx.DiGraph()
        _add_contract(g, "Vault")
        v_supply = _add_var(g, "Vault", "totalSupply", ["ACCOUNTING_CRITICAL"])
        f = _add_func(g, "Vault", "mint")
        _writes(g, f, v_supply)
        _run_ds4_ds5_ds6(g)

        rows = GraphQueries(g).get_accounting_invariant_risks()
        assert len(rows) >= 1
        assert rows[0]["function_id"] == f

    def test_external_risk_query(self):
        g = nx.DiGraph()
        _add_contract(g, "A")
        f = _add_func(g, "A", "callOut", unchecked_external_return=True)
        _run_ds4_ds5_ds6(g)

        rows = GraphQueries(g).get_external_call_risks(risk_tag="UNCHECKED_RETURN")
        assert len(rows) == 1
        assert rows[0]["function_id"] == f

    def test_exploit_target_query(self):
        g = nx.DiGraph()
        _add_contract(g, "Vault")
        f = _add_func(
            g,
            "Vault",
            "withdraw",
            makes_external_call=True,
            reentrancy_risk=True,
            tainted_state_writes=[{"sensitivity": ["ACCESS_CRITICAL"]}],
            max_chain_length=3,
            is_unprotected_mutator=True, has_taint_risk=True,
        )
        _run_ds4_ds5_ds6(g)

        rows = GraphQueries(g).get_exploit_targets(min_exploit_score=50)
        assert any(r["function_id"] == f for r in rows)

    def test_get_high_risk_hotspots_respects_exploit_gate(self):
        g = nx.DiGraph()
        _add_contract(g, "Vault")
        f = _add_func(g, "Vault", "withdraw")
        g.nodes[f]["final_score"] = 95
        g.nodes[f]["risk_score"] = 95
        g.nodes[f]["structural_score"] = 50
        g.nodes[f]["exploitability_score"] = 40
        g.nodes[f]["send_to_exploit_writer"] = False

        hs = GraphQueries(g).get_high_risk_hotspots(min_score=70)
        assert hs == []

    def test_wrapper_functions(self):
        g = nx.DiGraph()
        _add_contract(g, "A")
        f = _add_func(g, "A", "callOut", unchecked_external_return=True)
        _run_ds4_ds5_ds6(g)

        assert len(get_external_call_risks(g)) >= 1
        assert isinstance(get_accounting_invariant_risks(g), list)
        assert isinstance(get_exploit_targets(g), list)


class TestReadOnlyReentrancy:
    """Improvement 2A: read_only_reentrancy_risk flag tests."""

    def _run_with_read_only_detection(self, g: nx.DiGraph) -> GraphBuilder:
        gb = GraphBuilder()
        gb.graph = g
        gb._detect_read_only_reentrancy_risk()
        gb._compute_negative_safety_signals()
        gb._compute_global_risk_scores()
        return gb

    def test_staticcall_with_accounting_write_flagged(self):
        """Function with staticcall edge + writes_total_supply → flagged."""
        g = nx.DiGraph()
        _add_contract(g, "Vault")
        f = _add_func(
            g, "Vault", "deposit",
            writes_total_supply=True,
            makes_external_call=True,
        )
        # Add a staticcall external call edge
        target = "ExternalOracle::getPrice"
        g.add_node(target, type="function", name="getPrice", contract="ExternalOracle",
                   is_view_or_pure=True)
        g.add_edge(f, target, relationship="EXTERNAL_CALL", call_type="staticcall",
                   forwards_gas="full", target_expression="oracle.getPrice()")

        self._run_with_read_only_detection(g)
        assert g.nodes[f]["read_only_reentrancy_risk"] is True

    def test_no_staticcall_not_flagged(self):
        """Function with only call edge (not staticcall) → NOT flagged."""
        g = nx.DiGraph()
        _add_contract(g, "Vault")
        f = _add_func(
            g, "Vault", "withdraw",
            writes_total_supply=True,
            makes_external_call=True,
        )
        # Add a regular call edge (not staticcall)
        target = "ExternalToken::transfer"
        g.add_node(target, type="function", name="transfer", contract="ExternalToken")
        g.add_edge(f, target, relationship="EXTERNAL_CALL", call_type="call",
                   forwards_gas="full", target_expression="token.transfer()")

        self._run_with_read_only_detection(g)
        assert g.nodes[f]["read_only_reentrancy_risk"] is False

    def test_staticcall_without_sensitive_write_not_flagged(self):
        """Function with staticcall but no accounting-sensitive state → NOT flagged."""
        g = nx.DiGraph()
        _add_contract(g, "Vault")
        f = _add_func(
            g, "Vault", "checkBalance",
            makes_external_call=True,
            # No writes_total_supply, writes_total_assets, etc.
        )
        target = "ExternalOracle::getPrice"
        g.add_node(target, type="function", name="getPrice", contract="ExternalOracle",
                   is_view_or_pure=True)
        g.add_edge(f, target, relationship="EXTERNAL_CALL", call_type="staticcall",
                   forwards_gas="full", target_expression="oracle.getPrice()")

        self._run_with_read_only_detection(g)
        assert g.nodes[f]["read_only_reentrancy_risk"] is False

    def test_read_only_reentrancy_in_risk_scoring(self):
        """Verify structural score includes the 35-point boost for read_only_reentrancy_risk."""
        g = nx.DiGraph()
        _add_contract(g, "Vault")
        f = _add_func(
            g, "Vault", "deposit",
            writes_total_supply=True,
            makes_external_call=True,
        )
        target = "ExternalOracle::getPrice"
        g.add_node(target, type="function", name="getPrice", contract="ExternalOracle",
                   is_view_or_pure=True)
        g.add_edge(f, target, relationship="EXTERNAL_CALL", call_type="staticcall",
                   forwards_gas="full", target_expression="oracle.getPrice()")

        self._run_with_read_only_detection(g)
        assert g.nodes[f]["read_only_reentrancy_risk"] is True
        assert "read_only_reentrancy" in g.nodes[f]["risk_categories"]
        assert g.nodes[f]["structural_score"] >= 35

    def test_writes_total_assets_flagged(self):
        """Function with staticcall + writes_total_assets → flagged."""
        g = nx.DiGraph()
        _add_contract(g, "Lending")
        f = _add_func(
            g, "Lending", "accrue",
            writes_total_assets=True,
            makes_external_call=True,
        )
        target = "ExternalOracle::getRate"
        g.add_node(target, type="function", name="getRate", contract="ExternalOracle",
                   is_view_or_pure=True)
        g.add_edge(f, target, relationship="EXTERNAL_CALL", call_type="staticcall",
                   forwards_gas="full", target_expression="oracle.getRate()")

        self._run_with_read_only_detection(g)
        assert g.nodes[f]["read_only_reentrancy_risk"] is True

    def test_sensitive_variable_write_flagged(self):
        """Function with staticcall + WRITES edge to ACCOUNTING_CRITICAL var → flagged."""
        g = nx.DiGraph()
        _add_contract(g, "Pool")
        v = _add_var(g, "Pool", "totalLiquidity", ["ACCOUNTING_CRITICAL"])
        f = _add_func(
            g, "Pool", "addLiquidity",
            makes_external_call=True,
        )
        _writes(g, f, v)
        target = "ExternalOracle::getReserves"
        g.add_node(target, type="function", name="getReserves", contract="ExternalOracle",
                   is_view_or_pure=True)
        g.add_edge(f, target, relationship="EXTERNAL_CALL", call_type="staticcall",
                   forwards_gas="full", target_expression="oracle.getReserves()")

        self._run_with_read_only_detection(g)
        assert g.nodes[f]["read_only_reentrancy_risk"] is True
