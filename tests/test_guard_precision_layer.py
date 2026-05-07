"""
Tests for Dev Story 1 — Inline Guard & Access Pattern Precision Layer.

Covers:
  1.1 Inline Initializer Guard Detection
  1.2 Require-Based Access Control Detection
  1.3 Modifier Equivalence Detection
  Integration: Risk score downgrading for guarded patterns
  Query layer: graph_queries methods
"""

from unittest.mock import MagicMock

import networkx as nx

from src.utils.graph_queries import (
    GraphQueries,
    get_access_control_types,
    get_guarded_initializers,
    get_modifier_equivalences,
    get_safe_functions,
)

# ═══════════════════════════════════════════════════════════════
#  Helpers — build minimal graph fragments for unit tests
# ═══════════════════════════════════════════════════════════════

def _make_function_node(
    graph: nx.DiGraph,
    contract: str,
    name: str,
    source_code: str = "",
    modifiers: list | None = None,
    visibility: str = "public",
    is_external_entry: bool = True,
    writes_state: bool = False,
    is_protected: bool = False,
    has_access_control: bool = False,
    has_inline_access_check: bool = False,
    is_constructor: bool = False,
    **extra,
):
    node_id = f"{contract}::{name}"
    graph.add_node(node_id, **{
        "type": "function",
        "name": name,
        "contract": contract,
        "source_code": source_code,
        "modifiers": modifiers or [],
        "visibility": visibility,
        "is_external_entry": is_external_entry,
        "writes_state": writes_state,
        "is_protected": is_protected,
        "has_access_control": has_access_control,
        "has_inline_access_check": has_inline_access_check,
        "is_constructor": is_constructor,
        "is_view_or_pure": False,
        "is_payable": False,
        "propagated_state_variables": [],
        "reachable_from_external_entry": True,
        **extra,
    })
    return node_id


def _make_modifier_node(
    graph: nx.DiGraph,
    contract: str,
    name: str,
    conditions: list | None = None,
    is_access_control: bool = False,
    access_control_pattern: str = "none",
):
    node_id = f"{contract}::modifier::{name}"
    graph.add_node(node_id, **{
        "type": "modifier",
        "name": name,
        "contract": contract,
        "conditions": conditions or [],
        "is_access_control": is_access_control,
        "access_control_pattern": access_control_pattern,
    })
    return node_id


def _make_state_var(graph: nx.DiGraph, contract: str, name: str):
    node_id = f"{contract}::{name}"
    graph.add_node(node_id, **{
        "type": "state_variable",
        "node_type": "StateVariable",
        "name": name,
        "contract": contract,
    })
    return node_id


# ═══════════════════════════════════════════════════════════════
#  1.1 Inline Initializer Guard Detection
# ═══════════════════════════════════════════════════════════════

class TestInitializerGuardDetection:

    def test_require_not_initialized_detected(self):
        g = nx.DiGraph()
        _make_function_node(g, "Vault", "initialize",
            source_code='function initialize() external {\n  require(!initialized);\n  initialized = true;\n}')
        from src.graph import GraphBuilder
        gb = GraphBuilder()
        gb.graph = g
        gb._classify_modifier_equivalence()
        gb._detect_initializer_guards(MagicMock(contracts=[]))
        assert g.nodes["Vault::initialize"]["has_initializer_guard"] is True

    def test_require_initialized_eq_false_detected(self):
        g = nx.DiGraph()
        _make_function_node(g, "Token", "init",
            source_code='function init() public {\n  require(initialized == false);\n}')
        from src.graph import GraphBuilder
        gb = GraphBuilder()
        gb.graph = g
        gb._classify_modifier_equivalence()
        gb._detect_initializer_guards(MagicMock(contracts=[]))
        assert g.nodes["Token::init"]["has_initializer_guard"] is True

    def test_if_initialized_revert_detected(self):
        g = nx.DiGraph()
        _make_function_node(g, "Pool", "setup",
            source_code='function setup() external {\n  if (initialized) revert AlreadyInit();\n}')
        from src.graph import GraphBuilder
        gb = GraphBuilder()
        gb.graph = g
        gb._classify_modifier_equivalence()
        gb._detect_initializer_guards(MagicMock(contracts=[]))
        assert g.nodes["Pool::setup"]["has_initializer_guard"] is True

    def test_underscore_initialized_variant(self):
        g = nx.DiGraph()
        _make_function_node(g, "Proxy", "initialize",
            source_code='function initialize() external {\n  require(!_initialized);\n}')
        from src.graph import GraphBuilder
        gb = GraphBuilder()
        gb.graph = g
        gb._classify_modifier_equivalence()
        gb._detect_initializer_guards(MagicMock(contracts=[]))
        assert g.nodes["Proxy::initialize"]["has_initializer_guard"] is True

    def test_no_guard_not_flagged(self):
        g = nx.DiGraph()
        _make_function_node(g, "Vault", "initialize",
            source_code='function initialize() external {\n  owner = msg.sender;\n}')
        from src.graph import GraphBuilder
        gb = GraphBuilder()
        gb.graph = g
        gb._classify_modifier_equivalence()
        gb._detect_initializer_guards(MagicMock(contracts=[]))
        assert g.nodes["Vault::initialize"]["has_initializer_guard"] is False

    def test_safe_init_pattern_with_guard_and_modifier(self):
        g = nx.DiGraph()
        _make_modifier_node(g, "Vault", "initializer")
        _make_function_node(g, "Vault", "initialize",
            source_code='function initialize() external initializer {\n  require(!initialized);\n}',
            modifiers=["initializer"],
            is_protected=True)
        from src.graph import GraphBuilder
        gb = GraphBuilder()
        gb.graph = g
        gb._classify_modifier_equivalence()
        gb._detect_initializer_guards(MagicMock(contracts=[]))
        assert g.nodes["Vault::initialize"]["has_initializer_guard"] is True
        assert g.nodes["Vault::initialize"]["safe_init_pattern"] is True

    def test_safe_init_pattern_guard_only_no_modifier(self):
        g = nx.DiGraph()
        _make_function_node(g, "Vault", "initialize",
            source_code='function initialize() external {\n  require(!initialized);\n}',
            is_protected=False)
        from src.graph import GraphBuilder
        gb = GraphBuilder()
        gb.graph = g
        gb._classify_modifier_equivalence()
        gb._detect_initializer_guards(MagicMock(contracts=[]))
        assert g.nodes["Vault::initialize"]["has_initializer_guard"] is True
        assert g.nodes["Vault::initialize"]["safe_init_pattern"] is False

    def test_require_initialized_eq_zero(self):
        g = nx.DiGraph()
        _make_function_node(g, "V2", "init",
            source_code='function init() external {\n  require(_initialized == 0);\n}')
        from src.graph import GraphBuilder
        gb = GraphBuilder()
        gb.graph = g
        gb._classify_modifier_equivalence()
        gb._detect_initializer_guards(MagicMock(contracts=[]))
        assert g.nodes["V2::init"]["has_initializer_guard"] is True


# ═══════════════════════════════════════════════════════════════
#  1.2 Require-Based Access Control Detection
# ═══════════════════════════════════════════════════════════════

class TestRequireAccessControl:

    def test_require_msg_sender_eq_owner(self):
        g = nx.DiGraph()
        _make_state_var(g, "Vault", "owner")
        _make_function_node(g, "Vault", "setFee",
            source_code='function setFee(uint f) external {\n  require(msg.sender == owner);\n  fee = f;\n}',
            writes_state=True)
        from src.graph import GraphBuilder
        gb = GraphBuilder()
        gb.graph = g
        gb._classify_modifier_equivalence()
        gb._detect_require_access_control(MagicMock(contracts=[]))
        data = g.nodes["Vault::setFee"]
        assert data["access_control_type"] == "require-based"
        assert data["is_protected"] is True

    def test_require_hasRole_detected(self):
        g = nx.DiGraph()
        _make_function_node(g, "Token", "mint",
            source_code='function mint(uint a) external {\n  require(hasRole(MINTER_ROLE, msg.sender));\n}')
        from src.graph import GraphBuilder
        gb = GraphBuilder()
        gb.graph = g
        gb._classify_modifier_equivalence()
        gb._detect_require_access_control(MagicMock(contracts=[]))
        assert g.nodes["Token::mint"]["access_control_type"] == "require-based"

    def test_modifier_and_require_gives_both(self):
        g = nx.DiGraph()
        _make_function_node(g, "Vault", "withdraw",
            source_code='function withdraw() external onlyOwner {\n  require(msg.sender == admin);\n}',
            modifiers=["onlyOwner"],
            has_access_control=True)
        from src.graph import GraphBuilder
        gb = GraphBuilder()
        gb.graph = g
        gb._classify_modifier_equivalence()
        gb._detect_require_access_control(MagicMock(contracts=[]))
        assert g.nodes["Vault::withdraw"]["access_control_type"] == "both"

    def test_no_access_control_gives_none(self):
        g = nx.DiGraph()
        _make_function_node(g, "Vault", "deposit",
            source_code='function deposit() external payable {\n  balances[msg.sender] += msg.value;\n}')
        from src.graph import GraphBuilder
        gb = GraphBuilder()
        gb.graph = g
        gb._classify_modifier_equivalence()
        gb._detect_require_access_control(MagicMock(contracts=[]))
        assert g.nodes["Vault::deposit"]["access_control_type"] == "none"

    def test_if_sender_ne_revert_detected(self):
        g = nx.DiGraph()
        _make_function_node(g, "Box", "store",
            source_code='function store(uint v) external {\n  if (msg.sender != owner) revert Unauthorized();\n}')
        from src.graph import GraphBuilder
        gb = GraphBuilder()
        gb.graph = g
        gb._classify_modifier_equivalence()
        gb._detect_require_access_control(MagicMock(contracts=[]))
        assert g.nodes["Box::store"]["access_control_type"] == "require-based"

    def test_require_target_traced_to_storage(self):
        g = nx.DiGraph()
        _make_state_var(g, "Vault", "owner")
        _make_function_node(g, "Vault", "setFee",
            source_code='function setFee(uint f) external {\n  require(msg.sender == owner);\n}')
        from src.graph import GraphBuilder
        gb = GraphBuilder()
        gb.graph = g
        gb._classify_modifier_equivalence()
        gb._detect_require_access_control(MagicMock(contracts=[]))
        targets = g.nodes["Vault::setFee"]["require_access_control_targets"]
        assert "Vault::owner" in targets

    def test_require_based_upgrades_is_protected(self):
        g = nx.DiGraph()
        _make_function_node(g, "Vault", "admin_only",
            source_code='function admin_only() external {\n  require(msg.sender == admin);\n}',
            is_protected=False)
        from src.graph import GraphBuilder
        gb = GraphBuilder()
        gb.graph = g
        gb._classify_modifier_equivalence()
        gb._detect_require_access_control(MagicMock(contracts=[]))
        assert g.nodes["Vault::admin_only"]["is_protected"] is True


# ═══════════════════════════════════════════════════════════════
#  1.3 Modifier Equivalence Detection
# ═══════════════════════════════════════════════════════════════

class TestModifierEquivalence:

    def test_onlyOwner_classified_as_owner(self):
        g = nx.DiGraph()
        _make_modifier_node(g, "Owned", "onlyOwner")
        from src.graph import GraphBuilder
        gb = GraphBuilder()
        gb.graph = g
        gb._classify_modifier_equivalence()
        assert g.nodes["Owned::modifier::onlyOwner"]["semantic_category"] == "owner"

    def test_onlyAdmin_classified_as_admin(self):
        g = nx.DiGraph()
        _make_modifier_node(g, "Gov", "onlyAdmin")
        from src.graph import GraphBuilder
        gb = GraphBuilder()
        gb.graph = g
        gb._classify_modifier_equivalence()
        assert g.nodes["Gov::modifier::onlyAdmin"]["semantic_category"] == "admin"

    def test_initializer_classified(self):
        g = nx.DiGraph()
        _make_modifier_node(g, "Proxy", "initializer")
        from src.graph import GraphBuilder
        gb = GraphBuilder()
        gb.graph = g
        gb._classify_modifier_equivalence()
        assert g.nodes["Proxy::modifier::initializer"]["semantic_category"] == "initializer"

    def test_nonReentrant_classified(self):
        g = nx.DiGraph()
        _make_modifier_node(g, "Vault", "nonReentrant")
        from src.graph import GraphBuilder
        gb = GraphBuilder()
        gb.graph = g
        gb._classify_modifier_equivalence()
        assert g.nodes["Vault::modifier::nonReentrant"]["semantic_category"] == "reentrancy_guard"

    def test_lock_classified_as_reentrancy_guard(self):
        g = nx.DiGraph()
        _make_modifier_node(g, "Vault", "lock")
        from src.graph import GraphBuilder
        gb = GraphBuilder()
        gb.graph = g
        gb._classify_modifier_equivalence()
        assert g.nodes["Vault::modifier::lock"]["semantic_category"] == "reentrancy_guard"

    def test_custom_modifier_stays_custom(self):
        g = nx.DiGraph()
        _make_modifier_node(g, "Pool", "whenNotPaused")
        from src.graph import GraphBuilder
        gb = GraphBuilder()
        gb.graph = g
        gb._classify_modifier_equivalence()
        assert g.nodes["Pool::modifier::whenNotPaused"]["semantic_category"] == "custom"

    def test_function_gets_equivalences_dict(self):
        g = nx.DiGraph()
        _make_modifier_node(g, "Vault", "onlyOwner")
        _make_modifier_node(g, "Vault", "nonReentrant")
        _make_function_node(g, "Vault", "withdraw", modifiers=["onlyOwner", "nonReentrant"])
        from src.graph import GraphBuilder
        gb = GraphBuilder()
        gb.graph = g
        gb._classify_modifier_equivalence()
        eq = g.nodes["Vault::withdraw"]["modifier_equivalences"]
        assert eq["onlyOwner"] == "owner"
        assert eq["nonReentrant"] == "reentrancy_guard"

    def test_has_reentrancy_guard_flag(self):
        g = nx.DiGraph()
        _make_modifier_node(g, "Vault", "nonReentrant")
        _make_function_node(g, "Vault", "swap", modifiers=["nonReentrant"])
        from src.graph import GraphBuilder
        gb = GraphBuilder()
        gb.graph = g
        gb._classify_modifier_equivalence()
        assert g.nodes["Vault::swap"]["has_reentrancy_guard"] is True

    def test_has_initializer_modifier_flag(self):
        g = nx.DiGraph()
        _make_modifier_node(g, "Proxy", "initializer")
        _make_function_node(g, "Proxy", "initialize", modifiers=["initializer"])
        from src.graph import GraphBuilder
        gb = GraphBuilder()
        gb.graph = g
        gb._classify_modifier_equivalence()
        assert g.nodes["Proxy::initialize"]["has_initializer_modifier"] is True

    def test_onlyRole_classified_as_admin(self):
        g = nx.DiGraph()
        _make_modifier_node(g, "Token", "onlyRole")
        from src.graph import GraphBuilder
        gb = GraphBuilder()
        gb.graph = g
        gb._classify_modifier_equivalence()
        assert g.nodes["Token::modifier::onlyRole"]["semantic_category"] == "admin"

    def test_msg_sender_condition_falls_back_to_owner(self):
        g = nx.DiGraph()
        _make_modifier_node(g, "Vault", "myCustomMod",
            conditions=[{"checks_msg_sender": True, "compared_variable": "boss"}])
        from src.graph import GraphBuilder
        gb = GraphBuilder()
        gb.graph = g
        gb._classify_modifier_equivalence()
        assert g.nodes["Vault::modifier::myCustomMod"]["semantic_category"] == "owner"


# ═══════════════════════════════════════════════════════════════
#  Risk Score Integration Tests
# ═══════════════════════════════════════════════════════════════

class TestRiskScoreDowngrade:

    def _build_scored_graph(self, func_attrs: dict) -> nx.DiGraph:
        """Build a minimal graph and run risk scoring."""
        g = nx.DiGraph()
        defaults = {
            "type": "function",
            "name": "target",
            "contract": "C",
            "visibility": "public",
            "is_external_entry": True,
            "is_view_or_pure": False,
            "is_payable": False,
            "is_constructor": False,
            "is_protected": False,
            "writes_state": True,
            "makes_external_call": True,
            "has_taint_risk": True,
            "modifiers": [],
            "propagated_state_variables": [],
            "reachable_from_external_entry": True,
            "reentrancy_risk": False,
            "can_escalate_privileges": False,
            "is_unprotected_mutator": False,
            "state_write_after_external_call": False,
            "cei_violation_only": False,
            "has_array_length_mutation": False,
            "delegatecall_storage_risk": False,
            "safe_init_pattern": False,
            "has_initializer_guard": False,
            "has_reentrancy_guard": False,
            "access_control_type": "none",
            "unprotected_risk_level": "NONE",
        }
        defaults.update(func_attrs)
        g.add_node("C::target", **defaults)
        g.add_node("C", type="contract", name="C", tier="CORE")
        from src.graph import GraphBuilder
        gb = GraphBuilder()
        gb.graph = g
        gb._compute_global_risk_scores()
        return g

    def test_reentrancy_guarded_lower_structural(self):
        g_unguarded = self._build_scored_graph({"reentrancy_risk": True})
        g_guarded = self._build_scored_graph({"reentrancy_risk": True, "has_reentrancy_guard": True})
        s_ung = g_unguarded.nodes["C::target"]["structural_score"]
        s_grd = g_guarded.nodes["C::target"]["structural_score"]
        assert s_grd < s_ung, f"Guarded ({s_grd}) should be less than unguarded ({s_ung})"

    def test_reentrancy_guarded_category_suffix(self):
        g = self._build_scored_graph({"reentrancy_risk": True, "has_reentrancy_guard": True})
        cats = g.nodes["C::target"]["risk_categories"]
        assert "reentrancy_guarded" in cats
        assert "reentrancy" not in cats

    def test_privilege_escalation_guarded_by_safe_init(self):
        g_plain = self._build_scored_graph({"can_escalate_privileges": True})
        g_safe = self._build_scored_graph({
            "can_escalate_privileges": True,
            "safe_init_pattern": True,
        })
        assert g_safe.nodes["C::target"]["structural_score"] < g_plain.nodes["C::target"]["structural_score"]

    def test_privilege_escalation_guarded_by_require_ac(self):
        g_plain = self._build_scored_graph({"can_escalate_privileges": True})
        g_req = self._build_scored_graph({
            "can_escalate_privileges": True,
            "access_control_type": "require-based",
        })
        assert g_req.nodes["C::target"]["structural_score"] < g_plain.nodes["C::target"]["structural_score"]

    def test_unprotected_mutator_guarded_by_require_ac(self):
        g_plain = self._build_scored_graph({"is_unprotected_mutator": True})
        g_req = self._build_scored_graph({
            "is_unprotected_mutator": True,
            "access_control_type": "require-based",
        })
        s_plain = g_plain.nodes["C::target"]["structural_score"]
        s_req = g_req.nodes["C::target"]["structural_score"]
        assert s_req < s_plain

    def test_final_score_reflects_downgrade(self):
        g_plain = self._build_scored_graph({
            "reentrancy_risk": True,
            "can_escalate_privileges": True,
        })
        g_safe = self._build_scored_graph({
            "reentrancy_risk": True,
            "has_reentrancy_guard": True,
            "can_escalate_privileges": True,
            "safe_init_pattern": True,
        })
        assert g_safe.nodes["C::target"]["final_score"] < g_plain.nodes["C::target"]["final_score"]


# ═══════════════════════════════════════════════════════════════
#  Query Layer Tests
# ═══════════════════════════════════════════════════════════════

class TestQueryLayer:

    def test_get_guarded_initializers(self):
        g = nx.DiGraph()
        _make_function_node(g, "V", "initialize", has_initializer_guard=True, safe_init_pattern=True)
        _make_function_node(g, "V", "deposit")
        result = GraphQueries(g).get_guarded_initializers()
        assert len(result) == 1
        assert result[0]["function_id"] == "V::initialize"
        assert result[0]["safe_init_pattern"] is True

    def test_get_guarded_initializers_contract_filter(self):
        g = nx.DiGraph()
        _make_function_node(g, "A", "init", has_initializer_guard=True)
        _make_function_node(g, "B", "init", has_initializer_guard=True)
        result = GraphQueries(g).get_guarded_initializers(contract_name="A")
        assert len(result) == 1
        assert result[0]["contract"] == "A"

    def test_get_access_control_types_filters_none(self):
        g = nx.DiGraph()
        _make_function_node(g, "V", "deposit", access_control_type="none")
        _make_function_node(g, "V", "withdraw", access_control_type="modifier")
        _make_function_node(g, "V", "admin", access_control_type="require-based")
        result = GraphQueries(g).get_access_control_types()
        names = {r["name"] for r in result}
        assert "deposit" not in names
        assert "withdraw" in names
        assert "admin" in names

    def test_get_modifier_equivalences(self):
        g = nx.DiGraph()
        _make_modifier_node(g, "V", "onlyOwner")
        g.nodes["V::modifier::onlyOwner"]["semantic_category"] = "owner"
        _make_modifier_node(g, "V", "nonReentrant")
        g.nodes["V::modifier::nonReentrant"]["semantic_category"] = "reentrancy_guard"
        result = GraphQueries(g).get_modifier_equivalences()
        cats = {r["name"]: r["semantic_category"] for r in result}
        assert cats["onlyOwner"] == "owner"
        assert cats["nonReentrant"] == "reentrancy_guard"

    def test_get_safe_functions(self):
        g = nx.DiGraph()
        _make_function_node(g, "V", "init",
            safe_init_pattern=True, access_control_type="modifier",
            risk_categories=["privilege_escalation_guarded"], final_score=20)
        _make_function_node(g, "V", "swap",
            has_reentrancy_guard=True, access_control_type="none",
            risk_categories=["reentrancy_guarded"], final_score=15)
        _make_function_node(g, "V", "deposit",
            access_control_type="none",
            risk_categories=[], final_score=50)
        result = GraphQueries(g).get_safe_functions()
        ids = {r["function_id"] for r in result}
        assert "V::init" in ids
        assert "V::swap" in ids
        assert "V::deposit" not in ids

    def test_standalone_wrappers(self):
        g = nx.DiGraph()
        _make_function_node(g, "V", "init", has_initializer_guard=True)
        _make_function_node(g, "V", "setFee", access_control_type="require-based")
        _make_modifier_node(g, "V", "nonReentrant")
        g.nodes["V::modifier::nonReentrant"]["semantic_category"] = "reentrancy_guard"

        assert len(get_guarded_initializers(g)) == 1
        assert len(get_access_control_types(g)) == 1
        assert len(get_modifier_equivalences(g)) == 1
        assert len(get_safe_functions(g)) >= 1


# ═══════════════════════════════════════════════════════════════
#  Hotspot Gate Integration — guarded patterns drop below gate
# ═══════════════════════════════════════════════════════════════

class TestHotspotGateIntegration:

    def test_guarded_reentrancy_drops_below_hotspot_gate(self):
        """
        A reentrancy-risk function with nonReentrant should score lower
        than the multi-dimensional gate (structural >= 40).
        """
        g = nx.DiGraph()
        g.add_node("C", type="contract", name="C", tier="CORE")
        _make_function_node(g, "C", "swap",
            reentrancy_risk=True,
            has_reentrancy_guard=True,
            access_control_type="none",
            safe_init_pattern=False,
            has_initializer_guard=False,
            state_write_after_external_call=False,
            cei_violation_only=False,
            has_array_length_mutation=False,
            delegatecall_storage_risk=False,
            can_escalate_privileges=False,
            is_unprotected_mutator=False,
            unprotected_risk_level="NONE",
        )
        from src.graph import GraphBuilder
        gb = GraphBuilder()
        gb.graph = g
        gb._compute_global_risk_scores()
        structural = g.nodes["C::swap"]["structural_score"]
        assert structural < 40, (
            f"Guarded reentrancy structural ({structural}) should be below gate (40)"
        )
