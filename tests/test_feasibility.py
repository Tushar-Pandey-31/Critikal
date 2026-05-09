import networkx as nx

from src.graph import GraphBuilder


def _make_function(
    g: nx.DiGraph,
    contract: str,
    name: str,
    writes_state: bool = False,
    is_protected: bool = False,
    is_external_entry: bool = True,
    reachable_from_external_entry: bool = True,
    has_taint_risk: bool = False,
    attacker_controlled_input: bool = False,
    modifies_sensitive_storage: bool = False,
    can_escalate_privileges: bool = False,
    access_control_type: str = "none",
    source_code: str = "",
):
    fid = f"{contract}::{name}"
    g.add_node(
        fid,
        type="function",
        name=name,
        contract=contract,
        writes_state=writes_state,
        is_protected=is_protected,
        is_external_entry=is_external_entry,
        reachable_from_external_entry=reachable_from_external_entry,
        has_taint_risk=has_taint_risk,
        attacker_controlled_input=attacker_controlled_input,
        modifies_sensitive_storage=modifies_sensitive_storage,
        can_escalate_privileges=can_escalate_privileges,
        access_control_type=access_control_type,
        source_code=source_code,
        impact_score=30 if modifies_sensitive_storage else 10,
    )
    return fid


def _make_state_var(g: nx.DiGraph, contract: str, name: str):
    vid = f"{contract}::{name}"
    g.add_node(vid, type="state_variable", name=name, contract=contract)
    return vid


class TestFeasibilityValidator:
    def test_strict_access_guard_hard_drop(self):
        # A protected function with no escalation in the chain
        g = nx.DiGraph()
        v = _make_state_var(g, "Bank", "balance")

        s1 = _make_function(g, "Bank", "f1", writes_state=True, attacker_controlled_input=True)
        s2 = _make_function(g, "Bank", "f2", writes_state=True, is_protected=True, access_control_type="modifier")

        g.add_edge(
            s1, s2, relationship="STATE_DEPENDENCY", shared_variables=[v], sensitivity_overlap=["ACCOUNTING_CRITICAL"]
        )
        g.nodes[s1]["dangerous_sequences"] = [
            {
                "writer": s1,
                "reader": s2,
                "shared_variables": [v],
                "sensitivity": ["ACCOUNTING_CRITICAL"],
                "danger_types": ["ACCOUNTING_MANIPULATION"],
                "writer_protected": False,
                "reader_protected": True,
                "score": 40,
            }
        ]

        builder = GraphBuilder()
        builder.graph = g
        builder._generate_exploit_chains()

        chains = g.nodes[s1].get("exploit_chains", [])
        assert len(chains) == 1
        assert chains[0]["feasibility_score"] == 0.0
        assert chains[0]["is_deterministically_impossible"] is True

    def test_multi_step_escalation_survives(self):
        # Dev Story 7 explicit test case: A modifies owner, B requires owner
        g = nx.DiGraph()
        v1 = _make_state_var(g, "Gov", "owner")
        v2 = _make_state_var(g, "Bank", "funds")

        s1 = _make_function(
            g, "Gov", "setOwner", writes_state=True, attacker_controlled_input=True, can_escalate_privileges=True
        )
        s2 = _make_function(
            g,
            "Bank",
            "drain",
            writes_state=True,
            is_protected=True,
            access_control_type="modifier",
            modifies_sensitive_storage=True,
        )

        g.add_edge(
            s1, s2, relationship="STATE_DEPENDENCY", shared_variables=[v1], sensitivity_overlap=["ACCESS_CRITICAL"]
        )
        g.nodes[s1]["dangerous_sequences"] = [
            {
                "writer": s1,
                "reader": s2,
                "shared_variables": [v1],
                "sensitivity": ["ACCESS_CRITICAL"],
                "danger_types": ["PRIVILEGE_CHAIN"],
                "writer_protected": False,
                "reader_protected": True,
                "score": 50,
            }
        ]

        builder = GraphBuilder()
        builder.graph = g
        builder._generate_exploit_chains()

        chains = g.nodes[s1].get("exploit_chains", [])
        assert len(chains) == 1
        assert chains[0]["feasibility_score"] > 0.0  # Kept alive
        assert chains[0]["is_deterministically_impossible"] is False

    def test_external_entry_verification(self):
        # Chain where no step is callable externally
        g = nx.DiGraph()
        v = _make_state_var(g, "Pool", "reserve")

        s1 = _make_function(g, "Pool", "internal1", is_external_entry=False, reachable_from_external_entry=False)
        s2 = _make_function(g, "Pool", "internal2", writes_state=True)

        # Override reachable flag since external_funcs iteration checks it before processing chains normally.
        # But for test sake, let's force the function to behave like it is processed but feasibility says NO.
        g.nodes[s1]["reachable_from_external_entry"] = True  # To trigger _generate_exploit_chains looking at it
        g.nodes[s1]["is_external_entry"] = False
        g.nodes[s1]["attacker_controlled_input"] = False
        g.nodes[s1]["has_taint_risk"] = False

        g.add_edge(
            s1, s2, relationship="STATE_DEPENDENCY", shared_variables=[v], sensitivity_overlap=["ACCOUNTING_CRITICAL"]
        )
        g.nodes[s1]["dangerous_sequences"] = [
            {
                "writer": s1,
                "reader": s2,
                "shared_variables": [v],
                "sensitivity": ["ACCOUNTING_CRITICAL"],
                "danger_types": ["ACCOUNTING_MANIPULATION"],
                "writer_protected": False,
                "reader_protected": False,
                "score": 40,
            }
        ]

        builder = GraphBuilder()
        builder.graph = g
        builder._generate_exploit_chains()

        chains = g.nodes[s1].get("exploit_chains", [])
        assert len(chains) == 1
        assert chains[0]["feasibility_score"] == 0.0
        assert chains[0]["is_deterministically_impossible"] is True

    def test_deterministic_revert_downgrade(self):
        g = nx.DiGraph()
        v = _make_state_var(g, "Game", "state")

        s1 = _make_function(g, "Game", "set", writes_state=True, attacker_controlled_input=True)
        s2 = _make_function(g, "Game", "play", source_code='require(state == 1, "bad");')

        g.add_edge(
            s1, s2, relationship="STATE_DEPENDENCY", shared_variables=[v], sensitivity_overlap=["ACCOUNTING_CRITICAL"]
        )
        g.nodes[s1]["dangerous_sequences"] = [
            {
                "writer": s1,
                "reader": s2,
                "shared_variables": [v],
                "sensitivity": ["ACCOUNTING_CRITICAL"],
                "danger_types": ["ACCOUNTING_MANIPULATION"],
                "writer_protected": False,
                "reader_protected": False,
                "score": 40,
            }
        ]

        builder = GraphBuilder()
        builder.graph = g
        builder._generate_exploit_chains()

        chains = g.nodes[s1].get("exploit_chains", [])
        assert len(chains) == 1
        assert chains[0]["feasibility_score"] < 1.0
        assert chains[0]["feasibility_score"] > 0.0

    def test_ranking_stability(self):
        g = nx.DiGraph()

        # S1 > S2 structurally, but F1 == F2.
        # has_taint_risk gives score boost.
        s1 = _make_function(g, "C", "f1", writes_state=True, has_taint_risk=True, attacker_controlled_input=True)
        s2 = _make_function(g, "C", "f2", writes_state=True, has_taint_risk=False, attacker_controlled_input=True)

        g.nodes[s1]["is_chain_entry"] = True
        g.nodes[s1]["exploit_chains"] = [{"feasibility_score": 0.5}]

        g.nodes[s2]["is_chain_entry"] = True
        g.nodes[s2]["exploit_chains"] = [{"feasibility_score": 0.5}]

        builder = GraphBuilder()
        builder.graph = g
        # Give them valid paths to ensure it evaluates target scores properly
        v1 = _make_state_var(g, "C", "v1")
        g.add_edge(s1, v1, relationship="WRITES_STATE")
        g.add_edge(s2, v1, relationship="WRITES_STATE")

        builder._compute_exploit_target_scores()

        # Final should maintain S1 > S2 since F1 == F2
        assert g.nodes[s1]["exploit_target_score"] > g.nodes[s2]["exploit_target_score"]

    def test_feasibility_sensitivity(self):
        g = nx.DiGraph()
        # Same structural score, but different feasibility scores
        s1 = _make_function(g, "C", "f1", writes_state=True, has_taint_risk=True)
        s2 = _make_function(g, "C", "f2", writes_state=True, has_taint_risk=True)
        s3 = _make_function(g, "C", "f3", writes_state=True, has_taint_risk=True)

        g.nodes[s1]["is_chain_entry"] = True
        g.nodes[s1]["exploit_chains"] = [{"feasibility_score": 0.6}]

        g.nodes[s2]["is_chain_entry"] = True
        g.nodes[s2]["exploit_chains"] = [{"feasibility_score": 0.5}]

        g.nodes[s3]["is_chain_entry"] = True
        g.nodes[s3]["exploit_chains"] = [{"feasibility_score": 0.8}]

        builder = GraphBuilder()
        builder.graph = g
        builder._compute_exploit_target_scores()

        assert g.nodes[s3]["exploit_target_score"] > g.nodes[s1]["exploit_target_score"]
        assert g.nodes[s1]["exploit_target_score"] > g.nodes[s2]["exploit_target_score"]

    def test_boundary_conditions(self):
        # Test F=1.0 stays the same as base structural score, and F=0.0 drops to 0.
        g_base = nx.DiGraph()
        s_base = _make_function(g_base, "C", "f", writes_state=True, has_taint_risk=True)
        # Compute base structural score without any exploit chains attached (won't trigger valid_chains modification)
        b_base = GraphBuilder()
        b_base.graph = g_base
        b_base._compute_exploit_target_scores()
        base_score = g_base.nodes[s_base]["exploit_target_score"]

        g = nx.DiGraph()
        s1 = _make_function(g, "C", "f1", writes_state=True, has_taint_risk=True)
        s2 = _make_function(g, "C", "f2", writes_state=True, has_taint_risk=True)

        g.nodes[s1]["is_chain_entry"] = True
        g.nodes[s1]["exploit_chains"] = [{"feasibility_score": 1.0}]

        g.nodes[s2]["is_chain_entry"] = True
        g.nodes[s2]["exploit_chains"] = [{"feasibility_score": 0.0}]

        builder = GraphBuilder()
        builder.graph = g
        builder._compute_exploit_target_scores()

        assert g.nodes[s1]["exploit_target_score"] == base_score
        assert g.nodes[s2]["exploit_target_score"] == 0
