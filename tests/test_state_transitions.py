"""
Epic 6 — StateTransition Node Tests

Tests:
  Story 6.1 — StateTransition node creation, operation classification,
              PERFORMS / AFFECTS edges, attacker-controlled detection,
              privilege enrichment.
  Story 6.2 — Array length mutation detection (pop / decrement_length).
  Story 6.3 — Delegatecall storage collision risk detection.
"""

import os
import sys

import pytest

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

from analysis_engine import AnalysisEngine
from src.graph import GraphBuilder
from utils.graph_queries import GraphQueries

# ════════════════════════════════════════════════════════════
#  Shared Fixture
# ════════════════════════════════════════════════════════════

@pytest.fixture(scope="module")
def graph_and_queries():
    repo_path = os.path.join(os.getcwd(), "tests", "contracts")
    engine = AnalysisEngine()
    slither_obj = engine.run_analysis(repo_path)
    assert slither_obj is not None, "Slither analysis failed"

    builder = GraphBuilder()
    builder.build_graph(slither_obj)
    queries = GraphQueries(builder.graph)
    return builder.graph, queries


# ════════════════════════════════════════════════════════════
#  Story 6.1 — StateTransition Node Basics
# ════════════════════════════════════════════════════════════

class TestStateTransitionNodes:
    """Verify that StateTransition nodes are created with correct topology."""

    def test_state_transition_nodes_exist(self, graph_and_queries):
        graph, _ = graph_and_queries
        st_nodes = [
            (nid, d) for nid, d in graph.nodes(data=True)
            if d.get("type") == "state_transition"
        ]
        assert len(st_nodes) > 0, "Expected at least one StateTransition node"

    def test_performs_edges_exist(self, graph_and_queries):
        graph, _ = graph_and_queries
        performs_edges = [
            (u, v) for u, v, d in graph.edges(data=True)
            if d.get("relationship") == "PERFORMS"
        ]
        assert len(performs_edges) > 0, "Expected at least one PERFORMS edge"

    def test_affects_edges_exist(self, graph_and_queries):
        graph, _ = graph_and_queries
        affects_edges = [
            (u, v) for u, v, d in graph.edges(data=True)
            if d.get("relationship") == "AFFECTS"
        ]
        assert len(affects_edges) > 0, "Expected at least one AFFECTS edge"

    def test_topology_function_performs_st_affects_var(self, graph_and_queries):
        """Every StateTransition should have exactly one incoming PERFORMS
        from a Function and one outgoing AFFECTS to a StateVariable."""
        graph, _ = graph_and_queries

        for nid, ndata in graph.nodes(data=True):
            if ndata.get("type") != "state_transition":
                continue

            performs_sources = [
                u for u in graph.predecessors(nid)
                if graph.get_edge_data(u, nid).get("relationship") == "PERFORMS"
            ]
            assert len(performs_sources) == 1, (
                f"{nid}: expected 1 PERFORMS predecessor, got {len(performs_sources)}"
            )
            src_type = graph.nodes[performs_sources[0]].get("type")
            assert src_type == "function", (
                f"{nid}: PERFORMS source should be function, got {src_type}"
            )

            affects_targets = [
                v for v in graph.successors(nid)
                if graph.get_edge_data(nid, v).get("relationship") == "AFFECTS"
            ]
            assert len(affects_targets) == 1, (
                f"{nid}: expected 1 AFFECTS target, got {len(affects_targets)}"
            )
            tgt_type = graph.nodes[affects_targets[0]].get("node_type")
            assert tgt_type == "StateVariable", (
                f"{nid}: AFFECTS target should be StateVariable, got {tgt_type}"
            )

    def test_writes_edges_still_exist(self, graph_and_queries):
        """Backward compat: WRITES edges are preserved alongside new model."""
        graph, _ = graph_and_queries
        writes_edges = [
            (u, v) for u, v, d in graph.edges(data=True)
            if d.get("relationship") == "WRITES"
        ]
        assert len(writes_edges) > 0, "WRITES edges should still be present"


# ════════════════════════════════════════════════════════════
#  Story 6.1 — Operation Classification
# ════════════════════════════════════════════════════════════

class TestOperationClassification:

    def test_assign_operation(self, graph_and_queries):
        _, queries = graph_and_queries
        transitions = queries.get_state_transitions(
            function_id="StateTransitionTest::setCounter"
        )
        assert len(transitions) > 0, "setCounter should produce transitions"
        ops = {t["operation"] for t in transitions}
        assert "assign" in ops, f"setCounter should have 'assign' operation, got {ops}"

    def test_add_operation(self, graph_and_queries):
        _, queries = graph_and_queries
        transitions = queries.get_state_transitions(
            function_id="StateTransitionTest::incrementCounter"
        )
        assert len(transitions) > 0, "incrementCounter should produce transitions"
        ops = {t["operation"] for t in transitions}
        assert "add" in ops, f"incrementCounter should have 'add' operation, got {ops}"

    def test_sub_operation(self, graph_and_queries):
        _, queries = graph_and_queries
        transitions = queries.get_state_transitions(
            function_id="StateTransitionTest::decrementCounter"
        )
        assert len(transitions) > 0, "decrementCounter should produce transitions"
        ops = {t["operation"] for t in transitions}
        assert "sub" in ops, f"decrementCounter should have 'sub' operation, got {ops}"

    def test_push_operation(self, graph_and_queries):
        _, queries = graph_and_queries
        transitions = queries.get_state_transitions(
            function_id="StateTransitionTest::pushData"
        )
        assert len(transitions) > 0, "pushData should produce transitions"
        ops = {t["operation"] for t in transitions}
        assert "push" in ops, f"pushData should have 'push' operation, got {ops}"

    def test_pop_operation(self, graph_and_queries):
        _, queries = graph_and_queries
        transitions = queries.get_state_transitions(
            function_id="StateTransitionTest::popData"
        )
        assert len(transitions) > 0, "popData should produce transitions"
        ops = {t["operation"] for t in transitions}
        assert "pop" in ops, f"popData should have 'pop' operation, got {ops}"

    def test_mapping_write_detected(self, graph_and_queries):
        _, queries = graph_and_queries
        transitions = queries.get_state_transitions(
            function_id="StateTransitionTest::deposit"
        )
        mapping_transitions = [t for t in transitions if t["is_mapping"]]
        assert len(mapping_transitions) > 0, "deposit should write to a mapping"

    def test_read_only_no_transitions(self, graph_and_queries):
        _, queries = graph_and_queries
        transitions = queries.get_state_transitions(
            function_id="StateTransitionTest::readOnly"
        )
        assert len(transitions) == 0, "readOnly should produce zero transitions"


# ════════════════════════════════════════════════════════════
#  Story 6.1 — StateTransition Properties
# ════════════════════════════════════════════════════════════

class TestStateTransitionProperties:

    def test_required_properties_present(self, graph_and_queries):
        graph, _ = graph_and_queries
        required = {
            "type", "node_type", "function", "variable", "operation",
            "is_array_length", "is_mapping", "is_owner_assignment",
            "attacker_controlled_input", "affects_privileged_var",
        }
        for nid, ndata in graph.nodes(data=True):
            if ndata.get("type") != "state_transition":
                continue
            missing = required - set(ndata.keys())
            assert not missing, f"{nid} missing properties: {missing}"

    def test_attacker_controlled_on_public_param(self, graph_and_queries):
        """setCounter(uint256 _val) is public with a parameter in the write."""
        _, queries = graph_and_queries
        transitions = queries.get_state_transitions(
            function_id="StateTransitionTest::setCounter"
        )
        controlled = [t for t in transitions if t["attacker_controlled_input"]]
        assert len(controlled) > 0, (
            "setCounter should flag attacker_controlled_input (public + param)"
        )

    def test_owner_assignment_flag(self, graph_and_queries):
        """setOwner writes to 'owner', should flag is_owner_assignment."""
        _, queries = graph_and_queries
        transitions = queries.get_state_transitions(
            function_id="StateTransitionTest::setOwner"
        )
        owner_transitions = [t for t in transitions if t["is_owner_assignment"]]
        assert len(owner_transitions) > 0, (
            "setOwner should flag is_owner_assignment"
        )

    def test_complex_write_multiple_transitions(self, graph_and_queries):
        """complexWrite writes counter + balances → two distinct transitions."""
        _, queries = graph_and_queries
        transitions = queries.get_state_transitions(
            function_id="StateTransitionTest::complexWrite"
        )
        variables = {t["variable"] for t in transitions}
        assert len(variables) >= 2, (
            f"complexWrite should affect ≥2 variables, got {variables}"
        )


# ════════════════════════════════════════════════════════════
#  Story 6.1 — Query API
# ════════════════════════════════════════════════════════════

class TestStateTransitionQueries:

    def test_filter_by_contract(self, graph_and_queries):
        _, queries = graph_and_queries
        transitions = queries.get_state_transitions(
            contract_name="StateTransitionTest"
        )
        assert len(transitions) > 0
        for t in transitions:
            func_id = t["function"]
            assert "StateTransitionTest" in func_id

    def test_filter_by_operation(self, graph_and_queries):
        _, queries = graph_and_queries
        add_transitions = queries.get_state_transitions(operation="add")
        for t in add_transitions:
            assert t["operation"] == "add"

    def test_filter_by_variable(self, graph_and_queries):
        _, queries = graph_and_queries
        transitions = queries.get_state_transitions(
            variable_id="StateTransitionTest::counter"
        )
        for t in transitions:
            assert t["variable"] == "StateTransitionTest::counter"


# ════════════════════════════════════════════════════════════
#  Story 6.2 — Array Length Mutation Detection
# ════════════════════════════════════════════════════════════

class TestArrayLengthMutation:

    def test_pop_flags_array_length_mutation(self, graph_and_queries):
        graph, queries = graph_and_queries
        func_id = "StateTransitionTest::popData"
        if not graph.has_node(func_id):
            pytest.skip("popData node not found")
        node_data = graph.nodes[func_id]
        assert node_data.get("has_array_length_mutation") is True, (
            "popData should be flagged with has_array_length_mutation"
        )

    def test_push_does_not_flag_mutation(self, graph_and_queries):
        graph, _ = graph_and_queries
        func_id = "StateTransitionTest::pushData"
        if not graph.has_node(func_id):
            pytest.skip("pushData node not found")
        node_data = graph.nodes[func_id]
        assert not node_data.get("has_array_length_mutation"), (
            "pushData should NOT be flagged as array_length_mutation"
        )

    def test_array_length_mutations_query(self, graph_and_queries):
        _, queries = graph_and_queries
        mutations = queries.get_array_length_mutations(
            contract_name="StateTransitionTest"
        )
        func_ids = [m["function_id"] for m in mutations]
        assert "StateTransitionTest::popData" in func_ids, (
            "popData should appear in array_length_mutations query"
        )

    def test_array_length_mutation_in_risk_categories(self, graph_and_queries):
        graph, _ = graph_and_queries
        func_id = "StateTransitionTest::popData"
        if not graph.has_node(func_id):
            pytest.skip("popData node not found")
        categories = graph.nodes[func_id].get("risk_categories", [])
        assert "array_length_mutation" in categories, (
            f"popData risk_categories should contain 'array_length_mutation', got {categories}"
        )


# ════════════════════════════════════════════════════════════
#  Story 6.3 — Delegatecall Storage Collision Detection
# ════════════════════════════════════════════════════════════

class TestDelegatecallStorageRisk:

    def test_unsafe_delegatecall_flagged(self, graph_and_queries):
        """unsafeDelegatecall: attacker-controlled target + state write after."""
        graph, _ = graph_and_queries
        func_id = "StateTransitionTest::unsafeDelegatecall"
        if not graph.has_node(func_id):
            pytest.skip("unsafeDelegatecall node not found")
        node_data = graph.nodes[func_id]
        assert node_data.get("delegatecall_storage_risk") is True, (
            "unsafeDelegatecall should be flagged as delegatecall_storage_risk"
        )

    def test_delegatecall_no_write_still_flagged_if_target_controlled(self, graph_and_queries):
        """delegatecallNoWrite: attacker-controlled target, no state write."""
        graph, _ = graph_and_queries
        func_id = "StateTransitionTest::delegatecallNoWrite"
        if not graph.has_node(func_id):
            pytest.skip("delegatecallNoWrite node not found")
        node_data = graph.nodes[func_id]
        assert node_data.get("delegatecall_storage_risk") is True, (
            "delegatecallNoWrite should still be flagged (attacker-controlled target)"
        )

    def test_fixed_delegatecall_lower_risk(self, graph_and_queries):
        """fixedDelegatecall: target from state variable, non-upgradeable."""
        graph, _ = graph_and_queries
        func_id = "StateTransitionTest::fixedDelegatecall"
        if not graph.has_node(func_id):
            pytest.skip("fixedDelegatecall node not found")
        node_data = graph.nodes[func_id]
        assert node_data.get("delegatecall_storage_risk") is False, (
            "fixedDelegatecall should NOT be flagged (target from state var, non-upgradeable)"
        )

    def test_delegatecall_storage_risk_in_risk_categories(self, graph_and_queries):
        graph, _ = graph_and_queries
        func_id = "StateTransitionTest::unsafeDelegatecall"
        if not graph.has_node(func_id):
            pytest.skip("unsafeDelegatecall node not found")
        categories = graph.nodes[func_id].get("risk_categories", [])
        assert "delegatecall_storage_risk" in categories, (
            f"unsafeDelegatecall risk_categories should contain "
            f"'delegatecall_storage_risk', got {categories}"
        )

    def test_delegatecall_storage_risks_query(self, graph_and_queries):
        _, queries = graph_and_queries
        risks = queries.get_delegatecall_storage_risks(
            contract_name="StateTransitionTest"
        )
        func_ids = [r["function_id"] for r in risks]
        assert "StateTransitionTest::unsafeDelegatecall" in func_ids

    def test_no_false_positive_on_non_delegatecall(self, graph_and_queries):
        """incrementCounter has no delegatecall; should never be flagged."""
        graph, _ = graph_and_queries
        func_id = "StateTransitionTest::incrementCounter"
        if not graph.has_node(func_id):
            pytest.skip("incrementCounter not found")
        assert not graph.nodes[func_id].get("delegatecall_storage_risk")


# ════════════════════════════════════════════════════════════
#  Cross-cutting: Existing Tests Must Not Regress
# ════════════════════════════════════════════════════════════

class TestBackwardCompatibility:
    """WRITES-based metadata must remain correct after Epic 6 changes."""

    def test_writes_state_flag_intact(self, graph_and_queries):
        graph, _ = graph_and_queries
        func_id = "StateTransitionTest::incrementCounter"
        if not graph.has_node(func_id):
            pytest.skip("incrementCounter not found")
        assert graph.nodes[func_id].get("writes_state") is True

    def test_state_variables_written_intact(self, graph_and_queries):
        graph, _ = graph_and_queries
        func_id = "StateTransitionTest::setCounter"
        if not graph.has_node(func_id):
            pytest.skip("setCounter not found")
        svw = graph.nodes[func_id].get("state_variables_written", [])
        assert any("counter" in v for v in svw)

    def test_find_state_mutators_query_works(self, graph_and_queries):
        _, queries = graph_and_queries
        mutators = queries.find_state_mutators("StateTransitionTest::counter")
        assert len(mutators) > 0, "counter should have at least one mutator"
