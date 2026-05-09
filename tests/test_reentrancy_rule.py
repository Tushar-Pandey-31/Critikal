import os
import sys

import pytest

# Add src to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

from analysis_engine import AnalysisEngine
from src.graph import GraphBuilder
from utils.graph_queries import GraphQueries


@pytest.fixture(scope="module")
def graph_and_queries():
    """Builds the graph once and shares it across all tests in this module."""
    repo_path = os.path.join(os.getcwd(), "tests", "contracts")
    engine = AnalysisEngine()
    slither_obj = engine.run_analysis(repo_path)
    assert slither_obj is not None, "Analysis failed"

    builder = GraphBuilder()
    builder.build_graph(slither_obj)
    queries = GraphQueries(builder.graph)
    return builder.graph, queries


def test_reentrancy_risk_low_level_call(graph_and_queries):
    graph, _ = graph_and_queries
    node_id = "ExternalCallTest::lowLevelCall"
    data = graph.nodes[node_id]

    # This should be a risk: external entry, makes call, writes state, CEI violation
    assert data.get("reentrancy_risk") == True
    assert data.get("reentrancy_risk_score") >= 10


def test_reentrancy_risk_safe_pull(graph_and_queries):
    graph, _ = graph_and_queries
    node_id = "ExternalCallTest::safePull"
    data = graph.nodes[node_id]

    # This should NOT be a risk: safe CEI
    assert data.get("reentrancy_risk") == False
    assert data.get("reentrancy_risk_score") == 0


def test_reentrancy_risk_no_mutation(graph_and_queries):
    graph, _ = graph_and_queries
    node_id = "ExternalCallTest::externalCallNoMutation"
    data = graph.nodes[node_id]

    # This should NOT be a risk: no mutation
    assert data.get("reentrancy_risk") == False
    assert data.get("reentrancy_risk_score") == 0


def test_reentrancy_risk_internal_function(graph_and_queries):
    graph, _ = graph_and_queries
    # Find an internal function that might have CEI violation but isn't reachable from external entry
    # (If one exists in ExternalCallTest.sol)
    node_id = "ExternalCallTest::_updateBalance"
    if graph.has_node(node_id):
        data = graph.nodes[node_id]
        # It's private/internal, so reachable_from_external_entry depends on callers.
        # But _updateBalance itself doesn't make external calls.
        assert data.get("reentrancy_risk") == False


# ================================================================
# Story 1.3: transfer/send/staticcall NOT flagged as reentrancy
# ================================================================
def test_reentrancy_transfer_not_flagged(graph_and_queries):
    graph, _ = graph_and_queries
    node_id = "ExternalCallTest::transferThenWrite"
    if graph.has_node(node_id):
        data = graph.nodes[node_id]
        assert data.get("reentrancy_risk") is False, "transfer (2300 gas) should NOT trigger reentrancy"
        assert data.get("reentrancy_risk_score") == 0


def test_reentrancy_send_not_flagged(graph_and_queries):
    graph, _ = graph_and_queries
    node_id = "ExternalCallTest::sendThenWrite"
    if graph.has_node(node_id):
        data = graph.nodes[node_id]
        assert data.get("reentrancy_risk") is False, "send (2300 gas) should NOT trigger reentrancy"
        assert data.get("reentrancy_risk_score") == 0


def test_reentrancy_staticcall_not_flagged(graph_and_queries):
    graph, _ = graph_and_queries
    node_id = "ExternalCallTest::viewCallThenWrite"
    if graph.has_node(node_id):
        data = graph.nodes[node_id]
        assert data.get("reentrancy_risk") is False, "staticcall (view function) should NOT trigger reentrancy"
        assert data.get("reentrancy_risk_score") == 0


def test_reentrancy_send_ether_not_flagged(graph_and_queries):
    """sendEther() uses send (2300 gas) + state write → NOT reentrancy."""
    graph, _ = graph_and_queries
    node_id = "ExternalCallTest::sendEther"
    data = graph.nodes[node_id]
    assert data.get("reentrancy_risk") is False, "sendEther (send with 2300 gas) should NOT trigger reentrancy"


def test_cei_violation_only_for_transfer(graph_and_queries):
    """transferThenWrite should be flagged as CEI violation only, not reentrancy."""
    graph, queries = graph_and_queries
    node_id = "ExternalCallTest::transferThenWrite"
    if graph.has_node(node_id):
        data = graph.nodes[node_id]
        assert data.get("cei_violation_only") is True, "transferThenWrite should be cei_violation_only"

        cei_results = queries.get_cei_violations(contract_name="ExternalCallTest")
        cei_ids = [r["function_id"] for r in cei_results]
        assert node_id in cei_ids, "transferThenWrite should appear in get_cei_violations()"


def test_query_reentrancy_risks(graph_and_queries):
    _, queries = graph_and_queries
    risks = queries.get_reentrancy_risks(contract_name="ExternalCallTest")

    risk_ids = [r["function_id"] for r in risks]
    assert "ExternalCallTest::lowLevelCall" in risk_ids
    assert "ExternalCallTest::callThenWrite" in risk_ids
    assert "ExternalCallTest::safePull" not in risk_ids

    # Story 1.3: transfer/send/staticcall should NOT appear
    assert "ExternalCallTest::transferThenWrite" not in risk_ids
    assert "ExternalCallTest::sendThenWrite" not in risk_ids
    assert "ExternalCallTest::sendEther" not in risk_ids
    assert "ExternalCallTest::viewCallThenWrite" not in risk_ids

    for r in risks:
        assert r["reentrancy_risk_score"] >= 10
        assert len(r["propagated_state_variables"]) > 0


if __name__ == "__main__":
    pytest.main([__file__])
