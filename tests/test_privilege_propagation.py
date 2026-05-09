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


def test_owner_overwrite_detection(graph_and_queries):
    graph, _ = graph_and_queries

    # 1. Check the owner variable node
    var_id = "PrivilegeEscalationTest::owner"
    assert graph.has_node(var_id)
    var_data = graph.nodes[var_id]
    assert var_data.get("privilege_escalation_risk") == True

    # 2. Check the setOwner function node
    func_id = "PrivilegeEscalationTest::setOwner"
    assert graph.has_node(func_id)
    func_data = graph.nodes[func_id]
    assert func_data.get("can_escalate_privileges") == True


def test_admin_poisoning_detection(graph_and_queries):
    graph, _ = graph_and_queries

    # 1. Check the admins variable node
    var_id = "PrivilegeEscalationTest::admins"
    assert graph.has_node(var_id)
    var_data = graph.nodes[var_id]
    assert var_data.get("privilege_escalation_risk") == True

    # 2. Check the addAdmin function node
    func_id = "PrivilegeEscalationTest::addAdmin"
    func_data = graph.nodes[func_id]
    assert func_data.get("can_escalate_privileges") == True


def test_boolean_guard_flip_detection(graph_and_queries):
    graph, _ = graph_and_queries

    # 1. Check the isInitialized variable node
    var_id = "PrivilegeEscalationTest::isInitialized"
    var_data = graph.nodes[var_id]
    assert var_data.get("privilege_escalation_risk") == True

    # 2. Check the resetInitialization function node
    func_id = "PrivilegeEscalationTest::resetInitialization"
    func_data = graph.nodes[func_id]
    assert func_data.get("can_escalate_privileges") == True


def test_safe_functions_not_flagged(graph_and_queries):
    graph, _ = graph_and_queries

    # updateData modifies 'data' which is NOT used in any access check
    func_id = "PrivilegeEscalationTest::updateData"
    func_data = graph.nodes[func_id]
    assert func_data.get("can_escalate_privileges", False) == False

    # setData is protected by onlyOwner
    func_id = "PrivilegeEscalationTest::setData"
    func_data = graph.nodes[func_id]
    assert func_data.get("can_escalate_privileges", False) == False


def test_query_privilege_escalation(graph_and_queries):
    _, queries = graph_and_queries
    risks = queries.get_privilege_escalation_risks(contract_name="PrivilegeEscalationTest")

    risky_funcs = [f["function_id"] for f in risks["risky_functions"]]
    assert "PrivilegeEscalationTest::setOwner" in risky_funcs
    assert "PrivilegeEscalationTest::addAdmin" in risky_funcs
    assert "PrivilegeEscalationTest::resetInitialization" in risky_funcs
    assert "PrivilegeEscalationTest::updateData" not in risky_funcs

    risky_vars = [v["variable_id"] for v in risks["risky_variables"]]
    assert "PrivilegeEscalationTest::owner" in risky_vars


if __name__ == "__main__":
    pytest.main([__file__])
