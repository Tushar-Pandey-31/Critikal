"""
Test Suite for Story 3.3 — Reachability from External Entry

Verifies that BFS from external entries correctly marks reachable functions
and leaves dead code unmarked.
"""
import os
import sys

import pytest

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

from analysis_engine import AnalysisEngine
from src.graph import GraphBuilder


@pytest.fixture(scope="module")
def graph():
    """Build graph from all test contracts."""
    contract_path = os.path.join(os.getcwd(), 'tests', 'contracts')

    engine = AnalysisEngine()
    slither_obj = engine.run_analysis(contract_path)
    assert slither_obj is not None, "Slither analysis failed"

    builder = GraphBuilder()
    builder.build_graph(slither_obj)
    return builder.graph


# ─── Pattern 1: Direct External Entry (depth 0) ─────────
class TestDirectExternal:
    def test_deposit_is_reachable(self, graph):
        data = graph.nodes["ReachabilityTest::deposit"]
        assert data["reachable_from_external_entry"] is True

    def test_deposit_entry_is_self(self, graph):
        data = graph.nodes["ReachabilityTest::deposit"]
        assert "ReachabilityTest::deposit" in data["entry_points"]


# ─── Pattern 2: One-Hop Reachability (depth 1) ──────────
class TestOneHop:
    def test_internalA_is_reachable(self, graph):
        data = graph.nodes["ReachabilityTest::internalA"]
        assert data["reachable_from_external_entry"] is True

    def test_internalA_reached_from_externalCaller(self, graph):
        data = graph.nodes["ReachabilityTest::internalA"]
        assert "ReachabilityTest::externalCaller" in data["entry_points"]


# ─── Pattern 3: Multi-Hop Reachability (depth 2) ────────
class TestMultiHop:
    def test_deepHelper_is_reachable(self, graph):
        data = graph.nodes["ReachabilityTest::deepHelper"]
        assert data["reachable_from_external_entry"] is True


# ─── Pattern 4: Multiple External Callers ────────────────
class TestMultipleCallers:
    def test_leafHelper_reachable(self, graph):
        data = graph.nodes["ReachabilityTest::leafHelper"]
        assert data["reachable_from_external_entry"] is True

    def test_leafHelper_multiple_entries(self, graph):
        data = graph.nodes["ReachabilityTest::leafHelper"]
        entries = data["entry_points"]
        # leafHelper is called from multiCaller and externalCaller2
        assert "ReachabilityTest::multiCaller" in entries
        assert "ReachabilityTest::externalCaller2" in entries

    def test_internalA_reached_from_multiple(self, graph):
        data = graph.nodes["ReachabilityTest::internalA"]
        entries = data["entry_points"]
        # internalA is called from externalCaller and externalCaller2
        assert "ReachabilityTest::externalCaller" in entries
        assert "ReachabilityTest::externalCaller2" in entries


# ─── Pattern 5: Dead Code (Unreachable) ──────────────────
class TestDeadCode:
    def test_unusedInternal_not_reachable(self, graph):
        data = graph.nodes["ReachabilityTest::_unusedInternal"]
        assert data["reachable_from_external_entry"] is False

    def test_unusedInternal_no_entry_points(self, graph):
        data = graph.nodes["ReachabilityTest::_unusedInternal"]
        assert data["entry_points"] == []

    def test_alsoUnused_not_reachable(self, graph):
        data = graph.nodes["ReachabilityTest::_alsoUnused"]
        assert data["reachable_from_external_entry"] is False


# ─── Pattern 6: Receive/Fallback ─────────────────────────
class TestReceiveFallback:
    def test_receive_is_reachable(self, graph):
        # Slither names receive as "receive()" or similar
        receive_nodes = [
            nid for nid, d in graph.nodes(data=True)
            if d.get("contract") == "ReachabilityTest" and d.get("is_receive", False)
        ]
        assert len(receive_nodes) > 0, "receive() not found in graph"
        data = graph.nodes[receive_nodes[0]]
        assert data["reachable_from_external_entry"] is True

    def test_fallback_is_reachable(self, graph):
        fallback_nodes = [
            nid for nid, d in graph.nodes(data=True)
            if d.get("contract") == "ReachabilityTest" and d.get("is_fallback", False)
        ]
        assert len(fallback_nodes) > 0, "fallback() not found in graph"
        data = graph.nodes[fallback_nodes[0]]
        assert data["reachable_from_external_entry"] is True
