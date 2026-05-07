"""
Test Suite for Story 3.1 — Recursive Write Propagation

Verifies that state variable writes propagate correctly through
CALLS edges in the knowledge graph.
"""
import os
import sys

import pytest

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

from analysis_engine import AnalysisEngine
from src.graph import GraphBuilder


@pytest.fixture(scope="module")
def graph():
    """Build graph from all test contracts (including WritePropagationTest.sol)."""
    contract_path = os.path.join(os.getcwd(), 'tests', 'contracts')

    engine = AnalysisEngine()
    slither_obj = engine.run_analysis(contract_path)
    assert slither_obj is not None, "Slither analysis failed"

    builder = GraphBuilder()
    builder.build_graph(slither_obj)
    return builder.graph


# ─── Pattern 1: Simple Chain ─────────────────────────────
# entry() -> helper() -> writes counter
class TestSimpleChain:
    def test_entry_has_indirect_writes(self, graph):
        data = graph.nodes["WritePropagationTest::entry"]
        assert data["indirect_writes_state"] is True

    def test_entry_propagated_includes_counter(self, graph):
        data = graph.nodes["WritePropagationTest::entry"]
        assert "WritePropagationTest::counter" in data["propagated_state_variables"]

    def test_entry_does_not_directly_write(self, graph):
        data = graph.nodes["WritePropagationTest::entry"]
        assert data["writes_state"] is False

    def test_entry_propagation_depth(self, graph):
        data = graph.nodes["WritePropagationTest::entry"]
        assert data["propagation_depth"] == 1

    def test_helper_is_direct_writer(self, graph):
        data = graph.nodes["WritePropagationTest::helper"]
        assert data["writes_state"] is True
        assert data["indirect_writes_state"] is False


# ─── Pattern 2: Multi-Level Chain ────────────────────────
# top() -> mid() -> bottom() -> writes counter
class TestMultiLevel:
    def test_top_has_indirect_writes(self, graph):
        data = graph.nodes["WritePropagationTest::top"]
        assert data["indirect_writes_state"] is True

    def test_top_propagated_includes_counter(self, graph):
        data = graph.nodes["WritePropagationTest::top"]
        assert "WritePropagationTest::counter" in data["propagated_state_variables"]

    def test_top_propagation_depth(self, graph):
        data = graph.nodes["WritePropagationTest::top"]
        # mid doesn't write directly, bottom does -> depth should be 2
        # But mid CALLS bottom which writes, so mid.writes_state could be False
        # BFS finds first callee with writes_state=True
        # mid.writes_state is False (only indirect), bottom.writes_state is True
        # So BFS: depth 1 = mid (no direct writes) -> depth 2 = bottom (direct writes) -> depth=2
        assert data["propagation_depth"] == 2

    def test_mid_has_indirect_writes(self, graph):
        data = graph.nodes["WritePropagationTest::mid"]
        assert data["indirect_writes_state"] is True
        assert data["propagation_depth"] == 1


# ─── Pattern 3: Diamond ─────────────────────────────────
# diamond() -> branchA() -> leafWriter() -> writes balance
# diamond() -> branchB() -> leafWriter() -> writes balance
class TestDiamond:
    def test_diamond_has_indirect_writes(self, graph):
        data = graph.nodes["WritePropagationTest::diamond"]
        assert data["indirect_writes_state"] is True

    def test_diamond_propagated_includes_balance(self, graph):
        data = graph.nodes["WritePropagationTest::diamond"]
        assert "WritePropagationTest::balance" in data["propagated_state_variables"]

    def test_no_duplicate_in_propagated(self, graph):
        data = graph.nodes["WritePropagationTest::diamond"]
        # balance should appear only once even though two paths lead to it
        count = data["propagated_state_variables"].count("WritePropagationTest::balance")
        assert count == 1


# ─── Pattern 4: Cycle ───────────────────────────────────
# cycleA() -> cycleB() (both write state directly)
class TestCycle:
    def test_cycleA_terminates(self, graph):
        """The graph should build without infinite loops."""
        data = graph.nodes["WritePropagationTest::cycleA"]
        assert "propagated_state_variables" in data

    def test_cycleA_propagated_includes_both_vars(self, graph):
        data = graph.nodes["WritePropagationTest::cycleA"]
        # cycleA writes counter directly, cycleB writes balance
        assert "WritePropagationTest::counter" in data["propagated_state_variables"]
        assert "WritePropagationTest::balance" in data["propagated_state_variables"]


# ─── Pattern 5: Leaf / Direct Writer ────────────────────
# directWriter() writes counter directly, no calls
class TestDirectWriter:
    def test_direct_writer_not_indirect(self, graph):
        data = graph.nodes["WritePropagationTest::directWriter"]
        assert data["indirect_writes_state"] is False

    def test_direct_writer_propagated_equals_direct(self, graph):
        data = graph.nodes["WritePropagationTest::directWriter"]
        assert data["propagated_state_variables"] == data["state_variables_written"]

    def test_direct_writer_depth_zero(self, graph):
        data = graph.nodes["WritePropagationTest::directWriter"]
        assert data["propagation_depth"] == 0


# ─── Pattern 6: Mixed ───────────────────────────────────
# mixedWriter() writes balance directly AND calls helper() which writes counter
class TestMixed:
    def test_mixed_has_indirect_writes(self, graph):
        data = graph.nodes["WritePropagationTest::mixedWriter"]
        assert data["indirect_writes_state"] is True

    def test_mixed_propagated_includes_both(self, graph):
        data = graph.nodes["WritePropagationTest::mixedWriter"]
        assert "WritePropagationTest::balance" in data["propagated_state_variables"]
        assert "WritePropagationTest::counter" in data["propagated_state_variables"]

    def test_mixed_direct_writes_only_balance(self, graph):
        data = graph.nodes["WritePropagationTest::mixedWriter"]
        assert "WritePropagationTest::balance" in data["state_variables_written"]


# ─── Pattern 7: Pure Reader ─────────────────────────────
# pureReader() only reads, no writes
class TestPureReader:
    def test_pure_reader_no_propagated_writes(self, graph):
        data = graph.nodes["WritePropagationTest::pureReader"]
        assert data["propagated_state_variables"] == []
        assert data["indirect_writes_state"] is False
        assert data["propagation_depth"] == 0
