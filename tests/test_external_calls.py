import os
import sys
import pytest

# Add src to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

from analysis_engine import AnalysisEngine
from graph_builder import GraphBuilder
from utils.graph_queries import GraphQueries


# ================================================================
# Shared fixture: build graph once for all tests
# ================================================================
@pytest.fixture(scope="module")
def graph_and_queries():
    """Builds the graph once and shares it across all tests in this module."""
    repo_path = os.path.join(os.getcwd(), 'tests', 'contracts')
    engine = AnalysisEngine()
    slither_obj = engine.run_analysis(repo_path)
    assert slither_obj is not None, "Analysis failed, cannot run external call tests"

    builder = GraphBuilder()
    builder.build_graph(slither_obj)
    queries = GraphQueries(builder.graph)
    return builder.graph, queries


# ================================================================
# Test 1: lowLevelCall() — addr.call{value:}("") with state write after
# ================================================================
def test_low_level_call(graph_and_queries):
    graph, _ = graph_and_queries
    node_id = "ExternalCallTest::lowLevelCall"
    assert graph.has_node(node_id), f"Node {node_id} not found"

    data = graph.nodes[node_id]
    assert data.get("makes_external_call") == True, \
        "lowLevelCall() should make external call"
    assert "call" in data.get("external_call_type", []), \
        f"lowLevelCall() should have 'call' type, got {data.get('external_call_type')}"
    assert data.get("state_write_after_external_call") == True, \
        "lowLevelCall() writes state AFTER external call"

    print(f"✓ PASS: {node_id}")
    print(f"  - external_call_type: {data.get('external_call_type')}")
    print(f"  - state_write_after_external_call: {data.get('state_write_after_external_call')}")


# ================================================================
# Test 2: sendEther() — addr.send() with state write after
# ================================================================
def test_send_ether(graph_and_queries):
    graph, _ = graph_and_queries
    node_id = "ExternalCallTest::sendEther"
    assert graph.has_node(node_id), f"Node {node_id} not found"

    data = graph.nodes[node_id]
    assert data.get("makes_external_call") == True, \
        "sendEther() should make external call"
    assert "send" in data.get("external_call_type", []), \
        f"sendEther() should have 'send' type, got {data.get('external_call_type')}"
    assert data.get("state_write_after_external_call") == True, \
        "sendEther() writes state AFTER external call"

    print(f"✓ PASS: {node_id}")
    print(f"  - external_call_type: {data.get('external_call_type')}")


# ================================================================
# Test 3: transferEther() — addr.transfer() with NO state write after
# ================================================================
def test_transfer_ether(graph_and_queries):
    graph, _ = graph_and_queries
    node_id = "ExternalCallTest::transferEther"
    assert graph.has_node(node_id), f"Node {node_id} not found"

    data = graph.nodes[node_id]
    assert data.get("makes_external_call") == True, \
        "transferEther() should make external call"
    assert "transfer" in data.get("external_call_type", []), \
        f"transferEther() should have 'transfer' type, got {data.get('external_call_type')}"
    assert data.get("state_write_after_external_call") == False, \
        "transferEther() has NO state write after external call"

    print(f"✓ PASS: {node_id}")
    print(f"  - external_call_type: {data.get('external_call_type')}")
    print(f"  - state_write_after_external_call: {data.get('state_write_after_external_call')}")


# ================================================================
# Test 4: delegateCall() — addr.delegatecall("")
# ================================================================
def test_delegate_call(graph_and_queries):
    graph, _ = graph_and_queries
    node_id = "ExternalCallTest::delegateCall"
    assert graph.has_node(node_id), f"Node {node_id} not found"

    data = graph.nodes[node_id]
    assert data.get("makes_external_call") == True, \
        "delegateCall() should make external call"
    assert "delegatecall" in data.get("external_call_type", []), \
        f"delegateCall() should have 'delegatecall' type, got {data.get('external_call_type')}"

    print(f"✓ PASS: {node_id}")
    print(f"  - external_call_type: {data.get('external_call_type')}")


# ================================================================
# Test 5: highLevelCall() — token.transfer() (interface call)
# ================================================================
def test_high_level_call(graph_and_queries):
    graph, _ = graph_and_queries
    node_id = "ExternalCallTest::highLevelCall"
    assert graph.has_node(node_id), f"Node {node_id} not found"

    data = graph.nodes[node_id]
    assert data.get("makes_external_call") == True, \
        "highLevelCall() should make external call"
    assert "interface" in data.get("external_call_type", []), \
        f"highLevelCall() should have 'interface' type, got {data.get('external_call_type')}"
    assert data.get("state_write_after_external_call") == True, \
        "highLevelCall() writes state AFTER external call"

    print(f"✓ PASS: {node_id}")
    print(f"  - external_call_type: {data.get('external_call_type')}")
    print(f"  - state_write_after_external_call: {data.get('state_write_after_external_call')}")


# ================================================================
# Test 6: noExternalCall() — pure internal logic, NO external call
# ================================================================
def test_no_external_call(graph_and_queries):
    graph, _ = graph_and_queries
    node_id = "ExternalCallTest::noExternalCall"
    assert graph.has_node(node_id), f"Node {node_id} not found"

    data = graph.nodes[node_id]
    assert data.get("makes_external_call") == False, \
        "noExternalCall() should NOT make external call"
    assert len(data.get("external_call_type", [])) == 0, \
        "noExternalCall() should have empty external_call_type"
    assert data.get("state_write_after_external_call") == False, \
        "noExternalCall() should not flag state_write_after_external_call"

    print(f"✓ PASS: {node_id}")
    print(f"  - makes_external_call: {data.get('makes_external_call')}")


# ================================================================
# Test 7: multipleExternalCalls() — multiple different call types
# ================================================================
def test_multiple_external_calls(graph_and_queries):
    graph, _ = graph_and_queries
    node_id = "ExternalCallTest::multipleExternalCalls"
    assert graph.has_node(node_id), f"Node {node_id} not found"

    data = graph.nodes[node_id]
    assert data.get("makes_external_call") == True, \
        "multipleExternalCalls() should make external calls"
    
    call_types = data.get("external_call_type", [])
    assert len(call_types) >= 2, \
        f"multipleExternalCalls() should have >= 2 call types, got {call_types}"
    
    call_nodes = data.get("external_call_nodes", [])
    assert len(call_nodes) >= 2, \
        f"multipleExternalCalls() should have >= 2 call descriptions, got {len(call_nodes)}"

    print(f"✓ PASS: {node_id}")
    print(f"  - external_call_type: {call_types}")
    print(f"  - external_call_nodes count: {len(call_nodes)}")


# ================================================================
# Test 8: callThenWrite() — CEI violation: external call THEN state write
# ================================================================
def test_call_then_write(graph_and_queries):
    graph, _ = graph_and_queries
    node_id = "ExternalCallTest::callThenWrite"
    assert graph.has_node(node_id), f"Node {node_id} not found"

    data = graph.nodes[node_id]
    assert data.get("makes_external_call") == True, \
        "callThenWrite() should make external call"
    assert data.get("state_write_after_external_call") == True, \
        "callThenWrite() should flag state_write_after_external_call (CEI violation)"

    print(f"✓ PASS: {node_id}")
    print(f"  - state_write_after_external_call: {data.get('state_write_after_external_call')}")


# ================================================================
# Test 9: writeThenCall() — Safe CEI: state write BEFORE external call
# ================================================================
def test_write_then_call(graph_and_queries):
    graph, _ = graph_and_queries
    node_id = "ExternalCallTest::writeThenCall"
    assert graph.has_node(node_id), f"Node {node_id} not found"

    data = graph.nodes[node_id]
    assert data.get("makes_external_call") == True, \
        "writeThenCall() should make external call"
    assert data.get("state_write_after_external_call") == False, \
        "writeThenCall() should NOT flag state_write_after_external_call (safe CEI)"

    print(f"✓ PASS: {node_id}")
    print(f"  - state_write_after_external_call: {data.get('state_write_after_external_call')}")


# ================================================================
# Critical Edge Case 1: Multiple Writes and Calls
# ================================================================
def test_multiple_writes_and_calls(graph_and_queries):
    graph, _ = graph_and_queries
    node_id = "ExternalCallTest::multipleWritesAndCalls"
    assert graph.has_node(node_id), f"Node {node_id} not found"

    data = graph.nodes[node_id]
    assert data.get("makes_external_call") == True, \
        "multipleWritesAndCalls() should make external call"
    
    # Should be flagged as unsafe because of the second write AFTER the call
    assert data.get("state_write_after_external_call") == True, \
        "multipleWritesAndCalls() should flag state_write_after_external_call (second write is after call)"

    print(f"✓ PASS: {node_id}")
    print(f"  - state_write_after_external_call: {data.get('state_write_after_external_call')}")


# ================================================================
# Critical Edge Case 2: Write in Callee (Indirect Write)
# ================================================================
def test_write_in_callee(graph_and_queries):
    graph, _ = graph_and_queries
    node_id = "ExternalCallTest::writeInCallee"
    assert graph.has_node(node_id), f"Node {node_id} not found"

    data = graph.nodes[node_id]
    assert data.get("makes_external_call") == True, \
        "writeInCallee() should make external call"
    
    # Should be flagged as unsafe because call happens before indirect write in _updateBalance
    assert data.get("state_write_after_external_call") == True, \
        "writeInCallee() should flag state_write_after_external_call (indirect write via internal call)"

    print(f"✓ PASS: {node_id}")
    print(f"  - state_write_after_external_call: {data.get('state_write_after_external_call')}")


# ================================================================
# Critical Edge Case 3: External Call Inside Modifier
# ================================================================
def test_modifier_call_write(graph_and_queries):
    graph, _ = graph_and_queries
    node_id = "ExternalCallTest::modifierCallWrite"
    assert graph.has_node(node_id), f"Node {node_id} not found"

    data = graph.nodes[node_id]
    # Modifier makes external call, function body writes state -> Violation
    assert data.get("makes_external_call") == True, \
        "modifierCallWrite() should make external call (via modifier)"
    
    assert data.get("state_write_after_external_call") == True, \
        "modifierCallWrite() should flag state_write_after_external_call (modifier call before body write)"

    print(f"✓ PASS: {node_id}")
    print(f"  - state_write_after_external_call: {data.get('state_write_after_external_call')}")


# ================================================================
# Critical Edge Case 4: Conditional Write
# ================================================================
def test_conditional_write(graph_and_queries):
    graph, _ = graph_and_queries
    node_id = "ExternalCallTest::conditionalWrite"
    assert graph.has_node(node_id), f"Node {node_id} not found"

    data = graph.nodes[node_id]
    assert data.get("makes_external_call") == True, \
        "conditionalWrite() should make external call"
    
    # Write inside if block is structurally after the call -> Violation
    assert data.get("state_write_after_external_call") == True, \
        "conditionalWrite() should flag state_write_after_external_call (conditional write)"

    print(f"✓ PASS: {node_id}")
    print(f"  - state_write_after_external_call: {data.get('state_write_after_external_call')}")


# ================================================================
# Critical Edge Case 5: Safe Pull Pattern
# ================================================================
def test_safe_pull(graph_and_queries):
    graph, _ = graph_and_queries
    node_id = "ExternalCallTest::safePull"
    assert graph.has_node(node_id), f"Node {node_id} not found"

    data = graph.nodes[node_id]
    assert data.get("makes_external_call") == True, \
        "safePull() should make external call"
    
    # Write happens before call -> Safe
    assert data.get("state_write_after_external_call") == False, \
        "safePull() should NOT flag state_write_after_external_call (safe check-effect-interaction)"

    print(f"✓ PASS: {node_id}")
    print(f"  - state_write_after_external_call: {data.get('state_write_after_external_call')}")


# ================================================================
# Critical Edge Case 6: External Call With No State Mutation
# ================================================================
def test_external_call_no_mutation(graph_and_queries):
    graph, _ = graph_and_queries
    node_id = "ExternalCallTest::externalCallNoMutation"
    assert graph.has_node(node_id), f"Node {node_id} not found"

    data = graph.nodes[node_id]
    assert data.get("makes_external_call") == True, \
        "externalCallNoMutation() should make external call"
    
    # No state writes anywhere -> Safe
    assert data.get("state_write_after_external_call") == False, \
        "externalCallNoMutation() should NOT flag state_write_after_external_call (no mutation)"

    print(f"✓ PASS: {node_id}")

# ================================================================
# NEW: Modifier Stacking & Order Cases
# ================================================================

def test_body_write_modifier_post_call(graph_and_queries):
    graph, _ = graph_and_queries
    node_id = "ExternalCallTest::bodyWriteModifierPostCall"
    assert graph.has_node(node_id), f"Node {node_id} not found"

    data = graph.nodes[node_id]
    # Write in body (Phase 1), Call in modifier POST (Phase 2)
    # This is SAFE because write happens BEFORE call starts
    assert data.get("state_write_after_external_call") == False, \
        "bodyWriteModifierPostCall() should NOT flag violation (call happens AFTER body write)"

    print(f"✓ PASS: {node_id}")


def test_modifier_internal_write_safe(graph_and_queries):
    graph, _ = graph_and_queries
    node_id = "ExternalCallTest::modifierInternalWriteSafe"
    assert graph.has_node(node_id), f"Node {node_id} not found"

    data = graph.nodes[node_id]
    # Write then Call in same modifier (Phase 0) -> Safe
    assert data.get("state_write_after_external_call") == False, \
        "modifierInternalWriteSafe() should NOT flag violation (write before call in same mod)"

    print(f"✓ PASS: {node_id}")


def test_modifier_internal_write_violation(graph_and_queries):
    graph, _ = graph_and_queries
    node_id = "ExternalCallTest::modifierInternalWriteViolation"
    assert graph.has_node(node_id), f"Node {node_id} not found"

    data = graph.nodes[node_id]
    # Call then Write in same modifier (Phase 0) -> Violation
    assert data.get("state_write_after_external_call") == True, \
        "modifierInternalWriteViolation() should flag violation (call before write in same mod)"

    print(f"✓ PASS: {node_id}")


def test_multiple_modifiers_stacking(graph_and_queries):
    graph, _ = graph_and_queries
    node_id = "ExternalCallTest::multipleModifiersStacking"
    assert graph.has_node(node_id), f"Node {node_id} not found"

    data = graph.nodes[node_id]
    # Execution: A-pre(call) -> Body -> B-post(write) -> Violation
    assert data.get("state_write_after_external_call") == True, \
        "multipleModifiersStacking() should flag violation (call in A-pre before write in B-post)"

    print(f"✓ PASS: {node_id}")


# ================================================================
# Test 10: All function nodes have external call metadata fields
# ================================================================
def test_all_functions_have_metadata(graph_and_queries):
    graph, _ = graph_and_queries

    required_fields = [
        "makes_external_call",
        "external_call_nodes",
        "external_call_type",
        "state_write_after_external_call"
    ]

    for node_id, node_data in graph.nodes(data=True):
        if node_data.get("type") != "function":
            continue
        for field in required_fields:
            assert field in node_data, \
                f"Function {node_id} missing field: {field}"

    print("✓ PASS: All function nodes have external call metadata fields")


# ================================================================
# Test 11: Query API — get_external_call_functions()
# ================================================================
def test_query_external_call_functions(graph_and_queries):
    _, queries = graph_and_queries

    # All external call functions
    results = queries.get_external_call_functions()
    assert len(results) > 0, "Should find at least one external call function"

    result_ids = [r["function_id"] for r in results]
    assert "ExternalCallTest::lowLevelCall" in result_ids, \
        "lowLevelCall should be in external call functions"
    assert "ExternalCallTest::noExternalCall" not in result_ids, \
        "noExternalCall should NOT be in external call functions"

    # Filter by contract
    filtered = queries.get_external_call_functions(contract_name="ExternalCallTest")
    for r in filtered:
        assert r["contract"] == "ExternalCallTest", \
            f"Filtered result {r['function_id']} should be from ExternalCallTest"

    # Non-existent contract
    empty = queries.get_external_call_functions(contract_name="NonExistent")
    assert len(empty) == 0, "Non-existent contract should return empty"

    # Verify required fields
    required_fields = [
        "function_id", "name", "contract", "external_call_type",
        "external_call_nodes", "state_write_after_external_call"
    ]
    for r in results:
        for field in required_fields:
            assert field in r, f"Query result missing field: {field}"

    print(f"✓ PASS: Query API returns {len(results)} external call functions")
    print(f"  - Filtered to ExternalCallTest: {len(filtered)} results")


# ================================================================
# Run tests standalone
# ================================================================
if __name__ == "__main__":
    print("=" * 60)
    print("Testing External Call Classification (Story 3.2)")
    print("=" * 60)

    # Build graph once
    repo_path = os.path.join(os.getcwd(), 'tests', 'contracts')
    engine = AnalysisEngine()
    slither_obj = engine.run_analysis(repo_path)
    assert slither_obj is not None, "Analysis failed"

    builder = GraphBuilder()
    builder.build_graph(slither_obj)
    queries = GraphQueries(builder.graph)
    fixture = (builder.graph, queries)

    tests = [
        test_low_level_call,
        test_send_ether,
        test_transfer_ether,
        test_delegate_call,
        test_high_level_call,
        test_no_external_call,
        test_multiple_external_calls,
        test_call_then_write,
        test_write_then_call,
        test_multiple_writes_and_calls,
        test_write_in_callee,
        test_modifier_call_write,
        test_conditional_write,
        test_safe_pull,
        test_external_call_no_mutation,
        test_body_write_modifier_post_call,
        test_modifier_internal_write_safe,
        test_modifier_internal_write_violation,
        test_multiple_modifiers_stacking,
        test_all_functions_have_metadata,
        test_query_external_call_functions,
    ]

    passed = 0
    failed = 0
    for test in tests:
        try:
            print(f"\n--- {test.__name__} ---")
            test(fixture)
            passed += 1
        except Exception as e:
            print(f"✗ FAIL: {test.__name__}: {e}")
            failed += 1

    print(f"\n{'=' * 60}")
    print(f"Results: {passed} passed, {failed} failed out of {len(tests)}")
    print("=" * 60)
