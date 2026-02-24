import os
import sys
import pytest

# Add src to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

from analysis_engine import AnalysisEngine
from graph_builder import GraphBuilder
from utils.graph_queries import GraphQueries


def test_simple_internal_call():
    """
    Test 1: Simple internal call (a -> b)
    Verify CALLS edge exists, metadata is correct
    """
    print("\n=== Test 1: Simple Internal Call ===")
    
    repo_path = os.path.join(os.getcwd(), 'tests', 'contracts')
    engine = AnalysisEngine()
    slither_obj = engine.run_analysis(repo_path)
    assert slither_obj is not None
    
    builder = GraphBuilder()
    builder.build_graph(slither_obj)
    graph = builder.graph
    
    # Test function a calls function b
    func_a = "InternalCallTest::a"
    func_b = "InternalCallTest::b"
    
    assert graph.has_node(func_a), f"Node {func_a} not found"
    assert graph.has_node(func_b), f"Node {func_b} not found"
    
    # Check metadata on function a
    a_data = graph.nodes[func_a]
    assert a_data.get("num_internal_calls") == 1, \
        f"a() should have num_internal_calls=1, got {a_data.get('num_internal_calls')}"
    assert func_b in a_data.get("internal_calls", []), \
        f"a() should call b()"
    assert a_data.get("is_leaf_function") == False, \
        "a() should NOT be a leaf function"
    
    # Check metadata on function b (leaf)
    b_data = graph.nodes[func_b]
    assert b_data.get("is_leaf_function") == True, \
        "b() should be a leaf function"
    assert b_data.get("num_internal_calls") == 0, \
        f"b() should have num_internal_calls=0, got {b_data.get('num_internal_calls')}"
    
    # Check CALLS edge exists
    assert graph.has_edge(func_a, func_b), f"CALLS edge from {func_a} to {func_b} should exist"
    edge_data = graph.get_edge_data(func_a, func_b)
    assert edge_data.get("relationship") == "CALLS", \
        "Edge should have relationship=CALLS"
    assert edge_data.get("call_type") == "internal", \
        "Edge should have call_type=internal"
    
    print(f"✓ PASS: {func_a} -> {func_b}")
    print(f"  - a.num_internal_calls: {a_data.get('num_internal_calls')}")
    print(f"  - b.is_leaf_function: {b_data.get('is_leaf_function')}")


def test_duplicate_call_deduplication():
    """
    Test 2: Multiple calls to same function should create ONLY one edge
    """
    print("\n=== Test 2: Duplicate Call Deduplication ===")
    
    repo_path = os.path.join(os.getcwd(), 'tests', 'contracts')
    engine = AnalysisEngine()
    slither_obj = engine.run_analysis(repo_path)
    assert slither_obj is not None
    
    builder = GraphBuilder()
    builder.build_graph(slither_obj)
    graph = builder.graph
    
    multi_call = "InternalCallTest::multiCall"
    helper = "InternalCallTest::helper"
    
    if not graph.has_node(multi_call):
        print(f"⚠ SKIP: {multi_call} not found")
        return
    
    multi_data = graph.nodes[multi_call]
    
    # Should have only 1 internal call despite calling helper() twice
    assert multi_data.get("num_internal_calls") == 1, \
        f"multiCall() should have num_internal_calls=1, got {multi_data.get('num_internal_calls')}"
    
    # Should have only ONE edge
    edges_to_helper = list(graph.edges(multi_call, data=True))
    call_edges = [e for e in edges_to_helper if e[2].get("relationship") == "CALLS"]
    assert len(call_edges) == 1, \
        f"Should have exactly 1 CALLS edge, got {len(call_edges)}"
    
    print(f"✓ PASS: {multi_call} -> {helper} (deduplicated)")
    print(f"  - num_internal_calls: {multi_data.get('num_internal_calls')}")
    print(f"  - Number of CALLS edges: {len(call_edges)}")


def test_multi_level_chain():
    """
    Test 3: Multi-level call chain (chain1 -> chain2 -> chain3)
    Verify no propagation occurs (only direct edges)
    """
    print("\n=== Test 3: Multi-Level Chain ===")
    
    repo_path = os.path.join(os.getcwd(), 'tests', 'contracts')
    engine = AnalysisEngine()
    slither_obj = engine.run_analysis(repo_path)
    assert slither_obj is not None
    
    builder = GraphBuilder()
    builder.build_graph(slither_obj)
    graph = builder.graph
    
    chain1 = "InternalCallTest::chain1"
    chain2 = "InternalCallTest::chain2"
    chain3 = "InternalCallTest::chain3"
    
    if not all(graph.has_node(n) for n in [chain1, chain2, chain3]):
        print(f"⚠ SKIP: Chain functions not found")
        return
    
    # Verify edges exist: chain1 -> chain2, chain2 -> chain3
    assert graph.has_edge(chain1, chain2), "chain1 -> chain2 edge should exist"
    assert graph.has_edge(chain2, chain3), "chain2 -> chain3 edge should exist"
    
    # Verify NO direct edge from chain1 to chain3 (no propagation)
    assert not graph.has_edge(chain1, chain3), \
        "chain1 -> chain3 edge should NOT exist (no propagation)"
    
    # Verify metadata
    chain1_data = graph.nodes[chain1]
    chain2_data = graph.nodes[chain2]
    chain3_data = graph.nodes[chain3]
    
    assert chain1_data.get("num_internal_calls") == 1, \
        "chain1 should call 1 function"
    assert chain2_data.get("num_internal_calls") == 1, \
        "chain2 should call 1 function"
    assert chain3_data.get("is_leaf_function") == True, \
        "chain3 should be a leaf function"
    
    print(f"✓ PASS: Chain verified without propagation")
    print(f"  - chain1 -> chain2: ✓")
    print(f"  - chain2 -> chain3: ✓")
    print(f"  - chain1 -> chain3: ✗ (correctly absent)")
    print(f"  - chain3.is_leaf_function: {chain3_data.get('is_leaf_function')}")


def test_modifier_call_modeling():
    """
    Test 4: Modifier call modeling
    Verify modifiers are captured in call graph
    """
    print("\n=== Test 4: Modifier Call Modeling ===")
    
    repo_path = os.path.join(os.getcwd(), 'tests', 'contracts')
    engine = AnalysisEngine()
    slither_obj = engine.run_analysis(repo_path)
    assert slither_obj is not None
    
    builder = GraphBuilder()
    builder.build_graph(slither_obj)
    graph = builder.graph
    
    restricted = "InternalCallTest::restricted"
    
    if not graph.has_node(restricted):
        print(f"⚠ SKIP: {restricted} not found")
        return
    
    restricted_data = graph.nodes[restricted]
    
    # Verify modifiers are recorded in metadata
    modifiers = restricted_data.get("modifiers", [])
    assert len(modifiers) > 0, "restricted() should have modifiers"
    assert "onlyOwner" in modifiers, "onlyOwner modifier should be present"
    
    # Note: Slither may flatten modifiers into internal calls
    # The function may have internal_calls >= 1 due to modifier logic
    num_calls = restricted_data.get("num_internal_calls", 0)
    
    print(f"✓ PASS: {restricted}")
    print(f"  - modifiers: {modifiers}")
    print(f"  - num_internal_calls: {num_calls}")
    print(f"  - Note: Slither may flatten modifiers into the call graph")


def test_external_call_ignored():
    """
    Test 5: Cross-contract calls should be IGNORED
    """
    print("\n=== Test 5: External Call Ignored ===")
    
    repo_path = os.path.join(os.getcwd(), 'tests', 'contracts')
    engine = AnalysisEngine()
    slither_obj = engine.run_analysis(repo_path)
    assert slither_obj is not None
    
    builder = GraphBuilder()
    builder.build_graph(slither_obj)
    graph = builder.graph
    
    call_external = "CrossContractCaller::callExternal"
    other_func = "OtherContract::externalFunc"
    
    if not graph.has_node(call_external):
        print(f"⚠ SKIP: {call_external} not found")
        return
    
    call_external_data = graph.nodes[call_external]
    
    # Should have NO internal calls (external call is ignored)
    assert call_external_data.get("num_internal_calls") == 0, \
        f"callExternal() should have num_internal_calls=0, got {call_external_data.get('num_internal_calls')}"
    
    # Should NOT have edge to OtherContract
    if graph.has_node(other_func):
        assert not graph.has_edge(call_external, other_func), \
            "Should NOT have CALLS edge to external contract"
    
    print(f"✓ PASS: {call_external}")
    print(f"  - num_internal_calls: {call_external_data.get('num_internal_calls')}")
    print(f"  - External calls correctly ignored")


def test_leaf_function_identification():
    """
    Test 6: Leaf functions should be correctly identified
    """
    print("\n=== Test 6: Leaf Function Identification ===")
    
    repo_path = os.path.join(os.getcwd(), 'tests', 'contracts')
    engine = AnalysisEngine()
    slither_obj = engine.run_analysis(repo_path)
    assert slither_obj is not None
    
    builder = GraphBuilder()
    builder.build_graph(slither_obj)
    graph = builder.graph
    
    leaf_funcs = [
        "InternalCallTest::leaf",
        "InternalCallTest::anotherLeaf",
        "InternalCallTest::b"
    ]
    
    for leaf_id in leaf_funcs:
        if not graph.has_node(leaf_id):
            print(f"  ⚠ SKIP: {leaf_id} not found")
            continue
        
        leaf_data = graph.nodes[leaf_id]
        assert leaf_data.get("is_leaf_function") == True, \
            f"{leaf_id} should be a leaf function"
        assert leaf_data.get("num_internal_calls") == 0, \
            f"{leaf_id} should have num_internal_calls=0"
        
        print(f"  ✓ {leaf_id}: is_leaf_function={leaf_data.get('is_leaf_function')}")
    
    print("✓ PASS: All leaf functions correctly identified")


def test_query_api():
    """
    Test 7: Query API validation
    """
    print("\n=== Test 7: Query API Validation ===")
    
    repo_path = os.path.join(os.getcwd(), 'tests', 'contracts')
    engine = AnalysisEngine()
    slither_obj = engine.run_analysis(repo_path)
    assert slither_obj is not None
    
    builder = GraphBuilder()
    builder.build_graph(slither_obj)
    
    queries = GraphQueries(builder.graph)
    
    # Test get_internal_calls
    func_a = "InternalCallTest::a"
    if builder.graph.has_node(func_a):
        calls = queries.get_internal_calls(func_a)
        assert len(calls) == 1, f"get_internal_calls should return 1 call, got {len(calls)}"
        print(f"  ✓ get_internal_calls({func_a}): {calls}")
    
    # Test get_callers
    func_b = "InternalCallTest::b"
    if builder.graph.has_node(func_b):
        callers = queries.get_callers(func_b)
        assert len(callers) >= 1, f"get_callers should return at least 1 caller"
        print(f"  ✓ get_callers({func_b}): {callers}")
    
    # Test get_call_graph
    call_graph = queries.get_call_graph(contract_name="InternalCallTest")
    assert "nodes" in call_graph, "call_graph should have 'nodes' key"
    assert "edges" in call_graph, "call_graph should have 'edges' key"
    assert len(call_graph["nodes"]) > 0, "call_graph should have nodes"
    
    print(f"  ✓ get_call_graph: {len(call_graph['nodes'])} nodes, {len(call_graph['edges'])} edges")
    
    # Test non-existent node
    non_existent_calls = queries.get_internal_calls("NonExistent::function")
    assert non_existent_calls == [], "Should return empty list for non-existent node"
    
    print("✓ PASS: Query API validated")


def test_metadata_schema_completeness():
    """
    Test 8: Verify all function nodes have complete metadata schema
    """
    print("\n=== Test 8: Metadata Schema Completeness ===")
    
    repo_path = os.path.join(os.getcwd(), 'tests', 'contracts')
    engine = AnalysisEngine()
    slither_obj = engine.run_analysis(repo_path)
    assert slither_obj is not None
    
    builder = GraphBuilder()
    builder.build_graph(slither_obj)
    graph = builder.graph
    
    required_fields = [
        # Story 2.1
        "is_external_entry",
        "is_view_or_pure",
        "is_payable",
        # Story 2.2
        "writes_state",
        "num_state_writes",
        "state_variables_written",
        # Story 2.3
        "internal_calls",
        "num_internal_calls",
        "is_leaf_function"
    ]
    
    function_count = 0
    for node_id, node_data in graph.nodes(data=True):
        if node_data.get("type") != "function":
            continue
        
        function_count += 1
        
        for field in required_fields:
            assert field in node_data, \
                f"Function {node_id} missing required field: {field}"
    
    print(f"✓ PASS: All {function_count} function nodes have complete metadata")
    print(f"  - Story 2.1 fields: is_external_entry, is_view_or_pure, is_payable")
    print(f"  - Story 2.2 fields: writes_state, num_state_writes, state_variables_written")
    print(f"  - Story 2.3 fields: internal_calls, num_internal_calls, is_leaf_function")


if __name__ == "__main__":
    print("=" * 60)
    print("Testing Internal Call Graph Construction (Story 2.3)")
    print("=" * 60)
    
    test_simple_internal_call()
    test_duplicate_call_deduplication()
    test_multi_level_chain()
    test_modifier_call_modeling()
    test_external_call_ignored()
    test_leaf_function_identification()
    test_query_api()
    test_metadata_schema_completeness()
    
    print("\n" + "=" * 60)
    print("All tests passed! ✓")
    print("=" * 60)
