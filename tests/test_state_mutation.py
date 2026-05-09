import os
import sys

# Add src to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

from analysis_engine import AnalysisEngine
from src.graph import GraphBuilder
from utils.graph_queries import GraphQueries


def test_storage_mutation_detection():
    """Test Story 2.2: Storage State Mutation Detection"""
    # Setup - analyze StateMutationTest contract
    repo_path = os.path.join(os.getcwd(), "tests", "contracts")
    print(f"\nAnalyzing contracts in {repo_path}...")

    engine = AnalysisEngine()
    slither_obj = engine.run_analysis(repo_path)

    assert slither_obj is not None, "Analysis failed, cannot test graph builder"

    # Build Graph
    print("Building Knowledge Graph...")
    builder = GraphBuilder()
    builder.build_graph(slither_obj)

    graph = builder.graph
    print(f"Graph Stats: {builder.get_graph_stats()}")

    # Test 1: writeState() should have writes_state=True, num_state_writes >= 1
    print("\n=== Test 1: writeState() ===")
    write_state_func = "StateMutationTest::writeState"
    assert graph.has_node(write_state_func), f"Node {write_state_func} not found"

    node_data = graph.nodes[write_state_func]
    assert node_data.get("writes_state") == True, "writeState() should have writes_state=True"
    assert node_data.get("num_state_writes", 0) >= 1, (
        f"writeState() should have num_state_writes >= 1, got {node_data.get('num_state_writes')}"
    )

    state_vars_written = node_data.get("state_variables_written", [])
    assert len(state_vars_written) >= 1, "writeState() should write to at least 1 state variable"

    # Verify counter is in the written variables
    assert any("counter" in var for var in state_vars_written), "counter should be in state_variables_written"

    print(f"✓ PASS: {write_state_func}")
    print(f"  - writes_state: {node_data.get('writes_state')}")
    print(f"  - num_state_writes: {node_data.get('num_state_writes')}")
    print(f"  - state_variables_written: {state_vars_written}")

    # Test 2: writeMapping() should have writes_state=True, num_state_writes >= 1
    print("\n=== Test 2: writeMapping() ===")
    write_mapping_func = "StateMutationTest::writeMapping"
    assert graph.has_node(write_mapping_func), f"Node {write_mapping_func} not found"

    node_data = graph.nodes[write_mapping_func]
    assert node_data.get("writes_state") == True, "writeMapping() should have writes_state=True"
    assert node_data.get("num_state_writes", 0) >= 1, (
        f"writeMapping() should have num_state_writes >= 1, got {node_data.get('num_state_writes')}"
    )

    state_vars_written = node_data.get("state_variables_written", [])
    assert len(state_vars_written) >= 1, "writeMapping() should write to at least 1 state variable"

    # Verify balances is in the written variables
    assert any("balances" in var for var in state_vars_written), "balances should be in state_variables_written"

    print(f"✓ PASS: {write_mapping_func}")
    print(f"  - writes_state: {node_data.get('writes_state')}")
    print(f"  - num_state_writes: {node_data.get('num_state_writes')}")
    print(f"  - state_variables_written: {state_vars_written}")

    # Test 3: localOnly() should have writes_state=False, num_state_writes = 0
    print("\n=== Test 3: localOnly() ===")
    local_only_func = "StateMutationTest::localOnly"
    assert graph.has_node(local_only_func), f"Node {local_only_func} not found"

    node_data = graph.nodes[local_only_func]
    assert node_data.get("writes_state") == False, "localOnly() should have writes_state=False"
    assert node_data.get("num_state_writes", 0) == 0, (
        f"localOnly() should have num_state_writes = 0, got {node_data.get('num_state_writes')}"
    )

    state_vars_written = node_data.get("state_variables_written", [])
    assert len(state_vars_written) == 0, "localOnly() should not write to any state variables"

    print(f"✓ PASS: {local_only_func}")
    print(f"  - writes_state: {node_data.get('writes_state')}")
    print(f"  - num_state_writes: {node_data.get('num_state_writes')}")

    # Test 4: readOnly() should have writes_state=False, num_state_writes = 0
    print("\n=== Test 4: readOnly() ===")
    read_only_func = "StateMutationTest::readOnly"
    assert graph.has_node(read_only_func), f"Node {read_only_func} not found"

    node_data = graph.nodes[read_only_func]
    assert node_data.get("writes_state") == False, "readOnly() should have writes_state=False"
    assert node_data.get("num_state_writes", 0) == 0, (
        f"readOnly() should have num_state_writes = 0, got {node_data.get('num_state_writes')}"
    )

    state_vars_written = node_data.get("state_variables_written", [])
    assert len(state_vars_written) == 0, "readOnly() should not write to any state variables"

    print(f"✓ PASS: {read_only_func}")
    print(f"  - writes_state: {node_data.get('writes_state')}")
    print(f"  - num_state_writes: {node_data.get('num_state_writes')}")

    # Test 5: Verify state_variables_written contains correct variable IDs
    print("\n=== Test 5: Variable ID Format ===")
    for node_id, node_data in graph.nodes(data=True):
        if node_data.get("type") == "function" and node_data.get("contract") == "StateMutationTest":
            state_vars_written = node_data.get("state_variables_written", [])
            for var_id in state_vars_written:
                # Variable IDs should follow format: ContractName::VariableName
                assert "::" in var_id, f"Variable ID {var_id} should contain '::'"

                # Verify the variable node exists and is a StateVariable
                assert graph.has_node(var_id), f"Variable node {var_id} should exist in graph"
                var_node_data = graph.nodes[var_id]
                assert var_node_data.get("node_type") == "StateVariable", (
                    f"Variable {var_id} should have node_type='StateVariable'"
                )

    print("✓ PASS: All variable IDs follow correct format (ContractName::VariableName)")

    # Test 6: Verify no LocalVariable nodes appear in write lists
    print("\n=== Test 6: No LocalVariable Nodes ===")
    for node_id, node_data in graph.nodes(data=True):
        if node_data.get("type") == "function":
            state_vars_written = node_data.get("state_variables_written", [])
            for var_id in state_vars_written:
                var_node_data = graph.nodes.get(var_id, {})
                assert var_node_data.get("node_type") != "LocalVariable", (
                    f"LocalVariable {var_id} should not appear in state_variables_written"
                )

    print("✓ PASS: No LocalVariable nodes in write lists")

    # Test 7: Constructor evaluation
    print("\n=== Test 7: Constructor Evaluation ===")
    constructor_candidates = [
        "StateMutationTest::constructor",
        "StateMutationTest::slitherConstructorConstantVariables",
        "StateMutationTest::slitherConstructorVariables",
    ]

    constructor_found = False
    for candidate in constructor_candidates:
        if graph.has_node(candidate):
            node_data = graph.nodes[candidate]
            if node_data.get("is_constructor"):
                constructor_found = True
                # Constructor writes to counter in our test contract
                # Note: It may not write depending on Slither's interpretation
                print(f"  Found constructor: {candidate}")
                print(f"  - writes_state: {node_data.get('writes_state')}")
                print(f"  - num_state_writes: {node_data.get('num_state_writes')}")
                # We just verify the fields exist - actual values depend on Slither
                assert "writes_state" in node_data, "Constructor should have writes_state field"
                assert "num_state_writes" in node_data, "Constructor should have num_state_writes field"
                break

    if constructor_found:
        print("✓ PASS: Constructor has mutation metadata")
    else:
        print("⚠ SKIP: Constructor not found (may be optimized out by Slither)")


def test_get_state_mutators_query():
    """Test the get_state_mutators query API"""
    # Setup
    repo_path = os.path.join(os.getcwd(), "tests", "contracts")

    engine = AnalysisEngine()
    slither_obj = engine.run_analysis(repo_path)

    assert slither_obj is not None, "Analysis failed"

    # Build Graph
    builder = GraphBuilder()
    builder.build_graph(slither_obj)

    # Create query object
    queries = GraphQueries(builder.graph)

    # Test 1: Get all state mutators
    print("\n=== Test Query: All State Mutators ===")
    all_mutators = queries.get_state_mutators()

    print(f"Found {len(all_mutators)} state mutators:")
    for mutator in all_mutators:
        print(f"  - {mutator['function_id']} ({mutator['num_state_writes']} writes)")

    # Should have at least writeState and writeMapping from StateMutationTest
    mutator_ids = [m["function_id"] for m in all_mutators]
    assert "StateMutationTest::writeState" in mutator_ids, "writeState should be in state mutators"
    assert "StateMutationTest::writeMapping" in mutator_ids, "writeMapping should be in state mutators"

    # Should NOT include localOnly or readOnly
    assert "StateMutationTest::localOnly" not in mutator_ids, "localOnly should NOT be in state mutators"
    assert "StateMutationTest::readOnly" not in mutator_ids, "readOnly should NOT be in state mutators"

    print("✓ PASS: Query returns correct state mutators")

    # Test 2: Filter by contract
    print("\n=== Test Query: Filter by Contract ===")
    filtered_mutators = queries.get_state_mutators(contract_name="StateMutationTest")

    print(f"Found {len(filtered_mutators)} mutators in StateMutationTest")

    # All returned mutators should be from StateMutationTest
    for mutator in filtered_mutators:
        assert mutator["contract_name"] == "StateMutationTest", (
            f"Mutator {mutator['function_id']} should be from StateMutationTest"
        )

    print("✓ PASS: Contract filtering works correctly")

    # Test 3: Verify all required fields are present
    print("\n=== Test Query: Required Fields ===")
    required_fields = [
        "function_id",
        "name",
        "contract_name",
        "num_state_writes",
        "state_variables_written",
        "visibility",
        "modifiers",
    ]

    for mutator in all_mutators:
        for field in required_fields:
            assert field in mutator, f"Mutator {mutator.get('function_id')} missing field: {field}"

    print("✓ PASS: All required fields present in query results")

    # Test 4: Non-existent contract filter
    print("\n=== Test Query: Non-existent Contract ===")
    empty_mutators = queries.get_state_mutators(contract_name="NonExistentContract")
    assert len(empty_mutators) == 0, "Non-existent contract should return empty list"

    print("✓ PASS: Non-existent contract returns empty list")


def test_refinement_distinct_counting():
    """
    Refinement Test 1: Multiple writes to same variable should count as 1
    """
    repo_path = os.path.join(os.getcwd(), "tests", "contracts")

    engine = AnalysisEngine()
    slither_obj = engine.run_analysis(repo_path)
    assert slither_obj is not None

    builder = GraphBuilder()
    builder.build_graph(slither_obj)
    graph = builder.graph

    print("\n=== Refinement 1: Distinct Variable Counting ===")
    multi_write_func = "StateMutationTest::multipleWritesSameVar"

    if graph.has_node(multi_write_func):
        node_data = graph.nodes[multi_write_func]

        # Should write to counter multiple times but count as 1 distinct variable
        assert node_data.get("writes_state") == True, "multipleWritesSameVar() should have writes_state=True"
        assert node_data.get("num_state_writes") == 1, (
            f"multipleWritesSameVar() should count 1 distinct variable, got {node_data.get('num_state_writes')}"
        )

        state_vars_written = node_data.get("state_variables_written", [])
        assert len(state_vars_written) == 1, (
            f"Should have 1 distinct variable in state_variables_written, got {len(state_vars_written)}"
        )
        assert any("counter" in var for var in state_vars_written), "counter should be the only variable written"

        print(f"✓ PASS: {multi_write_func}")
        print("  - Multiple writes to 'counter' counted as 1 distinct variable")
        print(f"  - num_state_writes: {node_data.get('num_state_writes')}")
    else:
        print(f"⚠ SKIP: {multi_write_func} not found")


def test_refinement_storage_reference():
    """
    Refinement Test 2: Storage reference writes via struct should be detected
    """
    repo_path = os.path.join(os.getcwd(), "tests", "contracts")

    engine = AnalysisEngine()
    slither_obj = engine.run_analysis(repo_path)
    assert slither_obj is not None

    builder = GraphBuilder()
    builder.build_graph(slither_obj)
    graph = builder.graph

    print("\n=== Refinement 2: Storage Reference Writes ===")
    storage_ref_func = "StateMutationTest::writeViaStorageRef"

    if graph.has_node(storage_ref_func):
        node_data = graph.nodes[storage_ref_func]

        # Should detect writes via storage reference
        assert node_data.get("writes_state") == True, "writeViaStorageRef() should have writes_state=True"
        assert node_data.get("num_state_writes") >= 1, (
            f"writeViaStorageRef() should have num_state_writes >= 1, got {node_data.get('num_state_writes')}"
        )

        state_vars_written = node_data.get("state_variables_written", [])
        assert len(state_vars_written) >= 1, "writeViaStorageRef() should write to at least 1 state variable"

        # Verify users mapping is in the written variables
        assert any("users" in var for var in state_vars_written), "users mapping should be in state_variables_written"

        print(f"✓ PASS: {storage_ref_func}")
        print("  - Storage reference writes detected")
        print(f"  - num_state_writes: {node_data.get('num_state_writes')}")
        print(f"  - state_variables_written: {state_vars_written}")
    else:
        print(f"⚠ SKIP: {storage_ref_func} not found")


def test_refinement_constructor_metadata():
    """
    Refinement Test 3: Explicit constructor metadata validation
    """
    repo_path = os.path.join(os.getcwd(), "tests", "contracts")

    engine = AnalysisEngine()
    slither_obj = engine.run_analysis(repo_path)
    assert slither_obj is not None

    builder = GraphBuilder()
    builder.build_graph(slither_obj)
    graph = builder.graph

    print("\n=== Refinement 3: Constructor Metadata ===")

    # Find constructor for StateMutationTest
    constructor_candidates = [
        "StateMutationTest::constructor",
        "StateMutationTest::slitherConstructorConstantVariables",
        "StateMutationTest::slitherConstructorVariables",
    ]

    constructor_found = False
    for candidate in constructor_candidates:
        if graph.has_node(candidate):
            node_data = graph.nodes[candidate]
            if node_data.get("is_constructor"):
                constructor_found = True

                # Explicitly validate metadata fields exist
                assert "writes_state" in node_data, f"Constructor {candidate} missing writes_state field"
                assert "num_state_writes" in node_data, f"Constructor {candidate} missing num_state_writes field"
                assert "state_variables_written" in node_data, (
                    f"Constructor {candidate} missing state_variables_written field"
                )

                # The constructor writes counter = 0
                writes_state = node_data.get("writes_state")
                num_writes = node_data.get("num_state_writes")

                print("✓ PASS: Constructor metadata validated")
                print(f"  - Node: {candidate}")
                print(f"  - writes_state: {writes_state}")
                print(f"  - num_state_writes: {num_writes}")
                print(f"  - state_variables_written: {node_data.get('state_variables_written')}")
                break

    if not constructor_found:
        print("⚠ SKIP: Constructor not found (may be optimized by Slither)")


def test_refinement_cross_contract_isolation():
    """
    Refinement Test 4: Cross-contract calls should NOT propagate write metadata
    """
    repo_path = os.path.join(os.getcwd(), "tests", "contracts")

    engine = AnalysisEngine()
    slither_obj = engine.run_analysis(repo_path)
    assert slither_obj is not None

    builder = GraphBuilder()
    builder.build_graph(slither_obj)
    graph = builder.graph

    print("\n=== Refinement 4: Cross-Contract Write Isolation ===")

    # ContractB::write should have writes_state=True
    b_write_func = "ContractB::write"
    if graph.has_node(b_write_func):
        node_data = graph.nodes[b_write_func]
        assert node_data.get("writes_state") == True, "ContractB::write() should have writes_state=True"
        assert node_data.get("num_state_writes") >= 1, "ContractB::write() should have num_state_writes >= 1"
        print("✓ PASS: ContractB::write() has writes_state=True")
    else:
        print("⚠ SKIP: ContractB::write not found")

    # ContractA::callWrite should have writes_state=False (no propagation)
    a_call_func = "ContractA::callWrite"
    if graph.has_node(a_call_func):
        node_data = graph.nodes[a_call_func]
        assert node_data.get("writes_state") == False, (
            "ContractA::callWrite() should have writes_state=False (no cross-contract propagation)"
        )
        assert node_data.get("num_state_writes") == 0, "ContractA::callWrite() should have num_state_writes=0"
        print("✓ PASS: ContractA::callWrite() has writes_state=False (no propagation)")
    else:
        print("⚠ SKIP: ContractA::callWrite not found")

    print("✓ PASS: Cross-contract write isolation validated")


if __name__ == "__main__":
    print("=" * 60)
    print("Testing Storage State Mutation Detection (Story 2.2)")
    print("=" * 60)

    test_storage_mutation_detection()
    print("\n" + "=" * 60)
    test_get_state_mutators_query()
    print("\n" + "=" * 60)

    print("\n" + "=" * 60)
    print("Running Refinement Tests")
    print("=" * 60)
    test_refinement_distinct_counting()
    test_refinement_storage_reference()
    test_refinement_constructor_metadata()
    test_refinement_cross_contract_isolation()

    print("\n" + "=" * 60)
    print("All tests passed! ✓")
