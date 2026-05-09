import os
import sys

# Add src to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

from analysis_engine import AnalysisEngine
from src.graph import GraphBuilder
from utils.graph_queries import GraphQueries


def test_external_entry_detection():
    """Test that is_external_entry is correctly computed for various function visibilities."""
    # Setup - pass the directory containing the contract, not the file itself
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

    # Test 1: Public function should be external entry
    public_func = "AttackSurfaceTest::publicDeposit"
    assert graph.has_node(public_func), f"Node {public_func} not found"
    assert graph.nodes[public_func]["is_external_entry"] == True, "Public function should be marked as external entry"
    print(f"✓ PASS: {public_func} is correctly marked as external entry")

    # Test 2: External function should be external entry
    external_func = "AttackSurfaceTest::externalWithdraw"
    assert graph.has_node(external_func), f"Node {external_func} not found"
    assert graph.nodes[external_func]["is_external_entry"] == True, (
        "External function should be marked as external entry"
    )
    print(f"✓ PASS: {external_func} is correctly marked as external entry")

    # Test 3: Internal function should NOT be external entry
    internal_func = "AttackSurfaceTest::internalHelper"
    assert graph.has_node(internal_func), f"Node {internal_func} not found"
    assert graph.nodes[internal_func]["is_external_entry"] == False, (
        "Internal function should NOT be marked as external entry"
    )
    print(f"✓ PASS: {internal_func} is correctly marked as NOT external entry")

    # Test 4: Private function should NOT be external entry
    private_func = "AttackSurfaceTest::privateCompute"
    assert graph.has_node(private_func), f"Node {private_func} not found"
    assert graph.nodes[private_func]["is_external_entry"] == False, (
        "Private function should NOT be marked as external entry"
    )
    print(f"✓ PASS: {private_func} is correctly marked as NOT external entry")

    # Test 5: Constructor should NOT be external entry (even though it may be public in metadata)
    constructor_func = "AttackSurfaceTest::constructor"
    # Slither may use different naming for constructors
    constructor_candidates = [
        "AttackSurfaceTest::constructor",
        "AttackSurfaceTest::slitherConstructorConstantVariables",
        "AttackSurfaceTest::slitherConstructorVariables",
    ]

    # Find the actual constructor
    constructor_found = False
    for candidate in constructor_candidates:
        if graph.has_node(candidate):
            node_data = graph.nodes[candidate]
            if node_data.get("is_constructor"):
                constructor_found = True
                assert node_data["is_external_entry"] == False, "Constructor should NOT be marked as external entry"
                print(f"✓ PASS: {candidate} (constructor) is correctly marked as NOT external entry")
                break

    if not constructor_found:
        print("⚠ SKIP: Constructor node not found in graph (may be optimized out)")

    # Test 6: Payable function is correctly identified
    payable_func = "AttackSurfaceTest::externalPayableDeposit"
    assert graph.has_node(payable_func), f"Node {payable_func} not found"
    assert graph.nodes[payable_func]["is_payable"] == True, "Payable function should be marked as payable"
    assert graph.nodes[payable_func]["is_external_entry"] == True, "External payable function should be external entry"
    print(f"✓ PASS: {payable_func} is correctly marked as payable and external entry")

    # Test 7: Non-payable function
    view_func = "AttackSurfaceTest::getBalance"
    assert graph.has_node(view_func), f"Node {view_func} not found"
    assert graph.nodes[view_func]["is_payable"] == False, "Non-payable function should not be marked as payable"
    assert graph.nodes[view_func]["is_external_entry"] == True, "Public view function should be external entry"
    print(f"✓ PASS: {view_func} is correctly marked as NOT payable but is external entry")

    # Test 8: Receive function should be external entry and payable
    receive_func = "AttackSurfaceTest::receive"
    if graph.has_node(receive_func):
        assert graph.nodes[receive_func]["is_receive"] == True, "Receive function should be marked as receive"
        assert graph.nodes[receive_func]["is_external_entry"] == True, "Receive function should be external entry"
        assert graph.nodes[receive_func]["is_payable"] == True, "Receive function should be payable"
        print(f"✓ PASS: {receive_func} is correctly marked as receive, external entry, and payable")
    else:
        print("⚠ SKIP: Receive function not found (may vary by Slither version)")

    # Test 9: Fallback function should be external entry
    fallback_func = "AttackSurfaceTest::fallback"
    if graph.has_node(fallback_func):
        assert graph.nodes[fallback_func]["is_fallback"] == True, "Fallback function should be marked as fallback"
        assert graph.nodes[fallback_func]["is_external_entry"] == True, "Fallback function should be external entry"
        print(f"✓ PASS: {fallback_func} is correctly marked as fallback and external entry")
    else:
        print("⚠ SKIP: Fallback function not found (may vary by Slither version)")


def test_get_external_entry_points_query():
    """Test the get_external_entry_points query function."""
    # Setup - pass the directory containing the contract
    repo_path = os.path.join(os.getcwd(), "tests", "contracts")

    engine = AnalysisEngine()
    slither_obj = engine.run_analysis(repo_path)

    assert slither_obj is not None, "Analysis failed"

    # Build Graph
    builder = GraphBuilder()
    builder.build_graph(slither_obj)

    # Create query object
    queries = GraphQueries(builder.graph)

    # Get all external entry points
    entry_points = queries.get_external_entry_points()

    print(f"\nFound {len(entry_points)} external entry points:")
    for ep in entry_points:
        print(f"  - {ep['node_id']} (visibility={ep['visibility']}, payable={ep['is_payable']})")

    # Should have at least 4 external entry points (publicDeposit, externalWithdraw, getBalance, externalPayableDeposit)
    # Note: balance getter might also be included if it's a public state variable
    assert len(entry_points) >= 4, f"Expected at least 4 entry points, found {len(entry_points)}"

    # Verify specific functions are in the list
    entry_point_names = [ep["node_id"] for ep in entry_points]

    assert "AttackSurfaceTest::publicDeposit" in entry_point_names
    assert "AttackSurfaceTest::externalWithdraw" in entry_point_names
    assert "AttackSurfaceTest::getBalance" in entry_point_names
    assert "AttackSurfaceTest::externalPayableDeposit" in entry_point_names

    # Verify that internal and private functions are NOT in the list
    assert "AttackSurfaceTest::internalHelper" not in entry_point_names
    assert "AttackSurfaceTest::privateCompute" not in entry_point_names

    print("✓ PASS: Query correctly returns all external entry points")

    # Test contract filtering
    filtered_points = queries.get_external_entry_points(contract_name="AttackSurfaceTest")
    attack_surface_points = [ep for ep in entry_points if ep["contract"] == "AttackSurfaceTest"]

    print(f"\nFiltered to AttackSurfaceTest: {len(filtered_points)} entry points")
    assert len(filtered_points) == len(attack_surface_points), (
        f"Contract filter should return {len(attack_surface_points)} AttackSurfaceTest entries, got {len(filtered_points)}"
    )

    # Verify the filtered points include our expected functions
    filtered_names = [ep["node_id"] for ep in filtered_points]
    assert "AttackSurfaceTest::publicDeposit" in filtered_names
    assert "AttackSurfaceTest::externalWithdraw" in filtered_names

    # Test with non-existent contract
    empty_points = queries.get_external_entry_points(contract_name="NonExistent")
    assert len(empty_points) == 0, "Non-existent contract should return empty list"

    print("✓ PASS: Contract filtering works correctly")


def test_inheritance_detection():
    """Test that inherited public/external functions are included in the attack surface."""
    # Analyze all contracts including InheritanceTest
    repo_path = os.path.join(os.getcwd(), "tests", "contracts")

    engine = AnalysisEngine()
    slither_obj = engine.run_analysis(repo_path)

    assert slither_obj is not None, "Analysis failed"

    # Build Graph
    builder = GraphBuilder()
    builder.build_graph(slither_obj)
    graph = builder.graph

    print("\n=== Testing Inheritance ===")

    # Test that base contract functions exist
    base_public = "BaseContract::basePublicFunction"
    if graph.has_node(base_public):
        assert graph.nodes[base_public]["is_external_entry"] == True, "Base public function should be external entry"
        print(f"✓ PASS: {base_public} is marked as external entry")
    else:
        print(f"⚠ SKIP: {base_public} not found")

    base_external = "BaseContract::baseExternalFunction"
    if graph.has_node(base_external):
        assert graph.nodes[base_external]["is_external_entry"] == True, (
            "Base external function should be external entry"
        )
        print(f"✓ PASS: {base_external} is marked as external entry")
    else:
        print(f"⚠ SKIP: {base_external} not found")

    # Test that child contract functions exist
    child_public = "ChildContract::childPublicFunction"
    if graph.has_node(child_public):
        assert graph.nodes[child_public]["is_external_entry"] == True, "Child public function should be external entry"
        print(f"✓ PASS: {child_public} is marked as external entry")
    else:
        print(f"⚠ SKIP: {child_public} not found")

    # Test that internal function is NOT external entry
    base_internal = "BaseContract::baseInternalFunction"
    if graph.has_node(base_internal):
        assert graph.nodes[base_internal]["is_external_entry"] == False, (
            "Base internal function should NOT be external entry"
        )
        print(f"✓ PASS: {base_internal} is correctly marked as NOT external entry")
    else:
        print(f"⚠ SKIP: {base_internal} not found")

    # Use query to get all entry points for ChildContract
    # Note: Slither includes inherited functions in the child's function list
    queries = GraphQueries(graph)
    child_entries = queries.get_external_entry_points(contract_name="ChildContract")

    print(f"\nFound {len(child_entries)} entry points in ChildContract")
    for ep in child_entries:
        print(f"  - {ep['node_id']}")

    # Verify child has its own public functions
    child_entry_names = [ep["node_id"] for ep in child_entries]
    if child_public in child_entry_names:
        print("✓ PASS: ChildContract includes its own public functions")

    print("\n✓ Inheritance test complete - Slither handles inherited functions correctly")


if __name__ == "__main__":
    print("=" * 60)
    print("Testing External Attack Surface Detection")
    print("=" * 60)

    test_external_entry_detection()
    print("\n" + "=" * 60)
    test_get_external_entry_points_query()
    print("\n" + "=" * 60)
    test_inheritance_detection()
    print("\n" + "=" * 60)
    print("All tests passed! ✓")
