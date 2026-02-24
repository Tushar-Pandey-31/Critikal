import os
import sys
import networkx as nx

# Add src to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

from analysis_engine import AnalysisEngine
from graph_builder import GraphBuilder

def test_graph_builder():
    # Setup
    repo_path = os.path.join(os.getcwd(), 'tests', 'contracts', 'Complex.sol')
    print(f"Analyzing {repo_path}...")
    
    engine = AnalysisEngine()
    slither_obj = engine.run_analysis(repo_path)
    
    if not slither_obj:
        print("FAIL: Analysis failed, cannot test graph builder.")
        return

    # Build Graph
    print("Building Knowledge Graph...")
    builder = GraphBuilder()
    builder.build_graph(slither_obj)
    
    graph = builder.graph
    print(f"Graph Stats: {builder.get_graph_stats()}")
    
    # 1. Verify Inheritance: Complex -> Parent
    if graph.has_edge("Complex", "Parent"):
        print("PASS: Inheritance Edge Complex -> Parent found.")
    else:
        print("FAIL: Inheritance Edge Complex -> Parent MISSING.")

    # 2. Verify Internal Call: Complex::setValue -> Complex::internalUpdate
    src = "Complex::setValue"
    dst = "Complex::internalUpdate"
    if graph.has_edge(src, dst):
        edge_data = graph.get_edge_data(src, dst)
        if edge_data["relationship"] == "CALLS":
             print(f"PASS: Call Edge {src} -> {dst} found.")
        else:
             print(f"FAIL: Edge {src} -> {dst} exists but type is {edge_data['relationship']}")
    else:
        print(f"FAIL: Call Edge {src} -> {dst} MISSING.")

    # 3. Verify State Access: Complex::setValue -> WRITES -> Complex::value
    # Note: State Variable ID format in builder is "{Contract}::{VarName}"
    var_id = "Complex::value"
    if graph.has_edge(src, var_id):
        edge_data = graph.get_edge_data(src, var_id)
        if edge_data["relationship"] == "WRITES":
            print(f"PASS: State Access {src} -> WRITES -> {var_id} found.")
        else:
             print(f"FAIL: Edge {src} -> {var_id} exists but type is {edge_data['relationship']}")
    else:
        print(f"FAIL: State Access {src} -> {var_id} MISSING.")

    # 4. Verify State Access: Complex::getValue -> READS -> Complex::value
    src_get = "Complex::getValue"
    if graph.has_edge(src_get, var_id):
        edge_data = graph.get_edge_data(src_get, var_id)
        if edge_data["relationship"] == "READS":
            print(f"PASS: State Access {src_get} -> READS -> {var_id} found.")
        else:
             print(f"FAIL: Edge {src_get} -> {var_id} exists but type is {edge_data['relationship']}")
    else:
        print(f"FAIL: State Access {src_get} -> {var_id} MISSING.")

    # 5. Verify Call to Parent Function: Complex::callParent -> Parent::setParentVar
    # Slither might resolve this to Parent::setParentVar or Complex::setParentVar depending on how it handles inherited functions.
    # Usually internal calls point to the definition.
    src_call = "Complex::callParent"
    dst_parent = "Parent::setParentVar" # Defined in Parent
    
    # Check if edge exists to Parent::setParentVar
    if graph.has_edge(src_call, dst_parent):
        print(f"PASS: Call Edge {src_call} -> {dst_parent} found.")
    else:
        # Fallback check: maybe it points to Complex::setParentVar?
        dst_complex = "Complex::setParentVar"
        if graph.has_edge(src_call, dst_complex):
             print(f"WARN: Call Edge points to {dst_complex} instead of {dst_parent}. Acceptable but noted.")
        else:
             print(f"FAIL: Call Edge from {src_call} to setParentVar MISSING.")
    
    # Export
    output_path = "test_graph_complex.json"
    builder.export_json(output_path)
    if os.path.exists(output_path):
        print(f"Graph exported to {output_path}")
        os.remove(output_path)

if __name__ == "__main__":
    test_graph_builder()
