
import pytest
import networkx as nx
from src.agents.tools import create_graph_tools

def test_create_graph_tools():
    # Setup mock graph
    G = nx.DiGraph()
    G.add_node("FuncA", type="function", source_code="code A")
    G.add_node("FuncB", type="function", source_code="code B")
    G.add_node("VarX", type="state_variable")
    G.add_edge("FuncA", "FuncB", relationship="CALLS")
    G.add_edge("FuncB", "VarX", relationship="WRITES")
    
    tools = create_graph_tools(G)
    assert len(tools) == 4
    
    tool_map = {t.name: t for t in tools}
    assert "get_function_context" in tool_map
    assert "find_state_mutators" in tool_map
    
    # Test get_function_context
    ctx_tool = tool_map["get_function_context"]
    res = ctx_tool.invoke({"node_id": "FuncA"})
    assert res["node_id"] == "FuncA"
    assert res["code"] == "code A"
    assert "FuncB" in res["callees"]
    
    # Test find_state_mutators
    mut_tool = tool_map["find_state_mutators"]
    res_mut = mut_tool.invoke({"variable_name": "VarX"})
    assert "FuncB" in res_mut
