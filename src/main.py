import sys
import os
import argparse
import networkx as nx
from dotenv import load_dotenv

load_dotenv()

from langchain_core.messages import HumanMessage
from langgraph.graph import StateGraph, START, END
from langgraph.prebuilt import ToolNode, tools_condition

from src.agents.state import AgentState, get_checkpointer
from src.agents.lead_agent import lead_researcher_node, set_tools
from src.agents.tools import create_graph_tools
from src.repo_manager import RepoManager
from src.analysis_engine import AnalysisEngine
from src.graph_builder import GraphBuilder

def build_agent_workflow(tools) -> StateGraph:
    """Builds the LangGraph workflow for the Lead Agent."""
    workflow = StateGraph(AgentState)
    
    workflow.add_node("LeadAgent", lead_researcher_node)
    workflow.add_node("tools", ToolNode(tools))
    
    workflow.add_edge(START, "LeadAgent")
    workflow.add_conditional_edges("LeadAgent", tools_condition)
    workflow.add_edge("tools", "LeadAgent")
    
    return workflow

def main():
    parser = argparse.ArgumentParser(description="Penteam Lead Agent - End-to-End Ingestion")
    parser.add_argument("--repo", type=str, help="Path to local folder or GitHub URL of the smart contract repo", required=True)
    args = parser.parse_args()

    print("Initializing Penteam Lead Agent Workflow...")

    # 1. Setup Environment
    if "GOOGLE_API_KEY" not in os.environ:
        print("Error: GOOGLE_API_KEY not set in .env")
        sys.exit(1)

    # 2. Ingest Repository
    print(f"Targeting Repository: {args.repo}")
    repo_manager = RepoManager("./data/scratch")
    try:
        repo_path = repo_manager.clone_repo(args.repo)
        repo_manager.install_dependencies(repo_path)
    except Exception as e:
        print(f"Error during repository ingestion: {e}")
        sys.exit(1)

    # 3. Analyze with Slither
    print("Running Static Analysis (Slither)...")
    engine = AnalysisEngine()
    slither_obj = engine.run_analysis(repo_path)
    if not slither_obj:
        print("Error: Slither analysis failed. Exiting.")
        sys.exit(1)

    # 4. Build Knowledge Graph
    print("Building Knowledge Graph...")
    builder = GraphBuilder()
    builder.build_graph(slither_obj)
    graph = builder.graph
    
    # Optional: Export graph for debugging
    builder.export_json("./data/graph_debug.json")
    print(f"Graph built with {graph.number_of_nodes()} nodes and {graph.number_of_edges()} edges.")

    # 5. Create Tools with Real Graph
    print("Creating Tools...")
    tools = create_graph_tools(graph)
    set_tools(tools)

    # 6. Build and Run LangGraph Workflow
    print("Building LangGraph...")
    workflow = build_agent_workflow(tools)
    checkpointer = get_checkpointer()
    app = workflow.compile(checkpointer=checkpointer)

    print("\n--- Starting Security Analysis ---")
    
    initial_message = HumanMessage(content="""
    Please analyze this codebase. 
    Start by understanding the high-level architecture.
    Then, identify potential vulnerabilities, focusing on:
    1. Missing access control
    2. Reentrancy
    3. Unsafe external calls
    """)
    
    config = {"configurable": {"thread_id": "live_run_1"}}
    
    # Run the graph
    events = app.stream({"messages": [initial_message], "vulnerability_leads": [], "target_nodes": []}, config, stream_mode="values")
    
    final_state = None
    for event in events:
        final_state = event
        if "messages" in event:
             last_msg = event["messages"][-1]
             print(f"Agent ({type(last_msg).__name__}): {last_msg.content[:100]}...")
             if hasattr(last_msg, "tool_calls") and last_msg.tool_calls:
                 print(f"  -> Tool Call: {last_msg.tool_calls}")

    print("\n--- Analysis Complete ---")
    if final_state and "vulnerability_leads" in final_state:
        leads = final_state["vulnerability_leads"]
        print(f"Found {len(leads)} vulnerability leads:")
        for lead in leads:
            print(f" - {lead}")
            
    print("Done.")

if __name__ == "__main__":
    main()
