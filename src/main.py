import sys
import os
import argparse
import asyncio
import networkx as nx
from dotenv import load_dotenv

load_dotenv()

from langchain_core.messages import HumanMessage
from langgraph.graph import StateGraph, START, END
from langgraph.prebuilt import ToolNode, tools_condition

from src.agents.state import AgentState, get_checkpointer
from src.agents.lead_agent import coordinator_node, lead_researcher_node, set_tools
from src.agents.tools import create_coordinator_tools, create_graph_tools
from src.repo_manager import RepoManager
from src.analysis_engine import AnalysisEngine
from src.graph_builder import GraphBuilder


def worker_executor_node(state: AgentState):
    """
    Processes pending_workers from state.

    Currently a stub: future stories will register concrete WorkerAgent
    subclasses here. For now, this node simply clears the pending list
    so the coordinator loop can proceed.
    """
    pending = state.get("pending_workers", [])
    worker_outputs = state.get("worker_outputs", [])

    # TODO (Story 4.2+): Look up registered workers by type and spawn them
    #   e.g.  worker_registry = {"reentrancy": ReentrancyWorker, ...}
    #         tasks = [registry[w]().run(input_data) for w in pending]
    #         results = asyncio.run(asyncio.gather(*tasks))

    # For now, log and pass through
    if pending:
        print(f"[WorkerExecutor] {len(pending)} worker(s) requested: {pending}")
        print("[WorkerExecutor] No concrete workers registered yet — passing through.")

    return {
        "pending_workers": [],  # Clear the queue
        "worker_outputs": worker_outputs,  # Preserve existing outputs
    }


def _should_route_to_workers(state: AgentState) -> str:
    """Conditional edge: route to worker_executor if workers are pending."""
    pending = state.get("pending_workers", [])
    if pending:
        return "worker_executor"
    return END


def build_agent_workflow(coordinator_tools, include_workers: bool = True) -> StateGraph:
    """
    Builds the LangGraph workflow for the Coordinator + Worker architecture.

    Graph topology:
        START → Coordinator → tools (coordinator tools)
                            → worker_executor → Coordinator (loop)
                            → END
    """
    workflow = StateGraph(AgentState)

    # Core nodes
    workflow.add_node("Coordinator", coordinator_node)
    workflow.add_node("tools", ToolNode(coordinator_tools))

    # Entry
    workflow.add_edge(START, "Coordinator")

    # Coordinator → tools (for get_high_risk_hotspots, search_security_knowledge)
    workflow.add_conditional_edges("Coordinator", tools_condition)

    # tools → back to Coordinator
    workflow.add_edge("tools", "Coordinator")

    if include_workers:
        workflow.add_node("worker_executor", worker_executor_node)
        # After coordinator finishes (no tool calls), check for pending workers
        # This is handled by the tools_condition already routing to END when no
        # tool calls. We add another path via conditional edges for worker routing.
        # NOTE: In the current setup, tools_condition handles tool calls.
        # When no tool calls, it routes to END. The worker spawning will be
        # triggered by post-processing or future conditional edges.

    return workflow


# ════════════════════════════════════════════════════════════
#  Legacy Compatibility
# ════════════════════════════════════════════════════════════

def build_agent_workflow_legacy(tools) -> StateGraph:
    """
    Original workflow builder, kept for backward compatibility.
    Uses lead_researcher_node (alias for coordinator_node).
    """
    workflow = StateGraph(AgentState)

    workflow.add_node("LeadAgent", lead_researcher_node)
    workflow.add_node("tools", ToolNode(tools))

    workflow.add_edge(START, "LeadAgent")
    workflow.add_conditional_edges("LeadAgent", tools_condition)
    workflow.add_edge("tools", "LeadAgent")

    return workflow


async def async_main():
    parser = argparse.ArgumentParser(description="Penteam Lead Agent - End-to-End Ingestion")
    parser.add_argument("--repo", type=str, help="Path to local folder or GitHub URL of the smart contract repo", required=True)
    args = parser.parse_args()

    print("Initializing Penteam Coordinator Workflow...")

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
    
    
    # Optional: logic to detect specific targets could go here
    targets = None
    
    slither_obj = engine.run_analysis(repo_path, targets=targets)
    if not slither_obj:
        print("Error: Slither analysis failed. Exiting.")
        sys.exit(1)

    # 4. Build Knowledge Graph
    print("Building Knowledge Graph...")
    builder = GraphBuilder()
    builder.build_graph(slither_obj)
    graph = builder.graph
    
    builder.export_json("./data/graph_debug.json")
    print(f"Graph built with {graph.number_of_nodes()} nodes and {graph.number_of_edges()} edges.")

    # 5. Create Tools — Coordinator gets summary tools only
    print("Creating Coordinator Tools...")
    coordinator_tools = create_coordinator_tools(graph)
    set_tools(coordinator_tools)

    # 6. Build and Run LangGraph Workflow
    print("Building LangGraph Workflow...")
    workflow = build_agent_workflow(coordinator_tools)
    # checkpointer = get_checkpointer()
    app = workflow.compile() # Disabled checkpointer to avoid NetworkX serialization issues

    # Build initial message from graph data
    contracts = set()
    functions = []
    for node_id, data in graph.nodes(data=True):
        if data.get("type") == "contract":
            contracts.add(data.get("name", node_id))
        elif data.get("type") == "function":
            functions.append(node_id)
    
    contract_list = ", ".join(contracts) if contracts else "Unknown"
    
    initial_message = HumanMessage(content=f"""Assess the risk landscape for: {contract_list}

The Knowledge Graph contains {len(functions)} function nodes across {len(contracts)} contract(s).

Use get_high_risk_hotspots() to identify the highest-priority targets, then formulate your analysis strategy.
""")
    
    config = {"configurable": {"thread_id": "live_run_1"}}
    
    # Run the graph
    initial_state = {
        "messages": [initial_message],
        "vulnerability_leads": [],
        "target_nodes": [],
        "human_feedback": None,
        "worker_outputs": [],
        "strategy": None,
        "pending_workers": [],
        "graph": graph,
        "contract_names": list(contracts),
        "repo_url": args.repo
    }
    
    events = app.astream(initial_state, config, stream_mode="values")
    
    final_state = None
    async for event in events:
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
    
    if final_state and final_state.get("strategy"):
        print(f"\nStrategy: {final_state['strategy']}")
            
    print("Done.")

def main():
    asyncio.run(async_main())

if __name__ == "__main__":
    main()
