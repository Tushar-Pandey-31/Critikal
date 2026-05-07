import argparse
import asyncio
import json
import os
import sys

import networkx as nx
from dotenv import load_dotenv

load_dotenv()

# Silence broken ChromaDB telemetry logger (posthog capture() API mismatch)
import logging as _logging

_logging.getLogger("chromadb.telemetry").setLevel(_logging.CRITICAL + 1)

from langchain_core.messages import HumanMessage
from langgraph.graph import END, START, StateGraph

from src.analysis_engine import AnalysisEngine
from src.graph import GraphBuilder
from src.pipeline.lead_agent import coordinator_node, set_tools
from src.pipeline.state import AgentState
from src.pipeline.tools import create_coordinator_tools
from src.pipeline_config import get_config
from src.repo_manager import RepoManager


def _parse_contract_addresses(raw: str | None) -> dict[str, str]:
    """
    Parse contract address mapping from JSON.
    Example: {"Vault":"0x1234...","Token":"0xabcd..."}
    """
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
    except Exception as e:
        raise ValueError(f"Invalid contract address JSON: {e}") from e

    if not isinstance(parsed, dict):
        raise ValueError("contract addresses must be a JSON object mapping contract names to addresses")

    normalized: dict[str, str] = {}
    for name, addr in parsed.items():
        if not isinstance(name, str) or not isinstance(addr, str):
            raise ValueError("contract address entries must be string:string pairs")
        normalized[name.strip()] = addr.strip()
    return normalized




def build_agent_workflow(coordinator_tools) -> StateGraph:
    """
    Builds the LangGraph workflow for the Coordinator + Worker architecture.

    Graph topology:
        START → Coordinator → END

    The Coordinator runs the entire pipeline programmatically
    (Recon → Hotspots → Attack Workers → TestWriter → LLM Synthesis).
    No LangGraph tool loop is needed — all graph queries and worker
    dispatch happen inside coordinator_node via direct Python calls.
    """
    workflow = StateGraph(AgentState)

    workflow.add_node("Coordinator", coordinator_node)
    workflow.add_edge(START, "Coordinator")
    workflow.add_edge("Coordinator", END)

    return workflow


# ════════════════════════════════════════════════════════════
#  Legacy Compatibility
# ════════════════════════════════════════════════════════════



async def async_main():
    parser = argparse.ArgumentParser(description="Critikal Lead Agent - End-to-End Ingestion")
    parser.add_argument("--repo", type=str, help="Path to local folder or GitHub URL of the smart contract repo", required=True)
    parser.add_argument(
        "--contract-addresses",
        type=str,
        default=None,
        help='Optional JSON mapping for on-chain recon, e.g. \'{"Vault":"0x...","Token":"0x..."}\'',
    )
    parser.add_argument(
        "--auto-ingest",
        action="store_true",
        default=False,
        help="Auto-ingest RAG knowledge base if ChromaDB is empty",
    )
    args = parser.parse_args()

    print("Initializing Critikal Coordinator Workflow...")

    contract_addresses_input = args.contract_addresses or os.getenv("CONTRACT_ADDRESSES_JSON")
    try:
        contract_addresses = _parse_contract_addresses(contract_addresses_input)
    except ValueError as e:
        print(f"Error: {e}")
        sys.exit(1)
    if contract_addresses:
        print(f"Loaded {len(contract_addresses)} contract address mapping(s) for recon.")

    # 1. Setup Environment
    if "GOOGLE_API_KEY" not in os.environ:
        print("Error: GOOGLE_API_KEY not set in .env")
        sys.exit(1)

    # 1b. Auto-ingest RAG knowledge base if empty
    if args.auto_ingest:
        from src.knowledge.paths import CHROMA_DB_PATH
        _chroma_empty = True
        if CHROMA_DB_PATH.exists():
            try:
                import chromadb
                _client = chromadb.PersistentClient(path=str(CHROMA_DB_PATH))
                _cols = _client.list_collections()
                if _cols and any(c.count() > 0 for c in _cols):
                    _chroma_empty = False
            except Exception:
                pass
        if _chroma_empty:
            print("RAG knowledge base is empty — running ingest...")
            from src.knowledge.ingest import ingest_knowledge
            ingest_knowledge()
        else:
            print("RAG knowledge base already populated — skipping ingest.")

    # 2. Ingest Repository
    print(f"Targeting Repository: {args.repo}")
    repo_manager = RepoManager("./data/scratch")
    try:
        repo_path = repo_manager.clone_repo(args.repo)
        repo_manager.install_dependencies(repo_path)
    except Exception as e:
        print(f"Error during repository ingestion: {e}")
        sys.exit(1)

    # 3. Analyze with Slither (cluster-based pipeline)
    config = get_config()
    if config.slither_enabled:
        print("Running Static Analysis (Slither)...")
        engine = AnalysisEngine()

        # Optional: logic to detect specific targets could go here
        targets = None

        slither_obj, ingestion_report = engine.run_analysis_v2(repo_path, targets=targets)
        if not slither_obj:
            print("WARNING: Slither analysis failed — continuing with semantic-only analysis.")
            if ingestion_report and ingestion_report.warnings:
                print("  Diagnostics:")
                for w in ingestion_report.warnings:
                    print(f"    - {w}")
            # Don't exit — fall through with an empty graph.
            # Semantic discovery agents (Step 1.5) analyze raw source code
            # from the repo directory and don't need a compiled AST.
            graph = nx.DiGraph()
            print(f"  Using empty graph. Semantic agents will analyze raw source files in {repo_path}.")
        else:
            if ingestion_report:
                print(f"  {ingestion_report.summary()}")

            # 4. Build Knowledge Graph
            print("Building Knowledge Graph...")
            builder = GraphBuilder()
            builder.build_graph(slither_obj)
            graph = builder.graph

            builder.export_json("./data/graph_debug.json")
            print(f"Graph built with {graph.number_of_nodes()} nodes and {graph.number_of_edges()} edges.")
    else:
        print("[Config] Slither disabled — using empty graph")
        graph = nx.DiGraph()

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

    langgraph_config = {"configurable": {"thread_id": "live_run_1"}}

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
        "recon_context": {},
        "findings": [],
        "contract_names": list(contracts),
        "contract_addresses": contract_addresses,
        "repo_url": args.repo,
        "escalate": False,
    }

    events = app.astream(initial_state, langgraph_config, stream_mode="values")

    final_state = None
    async for event in events:
        final_state = event
        if "messages" in event:
             last_msg = event["messages"][-1]
             print(f"Agent ({type(last_msg).__name__}): {last_msg.content[:100]}...")
             if hasattr(last_msg, "tool_calls") and last_msg.tool_calls:
                 print(f"  -> Tool Call: {last_msg.tool_calls}")

    print("\n--- Analysis Complete ---")
    leads = []
    if final_state:
        leads = final_state.get("vulnerability_leads", [])
        # Backup: check findings if leads is empty
        if not leads and final_state.get("findings"):
            findings = final_state["findings"]
            leads = [f.model_dump() if hasattr(f, "model_dump") else str(f) for f in findings]

    print(f"Found {len(leads)} vulnerability leads:\n")
    for lead in leads:
        if isinstance(lead, dict):
            title = lead.get("title") or lead.get("hypothesis") or "Unnamed Lead"
            severity = lead.get("severity_estimate") or "UNKNOWN"
            confidence = lead.get("confidence") or 0
            success = lead.get("exploit_success")
            contract = lead.get("affected_contract") or "N/A"
            func = lead.get("affected_function") or "N/A"
            test_code = lead.get("test_code")

            status_str = " → [PROVEN]" if success else ""
            print(f"  • {severity} | {title} (Confidence: {confidence}%){status_str}")
            print(f"    Contract: {contract} | Function: {func}")

            raw_output = lead.get("raw_output", {})
            if "test-writer" in str(lead.get("worker_type")).lower() or test_code:
                attempts = raw_output.get("attempts", "N/A")
                if success:
                    print(f"    Test Writer: Exploit succeeded ({attempts} attempts)")
                elif raw_output.get("compiled"):
                    print("    Test Writer: Compiled but exploit failed")
                elif raw_output.get("error"):
                    print(f"    Test Writer: Failed to compile ({raw_output.get('error')[:50]}...)")

            if test_code:
                print("    Test Code Snippet:")
                snippet = "\n".join(test_code.splitlines()[:15])
                print("    ---")
                for line in snippet.splitlines():
                    print(f"    {line}")
                print("    ---\n")
            else:
                print("")
        else:
            print(f"  • {lead}\n")

    if final_state and final_state.get("strategy"):
        print(f"Strategy: {final_state['strategy']}")

    print("Done.")

def main():
    import warnings
    warnings.warn(
        "src.main is the legacy LangGraph pipeline and is deprecated. "
        "Use 'python -m src.cli --repo <url>' for the new agentic system. "
        "This entry point will be removed in a future release.",
        DeprecationWarning,
        stacklevel=2,
    )
    print("=" * 60)
    print("⚠️  LEGACY MODE — Using old LangGraph pipeline")
    print("   New agent: python -m src.cli --repo <url>")
    print("=" * 60)
    asyncio.run(async_main())

if __name__ == "__main__":
    main()
