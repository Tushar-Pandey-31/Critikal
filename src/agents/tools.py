"""
Tool factories for the multi-agent orchestration layer.

Two categories:
  - Coordinator tools: high-level summary queries + RAG (used by Lead Agent)
  - Worker tools: detailed graph inspection (used by specialist workers)
"""

from typing import List, Dict, Any
from langchain_core.tools import tool, StructuredTool
import networkx as nx

from src.utils.graph_queries import GraphQueries

# ────────────────────────────────────────────────────────────
#  RAG Setup (shared across coordinator and workers)
# ────────────────────────────────────────────────────────────

DB_PATH = "./data/chroma_db"
try:
    from langchain_chroma import Chroma
    from langchain_huggingface import HuggingFaceEmbeddings

    _embedding_function = HuggingFaceEmbeddings(model_name="all-MiniLM-L6-v2")
    vector_db = Chroma(persist_directory=DB_PATH, embedding_function=_embedding_function)
    HAS_RAG = True
except Exception as e:
    print(f"Warning: RAG system not initialized (missing dependencies or DB): {e}")
    vector_db = None
    HAS_RAG = False


@tool("search_security_knowledge")
def search_security_knowledge(query: str) -> str:
    """
    Searches the internal library of Audit Reports and Solidity Documentation.
    Use this to find precedents for vulnerabilities or check official language rules.
    Example: "Has reentrancy on ERC777 tokens been exploited before?"
    """
    if not HAS_RAG or not vector_db:
        return "Error: Security knowledge base is not available."

    try:
        results = vector_db.similarity_search(query, k=3)
        response = "Security Knowledge Results:\n"
        for doc in results:
            source = doc.metadata.get('source', 'Unknown')
            response += f"---\nSource: {source}\nContent: {doc.page_content[:500]}...\n"
        return response
    except Exception as e:
        return f"Error searching knowledge base: {e}"


# ────────────────────────────────────────────────────────────
#  Coordinator Tools (summary-level, used by Lead Agent)
# ────────────────────────────────────────────────────────────

def create_coordinator_tools(graph: nx.DiGraph) -> List[StructuredTool]:
    """
    Creates tools for the Lead Agent / Coordinator.

    These are high-level summary queries — the coordinator never
    inspects individual function source code.
    """
    queries = GraphQueries(graph)

    @tool("get_high_risk_hotspots")
    def get_high_risk_hotspots() -> Dict[str, Any]:
        """
        Returns a consolidated risk summary across the entire codebase.
        Aggregates: reentrancy risks, unprotected state mutators,
        privilege escalation risks, and external entry points.
        Use this as the FIRST tool to identify where workers should focus.
        """
        reentrancy = queries.get_reentrancy_risks()
        unprotected = queries.get_unprotected_mutators()
        escalation = queries.get_privilege_escalation_risks()
        entry_points = queries.get_external_entry_points()
        external_calls = queries.get_external_call_functions()

        return {
            "total_entry_points": len(entry_points),
            "reentrancy_risks": reentrancy,
            "unprotected_mutators": unprotected,
            "privilege_escalation": escalation,
            "external_call_functions": external_calls,
            "risk_summary": {
                "reentrancy_count": len(reentrancy),
                "unprotected_count": len(unprotected),
                "escalation_risky_functions": len(escalation.get("risky_functions", [])),
                "escalation_risky_variables": len(escalation.get("risky_variables", [])),
                "external_call_count": len(external_calls),
            }
        }

    return [get_high_risk_hotspots, search_security_knowledge]


# ────────────────────────────────────────────────────────────
#  Worker Tools (detailed graph queries, used by specialists)
# ────────────────────────────────────────────────────────────

def create_graph_tools(graph: nx.DiGraph) -> List[StructuredTool]:
    """
    Creates LangChain tools that wrap GraphQueries methods.
    Used by specialist worker agents for detailed investigation.
    """
    queries = GraphQueries(graph)

    @tool("get_function_context")
    def get_function_context_tool(node_id: str) -> Dict[str, Any]:
        """
        Returns a function's code PLUS its immediate neighbors (callers and callees).
        Use this to understand what a function does and its local connections.
        """
        return queries.get_function_context(node_id)

    @tool("find_state_mutators")
    def find_state_mutators_tool(variable_name: str) -> List[str]:
        """
        Traces all functions with a WRITES edge to that variable.
        Use this to find which functions modify a specific state variable.
        variable_name should be the node_id of the state variable, e.g., "Contract::VarName".
        """
        return queries.find_state_mutators(variable_name)

    @tool("get_modifiers")
    def get_modifiers_tool(function_id: str) -> List[str]:
        """
        List all security modifiers (like onlyOwner or nonReentrant) applied to a function.
        Use this to check for access control or reentrancy guards.
        """
        return queries.get_modifiers(function_id)

    return [get_function_context_tool, find_state_mutators_tool, get_modifiers_tool, search_security_knowledge]
