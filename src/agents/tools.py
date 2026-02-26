"""
Tool factories for the multi-agent orchestration layer.

Two categories:
  - Coordinator tools: high-level summary queries + RAG (used by Lead Agent)
  - Worker tools: detailed graph inspection (used by specialist workers)
"""

from typing import List, Dict, Any
from pathlib import Path
from langchain_core.tools import tool, StructuredTool
import networkx as nx

from src.utils.graph_queries import GraphQueries
from src.knowledge.paths import CHROMA_DB_PATH

# ────────────────────────────────────────────────────────────
#  RAG Setup (lazy initialization — ARCH-004 fix)
# ────────────────────────────────────────────────────────────

DB_PATH = str(CHROMA_DB_PATH)
_vector_db = None
_rag_initialized = False


def _get_vector_db():
    """Lazy-load the RAG vector DB on first use, not at import time."""
    global _vector_db, _rag_initialized
    if _rag_initialized:
        return _vector_db
    _rag_initialized = True
    try:
        from langchain_chroma import Chroma
        from langchain_huggingface import HuggingFaceEmbeddings

        if Path(DB_PATH).exists():
            _embedding_function = HuggingFaceEmbeddings(model_name="all-MiniLM-L6-v2")
            _vector_db = Chroma(persist_directory=DB_PATH, embedding_function=_embedding_function)
        else:
            print(f"Warning: RAG DB not found at {DB_PATH}. Running without security knowledge search.")
    except Exception as e:
        print(f"Warning: RAG system not initialized (missing dependencies or DB): {e}")
    return _vector_db


@tool("search_security_knowledge")
def search_security_knowledge(query: str) -> str:
    """
    Searches the internal library of Audit Reports and Solidity Documentation.
    Use this to find precedents for vulnerabilities or check official language rules.
    Example: "Has reentrancy on ERC777 tokens been exploited before?"
    """
    vector_db = _get_vector_db()
    if not vector_db:
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
        hotspots = queries.get_high_risk_hotspots(min_score=70)

        return {
            "hotspots": [
                {
                    "node_id": h.node_id,
                    "contract": h.contract,
                    "function": h.function,
                    "risk_score": h.risk_score,
                    "structural_score": h.structural_score,
                    "exploitability_score": h.exploitability_score,
                    "impact_score": h.impact_score,
                    "priority": h.priority,
                    "risk_categories": h.risk_categories,
                }
                for h in hotspots
            ],
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
                "hotspot_count": len(hotspots),
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
