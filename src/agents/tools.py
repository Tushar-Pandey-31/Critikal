
from typing import List, Dict, Any, Callable
from langchain_core.tools import tool, StructuredTool
import networkx as nx
from langchain_chroma import Chroma
from langchain_huggingface import HuggingFaceEmbeddings

from src.utils.graph_queries import GraphQueries


# RAG Setup
DB_PATH = "./data/chroma_db"
try:
    _embedding_function = HuggingFaceEmbeddings(model_name="all-MiniLM-L6-v2")
    # Initialize Chroma only if we plan to use it, or handle empty DB
    # We delay loading to avoid errors during test if DB missing, unless we want to enforce it.
    # For now, let's load it.
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

def create_graph_tools(graph: nx.DiGraph) -> List[StructuredTool]:
    """
    Creates LangChain tools that wrap GraphQueries methods, allowing access to the provided graph.
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

