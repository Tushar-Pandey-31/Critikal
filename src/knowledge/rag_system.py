import os
from typing import List, Dict, Any
from langchain_chroma import Chroma
from langchain_huggingface import HuggingFaceEmbeddings

DB_PATH = os.path.join(os.getcwd(), "data", "chroma_db")

# Initialize shared components
try:
    _embedding_function = HuggingFaceEmbeddings(model_name="all-MiniLM-L6-v2")
    vector_db = Chroma(persist_directory=DB_PATH, embedding_function=_embedding_function)
    HAS_RAG = True
except Exception as e:
    print(f"Warning: RAG system not initialized: {e}")
    vector_db = None
    HAS_RAG = False

def search_security_knowledge(query: str, k: int = 3) -> List[Dict[str, Any]]:
    """
    Query the vector database for security knowledge.
    Returns a list of dictionaries containing content and source metadata.
    """
    if not HAS_RAG or not vector_db:
        return []

    try:
        docs = vector_db.similarity_search(query, k=k)
        results = []
        for doc in docs:
            results.append({
                "content": doc.page_content,
                "source": doc.metadata.get("source", "Unknown")
            })
        return results
    except Exception as e:
        print(f"Error searching RAG: {e}")
        return []
