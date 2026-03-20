from typing import List, Dict, Any
from pathlib import Path
from langchain_chroma import Chroma
from langchain_huggingface import HuggingFaceEmbeddings
from src.knowledge.paths import CHROMA_DB_PATH

DB_PATH = str(CHROMA_DB_PATH)

# Initialize shared components
try:
    if Path(DB_PATH).exists():
        _embedding_function = HuggingFaceEmbeddings(model_name="all-MiniLM-L6-v2")
        vector_db = Chroma(persist_directory=DB_PATH, embedding_function=_embedding_function)
        HAS_RAG = True
    else:
        print(f"Warning: RAG DB not found at {DB_PATH}. Running without RAG results.")
        vector_db = None
        HAS_RAG = False
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


def rag_batch_validate(findings: list, boost: int = 5, penalty: int = -10) -> list:
    """
    v2 Epic 5: Batch-validate findings against RAG knowledge base.

    For each finding, queries the RAG DB using vulnerability class + hypothesis.
    Enriches findings with:
      - rag_matches: list of matched historical vulns
      - confidence_rag_match: 0-100 based on match quality
      - confidence adjustment: boost per strong match, penalty for zero matches

    Returns the same list of findings, mutated in-place.
    """
    if not HAS_RAG or not vector_db:
        print("[Step 4.6] RAG not available — skipping batch validation")
        return findings

    validated = 0
    boosted = 0
    penalized = 0

    for finding in findings:
        vuln_class = getattr(finding, "vulnerability_class", "") or ""
        hypothesis = getattr(finding, "hypothesis", "") or ""
        contract = getattr(finding, "affected_contract", "") or ""
        function = getattr(finding, "affected_function", "") or ""

        # Build a targeted query combining vulnerability class + hypothesis
        query_parts = []
        if vuln_class:
            query_parts.append(f"vulnerability: {vuln_class}")
        if hypothesis:
            query_parts.append(hypothesis[:200])
        if contract and function:
            query_parts.append(f"in {contract}.{function}")

        query = " ".join(query_parts) if query_parts else f"{contract} {function} exploit"

        matches = search_security_knowledge(query, k=3)

        # Score match quality (rough heuristic: more matches + longer content = higher)
        match_score = 0
        if matches:
            for m in matches:
                content_len = len(m.get("content", ""))
                if content_len > 200:
                    match_score += 40  # Strong match
                elif content_len > 50:
                    match_score += 20  # Moderate match
                else:
                    match_score += 5   # Weak match
            match_score = min(100, match_score)

        # Enrich the finding
        finding.rag_matches = [
            {"source": m["source"], "snippet": m["content"][:150]}
            for m in matches
        ]
        finding.confidence_rag_match = match_score

        # Adjust confidence
        old_conf = finding.confidence
        if match_score >= 60:
            finding.confidence = min(100, finding.confidence + boost)
            boosted += 1
        elif match_score == 0:
            finding.confidence = max(10, finding.confidence + penalty)
            penalized += 1

        validated += 1

    print(
        f"[Step 4.6] RAG validation: {validated} finding(s) checked, "
        f"{boosted} boosted, {penalized} penalized"
    )
    return findings

