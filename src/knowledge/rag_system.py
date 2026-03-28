"""
RAG System — exploit-first retrieval for Critikal findings.

Queries ChromaDB for historical exploit precedent. Returns structured
matches with protocol, vulnerability class, and attack details.

Confidence scoring:
- High-quality match (same vuln class + similar protocol): +15 confidence
- Moderate match (same vuln class, different protocol): +5 confidence
- No precedent found: -10 confidence (penalize unsubstantiated claims)
"""

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
        _collection_count = vector_db._collection.count()
        HAS_RAG = _collection_count > 0
        if HAS_RAG:
            print(f"[RAG] Loaded {_collection_count} chunks from ChromaDB")
        else:
            print(f"[RAG] ChromaDB is empty. Run: poetry run python src/knowledge/ingest.py")
    else:
        print(f"[RAG] DB not found at {DB_PATH}. Run: poetry run python src/knowledge/ingest.py")
        vector_db = None
        HAS_RAG = False
except Exception as e:
    print(f"[RAG] Init error: {e}")
    vector_db = None
    HAS_RAG = False


def search_security_knowledge(query: str, k: int = 5) -> List[Dict[str, Any]]:
    """
    Query the vector database for exploit precedent.
    Returns list of dicts with content, source, and metadata.
    """
    if not HAS_RAG or not vector_db:
        return []

    try:
        results = vector_db.similarity_search_with_relevance_scores(query, k=k)
        matches = []
        for doc, score in results:
            # Filter out noise — MiniLM scores on exploit data range ~0.15-0.5
            if score < 0.15:
                continue
            matches.append({
                "content": doc.page_content,
                "source": doc.metadata.get("source", "Unknown"),
                "protocol": doc.metadata.get("protocol", ""),
                "vulnerability_class": doc.metadata.get("vulnerability_class", ""),
                "relevance_score": round(score, 3),
            })
        return matches
    except Exception as e:
        print(f"[RAG] Search error: {e}")
        return []


def _build_exploit_query(finding) -> str:
    """Build an exploit-focused query from a Finding object."""
    parts = []
    
    vuln_class = getattr(finding, "vulnerability_class", "") or ""
    hypothesis = getattr(finding, "hypothesis", "") or ""
    contract = getattr(finding, "affected_contract", "") or ""
    function = getattr(finding, "affected_function", "") or ""
    
    # Lead with vulnerability class — most important for exploit matching
    if vuln_class:
        # Expand common abbreviated classes
        expanded = vuln_class.replace("_", " ")
        parts.append(f"{expanded} exploit vulnerability")
    
    # Add function-level context
    if function:
        parts.append(f"in function {function}")
    
    # Add hypothesis (truncated — embedding models have limits)
    if hypothesis:
        # Extract the key action/bug from hypothesis
        parts.append(hypothesis[:150])
    
    # Add contract type hint
    if contract:
        parts.append(f"contract {contract}")
    
    return " ".join(parts) if parts else f"{contract} {function} exploit"


def _compute_rag_confidence(matches: list, finding) -> int:
    """
    Compute RAG confidence based on match QUALITY, not just quantity.
    
    Returns:
        0-100 confidence score for the RAG dimension
    """
    if not matches:
        return 0
    
    finding_vuln = (getattr(finding, "vulnerability_class", "") or "").lower().replace("_", " ")
    
    high_quality = 0
    moderate = 0
    
    for match in matches:
        match_vuln = (match.get("vulnerability_class", "") or "").lower().replace("_", " ")
        relevance = match.get("relevance_score", 0)
        
        # MiniLM scores on exploit data range ~0.15-0.5
        if relevance >= 0.35 and match_vuln and finding_vuln:
            # Check if same vuln class
            if match_vuln == finding_vuln or match_vuln in finding_vuln or finding_vuln in match_vuln:
                high_quality += 1
            else:
                moderate += 1
        elif relevance >= 0.2:
            moderate += 1
    
    if high_quality >= 2:
        return 100  # Strong precedent — this vuln class is well-known
    elif high_quality == 1:
        return 80   # Single strong match
    elif moderate >= 3:
        return 60   # Several moderate matches
    elif moderate >= 1:
        return 40   # Weak precedent
    else:
        return 0    # No relevant matches


async def rag_mandatory_sweep(findings: list) -> list:
    """
    Mandatory RAG sweep over all findings.
    Enriches each finding with rag_matches and confidence_rag_match.
    Applies confidence boost for precedent, penalty for no precedent.
    """
    if not HAS_RAG or not vector_db:
        print("[Step 4.6] RAG not available — skipping mandatory sweep")
        return findings

    import asyncio
    
    async def process_finding(finding):
        query = _build_exploit_query(finding)
        
        # RAG search is sync, wrap in to_thread
        matches = await asyncio.to_thread(search_security_knowledge, query, 5)
        
        # Store matches on finding
        finding.rag_matches = [
            {"source": m["source"], "snippet": m["content"][:200],
             "protocol": m.get("protocol", ""), "relevance": m.get("relevance_score", 0)}
            for m in matches
        ]
        
        # Compute quality-weighted confidence
        finding.confidence_rag_match = _compute_rag_confidence(matches, finding)
        
        # Apply confidence adjustment
        if matches:
            best_relevance = max(m.get("relevance_score", 0) for m in matches)
            if best_relevance >= 0.6:
                # Strong historical precedent — boost
                old_conf = getattr(finding, "confidence", 50)
                finding.confidence = min(100, old_conf + 15)
                if not hasattr(finding, "evidence_tags"):
                    finding.evidence_tags = []
                if "[RAG-MATCH]" not in finding.evidence_tags:
                    finding.evidence_tags.append("[RAG-MATCH]")
                return "strong"
            elif best_relevance >= 0.4:
                old_conf = getattr(finding, "confidence", 50)
                finding.confidence = min(100, old_conf + 5)
                if not hasattr(finding, "evidence_tags"):
                    finding.evidence_tags = []
                if "[RAG-MATCH]" not in finding.evidence_tags:
                    finding.evidence_tags.append("[RAG-MATCH]")
                return "moderate"
        else:
            # No precedent — penalize (novel claim needs stronger proof)
            old_conf = getattr(finding, "confidence", 50)
            finding.confidence = max(0, old_conf - 10)
            return "none"
        return "weak"

    results = await asyncio.gather(*[process_finding(f) for f in findings])
    
    strong = sum(1 for r in results if r == "strong")
    moderate = sum(1 for r in results if r == "moderate")
    none_count = sum(1 for r in results if r == "none")
    
    print(f"[Step 4.6] RAG sweep: {len(findings)} findings — "
          f"{strong} strong precedent, {moderate} moderate, {none_count} no match (-10 penalty)")
    
    return findings
