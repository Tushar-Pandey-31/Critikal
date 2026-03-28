"""
Exploit-aware knowledge ingestion for Critikal RAG.

Replaces the old Solidity-docs ingest with exploit-first chunking:
- Each exploit file is ONE chunk (not split by arbitrary char count)
- Metadata tags: protocol, vuln_class, date, loss_amount, source
- Old Solidity docs are excluded from ingestion
"""

import os
import re
from pathlib import Path
from langchain_chroma import Chroma
from langchain_huggingface import HuggingFaceEmbeddings
from langchain_text_splitters import RecursiveCharacterTextSplitter
from langchain_core.documents import Document

# Paths
DATA_PATH = Path(os.getcwd()) / "data" / "knowledge"
DB_PATH = Path(os.getcwd()) / "data" / "chroma_db"
EXPLOITS_DIR = DATA_PATH / "exploits"
DOCS_DIR = DATA_PATH / "docs"


def _parse_exploit_metadata(content: str, filepath: str) -> dict:
    """Extract structured metadata from exploit markdown frontmatter."""
    meta = {"source": filepath}
    
    patterns = {
        "protocol": r"\*\*Protocol:\*\*\s*(.+)",
        "vulnerability_class": r"\*\*Vulnerability Class:\*\*\s*(.+)",
        "date": r"\*\*Date:\*\*\s*(.+)",
        "loss": r"\*\*Loss:\*\*\s*(.+)",
        "data_source": r"\*\*Source:\*\*\s*(.+)",
    }
    
    for key, pattern in patterns.items():
        match = re.search(pattern, content)
        if match:
            meta[key] = match.group(1).strip()
    
    return meta


def _load_exploit_documents() -> list[Document]:
    """Load exploit files as documents with metadata. Each file = 1 document."""
    docs = []
    
    if not EXPLOITS_DIR.exists():
        print(f"⚠️  Exploits directory not found at {EXPLOITS_DIR}")
        print(f"   Run: poetry run python scripts/scrape_exploits.py")
        return docs
    
    for filepath in sorted(EXPLOITS_DIR.glob("*.md")):
        if filepath.name.startswith("_"):
            continue  # skip index files
        
        content = filepath.read_text(encoding="utf-8", errors="replace")
        if len(content) < 50:
            continue
        
        meta = _parse_exploit_metadata(content, str(filepath))
        docs.append(Document(page_content=content, metadata=meta))
    
    return docs


def _load_security_docs() -> list[Document]:
    """Load only security-relevant docs (not Solidity language docs)."""
    docs = []
    
    # Whitelist: only files that contain actual security/exploit knowledge
    security_filenames = {
        "satisloeb_kill_gates.md",
        "security-considerations.rst",
    }
    
    if not DOCS_DIR.exists():
        return docs
    
    for filepath in DOCS_DIR.iterdir():
        if filepath.name in security_filenames:
            content = filepath.read_text(encoding="utf-8", errors="replace")
            docs.append(Document(
                page_content=content,
                metadata={"source": str(filepath), "type": "security_doc"},
            ))
    
    return docs


def ingest_knowledge():
    """Main ingestion entry point. Builds ChromaDB from exploit data."""
    print("═══════════════════════════════════════════════")
    print("  Critikal RAG Knowledge Ingestion")
    print("═══════════════════════════════════════════════")
    
    # 1. Load exploit documents
    print("\n[1/4] Loading exploit documents...")
    exploit_docs = _load_exploit_documents()
    print(f"       Loaded {len(exploit_docs)} exploit records")
    
    # 2. Load security-relevant docs only
    print("[2/4] Loading security-relevant docs...")
    sec_docs = _load_security_docs()
    print(f"       Loaded {len(sec_docs)} security doc(s)")
    
    all_docs = exploit_docs + sec_docs
    if not all_docs:
        print("❌ No documents found. Run scripts/scrape_exploits.py first.")
        return
    
    # 3. Chunk — exploit docs stay small (most are <2K) so split gently
    # Security docs are larger and need splitting
    print("[3/4] Chunking documents...")
    
    # Exploit docs: split only if > 2000 chars, preserve exploit boundary
    exploit_splitter = RecursiveCharacterTextSplitter(
        chunk_size=2000,
        chunk_overlap=200,
        separators=["\n## ", "\n\n", "\n"],
    )
    
    # Security docs: split more aggressively
    doc_splitter = RecursiveCharacterTextSplitter(
        chunk_size=1000,
        chunk_overlap=200,
        separators=["\n## ", "\n### ", "\n\n", "\n"],
    )
    
    chunks = []
    for doc in exploit_docs:
        if len(doc.page_content) > 2000:
            chunks.extend(exploit_splitter.split_documents([doc]))
        else:
            chunks.append(doc)  # keep as single chunk
    
    for doc in sec_docs:
        chunks.extend(doc_splitter.split_documents([doc]))
    
    print(f"       {len(chunks)} total chunks")
    
    # 4. Nuke old DB and rebuild
    print("[4/4] Building embeddings & ChromaDB...")
    if DB_PATH.exists():
        import shutil
        shutil.rmtree(DB_PATH)
        print("       Cleared old ChromaDB")
    
    embedding_function = HuggingFaceEmbeddings(model_name="all-MiniLM-L6-v2")
    
    Chroma.from_documents(
        documents=chunks,
        embedding=embedding_function,
        persist_directory=str(DB_PATH),
    )
    
    # Summary stats
    vuln_classes = set()
    protocols = set()
    for doc in exploit_docs:
        vc = doc.metadata.get("vulnerability_class", "")
        if vc:
            vuln_classes.add(vc)
        proto = doc.metadata.get("protocol", "")
        if proto:
            protocols.add(proto)
    
    print(f"\n  ✅ Knowledge base built at {DB_PATH}")
    print(f"     {len(exploit_docs)} exploits, {len(sec_docs)} security docs")
    print(f"     {len(chunks)} total chunks in ChromaDB")
    print(f"     {len(vuln_classes)} vulnerability classes")
    print(f"     {len(protocols)} unique protocols")


if __name__ == "__main__":
    ingest_knowledge()
