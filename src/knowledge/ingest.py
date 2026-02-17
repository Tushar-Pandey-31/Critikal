import os
from langchain_chroma import Chroma
from langchain_huggingface import HuggingFaceEmbeddings
from langchain_community.document_loaders import PyPDFLoader, DirectoryLoader, TextLoader
from langchain_text_splitters import RecursiveCharacterTextSplitter

# 1. Configuration
DATA_PATH = os.path.join(os.getcwd(), "data", "knowledge")
DB_PATH = os.path.join(os.getcwd(), "data", "chroma_db")

def ingest_knowledge():
    print("📚 Starting Knowledge Ingestion...")
    
    # 2. Load Documents (PDF Audits & Markdown Docs)
    # Audits
    pdf_loader = DirectoryLoader(os.path.join(DATA_PATH, "audits"), glob="*.pdf", loader_cls=PyPDFLoader)
    # Docs - supporting .md and .rst
    # Using autodetect encoding or silent errors
    md_loader = DirectoryLoader(os.path.join(DATA_PATH, "docs"), glob="**/*.md", loader_cls=TextLoader, loader_kwargs={'autodetect_encoding': True}, silent_errors=True)
    rst_loader = DirectoryLoader(os.path.join(DATA_PATH, "docs"), glob="**/*.rst", loader_cls=TextLoader, loader_kwargs={'autodetect_encoding': True}, silent_errors=True)
    
    raw_docs = []
    try:
        raw_docs += pdf_loader.load()
    except Exception as e:
        print(f"⚠️ Warning loading PDFs: {e}")
        
    try:
        raw_docs += md_loader.load()
    except Exception as e:
        print(f"⚠️ Warning loading MDs: {e}")

    try:
        raw_docs += rst_loader.load()
    except Exception as e:
        print(f"⚠️ Warning loading RSTs: {e}")

    print(f"🔹 Loaded {len(raw_docs)} raw documents.")

    if not raw_docs:
        print("❌ No documents found. Exiting.")
        return

    # 3. Chunking Strategy
    text_splitter = RecursiveCharacterTextSplitter(
        chunk_size=1000,
        chunk_overlap=200,
        separators=["\n## ", "\n\n", "\n", " ", ""]
    )
    chunks = text_splitter.split_documents(raw_docs)
    print(f"🔹 Split into {len(chunks)} knowledge chunks.")

    # 4. Embed & Store
    print("🔹 Generating embeddings (this may take a while)...")
    embedding_function = HuggingFaceEmbeddings(model_name="all-MiniLM-L6-v2")
    
    Chroma.from_documents(
        documents=chunks,
        embedding=embedding_function,
        persist_directory=DB_PATH
    )
    print(f"✅ Knowledge Base saved to {DB_PATH}")

if __name__ == "__main__":
    ingest_knowledge()
