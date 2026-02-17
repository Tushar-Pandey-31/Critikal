# Penteam 🛡️

**AI-Assisted Smart Contract Security System**

Penteam is a "Plan-and-Execute" vulnerability hunting system that combines Knowledge Graphs for code structure understanding and Retrieval-Augmented Generation (RAG) for security knowledge retrieval.

[![Phase 2 Complete](https://img.shields.io/badge/Phase%202-Foundation%20Complete-success)]()
[![Python 3.13+](https://img.shields.io/badge/python-3.13+-blue.svg)]()
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)]()

---

## 🚀 Features

### Phase 2 - Structural Intelligence Layer ✅ **COMPLETE**

#### Story 2.1 - External Attack Surface Detection
- ✅ Identifies ALL externally callable functions (public, external, fallback, receive)
- ✅ Payable function detection for Ether-receiving analysis
- ✅ Inheritance support for proxy contracts
- ✅ Read-only vs state-changing classification

#### Story 2.2 - Storage State Mutation Detection
- ✅ Tracks functions that mutate persistent storage
- ✅ Distinguishes state variables from local variables
- ✅ Mapping and struct write detection
- ✅ Foundation for reentrancy and access control analysis

#### Story 2.3 - Internal Call Graph Construction
- ✅ Deterministic call relationships between functions
- ✅ Modifier function body capture
- ✅ Leaf function identification
- ✅ Enables future recursive analysis and propagation

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        Main Pipeline                         │
│  Repository → Slither Analysis → Knowledge Graph → Agent    │
└─────────────────────────────────────────────────────────────┘

┌────────────────┐     ┌──────────────────┐     ┌─────────────┐
│  Repo Manager  │────▶│ Analysis Engine  │────▶│   Graph     │
│  (Clone/Copy)  │     │  (Slither + IR)  │     │  Builder    │
└────────────────┘     └──────────────────┘     └──────┬──────┘
                                                        │
                       ┌────────────────────────────────┘
                       │
                       ▼
        ┌──────────────────────────────────────────┐
        │       NetworkX Knowledge Graph           │
        │  ┌────────────────────────────────────┐  │
        │  │ Nodes: Contracts, Functions, Vars  │  │
        │  │ Edges: DEFINES, CALLS, READS,      │  │
        │  │        WRITES, INHERITS            │  │
        │  │ Metadata: Security signals (2.1-3) │  │
        │  └────────────────────────────────────┘  │
        └──────────────┬───────────────────────────┘
                       │
                       ▼
        ┌──────────────────────────────┐
        │     Query API (Tools)        │
        │  - get_external_entry_points │
        │  - get_state_mutators        │
        │  - get_internal_calls        │
        │  - get_callers               │
        │  - get_call_graph            │
        └──────────────┬───────────────┘
                       │
                       ▼
        ┌──────────────────────────────┐
        │      Lead Agent (LangGraph)  │
        │   Gemini 2.5 Flash + RAG     │
        └──────────────────────────────┘
```

---

## 📦 Installation

### Prerequisites
- Python 3.13+
- Solidity compiler (`solc-select` for version management)
- Slither analyzer

### Setup

```bash
# Clone repository
git clone https://github.com/yourusername/penteam.git
cd penteam

# Install Python dependencies
pip install -e .

# Install Slither
pip install slither-analyzer

# Set up environment
cp .env.example .env
# Add your GOOGLE_API_KEY to .env

# (Optional) Ingest security knowledge
python -m src.knowledge.ingest
```

---

## 🎯 Quick Start

### Analyze a Smart Contract

```bash
# Local directory
python -m src.main --repo ./path/to/solidity/project

# GitHub repository
python -m src.main --repo https://github.com/user/contract-repo
```

### Run Tests

```bash
# All tests
pytest tests/ -v

# Specific phase
pytest tests/test_external_entry.py -v      # Story 2.1
pytest tests/test_state_mutation.py -v      # Story 2.2
pytest tests/test_internal_call_graph.py -v # Story 2.3
```

---

## 📊 Knowledge Graph Schema

### Node Types

- **Contract**: Smart contract definitions
- **Function**: Contract functions with comprehensive metadata
- **StateVariable**: Persistent storage variables

### Function Metadata (Phase 2 Complete)

```python
{
    # Story 2.1 - External Attack Surface
    "is_external_entry": bool,      # Externally callable?
    "is_view_or_pure": bool,        # Read-only?
    "is_payable": bool,             # Accepts Ether?
    
    # Story 2.2 - Storage Mutation
    "writes_state": bool,           # Mutates storage?
    "num_state_writes": int,        # How many variables?
    "state_variables_written": [],  # Which variables?
    
    # Story 2.3 - Internal Call Graph
    "internal_calls": [],           # What does it call?
    "num_internal_calls": int,      # How many calls?
    "is_leaf_function": bool        # No internal calls?
}
```

### Edge Types

- `DEFINES`: Contract → Function/Variable
- `INHERITS`: Contract → Parent Contract
- `CALLS`: Function → Function (internal)
- `READS`: Function → State Variable
- `WRITES`: Function → State Variable

---

## 🧪 Testing

### Test Coverage

- ✅ **Story 2.1**: External attack surface detection (12 test cases)
- ✅ **Story 2.2**: Storage mutation detection (8 test cases)
- ✅ **Story 2.3**: Internal call graph (8 test cases)
- ✅ Integration tests for end-to-end pipeline

All tests maintain **100% pass rate** for Phase 2 functionality.

---

## 📁 Project Structure

```
penteam/
├── src/
│   ├── agents/
│   │   ├── lead_agent.py      # Main AI agent (Gemini)
│   │   └── tools.py           # Graph query tools
│   ├── knowledge/
│   │   └── ingest.py          # RAG knowledge ingestion
│   ├── utils/
│   │   └── graph_queries.py   # Query API
│   ├── analysis_engine.py     # Slither wrapper
│   ├── graph_builder.py       # Knowledge graph construction
│   ├── repo_manager.py        # Repository handling
│   └── main.py                # Entry point
├── tests/
│   ├── contracts/             # Test Solidity contracts
│   ├── test_external_entry.py
│   ├── test_state_mutation.py
│   └── test_internal_call_graph.py
├── data/
│   ├── knowledge/             # RAG source documents
│   │   ├── audits/           # PDF audit reports
│   │   └── docs/             # Solidity documentation
│   └── chroma_db/            # Vector database
├── pyproject.toml
├── .env.example
└── README.md
```

---

## 🔮 Roadmap

### ✅ Phase 2 - Structural Intelligence Layer (COMPLETE)
- [x] Story 2.1: External Attack Surface Detection
- [x] Story 2.2: Storage State Mutation Detection
- [x] Story 2.3: Internal Call Graph Construction

### 📋 Phase 3 - Recursive Analysis & Propagation (NEXT)
- [ ] Recursive write propagation through call chains
- [ ] Reentrancy path detection
- [ ] Privilege escalation modeling
- [ ] Entry → mutation path analysis
- [ ] Attack surface reachability modeling

### 🔜 Future Enhancements
- [ ] Specialized worker agents (Cartographer, Taint Tracker)
- [ ] Enhanced RAG knowledge base
- [ ] Improved agent prompting
- [ ] Web UI for graph visualization

---

## 🤝 Contributing

Contributions are welcome! Please ensure:
- All tests pass: `pytest tests/ -v`
- Code follows existing patterns
- New features include comprehensive tests

---

## 📄 License

MIT License - see LICENSE file for details

---

## 📚 Documentation

For detailed technical documentation, see:
- **[project_status.md](./project_status.md)**: Complete project status and implementation details
- **Story Walkthroughs**: Located in `.gemini/antigravity/brain/` (if available)

---

## 🙏 Acknowledgments

Built with:
- [Slither](https://github.com/crytic/slither) - Smart contract static analyzer
- [LangGraph](https://github.com/langchain-ai/langgraph) - Agent orchestration
- [Google Gemini](https://ai.google.dev/) - Large language model
- [NetworkX](https://networkx.org/) - Graph data structures

---

**Status**: 🟢 Phase 2 Foundation Complete - Ready for Phase 3 Development

**Last Updated**: February 18, 2026
