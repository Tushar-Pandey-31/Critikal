# Penteam 🛡️

**AI-Assisted Smart Contract Security System**

Penteam is a "Plan-and-Execute" vulnerability hunting system that combines Knowledge Graphs for code structure understanding and Retrieval-Augmented Generation (RAG) for security knowledge retrieval.

[![Phase 3 Complete](https://img.shields.io/badge/Phase%203-Analysis%20Complete-success)]()
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

#### Story 2.4 - Access Control Modeling
- ✅ Extracts modifier logic and pattern classification
- ✅ Maps function access profiles (protected vs. unprotected)
- ✅ Detects privileged roles (owner, admin, etc.)
- ✅ Identifies unprotected state mutators

---

### Phase 3 - Deep Analysis Layer ✅ **COMPLETE**

#### Story 3.1 - Recursive Write Propagation
- ✅ Tracks state mutations through deep call chains
- ✅ Handles cycle/recursion safety in propagation
- ✅ Calculates min-depth to state-writing callees

#### Story 3.2 - Phase-based External Call Classification
- ✅ Production-grade CEI (Checks-Effects-Interactions) analysis
- ✅ Models execution in 3 phases (Pre-Modifier, Body, Post-Modifier)
- ✅ Understands modifier stacking and complex write order

#### Story 3.3 - Reachability Analysis
- ✅ DFS-based reachability from all external entry points
- ✅ Identifies live code vs. dead code in the attack surface
- ✅ Maps reachability paths through internal call graph

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
        │  │ Metadata: Phase 2/3 Security Sig.  │  │
        │  └────────────────────────────────────┘  │
        └──────────────┬───────────────────────────┘
                       │
                       ▼
        ┌──────────────────────────────┐
        │     Query API (Tools)        │
        │  - get_external_entry_points │
        │  - get_state_mutators        │
        │  - get_external_call_functions│
        │  - get_internal_calls        │
        │  - get_access_control_summary│
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

# (Optional) Ingest security knowledge base for RAG
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

# Specific components
pytest tests/test_reachability.py -v       # Story 3.3
pytest tests/test_external_calls.py -v     # Story 3.2
pytest tests/test_write_propagation.py -v  # Story 3.1
```

---

## 📊 Knowledge Graph Schema

### Node Types

- **Contract**: Smart contract definitions
- **Function**: Contract functions with comprehensive metadata
- **Modifier**: Access control modifiers as first-class nodes
- **StateVariable**: Persistent storage variables

### Function Metadata (Phase 3 Complete)

```python
{
    # Story 2.1-3 Core
    "is_external_entry": bool,      # Externally callable?
    "is_payable": bool,             # Accepts Ether?
    "writes_state": bool,           # Mutates storage?
    
    # Story 3.1 - Recursive Writes
    "propagated_state_variables": [],# List of ALL written vars (direct+indirect)
    "indirect_writes_state": bool,  # Writes ONLY via callees?
    
    # Story 3.2 - CEI Violation
    "state_write_after_external_call": bool, # Violation found?
    "makes_external_call": bool,    # Performs external call?
    
    # Story 3.3 - Reachability
    "reachable_from_external_entry": bool, # Alive in attack surface?
    "entry_points": ["Vault::deposit"]     # Reachable from these entries
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

- ✅ **Story 2.1-4**: Foundation layer (69 tests)
- ✅ **Story 3.1-3**: Deep analysis layer (55 tests)
- ✅ **Integration**: End-to-end repository ingestion pipeline

All tests maintain **100% pass rate** for Phase 3 functionality.

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
│   ├── test_reachability.py
│   ├── test_external_calls.py
│   └── test_write_propagation.py
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

### ✅ Phase 3 - Deep Analysis Layer (COMPLETE)
- [x] Story 3.1: Recursive Write Propagation
- [x] Story 3.2: Phase-based CEI Detection
- [x] Story 3.3: Reachability Analysis

### 📋 Phase 4 - Multi-Agent Orchestration & Taint Analysis (NEXT)
- [ ] Specialized worker agents (Cartographer, Taint Tracker)
- [ ] Automated taint analysis for user-controlled inputs
- [ ] Cross-contract reentrancy modeling
- [ ] Enhanced RAG knowledge base for specific exploit patterns

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
- **Walkthroughs**: Narrative documentation of major feature implementations

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
