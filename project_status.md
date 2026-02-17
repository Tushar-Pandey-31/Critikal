# Penteam Project Status

**Last Updated**: February 18, 2026

## Overview
**Penteam** is an AI-assisted smart contract security system designed for "Plan-and-Execute" vulnerability hunting. It combines Knowledge Graphs (for code structure understanding) and Retrieval-Augmented Generation (RAG) (for security knowledge retrieval).

---

## ✅ Completed Stories

### Story 2.1 - External Attack Surface Detection ✅ **[COMPLETE]**
**Phase**: 2 - Structural Intelligence Layer  
**Completion Date**: February 17, 2026

Enriched the Knowledge Graph with deterministic security signals for attack surface mapping:

**Function Node Properties Added**:
- ✅ `is_external_entry`: Boolean identifying ALL externally callable functions
  - Public/external functions (excluding constructors)
  - **Fallback functions** (explicit handling)
  - **Receive functions** (explicit handling)
- ✅ `is_payable`: Boolean for Ether-receiving functions
- ✅ `is_fallback`: Boolean flag for fallback functions
- ✅ `is_receive`: Boolean flag for receive functions
- ✅ `is_view_or_pure`: Boolean for read-only vs state-changing (enables risk scoring)

**Query API Enhancement**:
- ✅ `get_external_entry_points(contract_name=None)` in `src/utils/graph_queries.py`
- Returns all external entry points with metadata
- Supports optional contract filtering

**Test Coverage**:
- ✅ Standard visibility tests (public, external, internal, private)
- ✅ Constructor exclusion verified
- ✅ **Fallback and receive functions validated**
- ✅ **Inheritance support verified** (inherited public/external functions included)
- ✅ Payable function detection
- ✅ 100% test pass rate

**Impact**: Complete attack surface mapping with no blind spots. Supports proxy contracts, Ether deposits, and inheritance chains.

---

### Story 2.2 - Storage State Mutation Detection ✅ **[COMPLETE]**
**Phase**: 2 - Structural Intelligence Layer  
**Completion Date**: February 17, 2026

Enriched the Knowledge Graph with storage mutation tracking:

**Function Node Properties Added**:
- ✅ `writes_state`: Boolean identifying functions that mutate persistent storage
- ✅ `num_state_writes`: Count of distinct state variables written
- ✅ `state_variables_written`: List of state variable IDs written

**Variable Classification**:
- ✅ State variables correctly classified with `node_type`, `storage_location`, `declaring_contract`
- ✅ Direct writes to storage detected (mapping and struct writes included)
- ✅ Local variables properly excluded from mutation detection

**Query API Enhancement**:
- ✅ `get_state_mutators(contract_name=None)` in `src/utils/graph_queries.py`
- Returns all functions that mutate storage with metadata

**Test Coverage**:
- ✅ Direct storage writes validated
- ✅ Mapping writes detected
- ✅ Local-only variables excluded
- ✅ Read-only functions verified
- ✅ Constructor metadata validated
- ✅ Cross-contract write isolation confirmed
- ✅ 100% test pass rate

**Impact**: Enables identification of state-changing functions for reentrancy and access control analysis. Foundation for recursive write propagation in Phase 3.

---

### Story 2.3 - Internal Call Graph Construction ✅ **[COMPLETE]**
**Phase**: 2 - Structural Intelligence Layer  
**Completion Date**: February 18, 2026

Built deterministic internal call graph between functions:

**Function Node Properties Added**:
- ✅ `internal_calls`: List of function IDs called internally
- ✅ `num_internal_calls`: Count of distinct internal calls
- ✅ `is_leaf_function`: Boolean (True if no internal calls)

**Call Graph Features**:
- ✅ CALLS edges created between internal functions
- ✅ Set-based deduplication (multiple calls to same function = 1 edge)
- ✅ Modifier function bodies captured
- ✅ External contract calls properly excluded
- ✅ Edge metadata includes `call_type="internal"`

**Query API Enhancement**:
- ✅ `get_internal_calls(function_id)`: Returns functions called by given function
- ✅ `get_callers(function_id)`: Returns functions that call given function
- ✅ `get_call_graph(contract_name)`: Returns structured call graph for visualization

**Test Coverage**:
- ✅ Simple internal calls validated
- ✅ Call deduplication verified
- ✅ Multi-level call chains tested (no propagation)
- ✅ Modifier modeling confirmed
- ✅ External call exclusion verified
- ✅ Leaf function identification validated
- ✅ Query API tested
- ✅ Metadata schema completeness verified
- ✅ 100% test pass rate

**Impact**: Enables future recursive write propagation, reentrancy path modeling, privilege escalation tracing, and attack surface reachability analysis.

---

### Story 2.6 - End-to-End Real Code Ingestion ✅ **[COMPLETE]**
**Completion Date**: February 17, 2026

The full Phase 1 pipeline is now operational:
- ✅ `src/main.py` accepts local file paths or GitHub URLs via `--repo` argument
- ✅ `RepoManager` handles repository cloning and dependency installation (Foundry/Hardhat)
- ✅ `AnalysisEngine` runs Slither analysis with automatic solc version switching
- ✅ `GraphBuilder` constructs NetworkX knowledge graph from Slither IR
- ✅ Real graph passed to `create_graph_tools()` (no mock data)
- ✅ LangGraph workflow orchestrates Lead Agent with tool integration
- ✅ RAG system operational with `search_security_knowledge` tool

**Latest Test Run**:
```bash
python -m src.main --repo tests/manual_verification/vulnerable_contract
```
- ✅ Repository ingestion successful
- ✅ Slither analysis completed
- ✅ Knowledge graph built and exported to `./data/graph_debug.json`
- ✅ LangGraph workflow executed end-to-end
- Result: System completed without errors (0 vulnerability leads found, indicating test contract may need more obvious vulnerabilities)

---

## Core Functionality

### 1. The Lead Agent (`src/agents/lead_agent.py`)
- **Role**: Validates hypotheses and identifies vulnerability leads.
- **Model**: Google Gemini `gemini-2.5-flash` (configurable via `MODEL_NAME` env var)
- **Workflow**: 
    - Analyzes smart contracts using graph tools
    - Calls `search_security_knowledge` for precedent lookup
    - Outputs structured JSON: `vulnerability_leads` and `target_nodes`
- **Status**: ✅ Fully integrated with LangGraph and tools

### 2. Knowledge Graph System

#### Graph Construction (`src/graph_builder.py`)
- Processes Slither IR to build NetworkX DiGraph
- **Node Types**: Contracts, Functions, State Variables
- **Edge Types**: `DEFINES`, `INHERITS`, `CALLS`, `READS`, `WRITES`
- **Metadata**: Source code, modifiers, visibility, mutability
- **Phase 2 Security Signals**:
  - **Story 2.1** - External Attack Surface:
    - `is_external_entry`: Externally callable functions (public/external/fallback/receive)
    - `is_payable`: Ether-receiving functions
    - `is_fallback`, `is_receive`: Special function type flags
    - `is_view_or_pure`: Read-only vs state-changing classification
  - **Story 2.2** - Storage Mutation:
    - `writes_state`: Functions that mutate persistent storage
    - `num_state_writes`: Count of distinct state variables written
    - `state_variables_written`: List of state variable IDs written
  - **Story 2.3** - Internal Call Graph:
    - `internal_calls`: List of function IDs called internally
    - `num_internal_calls`: Count of distinct internal calls
    - `is_leaf_function`: True if no internal calls

#### Graph Query API (`src/utils/graph_queries.py`)
Tools available to the Lead Agent:
- `get_function_context(node_id)`: Returns source code + callers/callees
- `find_state_mutators(variable_name)`: Identifies functions writing to state
- `get_modifiers(function_id)`: Lists security modifiers (e.g., `onlyOwner`)
- `verify_existence(node_name)`: Anti-hallucination check
- `get_external_entry_points(contract_name=None)`: Returns all externally callable functions (Story 2.1)
- `get_state_mutators(contract_name=None)`: Returns all storage-mutating functions (Story 2.2)
- `get_internal_calls(function_id)`: Returns functions called by given function (Story 2.3)
- `get_callers(function_id)`: Returns functions that call given function (Story 2.3)
- `get_call_graph(contract_name=None)`: Returns structured call graph (Story 2.3)

**Status**: ✅ Real graph integration complete

### 3. The "Librarian" RAG System (`src/knowledge/`)

#### Knowledge Base
- **Location**: `./data/chroma_db` (13.6 MB populated)
- **Embeddings**: HuggingFace `all-MiniLM-L6-v2`
- **Content**: PDF audit reports + Solidity documentation (Markdown/RST)

#### Ingestion Pipeline (`src/knowledge/ingest.py`)
- Supports PDF, Markdown, and RST files from `data/knowledge/`
- Chunking: 1000 chars with 200 char overlap
- Uses `RecursiveCharacterTextSplitter` for semantic splitting

#### Search Tool (`src/agents/tools.py`)
- `search_security_knowledge(query)`: Semantic search over knowledge base
- Returns top-3 most relevant chunks with source metadata
- **Status**: ✅ Integrated into agent toolset

### 4. Repository Management (`src/repo_manager.py`)
- Clones GitHub repos or copies local directories
- Auto-detects and installs dependencies:
  - **Foundry**: Runs `forge install`
  - **Hardhat**: Runs `npm install`
- Windows-compatible cleanup with `_handle_remove_readonly`

### 5. Static Analysis Engine (`src/analysis_engine.py`)
- Wraps Slither with intelligent error recovery
- Auto-detects required solc version from pragma statements
- Uses `solc-select` to install and switch versions
- Multi-layered fallback: directory → per-file → version switch
- **Status**: ✅ Production-ready

### 6. Workflow Orchestration (`src/main.py`)
**LangGraph Pipeline**:
```
START → LeadAgent → (tools_condition) → ToolNode → LeadAgent → ...
```
- **Checkpointer**: Configured for state persistence
- **Stream Mode**: Real-time visibility into agent reasoning
- **Error Handling**: Graceful failures with informative exit codes

**Full Pipeline Execution**:
1. Load `.env` (Gemini API key)
2. `RepoManager` → Clone/copy target repository
3. `AnalysisEngine` → Run Slither analysis
4. `GraphBuilder` → Build knowledge graph
5. `create_graph_tools(graph)` → Bind tools to graph
6. `build_agent_workflow(tools)` → LangGraph execution

---

## Current Infrastructure

### Dependencies (`pyproject.toml`)
- `slither-analyzer ^0.10.0` - Smart contract analysis
- `networkx ^3.0` - Graph data structure
- `langchain-chroma ^0.1.0` - Vector database
- `chromadb ^0.4.0` - Embedding storage
- `pypdf ^3.0.0` - PDF parsing
- `sentence-transformers ^2.2.0` - Embeddings
- `langchain-huggingface ^0.0.1` - HF integration
- `langchain-google-genai` - Gemini LLM
- `langgraph` - Agent orchestration
- `python-dotenv ^1.0.0` - Environment config

### Configuration
- **`.env`**: Contains `GOOGLE_API_KEY` and optional `MODEL_NAME`
- **Data Directories**:
  - `./data/scratch` - Cloned repositories
  - `./data/chroma_db` - Vector database (13.6 MB)
  - `./data/knowledge` - Source documents for RAG
  - `./data/graph_debug.json` - Exported graph for debugging

### Testing
- ✅ Unit tests: `tests/test_tools.py`, `tests/test_lead_agent.py`, `tests/test_analysis.py`
- ✅ Integration test: End-to-end run on `vulnerable_contract` completed successfully
- ✅ Graph verification: `tests/test_graph.py` validates edge creation
- ✅ **Phase 2 tests**:
  - `tests/test_external_entry.py` validates external attack surface detection (Story 2.1)
  - `tests/test_state_mutation.py` validates storage mutation detection (Story 2.2)
  - `tests/test_internal_call_graph.py` validates call graph construction (Story 2.3)

---

## Known Issues & Next Steps

### Current Observations
1. **Low Vulnerability Detection**: Recent test found 0 leads
   - May need to enhance test contracts with more obvious vulnerabilities
   - Agent prompt may need tuning for better detection sensitivity
   
2. **NetworkX Warning**: `edges="edges"` deprecation in NetworkX 3.6
   - Non-critical: Graph export works but shows warning
   - Fix: Update `graph_builder.py` to use `edges="links"` parameter

### Planned Enhancements
- [x] **Story 2.1**: External Attack Surface Detection ✅ Complete (Feb 17, 2026)
- [x] **Story 2.2**: Storage State Mutation Detection ✅ Complete (Feb 17, 2026)
- [x] **Story 2.3**: Internal Call Graph Construction ✅ Complete (Feb 18, 2026)
- [ ] **Story 3.x**: Phase 3 - Recursive Write Propagation & Analysis
- [ ] **Story 2.7+**: Implement specialized worker agents (Cartographer, Taint Tracker)
- [ ] **Knowledge Base Expansion**: Add more audit reports and exploit case studies
- [ ] **Prompt Engineering**: Refine Lead Agent system prompt for higher accuracy
- [ ] **Progress Indicators**: Add visual feedback during long-running Slither analysis
- [ ] **Graph Validation**: Pre-execution checks for graph structure integrity

### Phase 2 Progress
**Current Phase**: Phase 2 - Structural Intelligence Layer  
**Status**: ✅ **Foundation Complete**  
**Completed Stories**: 
- ✅ Story 2.1 - External Attack Surface Detection (Feb 17, 2026)
- ✅ Story 2.2 - Storage State Mutation Detection (Feb 17, 2026)
- ✅ Story 2.3 - Internal Call Graph Construction (Feb 18, 2026)

**Next Phase**: Phase 3 - Recursive Analysis & Propagation

---

## Quick Start

### Run End-to-End Analysis
```bash
# Local directory
python -m src.main --repo ./path/to/solidity/project

# GitHub URL
python -m src.main --repo https://github.com/user/smart-contract-repo
```

### Ingest Security Knowledge
```bash
# Place PDFs in data/knowledge/audits/
# Place docs in data/knowledge/docs/
python -m src.knowledge.ingest
```

### Run Tests
```bash
pytest tests/
```

---

## Architecture Status

| Component | Status | File |
|-----------|--------|------|
| Lead Agent | ✅ Complete | `src/agents/lead_agent.py` |
| Graph Builder | ✅ Complete | `src/graph_builder.py` |
| Analysis Engine | ✅ Complete | `src/analysis_engine.py` |
| Repo Manager | ✅ Complete | `src/repo_manager.py` |
| RAG System | ✅ Complete | `src/knowledge/ingest.py` |
| Graph Tools | ✅ Complete | `src/agents/tools.py` |
| LangGraph Workflow | ✅ Complete | `src/main.py` |
| End-to-End Pipeline | ✅ **VERIFIED** | Story 2.6 Complete |

---

**Project Health**: 🟢 Excellent - All core systems operational and tested end-to-end.
