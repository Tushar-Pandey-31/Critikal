# Critikal Architecture

Critikal is an autonomous security research agent — a Claude Code-style agentic loop
specialized for smart contract hacking. It uses a multi-turn LLM reasoning loop with
29 tools to drive a full security research workflow: recon → attack surface mapping →
hypothesis formation → validation → PoC exploit generation → audit report.

---

## System Overview

```
User
  │
  ├── critikal --repo <url>      → Headless mode
  ├── critikal --interactive     → TUI (Textual)
  └── critikal --headless "..."  → Custom prompt

         src/cli.py (entry point dispatcher)
              │
      ┌───────┴────────┐
      │                │
 HeadlessRunner    CritikalApp (TUI)
 headless.py       tui/app.py
      │                │
      └───────┬─────────┘
              │
         QueryLoop
         query_loop.py
         ┌────────────────────────────────────┐
         │  Streaming LLM (provider-agnostic) │
         │  PermissionHandler (ask/auto/yolo) │
         │  AutoCompactor (90% threshold)     │
         │  SessionMemory (per-engagement)    │
         │  Tool execution (29 tools)         │
         └────────────────────────────────────┘
              │
         ToolContext (shared mutable state)
         context.py
         ┌─────────────────────────────────────┐
         │  graph: nx.DiGraph (Slither output) │
         │  findings: list[Finding]            │
         │  repo_path, repo_url                │
         │  recon_context, contract_names      │
         │  cost_tracker, event_bus, memory    │
         │  read_file_state (write guard)      │
         └─────────────────────────────────────┘
```

---

## Core Agent Layer (`src/agent/`)

### QueryLoop (`query_loop.py`)

The agentic reasoning loop. Sends messages to an LLM with tools, executes tool calls,
feeds results back, and continues until the model stops requesting tools or limits are hit.

**Per-turn flow:**
1. Check AutoCompactor (compact at 90% context capacity)
2. Call LLM via streaming (`astream`) — emits `MESSAGE_CHUNK` events in real time
3. Parse response → `(assistant_text, tool_calls)`
4. If no tool calls → return text (end turn)
5. Execute tool calls (permission-gated, parallel per turn)
6. Apply tool result budget (80K chars max, head+tail truncation)
7. Append tool results → loop
8. Check cost budget; extract memories every N turns

**Error recovery layers:**
- Rate limit → exponential backoff (2s, 4s, 8s)
- Prompt too long → reactive compact → fallback model
- Max output tokens → retry up to 3×
- Persistent failure → switch to fallback model (e.g., `claude-sonnet-4-6` → `gemini-3-flash-preview`)

**Defaults:**
- Model: `claude-sonnet-4-6` (env: `AGENT_MODEL_NAME`)
- Max turns: 200
- Tool result budget: 80,000 chars

### ToolContext (`context.py`)

Shared mutable state passed to every tool execution. The single source of truth for a session.

Key fields:
- `graph` — `nx.DiGraph` built from Slither IR (set by `ingest_repo`)
- `findings` — accumulated `Finding` objects
- `repo_path` — local path to cloned/copied repo
- `recon_context` — output from `ReconWorker`
- `cost_tracker` — running token/cost totals
- `event_bus` — decouples loop from UI
- `memory` — `SessionMemory` for this engagement
- `read_file_state` — read-before-write enforcement (inspired by Claude Code)

### Tool ABC (`tool.py`)

Every capability implements `Tool`:

```python
class Tool(ABC):
    def name(self) -> str              # Unique identifier
    def description(self) -> str       # Shown to LLM
    def permission_level(self) -> PermissionLevel  # none/read_only/write/execute/dangerous
    def input_schema(self) -> dict     # JSON Schema for params
    def is_available(self, ctx) -> bool  # Whether tool is offered (e.g., graph tools hide when no graph)
    async def execute(self, params, ctx) -> ToolResult
```

### PermissionHandler (`permissions.py`)

Three modes:
- `yolo` — auto-approve everything (headless/Docker)
- `auto` — auto-approve up to `EXECUTE`; prompt for `DANGEROUS`
- `ask` — auto-approve `NONE`/`READ_ONLY`; prompt for everything else

### AutoCompactor (`auto_compact.py`)

Proactive context management. Estimates token usage (4 chars/token). At 90% of the
model's context window, summarizes older messages into a condensed block, keeping the
last 10 messages verbatim. Circuit breaker disables after 3 failures.

### EventBus (`events.py`)

Decouples the query loop from the UI. The loop emits events; the TUI or headless
stdout consumer subscribes and renders them.

Event types: `MESSAGE_CHUNK`, `MESSAGE_COMPLETE`, `TOOL_START`, `TOOL_COMPLETE`,
`FINDING_ADDED`, `COST_UPDATE`, `WORKER_SPAWNED`, `WORKER_COMPLETE`, `TURN_COMPLETE`,
`COMPACT`, `STATUS`, `ERROR`

### SessionMemory (`memory/session_memory.py`)

Per-engagement memory persisted at `~/.critikal/memory/<engagement_id>/session.jsonl`.

- Extracted every 10 turns via a lightweight LLM sideQuery
- Types: `finding`, `recon`, `tactic`, `config`, `feedback`, `reference`
- Injected into system prompt at session start (top-K by keyword relevance)
- Post-session consolidation via `AutoDream` → `consolidated.md`

---

## Tool Catalog (`src/agent/tools/`)

### Pipeline Tools — Security Analysis

| Tool | Name | What it does |
|------|------|-------------|
| `IngestTool` | `ingest_repo` | Clone/copy repo → Slither → GraphBuilder → `ctx.graph` |
| `ReconTool` | `run_recon` | ReconWorker: 7 parallel intel sources (docs, NatSpec, Etherscan) |
| `HotspotTool` | `find_hotspots` | Score functions by risk using graph signals |
| `ThreatIntelTool` | `threat_intel` | Classify protocol type, match precomputed attack vectors |
| `AttackAnalysisTool` | `run_attack_analysis` | AttackHypothesis + Assumption + ExecutionTrace workers per hotspot |
| `SemanticDiscoveryTool` | `run_semantic_analysis` | InvariantHunter + EconomicAttacker + TrustBoundary + CrossContract |
| `GateFilterTool` | `run_gate_filter` | 4-gate pre-filter on findings (cheap fast model) |
| `JuryTool` | `run_jury_debate` | 4-LLM adversarial debate (Skeptic/Attacker/Auditor/Judge) |
| `RAGSearchTool` | `search_exploits` | ChromaDB similarity search against historical exploits |
| `DepthAnalysisTool` | `run_depth_analysis` | Re-analyze uncertain findings (StateTrace/EdgeCase/External) |
| `ChainAnalysisTool` | `run_chain_analysis` | Link findings into multi-step exploit chains |
| `TestWriterTool` | `write_exploit_test` | Phoenix-loop Foundry PoC generation + sandboxed execution |
| `FuzzGeneratorTool` | `generate_fuzz_tests` | Invariant fuzz tests for CRITICAL findings |
| `ReportTool` | `generate_report` | HTML + Markdown + D3 graph report |

### Graph Query Tools — EVM only (hidden until graph is loaded)

| Tool | Name | What it does |
|------|------|-------------|
| `FunctionContextTool` | `get_function_context` | Code + callers/callees for a function |
| `StateMutatorsTool` | `find_state_mutators` | All functions writing to a state variable |
| `ModifiersTool` | `get_modifiers` | Security modifiers on a function |

### Generic Tools — File / Shell / Web

| Tool | Name | What it does |
|------|------|-------------|
| `BashTool` | `bash` | Execute shell commands (persistent cwd, streaming output) |
| `FileReadTool` | `file_read` | Read file contents (registers for write-guard) |
| `FileWriteTool` | `file_write` | Write files (enforces read-before-write) |
| `FileEditTool` | `file_edit` | Exact-string replace in files (enforces read-before-write) |
| `GrepTool` | `grep` | ripgrep-based content search with context |
| `GlobTool` | `glob` | File pattern matching |
| `WebFetchTool` | `web_fetch` | HTTP fetch for docs, Etherscan, RPC endpoints |
| `WebSearchTool` | `web_search` | Discover URLs (pluggable backend — default Parallel AI via `PARALLEL_API_KEY`) |

### Chain Tools — Foundry + on-chain interaction

| Tool | Name | What it does |
|------|------|-------------|
| `SandboxRunTool` | `sandbox_run` | Execute Foundry tests in a sandboxed directory |
| `DeployContractTool` | `deploy_contract` | Deploy contracts via `forge create` |
| `CastTool` | `cast` | Invoke `cast` for on-chain calls, storage reads, tx simulation |

### Meta Tools

| Tool | Name | What it does |
|------|------|-------------|
| `SpawnAgentTool` | `spawn_agent` | Spawn a sub-agent for parallel investigation |

---

## Worker Layer (`src/agents/workers/`)

Pipeline tools delegate to these specialized workers. Workers are not called directly
by the agent — they are invoked through their corresponding tool.

### Analysis Workers

| Worker | File | Model | Purpose |
|--------|------|-------|---------|
| `ReconWorker` | `recon_worker.py` | `gemini-3-flash-preview` | 7 parallel intel sources: graph, RAG, Etherscan, docs, NatSpec, compiler, tests |
| `AttackHypothesisWorker` | `attack_hypothesis_worker.py` | `grok-3` | Pattern-guided vulnerability discovery per hotspot |
| `AssumptionWorker` | `assumption_worker.py` | `gemini-3-flash-preview` | First-principles zero-day discovery (no pattern hints) |
| `ExecutionTraceWorker` | `execution_trace_worker.py` | `gemini-3-flash-preview` | Cross-function symmetry analysis |

### Semantic Discovery Workers (no Slither required)

| Worker | File | Model | Focus |
|--------|------|-------|-------|
| `InvariantHunterWorker` | `semantic_discovery.py` | `gemini-3-flash-preview` | Derives protocol invariants, checks violations across all functions |
| `EconomicAttackerWorker` | `economic_attacker.py` | `gemini-3-flash-preview` | Flash loan, sandwich, share inflation, rounding |
| `TrustBoundaryAnalyzer` | `trust_boundary.py` | `gemini-3-flash-preview` | Privilege escalation, proxy abuse, delegatecall injection |
| `CrossContractStateChecker` | `cross_contract.py` | `gemini-3-flash-preview` | Cross-contract reentrancy, stale state, callback exploitation |

### Validation Workers

| Worker | File | Model | Purpose |
|--------|------|-------|---------|
| `GateWorker` (via `gate_evaluate`) | `jury_worker.py` | `gemini-3-flash-preview` | 4-gate pre-filter: Refutation → Reachability → Trigger → Impact |
| `JuryWorker` | `jury_worker.py` | Multi-model | Adversarial debate: Skeptic(Claude)/Attacker(Grok)/Auditor(GPT-4o)/Judge(Gemini) |
| `StateTraceDepthWorker` | `depth_workers.py` | `gemini-3-flash-preview` | Re-analyze reentrancy/CEI/invariant/privilege findings |
| `EdgeCaseDepthWorker` | `depth_workers.py` | `gemini-3-flash-preview` | Re-analyze arithmetic/rounding/boundary findings |
| `ExternalDepthWorker` | `depth_workers.py` | `gemini-3-flash-preview` | Re-analyze flash loan/oracle/MEV findings |

### Exploit Generation

| Worker | File | Model | Purpose |
|--------|------|-------|---------|
| `TestWriterWorker` | `test_writer_worker.py` | `gemini-3-flash-preview` | Phoenix loop: generate → compile → fix → retry. Bridge mode for legacy contracts |
| `FuzzGenerator` | `fuzz_generator.py` | `gemini-3-flash-preview` | Foundry invariant fuzz tests for CRITICAL proven findings |

---

## Finding Lifecycle

A `Finding` object (`src/models/finding.py`) accumulates evidence as it passes through
the validation pipeline.

```
WorkerOutput (confidence 0-100)
      │
      ▼ Finding.from_worker_output() / from_semantic_output()
Finding (plausibility seeded: attack÷3, assumption÷4)
      │
      ▼ 4-Gate Pre-Filter
      PASS (+20) | DEMOTED (+5) | REFUTED (-40)
      │
      ▼ Jury (optional)
      CONFIRMED (+30) | ESCALATE (+10) | REJECTED (-25) | CONFIRMED_UNPROVABLE (+20)
      │
      ▼ RAG Sweep
      High-quality match (+15) | Moderate (+5) | No precedent (-10)
      │
      ▼ Depth Workers (uncertain findings only)
      CONFIRMED (+20) | REFINED (+10) | CONTESTED (+5) | REFUTED (-15)
      │
      ▼ Chain Analysis
      Link findings where postconditions → preconditions_missing of next finding
      Severity upgrade when same-severity findings form a chain
      │
      ▼ TestWriter (plausibility ≥ 50)
      [POC-PASS] | [POC-FAIL] | [CODE-TRACE]
```

**Mechanical confidence formula:**
```
Confidence = (Evidence × 0.40 + Consensus × 0.30 + LLM_raw × 0.30) × 100

Evidence  = max weight of present evidence tags
Consensus = derived from jury verdict (CONFIRMED=100, CONFIRMED_UNPROVABLE=75,
            ESCALATE=50, REJECTED=10, no jury=0)
```

**Evidence tag weights:** `[POC-PASS]`=1.0, `[PROD-ONCHAIN]`=1.0, `[GRAPH-SIGNAL]`=0.6,
`[RAG-MATCH]`=0.4, `[INFERRED]`=0.3, `[LLM-ONLY]`=0.2

---

## Static Analysis Layer

### GraphBuilder (`src/graph_builder.py`, ~5,600 lines)

Constructs a NetworkX `DiGraph` from Slither IR. This is the most complex single file
in the codebase.

**Nodes:** `contract`, `function`, `state_variable`, `modifier`

**Edges:** `DEFINES`, `CALLS`, `WRITES`, `READS`, `INHERITS`, `EXTERNAL_CALL`, `HAS_MODIFIER`

**Enrichment passes:**
- Access control: modifier extraction, privileged role detection, unprotected mutators
- Reentrancy: CEI violation detection, guard extraction
- Oracle patterns: spot price vs TWAP detection
- Flash loan attack surface
- Taint analysis and data flow
- Accounting invariant detection (balance sums, monotonicity)
- Economic amplification multipliers
- Reachability: external entry points, transitive call graph

### HotspotEngine (`src/hotspot_engine.py` + `src/utils/graph_queries.py`)

Scores functions by multi-dimensional risk:
- `structural_score ≥ 40` (external calls, state mutations, missing guards)
- `exploitability_score ≥ 30` (reachability from external entry points)
- `final_score ≥ 70` (gate threshold)

Excludes: view/pure/constructor, test/mock contracts, library-tier contracts.
Budget cap: 15 hotspots per analysis run.

### Ingestion (`src/ingestion/`)

- `FrameworkDetector` — detects Foundry/Hardhat/Brownie, runs pre-build hooks
- `SolcManager` — pragma parsing, constraint resolution, per-cluster solc switching via `solc-select`
- `ClusterBuilder` — groups `.sol` files by import connectivity, splits by pragma incompatibility
- `MemoryGuard` — prevents OOM on massive repos by segmenting oversized clusters
- `AnalysisEngine` (`src/analysis_engine.py`) — orchestrates compilation, 4-level fallback hierarchy, graceful degradation to semantic-only

---

## Knowledge System (`src/knowledge/`)

### RAG System (`rag_system.py`)

ChromaDB vector store with HuggingFace `all-MiniLM-L6-v2` embeddings.

- Documents: historical DeFi exploits (Solodit, past audits)
- Query: similarity search → quality-weighted confidence adjustment
  - Same vuln class + relevance ≥ 0.35 → +15 confidence
  - Different class or relevance ≥ 0.2 → +5 confidence
  - No precedent → -10 confidence (penalizes unsubstantiated claims)
- Persisted at `data/chroma_db/`

### Threat Intelligence (`src/intelligence/`)

- `ThreatProfiler` — classifies protocol type (vault, dex, lending, governance, bridge, staking) and loads a threat profile with known adversaries, invariants, and composability risks
- `AttackVectorDB` — maps protocol type to concrete attack vector bundles

---

## Reporting (`src/reporting/`)

`ReportGenerator` produces four artifacts:

| Artifact | Format | Contents |
|----------|--------|---------|
| `report.html` | Interactive HTML | Evidence badges, jury verdicts, chain analysis, depth history, D3 graph, copy buttons |
| `report.md` | Markdown | Immunefi / HackerOne submission format, finding IDs (C-01, H-02, ...) |
| `graph.html` | D3.js | Force-directed attack surface graph, filterable by contract/risk/proven |
| `exploits/` | Solidity | Proven `.t.sol` Foundry PoC files |

Finding deduplication: same `(contract, function, vuln_class)` → keep highest confidence.
Root cause grouping links related findings across entry points.

---

## Configuration (`src/pipeline_config.py`)

All pipeline stages are flag-gated. `AUDIT_MODE` sets a preset; individual env vars override it.

| Flag | Env Var | fast | standard | deep | semantic_only |
|------|---------|:----:|:--------:|:----:|:-------------:|
| Slither | `SLITHER_ENABLED` | ✓ | ✓ | ✓ | |
| Semantic discovery | `SEMANTIC_DISCOVERY_ENABLED` | | | ✓ | ✓ |
| Assumption worker | `ASSUMPTION_WORKER_ENABLED` | | ✓ | ✓ | |
| 4-Gate filter | `GATE_ENABLED` | | ✓ | ✓ | ✓ |
| Jury | `JURY_ENABLED` | | | ✓ | ✓ |
| Depth workers | `DEPTH_WORKERS_ENABLED` | | ✓ | ✓ | ✓ |
| TestWriter | `TESTWRITER_ENABLED` | | ✓ | ✓ | ✓ |
| Fuzz generator | `FUZZ_GENERATOR_ENABLED` | | | ✓ | |
| RAG | `RAG_ENABLED` | | ✓ | ✓ | ✓ |
| Chain analysis | `CHAIN_ANALYSIS_ENABLED` | | ✓ | ✓ | ✓ |
| Etherscan recon | `ETHERSCAN_ENABLED` | | ✓ | ✓ | |

---

## Scheduler (`src/agent/scheduler.py`)

Cron-based recurring audit scheduling. Tasks persisted as JSON at
`~/.critikal/schedules.json`. Run via `critikal --run-scheduler`.

---

## Interactive TUI (`src/tui/`)

Textual-based terminal UI. Redirects all Python logging to
`~/.critikal/logs/tui_session.log` to prevent terminal corruption.

**Widgets:** `ConversationWidget`, `FindingsWidget`, `WorkerWidget`, `CostBar`, `PromptInput`

**Slash commands:** `/compact`, `/cost`, `/findings`, `/workers`, `/status`, `/model`, `/export`, `/dream`

---

## Deprecated: Legacy Pipeline

`src/main.py` → `src/agents/lead_agent.py:coordinator_node()` — the original
monolithic LangGraph pipeline. Still invocable via `critikal --legacy`. Will be removed.
Do not add features here. The modern agent system (`src/agent/`) supersedes it entirely.
