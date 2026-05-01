# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Is

Critikal is an autonomous security research agent — think Claude Code, but for hacking smart contracts. Given a repository URL it autonomously ingests the code, maps the attack surface, forms exploit hypotheses, validates them through a multi-stage pipeline (gates → jury → depth), and generates Foundry PoC tests. The output is a battle-tested audit report with proven exploits.

## Commands

```bash
# Install dependencies
poetry install

# Full headless audit (primary usage)
critikal --repo https://github.com/username/repo

# Headless audit with custom prompt
critikal --headless "Find flash loan vulnerabilities in this vault"

# Interactive TUI mode
critikal

# Resume a previous engagement
critikal --resume <engagement-id>

# Memory consolidation
critikal --dream <engagement-id>

# Schedule recurring audit
critikal --schedule "0 0 * * 1" --repo https://github.com/username/repo

# Run tests
pytest
pytest tests/test_query_loop.py   # single file
pytest tests/ -v                   # verbose

# Docker (includes Foundry, solc-select, Node.js)
docker-compose build
docker-compose run penteam /bin/bash
```

## Entry Points

The CLI is `src/cli.py` (not `src/main.py`, which is the deprecated legacy pipeline).

```
critikal [--repo URL]                → src/cli.py::main()
  --repo && !--interactive           → HeadlessRunner.run_audit(url)
  --headless "prompt"                → HeadlessRunner.run_prompt(prompt)
  --interactive / default            → CritikalApp (Textual TUI)
  --legacy                           → src/main.py [DEPRECATED]
  --dream                            → AutoDream memory consolidation
  --schedule / --list-schedules      → CronScheduler
```

## Configuration

Copy `.env.example` → `.env`. Critical env vars:

| Variable | Purpose |
|---|---|
| `ANTHROPIC_API_KEY`, `GOOGLE_API_KEY`, `OPENAI_API_KEY`, `XAI_API_KEY` | LLM providers |
| `AGENT_MODEL_NAME` | Brain model for the agentic loop (default: `claude-sonnet-4-6`) |
| `AUDIT_MODE` | Worker preset: `fast` / `standard` / `deep` / `semantic_only` |
| `SLITHER_ENABLED`, `JURY_ENABLED`, `GATE_ENABLED`, etc. | Per-stage toggles |
| `ATTACK_MODEL_NAME`, `ASSUMPTION_MODEL_NAME`, etc. | Per-worker model routing |
| `ETHERSCAN_API_KEY` | Required for on-chain recon |

All stage flags and model routing are centralized in `src/pipeline_config.py::PipelineConfig`.

## Architecture

### Core Agent System (`src/agent/`)

The primary codebase. Implements a Claude Code-style agentic loop.

```
HeadlessRunner / CritikalApp (TUI)
  └── QueryLoop                    # Agentic reasoning loop (src/agent/query_loop.py)
        ├── LLM (via LangChain)    # Provider-agnostic: Anthropic, Google, OpenAI, xAI
        ├── Tool execution         # 29 tools, permission-gated
        ├── HookRegistry           # User-configured PreToolUse/PostToolUse/SessionStart/SessionEnd shell hooks
        ├── AutoCompactor          # Proactive + reactive context compaction
        ├── PermissionHandler      # ask / auto / yolo modes
        └── SessionMemory          # Per-engagement memory, auto-extracted every N turns
```

**QueryLoop features:**
- Streaming via `astream()` with real-time `MESSAGE_CHUNK` events
- Multi-layer error recovery: rate limit backoff → reactive compact → fallback model
- Context compaction: proactive at 75% (`should_micro_compact`) + reactive at 90% (`should_compact`), with round-boundary slicing so `assistant.tool_calls` is never orphaned from its `tool` results
- Tool result budget: 80K chars max per result (head+tail truncation)
- Max 200 turns by default
- Preflight API-key check before session start (`check_provider_credentials`)

**Tool categories** (all in `src/agent/tools/` except `spawn_agent` in `src/agent/sub_agent.py`):

| Category | Count | Tools |
|---|---|---|
| Pipeline (security analysis) | 14 | `ingest_repo`, `run_recon`, `find_hotspots`, `threat_intel`, `run_attack_analysis`, `run_semantic_analysis`, `run_gate_filter`, `run_jury_debate`, `search_exploits`, `run_depth_analysis`, `run_chain_analysis`, `write_exploit_test`, `generate_fuzz_tests`, `generate_report` |
| Graph queries (EVM only) | 3 | `get_function_context`, `find_state_mutators`, `get_modifiers` |
| Generic (file/shell/web) | 8 | `bash`, `file_read`, `file_write`, `file_edit`, `grep`, `glob`, `web_fetch`, `web_search` |
| Chain (Foundry + on-chain) | 3 | `sandbox_run`, `deploy_contract`, `cast` |
| Meta | 1 | `spawn_agent` (sub-agent spawning — inherits parent's PermissionHandler) |

**Total: 29 tools.**

**Hooks** (`src/agent/hooks.py`): user-configured shell commands fired at lifecycle events. Load order: `$CRITIKAL_SETTINGS` → `./.critikal/settings.json` → `~/.critikal/settings.json`. Events: `SessionStart`, `SessionEnd`, `PreToolUse` (non-zero exit blocks the call), `PostToolUse` (advisory).

### Pipeline Workers (`src/agents/workers/`)

Specialized worker agents called by pipeline tools:

| Worker | Model | Purpose |
|---|---|---|
| `ReconWorker` | `gemini-3-flash-preview` | Protocol intelligence (docs, NatSpec, Etherscan) |
| `AttackHypothesisWorker` | `grok-3` | Pattern-guided vulnerability discovery per hotspot |
| `AssumptionWorker` | `gemini-3-flash-preview` | First-principles zero-day discovery (no pattern hints) |
| `ExecutionTraceWorker` | `gemini-3-flash-preview` | Cross-function symmetry analysis |
| `InvariantHunterWorker` | `gemini-3-flash-preview` | Derives protocol invariants, checks violations |
| `EconomicAttackerWorker` | `gemini-3-flash-preview` | Flash loan, sandwich, inflation attacks |
| `TrustBoundaryAnalyzer` | `gemini-3-flash-preview` | Privilege escalation, proxy abuse |
| `CrossContractStateChecker` | `gemini-3-flash-preview` | Cross-contract reentrancy, stale state |
| `JuryWorker` | Multi-model | 4-LLM adversarial debate (Skeptic/Attacker/Auditor/Judge) |
| `DepthWorkers` | `gemini-3-flash-preview` | Re-analysis of uncertain findings |
| `TestWriterWorker` | `gemini-3-flash-preview` | Foundry PoC generation + sandboxed execution |

### Finding Lifecycle

```
WorkerOutput (confidence 0-100)
  → Finding created (plausibility seeded)
  → 4-Gate Pre-Filter: PASS(+20) / DEMOTED(+5) / REFUTED(-40)
  → Jury (optional): CONFIRMED(+30) / ESCALATE(+10) / REJECTED(-25)
  → RAG sweep: high-quality(+15) / moderate(+5) / none(-10)
  → Depth workers: CONFIRMED(+20) / REFINED(+10) / CONTESTED(+5) / REFUTED(-15)
  → Chain analysis: link multi-step exploits, upgrade severity
  → TestWriter (plausibility ≥ 50): Foundry .t.sol PoC
```

**Mechanical confidence**: `(Evidence×0.40 + Consensus×0.30 + LLM×0.30) × 100`

Evidence tags: `[POC-PASS]`=1.0, `[PROD-ONCHAIN]`=1.0, `[GRAPH-SIGNAL]`=0.6, `[RAG-MATCH]`=0.4, `[LLM-ONLY]`=0.2

### Key Files

| File | Role |
|---|---|
| `src/cli.py` | CLI entry point — dispatches to headless/TUI/legacy/scheduler |
| `src/agent/query_loop.py` | Core agentic loop — streaming LLM calls, tool execution, recovery |
| `src/agent/headless.py` | Headless mode runner — initializes context, runs QueryLoop, prints events |
| `src/agent/context.py` | `ToolContext` — shared mutable state (graph, findings, memory, cost) |
| `src/agent/tool.py` | `Tool` ABC — interface all 29 tools implement |
| `src/agent/tools/` | Tool implementations (28 of 29; `spawn_agent` lives in `src/agent/sub_agent.py`) |
| `src/agent/hooks.py` | HookRegistry — PreToolUse/PostToolUse/SessionStart/SessionEnd shell hooks from settings.json |
| `src/agent/memory/session_memory.py` | Per-engagement memory (JSONL, extracted every N turns) |
| `src/agent/memory/auto_dream.py` | Post-session memory consolidation |
| `src/agent/system_prompt.py` | System prompt (dynamic: tool catalog + current state) |
| `src/tui/app.py` | Textual TUI application |
| `src/models/finding.py` | `Finding` dataclass — verdict, evidence tags, confidence decomposition |
| `src/graph_builder.py` | NetworkX DiGraph from Slither IR (5,600+ lines) |
| `src/agents/workers/jury_worker.py` | 4-gate pre-filter + multi-model jury debate |
| `src/knowledge/rag_system.py` | ChromaDB RAG queries |
| `src/agents/workers/test_writer_worker.py` | Phoenix loop PoC generation |
| `src/pipeline_config.py` | All stage flags and mode presets |

### Memory System

Per-engagement memory stored at `~/.critikal/memory/<engagement_id>/`:
- `session.jsonl` — raw memory entries (findings, recon, tactics, configs)
- `consolidated.md` — post-session LLM summary (via `--dream`)

Memory is extracted every 10 turns, injected into the system prompt at session start.

### Data Directories

- `data/chroma_db/` — Persisted ChromaDB vector store (RAG)
- `data/knowledge/` — Exploit knowledge base for RAG ingest
- `data/scratch/` — Cloned/copied repos for analysis
- `data/reports/` — All generated reports and exploit artifacts

### Legacy Pipeline (Deprecated)

`src/main.py` → `src/agents/lead_agent.py:coordinator_node()` — the old monolithic LangGraph pipeline. Still works via `--legacy` flag. Will be removed. Don't add features here.

### Benchmarks

`benchmarks/scone_results.jsonl` — SCONE benchmark runs against 405 real DeFi exploits (Etherscan V2 API). Used to measure detection accuracy.
