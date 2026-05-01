# Critikal

**Autonomous smart contract security research agent.**

Critikal thinks like an attacker. Give it a repository URL and it will autonomously find real, exploitable vulnerabilities — from initial recon through proven Foundry PoC tests.

---

## What it does

1. **Ingests** the repository (clone + Slither + knowledge graph)
2. **Recons** the protocol (docs, NatSpec, Etherscan on-chain data)
3. **Maps attack surface** (hotspot scoring from graph signals)
4. **Forms hypotheses** (attack workers + semantic discovery in parallel)
5. **Validates** (4-gate pre-filter → jury debate → depth analysis)
6. **Proves** (Foundry PoC test generation with self-correction)
7. **Reports** (HTML + Markdown audit report with proven exploits)

---

## Quick Start

### 1. Install

```bash
git clone https://github.com/Tushar-Pandey-31/critikal && cd critikal
poetry install
```

### 2. Configure

```bash
cp .env.example .env
# Required: at least one of ANTHROPIC_API_KEY, GOOGLE_API_KEY, XAI_API_KEY, OPENAI_API_KEY
# Recommended: ETHERSCAN_API_KEY for on-chain recon
```

### 3. Run

```bash
# Full audit — headless mode
critikal --repo https://github.com/theredguild/damn-vulnerable-defi

# Custom prompt
critikal --headless "Focus only on reentrancy and flash loan attack surfaces"

# Interactive TUI
critikal
```

---

## CLI Reference

```
critikal [OPTIONS]

--repo URL          Repository to audit (URL or local path)
--headless PROMPT   Run with custom prompt (no TUI)
--interactive       Force interactive TUI mode
--model MODEL       Override agent brain model (default: claude-sonnet-4-6)
--budget USD        Maximum spend in USD
--permission-mode   ask | auto | yolo (default: auto)
--resume ID         Resume a previous engagement
--dream [ID]        Run memory consolidation
--schedule CRON     Schedule recurring audit
--list-schedules    List scheduled tasks
--legacy            [DEPRECATED] Use old pipeline
-v / --verbose      Verbose logging
```

---

## Output

Reports are generated in `data/reports/<name>_<timestamp>/`:

- `report.html` — interactive dark-mode report with evidence badges, jury verdicts, chain analysis
- `report.md` — Immunefi / HackerOne submission-ready markdown
- `graph.html` — knowledge graph visualization (D3.js)
- `exploits/` — proven Foundry `.t.sol` PoC test files

---

## Pipeline Modes

Control via `AUDIT_MODE` env var (or set individual flags):

| Mode | Static | Semantic | Jury | Depth | TestWriter |
|------|--------|----------|------|-------|------------|
| `fast` | ✓ | | | | |
| `standard` | ✓ | | | ✓ | ✓ |
| `deep` | ✓ | ✓ | ✓ | ✓ | ✓ |
| `semantic_only` | | ✓ | ✓ | ✓ | ✓ |

---

## Model Routing

Different models handle different roles (all configurable via env vars):

| Role | Default | Env Var |
|------|---------|---------|
| Agent brain | `claude-sonnet-4-6` | `AGENT_MODEL_NAME` |
| Attack worker | `grok-3` | `ATTACK_MODEL_NAME` |
| Assumption / semantic workers | `gemini-3-flash-preview` | `ASSUMPTION_MODEL_NAME` |
| Gate filter | `gemini-3-flash-preview` | `GATE_MODEL_NAME` |
| Jury Skeptic | `claude-sonnet-4-6` | `JURY_SKEPTIC_MODEL` |
| Jury Attacker | `grok-3` | `JURY_ATTACKER_MODEL` |
| Jury Auditor | `gpt-4o` | `JURY_AUDITOR_MODEL` |
| Jury Judge | `gemini-3-flash-preview` | `JURY_JUDGE_MODEL` |
| TestWriter | `gemini-3-flash-preview` | `TEST_WRITER_MODEL_NAME` |

---

## Architecture

```
CLI (src/cli.py)
  └── HeadlessRunner / CritikalApp (TUI)
        └── QueryLoop (src/agent/query_loop.py)
              ├── LLM via LangChain (provider-agnostic)
              ├── 29 tools (pipeline + graph + file/shell/web + chain + meta)
              ├── AutoCompactor (context management)
              ├── PermissionHandler
              └── SessionMemory (~/.critikal/memory/<id>/)

Pipeline tools invoke workers from src/agents/workers/:
  ingest_repo        → RepoManager + AnalysisEngine + GraphBuilder
  run_recon          → ReconWorker (7 parallel intel sources)
  find_hotspots      → HotspotEngine + graph_queries
  threat_intel       → ThreatProfiler + AttackVectorDB
  run_attack_analysis→ AttackHypothesis + Assumption + ExecutionTrace workers
  run_semantic_analysis → InvariantHunter + EconomicAttacker + TrustBoundary + CrossContract
  run_gate_filter    → 4-gate pre-filter (fast LLM)
  run_jury_debate    → 4-LLM adversarial debate
  run_depth_analysis → StateTrace / EdgeCase / External depth workers
  run_chain_analysis → ChainAnalyzer (deterministic multi-step linking)
  search_exploits    → RAG similarity search (ChromaDB)
  write_exploit_test → TestWriterWorker (Phoenix loop + sandboxed Foundry)
  generate_fuzz_tests→ FuzzGenerator (invariant fuzz tests for CRITICAL findings)
  generate_report    → ReportGenerator (HTML + Markdown + D3 graph)

Generic tools: bash, file_read/write/edit, grep, glob, web_fetch, web_search
Chain tools:   sandbox_run (Foundry), deploy_contract, cast (on-chain RPC)
Meta tools:    spawn_agent (sub-agent for parallel investigation)
```

---

## Docker

```bash
docker-compose build
docker-compose run critikal /bin/bash
```

The Docker image includes Python 3.10, Node.js 20, Foundry, and solc-select.

---

## Disclaimer

Critikal is an automated research tool. It is not a substitute for professional manual audits. Always verify findings in a safe, isolated environment. Only use on targets you have authorization to test.
