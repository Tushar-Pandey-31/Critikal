# Critikal

[![CI](https://github.com/Tushar-Pandey-31/Critikal/actions/workflows/ci.yml/badge.svg)](https://github.com/Tushar-Pandey-31/Critikal/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.12](https://img.shields.io/badge/python-3.12-blue.svg)](https://www.python.org/downloads/)
[![Code style: ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)

**Autonomous smart contract security research agent.**

Critikal thinks like an attacker. Give it a repository URL and it will autonomously find real, exploitable vulnerabilities — from initial recon through proven Foundry PoC tests.

![Critikal TUI demo](docs/demo.gif)

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
# Required (defaults): OPENAI_API_KEY and XAI_API_KEY
#   Critikal's defaults route through GPT-5 and Grok-4 only. Set both
#   keys for the out-of-the-box config to work.
# Optional / opt-in: ANTHROPIC_API_KEY, GOOGLE_API_KEY, OPENROUTER_API_KEY
#   Only needed if you override *_MODEL_NAME env vars to claude-* / gemini-* / openrouter/*.
# Recommended: ETHERSCAN_API_KEY for on-chain recon
```

> **Heads-up — model IDs.** The built-in defaults reference frontier models
> (`grok-4-1-fast-reasoning`, `gpt-5.4-mini`, `gpt-5.5`, `grok-code-fast-1`)
> that are not yet generally available on every account. If your API keys
> don't have access to those exact IDs you'll get a 404 from the provider on
> the first run. Override every `*_MODEL_NAME` env var in `.env` to a model
> your account can actually call — see the **Model Routing** table below for
> the full list.

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
--model MODEL       Override agent brain model (default: grok-4-1-fast-reasoning)
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

Defaults route through xAI (Grok) and OpenAI (GPT) only. Every role is
overridable via env var — point any role at `claude-*`, `gemini-*`, or
`openrouter/<provider>/<model>` and the matching API key will be used.

| Role | Default | Env Var |
|------|---------|---------|
| Agent brain | `grok-4-1-fast-reasoning` | `AGENT_MODEL_NAME` |
| Attack worker (creative attacker) | `grok-4-1-fast-reasoning` | `ATTACK_MODEL_NAME` |
| Assumption worker (zero-day) | `grok-4-1-fast-reasoning` | `ASSUMPTION_MODEL_NAME` |
| Recon / Semantic / Execution-trace workers | `gpt-5.4-mini` | `RECON_MODEL_NAME`, `SEMANTIC_MODEL_NAME`, `EXECUTION_TRACE_MODEL_NAME` |
| Gate filter | `gpt-5.4-mini` | `GATE_MODEL_NAME` |
| Depth workers | `gpt-5.4-mini` | `DEPTH_MODEL_NAME` |
| Jury Skeptic | `gpt-5.5` | `JURY_SKEPTIC_MODEL` |
| Jury Attacker | `grok-4-1-fast-reasoning` | `JURY_ATTACKER_MODEL` |
| Jury Auditor | `gpt-5.4-mini` | `JURY_AUDITOR_MODEL` |
| Jury Judge | `grok-4-1-fast-reasoning` | `JURY_JUDGE_MODEL` |
| TestWriter (Foundry PoC) | `grok-code-fast-1` | `TEST_WRITER_MODEL_NAME` |
| Fuzz generator | `grok-code-fast-1` | `FUZZ_MODEL_NAME` |
| Memory / dream / compact / sub-agent | `gpt-5.4-mini` | `MEMORY_EXTRACT_MODEL`, `DREAM_MODEL_NAME`, `COMPACT_MODEL_NAME`, `SUB_AGENT_MODEL_NAME` |

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

Pipeline tools invoke workers from src/pipeline/workers/:
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

The Docker image includes Python 3.12, Node.js 20, Foundry, and solc-select.

---

## Disclaimer

Critikal is an automated research tool. It is not a substitute for professional manual audits. Always verify findings in a safe, isolated environment. Only use on targets you have authorization to test.
