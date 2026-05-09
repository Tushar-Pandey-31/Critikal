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

### 0. Prerequisites

You need the following installed before you start. If you'd rather skip all of
this, jump to the [Docker](#docker) section — the image bundles everything.

| Dependency | Version | Why | Install |
|---|---|---|---|
| **Python** | `>=3.12.1, <3.13` | Runtime | [python.org/downloads](https://www.python.org/downloads/) or `pyenv install 3.12` |
| **Poetry** | `>=1.8` (2.x supported) | Dependency / venv manager | `curl -sSL https://install.python-poetry.org \| python3 -` |
| **Git** | any recent | Cloning audit targets | `apt install git` / `brew install git` |
| **Foundry** (`forge`, `cast`, `anvil`) | latest | Compiles + runs the generated PoC tests | `curl -L https://foundry.paradigm.xyz \| bash && foundryup` |
| **solc-select** | latest | Switches Solidity compiler versions per target | `pip install solc-select && solc-select install 0.8.20 && solc-select use 0.8.20` |
| **Node.js** | `>=20` | Required by some Solidity toolchains pulled in by audit targets | [nodejs.org](https://nodejs.org/) or `nvm install 20` |
| **Build essentials** (Linux only) | — | Needed for some native Python deps | `sudo apt install build-essential` |

You'll also need at least these API keys (see step 2):

- `OPENAI_API_KEY` and `XAI_API_KEY` — required for the default model routing
- `ETHERSCAN_API_KEY` — recommended for on-chain recon

### 1. Install

```bash
# 1. Clone
git clone https://github.com/Tushar-Pandey-31/critikal.git
cd critikal

# 2. Resolve and pin the dependency graph (refreshes poetry.lock)
poetry lock

# 3. Install all deps + the `critikal` entry point into a project-local venv
poetry install
```

Poetry installs everything into `./.venv/` and registers a `critikal`
executable at `./.venv/bin/critikal`. That binary is **not** on your `PATH`
yet — see step 3.

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

Edit `.env` and fill in your keys (use any editor, e.g. `nano .env`).

> **Model Picker** now allows you to pick any model from all the available provider api keys, use /model to check it out
> **Model Routing** table below for
> the full list.

### 3. Run

Pick **one** of the three patterns below — they're equivalent, just different
ways to reach the `critikal` binary inside the project venv.

**Option A — `poetry run` (no activation, works from anywhere in the repo):**

```bash
# Full audit — headless mode
poetry run critikal --repo https://github.com/theredguild/damn-vulnerable-defi

# Custom prompt
poetry run critikal --headless "Focus only on reentrancy and flash loan attack surfaces"

# Interactive TUI
poetry run critikal
```

**Option B — activate the venv once per shell:**

```bash
# Poetry 2.x
eval $(poetry env activate)

# Or, on any Poetry version, source the venv directly
source .venv/bin/activate

# Now `critikal` is on your PATH until you `deactivate`
critikal --repo https://github.com/theredguild/damn-vulnerable-defi
critikal --headless "Focus only on reentrancy and flash loan attack surfaces"
critikal
```

**Option C — install globally with pipx (recommended for daily use):**

```bash
pipx install --editable .

# `critikal` is now on PATH from any directory; edits to src/ take effect live
critikal --repo https://github.com/theredguild/damn-vulnerable-defi
```

> If you see `critikal: command not found`, you almost certainly skipped the
> activation step — use one of the three options above.

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
