# Penteam v2.0

**AI-Powered Smart Contract Security System**  
*Human-in-the-loop • Multi-Agent • Graph-Powered • Hallucination-Resistant*

**Last Updated**: February 24, 2026

## Overview & Vision

Penteam is a **human-in-the-loop multi-agent system** designed for high-signal Web3 bug bounty hunting and smart contract security analysis.

Instead of a single generalist LLM, Penteam uses a **Mixture of Experts (MoE)** architecture where specialized agents work together under a central **Coordinator**. The system is built on a rich **Knowledge Graph** to ground every claim in deterministic facts, eliminating hallucinations.

**Core Philosophy**:
- Signal-to-noise ratio > Autonomy
- Graph memory + deterministic rules first
- Adversarial Jury layer (different model families)
- Compiler (Foundry) as the ultimate truth oracle
- Human always in the loop for final validation

---

## Architecture

Penteam is divided into clear phases:

- **Phase 1–3**: Structural Intelligence Layer (Knowledge Graph + deterministic security signals)
- **Phase 4**: Multi-Agent Orchestration (Lead Coordinator + specialized Workers)
- **Phase 5**: Jury System (adversarial validation — in progress)
- **Phase 6**: Exploit Proof Layer (Test Writer Worker — **live**)
- **Phase 7+**: Confidence Scoring, Reports, SaaS (planned)

---

## Core Components

### 1. Knowledge Graph (The Brain)
- Built from **Slither** IR analysis
- **NetworkX** DiGraph with 4000+ nodes typical
- Nodes: Contracts, Functions, State Variables, Modifiers
- Edges: `CALLS`, `READS`, `WRITES`, `HAS_MODIFIER`, `INHERITS`, etc.
- Rich security metadata:
  - Reentrancy risk, CEI violations, unprotected mutators, privilege escalation, reachability, write propagation, etc.
- Query API used by all agents (`get_high_risk_hotspots`, `get_function_context`, etc.)

### 2. Lead Coordinator
- Pure orchestrator (never analyzes code directly)
- Maintains global state using LangGraph
- Spawns workers in parallel
- Synthesizes findings
- Decides escalation to human
- Uses only high-level summary tools

### 3. Workers (Mixture of Experts)

**Recon Worker**
- Gathers protocol intelligence (RAG + Etherscan history)
- Classifies protocol type (Vault, DEX, Lending, etc.)
- Produces Security Dossier for downstream workers

**Attack Hypothesis Worker**
- Takes hotspots + recon context
- Generates structured vulnerability hypotheses
- Must cite real node IDs from the graph
- Produces `attack_path` and confidence score

**Test Writer Worker** (Live)
- Receives a finding
- Generates Foundry test code
- Runs isolated compile → test → fix loop (max 6 attempts)
- Uses real `forge build` and `forge test`
- Returns proven exploit or detailed failure reason
- Sandboxed using `tempfile` + `SandboxManager`

### 4. Tools & Infrastructure
- **Graph Tools**: `get_high_risk_hotspots`, `get_function_context`, etc.
- **RAG Librarian**: ChromaDB + embeddings for audit reports & docs
- **Etherscan Client**: On-chain history + exploit heuristics
- **AnalysisEngine**: Slither + auto solc version switching
- **RepoManager**: Git clone + Foundry/Hardhat dependency handling
- **SandboxManager**: Isolated Foundry environment per test attempt

### 5. Jury System (In Progress)
- Multi-model adversarial validation
- Sanity Jury (grounding)
- Logic Jury ("Prove this vulnerability is FALSE")
- Uses different model families (Gemini, GPT-5, Claude 4.6, Grok 4)

---

## Tech Stack

- **Language**: Python 3.12+
- **Orchestration**: LangGraph + LangChain
- **Graph**: NetworkX
- **Static Analysis**: Slither
- **Testing**: Foundry (Forge)
- **Vector DB**: ChromaDB
- **Embeddings**: all-MiniLM-L6-v2
- **LLMs**:
  - Lead & most workers: Gemini 2.5 / 3.0 Pro
  - Reasoning: GPT-5 / o3, Claude 4.6 Sonnet, Grok 4 Reasoning
- **Models**: Pydantic for strict schemas
- **Testing**: pytest (214+ tests, 100% pass)

---

## How It Works (End-to-End Flow)

1. **Ingestion** → Clone repo → Run Slither → Build Knowledge Graph
2. **Recon** → Gather protocol intelligence
3. **Hotspot Detection** → `get_high_risk_hotspots()`
4. **Attack Hypothesis** → Parallel workers generate leads with node IDs
5. **Test Writer** → Generate & validate Foundry PoC (retry loop)
6. **Jury** → Adversarial validation (planned)
7. **Coordinator Synthesis** → Final report + human escalation

---

## Quick Start

```bash
# 1. Clone & install
git clone https://github.com/yourusername/penteam.git
cd penteam
pip install -e .

# 2. Add API keys to .env
GOOGLE_API_KEY=...
XAI_API_KEY=...        # for Grok
# OPENAI_API_KEY=...

# 3. Run on any repo
python -m src.main --repo https://github.com/theredguild/damn-vulnerable-defi
```

## Current Status (February 24, 2026)

- **Phase 1–3**: Complete (Rich Knowledge Graph + all security signals)
- **Phase 4**: Complete (MoE + Coordinator + Recon + Attack Hypothesis)
- **Phase 6**: 60% Complete (Test Writer Worker live with sandbox + retry loop)
- **Total Tests**: 214 passing
- **Key Achievement**: Successfully generates real vulnerability hypotheses + Foundry tests on live protocols

## Roadmap

- [x] Phase 4 — Multi-Agent Orchestration
- [x] Phase 6.1–6.3 — Test Writer Core + Sandbox + Loop
- [ ] Story 6.4 — Confidence Adjustment & Integration
- [ ] Phase 5 — Full Jury System
- [ ] Phase 7 — Confidence Scoring & Reports
- [ ] SaaS / Hosted Version

---

*Penteam — Turning AI into a real smart contract security weapon.*  
*Built with ❤️ for the Web3 security community.*
