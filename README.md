# Critikal v2
**AI-Powered Smart Contract Security System**

Critikal is a multi-agent smart contract security system with two independent discovery tracks: **static analysis** (Slither-based graph signals) and **semantic discovery** (LLM-native 0-day agents reading raw source). Both tracks feed into a shared validation pipeline (Jury → RAG → Depth → Chain Analysis → TestWriter) to eliminate false positives and produce proven exploits.

## Dual-Track Discovery Architecture

### Track A: Static Analysis (Slither)
Compiles contracts via Slither → builds a NetworkX knowledge graph → deterministic hotspot scoring → Attack + Assumption workers analyze hotspots.

### Track B: Semantic Discovery (LLM-Native, No Slither)
Four parallel agents read raw `.sol` files and discover vulnerabilities from first principles:

| Agent | Focus | Unique Signal |
|-------|-------|---------------|
| **InvariantHunter** | Protocol invariant violations | Derives invariants from code, checks every function |
| **EconomicAttacker** | Flash loan / sandwich / price manipulation | Value flow mapping, ratio manipulation analysis |
| **TrustBoundaryAnalyzer** | Privilege escalation / proxy / delegatecall | msg.sender bypass, ownership races, initializer replay |
| **CrossContractStateChecker** | Cross-contract reentrancy / stale state | Read-after-external-call, callback exploitation |

Track B runs when `SEMANTIC_DISCOVERY_ENABLED=true` or `AUDIT_MODE=deep|semantic_only`.

### Shared Validation Pipeline
Both tracks produce `Finding` objects that flow through:

1. **4-Gate Pre-Filter** — cheap fast model kills obvious false positives
2. **Jury System** — 3 jurors (Skeptic/Attacker/Auditor) + 1 Judge adversarial debate
3. **RAG Sweep** — ChromaDB historical exploit matching (boost/penalize confidence)
4. **Mechanical Scoring** — evidence-tag-weighted composite confidence
5. **Depth Workers** — domain-specific re-analysis (StateTrace, EdgeCase, External)
6. **Chain Analysis** — links findings into multi-step exploit chains
7. **TestWriter (Phoenix Loop)** — auto-generates Foundry `.t.sol` exploit PoCs
8. **FuzzGenerator** — invariant fuzz tests for proven CRITICAL findings

## Pipeline Modes

| Mode | Static | Semantic | Jury | Depth | TestWriter | Fuzz |
|------|--------|----------|------|-------|------------|------|
| `fast` | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| `standard` | ✅ | ❌ | ❌ | ✅ | ✅ | ❌ |
| `deep` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| `semantic_only` | ❌ | ✅ | ✅ | ✅ | ✅ | ❌ |

Set via `AUDIT_MODE=<mode>`. Individual flags always override the preset.

## Model Routing

Critikal uses a "Mixture of Experts" approach. Different models handle different tasks:

| Role | Default Model | Env Var |
|------|---------------|---------|
| Coordinator | `gemini-2.5-pro` | `MODEL_NAME` |
| Recon | `gemini-2.5-flash` | `RECON_MODEL_NAME` |
| Attack Worker | `grok-3` | `ATTACK_MODEL_NAME` |
| Assumption Worker | `claude-sonnet-4-5` | `ASSUMPTION_MODEL_NAME` |
| Semantic Agents | `gemini-2.5-flash` | `SEMANTIC_MODEL_NAME` |
| TestWriter | `claude-sonnet-4-6` | `TEST_WRITER_MODEL_NAME` |
| Depth Workers | `gemini-2.5-flash` | `DEPTH_MODEL_NAME` |
| 4-Gate Filter | `gemini-2.0-flash` | `GATE_MODEL_NAME` |
| Jury Skeptic | `claude-sonnet-4-6` | `JURY_SKEPTIC_MODEL` |
| Jury Attacker | `grok-3` | `JURY_ATTACKER_MODEL` |
| Jury Auditor | `gpt-4o` | `JURY_AUDITOR_MODEL` |
| Jury Judge | `gemini-2.5-pro` | `JURY_JUDGE_MODEL` |

Thread-safe API key pooling with automatic rotation, 429 backoff, and cooldown.

## Quick Start

### 1. Install
```bash
git clone https://github.com/yourusername/Critikal.git && cd Critikal
pip install -e .
```

### 2. Configure
```bash
cp .env.example .env
# Add API keys: GOOGLE_API_KEY, XAI_API_KEY, ANTHROPIC_API_KEY, OPENAI_API_KEY
```

### 3. Run
```bash
# Local project
python -m src.main --repo /path/to/project

# Remote repo
python -m src.main --repo https://github.com/theredguild/damn-vulnerable-defi

# Semantic-only (no Slither)
AUDIT_MODE=semantic_only python -m src.main --repo /path/to/project

# Full deep scan
AUDIT_MODE=deep python -m src.main --repo /path/to/project
```

## Output

Reports generated in `data/reports/`:
- `report.html` — interactive dark-mode report with evidence badges, RAG matches, chain analysis, jury verdicts
- `report.md` — HackerOne/Immunefi submission-ready markdown
- `graph.html` — knowledge graph visualization
- `exploits/` — proven `.t.sol` Foundry PoC scripts

## Finding Taxonomy

Each `Finding` is a structured object containing:
- **Verdict**: `CONFIRMED` | `PARTIAL` | `CONTESTED` | `REFUTED` | `UNASSESSED`
- **Evidence Tags**: `[POC-PASS]`, `[POC-FAIL]`, `[CODE]`, `[GRAPH-SIGNAL]`, `[RAG-MATCH]`, `[INFERRED]`, `[LLM-ONLY]`
- **Confidence Decomposition**: evidence × 0.35 + consensus × 0.25 + RAG × 0.2 + LLM × 0.2
- **Chain Metadata**: chain_ids, chain_role (enabler/blocked), severity upgrades
- **Depth History**: which depth worker re-analyzed, verdict, reasoning
- **Jury Record**: full deliberation (vote summary, reasoning, rejection reason)
- **Gate Record**: which of 4 gates passed/refuted/demoted

## Disclaimer

Critikal is an automated analysis tool designed to aid security researchers. It is not a substitute for professional manual audits. Always verify findings in a safe, isolated environment.
