# Critikal Architecture

Critikal is a multi-agent smart contract security system with two independent discovery tracks and a shared validation pipeline. The system is orchestrated via `coordinator_node()` in `lead_agent.py`.

---

## The End-to-End Pipeline

```
                    ┌──── Track A: Static ────────────────────────────┐
                    │ AnalysisEngine → GraphBuilder → Hotspot Engine  │
                    │ → AttackHypothesisWorker + AssumptionWorker     │
                    └────────────────────┬───────────────────────────-┘
Ingestion → Recon ──┤                    ├─ Findings ─→ Gate → Jury → RAG
                    │                    │              → Depth → Chain
                    ┌────────────────────┘              → TestWriter → Fuzz
                    │ Track B: Semantic                  → Report
                    │ InvariantHunter + EconomicAttacker │
                    │ + TrustBoundary + CrossContract    │
                    └───────────────────────────────────-┘
```

### Phase 1: Ingestion & Recon

- **`AnalysisEngine`** (`analysis_engine.py`): Cluster-based Solidity compilation via Slither. Detects Foundry/Hardhat/Brownie frameworks, builds compilation clusters, handles multi-pragma repos. 4-level fallback hierarchy. Only runs when `SLITHER_ENABLED=true`.
- **`ReconWorker`** (`recon_worker.py`): Protocol context aggregation. Reads docs, natspec, compiler info, test files. Optionally queries Etherscan for on-chain data (when `ETHERSCAN_ENABLED=true`). Runs globally before any analysis workers.

### Phase 2: Graph Construction (Track A only)

- **`GraphBuilder`** (`graph_builder.py`): Constructs a NetworkX DiGraph from Slither IR. Nodes: Contract, Function, StateVariable, Modifier. Enriched with:
  - Taint analysis & data flow
  - Privilege & access control extraction
  - Economic amplification multipliers
  - Accounting invariant detection
  - Flash loan attack surface analysis
- **`hotspot_engine.py`**: Defines the `Hotspot` dataclass. Actual scoring logic lives in `graph_queries.py::get_high_risk_hotspots()`. Multi-dimensional gate: `structural_score >= 40`, `exploitability_score >= 30`, `final_score >= 70`. Excludes view/pure/constructor, test/mock contracts, and library-tier contracts. Budget cap of 15 hotspots.

### Phase 3: Discovery Workers

#### Track A: Graph-Seeded Workers (run per hotspot)

| Worker | Purpose | Graph Signals Used |
|--------|---------|-------------------|
| **AttackHypothesisWorker** | Pattern-aware vulnerability analysis | Reentrancy risk, unprotected mutators, external calls |
| **AssumptionWorker** | First-principles assumption violation | Raw source + call graph only (zero pattern hints) |

Both run in parallel via `asyncio.gather()` with independent concurrency semaphores (`ATTACK_WORKER_CONCURRENCY`, default 15 each). AssumptionWorker has a lower confidence threshold (25 vs 65) and uses a disk-based source fallback when the graph is empty.

**Output**: `WorkerOutput` → `Finding.from_worker_output(output, hotspot)`.

#### Track B: Semantic Discovery Agents (run per repo, no Slither)

Activated when `SEMANTIC_DISCOVERY_ENABLED=true`. Four agents run in parallel via `run_semantic_discovery()`:

| Agent | File | Focus |
|-------|------|-------|
| **InvariantHunterWorker** | `semantic_discovery.py` | Derives protocol invariants from source, checks every function |
| **EconomicAttackerWorker** | `economic_attacker.py` | Flash loan manipulation, sandwich attacks, inflation/rounding |
| **TrustBoundaryAnalyzer** | `trust_boundary.py` | Privilege escalation, proxy abuse, delegatecall injection |
| **CrossContractStateChecker** | `cross_contract.py` | Cross-contract reentrancy, stale state, callback exploitation |

All agents read raw `.sol` files via `glob` (no Slither dependency). Source budget: 30K chars for most agents, 50K for CrossContract.

**Output**: `WorkerOutput` → `Finding.from_semantic_output(output)` (no Hotspot required).

### Phase 4: Validation Pipeline

All findings from both tracks flow through the same pipeline:

#### Step 4.45 — 4-Gate Pre-Filter (`jury_worker.py::gate_evaluate`)
Cheap fast model (default: `gemini-2.0-flash`) runs 4 sequential gates. Verdicts: `PASS` (proceed to jury), `GATE_REFUTED` (dropped), `GATE_DEMOTED` (bypass jury, go to depth).

**Gating**: Controlled by `GATE_ENABLED` (independent of `JURY_ENABLED`). In `standard` mode, the gate runs without the full jury. In `deep` mode, both gate and jury run.

#### Step 4.5 — Jury System (`jury_worker.py`)
Optional multi-model adversarial debate. Enable with `JURY_ENABLED=true`.

- **Skeptic** (Claude): Finds reasons the hypothesis is wrong
- **Attacker** (Grok): Develops concrete attack scenarios
- **Auditor** (GPT-4o): Evaluates severity by professional audit standards
- **Judge** (Gemini Pro): Arbitrates votes, synthesizes TestWriter briefs

Decisions: `CONFIRMED`, `CONFIRMED_UNPROVABLE`, `ESCALATE`, `REJECTED`.

#### Step 4.6 — RAG Validation (`rag_system.py`)
ChromaDB vector search against historical exploits. Match: +5 confidence. No precedent: -10 confidence.

#### Step 4.65 — Mechanical Confidence Scoring (`finding.py::compute_mechanical_confidence`)
```
Composite = Evidence×0.35 + Consensus×0.25 + RAG×0.2 + LLM_raw×0.2
Evidence = max(EVIDENCE_TAG_WEIGHTS for each tag present)
Consensus = derived from jury verdict (CONFIRMED=100, CONFIRMED_UNPROVABLE=75, ESCALATE=50, REJECTED=10, no jury=0)
```

Evidence tag weights: `[POC-PASS]` = 1.0, `[CODE]` = 0.8, `[GRAPH-SIGNAL]` = 0.7, `[RAG-MATCH]` = 0.6, `[POC-FAIL]` = 0.4, `[INFERRED]` = 0.3, `[LLM-ONLY]` = 0.2.

#### Step 4.7 — Depth Workers (`depth_workers.py`)
Re-analyzes uncertain findings (verdict = `CONTESTED`, `PARTIAL`, `UNASSESSED`):

| Worker | Focus | Key Graph Queries |
|--------|-------|-------------------|
| **StateTraceDepthWorker** | Cross-function state mutation, constraint enforcement | `get_state_dependencies()`, `get_state_transitions()` |
| **EdgeCaseDepthWorker** | Zero-state, dust, boundary conditions, off-by-one | `get_taint_critical_paths()` |
| **ExternalDepthWorker** | External call side effects, MEV, flash loan, oracle | `get_external_call_edges()`, `get_external_call_functions()` |

Mandatory checks: Devil's Advocate, Evidence Quality tagging, Confidence Gating.
Verdicts: `CONFIRMED`, `REFINED`, `REFUTED`, `CONTESTED`.

#### Step 4.8 — Chain Analysis (`chain_analyzer.py`)
Deterministic engine (no LLM). Links findings by matching `postconditions` → `preconditions_missing`:
- Match types: `STATE`, `ACCESS`, `TIMING`, `BALANCE`
- Match strengths: `STRONG`, `MODERATE`, `WEAK` (weak discarded)
- Severity upgrade: same-severity chains upgrade one tier

### Phase 5: Coordinator Synthesis

LLM (Gemini Pro, no tools bound) produces final JSON report from deduplicated worker outputs. Synthetic finding creation is disabled — only Attack/Assumption/Semantic worker findings are accepted.

### Phase 6: Exploit Proof Layer

#### TestWriter (Phoenix Loop)
For every finding with confidence ≥ 65 and severity ∈ {CRITICAL, HIGH, MEDIUM}:
- Writes Foundry `.t.sol` exploit tests
- Iterative self-correction from compiler errors
- Variant exploration if assertion fails
- Evidence badges: `[POC-PASS]`, `[POC-PASS-VARIANT]`, `[POC-FAIL]`, `[CODE-TRACE]`
- **Jury-confirmed findings are protected**: TestWriter confidence can only raise (not lower) their score

#### FuzzGenerator
For CRITICAL findings that pass TestWriter (when `FUZZ_GENERATOR_ENABLED=true`):
- Generates Foundry invariant tests (`invariant_*` / `testFuzz_*`)
- Broken invariant = confidence boost (+20)

### Phase 7: Reporting

`ReportGenerator` produces:
- `report.html` — interactive UI with evidence badges, jury verdicts, chain analysis, depth history
- `report.md` — Immunefi/HackerOne submission format
- `graph.html` — NetworkX knowledge graph visualization
- `exploits/` — proven `.t.sol` files

---

## Pipeline Configuration

All stages are flag-gated via `PipelineConfig` (`pipeline_config.py`). Flags can be set via:
1. `AUDIT_MODE` preset (fast/standard/deep/semantic_only)
2. Individual env vars (always override the preset)

| Flag | Env Var | fast | standard | deep | semantic_only |
|------|---------|------|----------|------|---------------|
| Slither | `SLITHER_ENABLED` | ✅ | ✅ | ✅ | ❌ |
| Semantic Discovery | `SEMANTIC_DISCOVERY_ENABLED` | ❌ | ❌ | ✅ | ✅ |
| Assumption Worker | `ASSUMPTION_WORKER_ENABLED` | ❌ | ✅ | ✅ | ❌ |
| Depth Workers | `DEPTH_WORKERS_ENABLED` | ❌ | ✅ | ✅ | ✅ |
| Jury | `JURY_ENABLED` | ❌ | ❌ | ✅ | ✅ |
| 4-Gate Filter | `GATE_ENABLED` | ❌ | ✅ | ✅ | ✅ |
| TestWriter | `TESTWRITER_ENABLED` | ❌ | ✅ | ✅ | ✅ |
| Fuzz Generator | `FUZZ_GENERATOR_ENABLED` | ❌ | ❌ | ✅ | ❌ |
| RAG | `RAG_ENABLED` | ❌ | ✅ | ✅ | ✅ |
| Chain Analysis | `CHAIN_ANALYSIS_ENABLED` | ❌ | ✅ | ✅ | ✅ |
| Etherscan | `ETHERSCAN_ENABLED` | ❌ | ✅ | ✅ | ❌ |

---

## Finding Taxonomy

A `Finding` is a structured dataclass containing:
- `FindingVerdict`: `CONFIRMED` | `PARTIAL` | `CONTESTED` | `REFUTED` | `UNASSESSED`
- `confidence_decomposition`: Evidence, Consensus, RAG match, LLM raw
- `evidence_tags`: How the bug was validated (`[POC-PASS]`, `[CODE-TRACE]`, etc.)
- `preconditions` / `postconditions` / `preconditions_missing`: Chain analysis input
- `depth_verdicts`: History of depth worker re-analysis
- `chain_ids` / `chain_role` / `chain_severity_upgrade`: Multi-step exploit metadata
- `jury_decision` / `jury_vote_summary` / `jury_reasoning`: Jury deliberation record
- `gate_verdict` / `gate_failed` / `gate_quote`: 4-gate pre-filter results
- `root_cause_group`: Cross-entry-point consolidation
