# Critikal Architecture

Critikal is a multi-agent smart contract security system designed for high-signal vulnerability detection. Its architecture is built around a hybrid approach: **Pattern Scanning** seeds initial signals, a deterministic **Knowledge Graph** filters out noise and calculates exploitability, **LLM Agents** reason over the resulting high-risk hotspots, and a **Validation Layer** (Jury + Depth Workers + Chain Analysis) eliminates false positives and discovers multi-step exploit chains.

---

## The End-to-End Pipeline

The entire system is orchestrated programmatically via a central Lead Coordinator using a stateful LangGraph workflow. Execute the pipeline via `python -m src.main --repo <target>`.

```
Ingestion → Graph Build → Hotspot Selection → Attack Workers → Jury → RAG →
Depth Workers → Chain Analysis → LLM Synthesis → TestWriter → Report
```

### Phase 1: Ingestion & Analysis
- **Framework Detection & Repository Management:** Automatically detects framework types (Foundry, Hardhat, Brownie) and clones repositories.
- **`AnalysisEngine`:** Compiles the smart contracts using Slither to generate an Intermediate Representation (IR).

### Phase 2: Structural Intelligence (The Knowledge Graph)
- **Titan Pattern Engine (`pattern_scanner.py`)**: A static regex-based engine (30+ vulnerability categories) scans source code for known anti-patterns (e.g., reentrancy CEI violations, unprotected tx.origin, flash loan inflation).
- **`GraphBuilder`**: Constructs a massive **NetworkX DiGraph** from the Slither IR. Nodes represent `Contract`, `Function`, `StateVariable`, and `Modifier` elements. It enriches the graph with:
  - Taint Analysis & Data Flow
  - Privilege & Access Control Extraction
  - Economic Amplification Multipliers
  - Accounting Invariant Detection (supply consistency, cap enforcement, reward drift, monotonicity)
  - Flash Loan Attack Surface Analysis
  - Validated Pattern Hits (from Titan)
- **`hotspot_engine.py`**: A deterministic gate. It evaluates graph nodes computing a `structural_score`, `exploitability_score`, and `final_score`. Functions only pass if they exceed strict thresholds (e.g., `final_score >= 70`) and bypass view/pure/constructor and test-file filters. Enforces a hotspot budget cap of 15.

### Phase 3: Multi-Agent Orchestration (LangGraph Flow)
Specialized "Worker" LLM agents execute on the filtered hotspots.

1. **`ReconWorker`**: Runs globally. Analyzes the entire codebase to understand protocol architecture, intent, and tier (e.g., Vault, DEX Router, Periphery).
2. **`AttackHypothesisWorker`**: Runs in **parallel** for every Hotspot. Using the Recon dossier and Graph node data, it attempts to formulate an attack.
   - **Outputs**: Vulnerability Class, Exploit Hypothesis, Confidence Score, **Preconditions**, **Preconditions Missing**, and **Postconditions**.
   - **Verdict Assignment**: Each finding gets a verdict: `CONFIRMED`, `PARTIAL` (exploitable only if missing preconditions are met), or `CONTESTED` (mixed evidence).
   - **Anti-Dismissal Logic**: Forced to always produce a hypothesis — never returns confidence=0 unless the function is a pure getter with zero state access.

### Phase 4: Validation Layer

Before synthesizing findings into a final report, Critikal employs four validation stages:

#### Step 4.5 — Jury System (`jury_worker.py`)
An optional multi-model adversarial debate on findings to eliminate false positives. Enable with `JURY_ENABLED=true`.

- **The 3 Jurors**:
  - **Skeptic** (Claude Sonnet): Attempts to find reasons why the hypothesis is wrong, overstated, or guarded against.
  - **Attacker** (Grok): Develops the most realistic, concrete attack scenario requiring specific function calls and assessing test provability.
  - **Auditor** (GPT-4o): Evaluates the severity and impact realism according to professional top-tier audit standards.
- **The Judge** (Gemini Pro): Arbitrates the jurors' votes (`CONFIRM`, `REJECT`, `UNCERTAIN`). For confirmed bugs, it synthesizes a concrete **TestWriter Brief** with explicit attack steps, verified preconditions, and deployment gotchas.
- **Decisions**: `CONFIRMED` (majority agree), `REJECTED` (majority disagree — finding dropped), `ESCALATE` (split vote — human review needed).

#### Step 4.6 — RAG Batch Validation (`rag_system.py`)
- Every finding is queried against a ChromaDB vector database containing historical exploits.
- Matches dynamically **boost** confidence (+5).
- Lack of precedent dynamically **penalizes** confidence (-10).

#### Step 4.7 — Depth Worker Pass (`depth_workers.py`)
Re-analyzes uncertain findings (verdict = `CONTESTED`, `PARTIAL`, or `UNASSESSED`) from specialized angles. Each worker uses domain-specific graph queries and an LLM prompt:

| Worker | Focus | Key Graph Queries |
|--------|-------|-------------------|
| **StateTraceDepthWorker** | Cross-function state mutation tracing, constraint enforcement, increment/decrement pairing | `get_state_dependencies()`, `get_state_transitions()` |
| **EdgeCaseDepthWorker** | Zero-state, dust analysis, boundary conditions, off-by-one errors with real protocol constants | `get_taint_critical_paths()` |
| **ExternalDepthWorker** | External call side effects, MEV sandwich vectors, flash loan enablement, oracle manipulation | `get_external_call_edges()`, `get_external_call_functions()` |

All depth workers enforce mandatory analysis checks:
1. **Devil's Advocate**: "What would make this exploitable?" — never answer "nothing"
2. **Evidence Quality**: All evidence tagged `[CODE]`, `[GRAPH-SIGNAL]`, or `[INFERRED]`
3. **Confidence Gate**: If uncertain → `CONTESTED`, not `REFUTED`. Only `REFUTED` if defense proven with specific code refs.

Depth verdicts: `CONFIRMED` (upgrades finding), `REFINED` (real issue is different), `REFUTED` (concrete defense found), `CONTESTED` (escalate to human).

#### Step 4.8 — Chain Analysis (`chain_analyzer.py`)
A **deterministic engine** (no LLM needed) that links findings into multi-step exploit chains:

1. **Extract**: Collects `postconditions` (what a finding creates if exploited) and `preconditions_missing` (what another finding needs).
2. **Match**: For each `preconditions_missing` entry, searches all other findings for matching `postconditions` via keyword overlap and category analysis.
3. **Classify**: Match types: `STATE`, `ACCESS`, `TIMING`, `BALANCE`. Match strengths: `STRONG`, `MODERATE`, `WEAK` (weak matches are discarded).
4. **Upgrade**: Severity matrix — chain severity is never lower than the higher of the two findings. Same severity chains upgrade by one tier (e.g., `MEDIUM + MEDIUM → HIGH`, `HIGH + HIGH → CRITICAL`).
5. **Apply**: Findings are tagged with `chain_ids`, `chain_role` (enabler/blocked), and `chain_severity_upgrade`.

### Phase 5: Synthesis
The `LeadAgent` synthesizes the validated findings from the Attack Workers into a structured JSON pipeline state. The Coordinator LLM produces the final analysis summary.

### Phase 6: Exploit Proof Layer (Phoenix Loop)
For every synthesized high-confidence lead, the **`TestWriterWorker`** attempts to prove the vulnerability by writing executable Foundry tests.
- **Sandbox Manager**: Isolates the testing environment utilizing `tempfile`.
- **Iterative Refinement**: The agent reads the Forge compiler output. If an error occurs (e.g., Error 6160 or 5883), it uses explicit prompt taxonomy to self-correct `import` paths and constructor arguments.
- **Variant Exploration**: If a PoC test compiles but the assertion fails, the TestWriter analyzes the execution trace and generates **relaxed variants** (mutating amounts, timing, balances) to uncover edge-case triggers.
- **Tags**: Assigns definitive Evidence Badges to the finding (`[POC-PASS]`, `[POC-PASS-VARIANT]`, `[POC-FAIL]`, `[CODE-TRACE]`).

### Phase 7: Reporting
The `ReportGenerator` ingests the graph, leads, chain hypotheses, and proven exploit artifacts (`.t.sol` files).
- Outputs `report.html` (comprehensive UI with interactive evidence/verdict badges and root cause tracking).
- Outputs `report.md` (formatted for Immunefi/HackerOne submission), including:
  - Per-finding chain badges (chain role, severity upgrades)
  - Depth verdict history (which worker re-analyzed, what it found)
  - Multi-Step Exploit Chains section with combined attack sequences
- Visualizes the NetworkX execution logic into `graph.html`.

---

## Agent Details & Multi-Provider Support

Critikal utilizes a "Mixture of Experts" framework where different models can be designated for specialized tasks via `.env`:

| Role | Default Model | Purpose |
|------|--------------|---------|
| Coordinator LLM | `gemini-2.5-pro` | Synthesizes the overall state |
| `ReconWorker` | `gemini-2.5-flash` | Fast context aggregation |
| `AttackHypothesisWorker` | `grok-3` | Deep reasoning and lateral thinking |
| `TestWriterWorker` | `gemini-2.5-flash` | Heavy coding and prompt adherence |
| Jury Skeptic | `claude-sonnet` | Adversarial challenge |
| Jury Attacker | `grok-3` | Exploit development |
| Jury Auditor | `gpt-4o` | Professional audit standards |
| Jury Judge | `gemini-2.5-pro` | Arbitration and brief synthesis |
| Depth Workers | `gemini-2.5-flash` | Domain-specific re-analysis |

Critikal implements robust thread-safe **API Key Pooling**. The system automatically manages rotation, 429 backoff strategies, and cooldown periods.

## Finding Taxonomy

A `Finding` in Critikal is not merely a string. It is a highly structured Pydantic object containing:
- `FindingVerdict`: Explicit determination (`CONFIRMED`, `PARTIAL`, `CONTESTED`, `REFUTED`).
- `confidence_decomposition`: Broken down by Evidence, Consensus (Jury), and RAG match.
- `evidence_tag`: Identifies how the bug was validated (`[POC-PASS]`, `[CODE-TRACE]`, etc.).
- `preconditions` / `postconditions`: Tracks precisely what state must exist to exploit the bug, enabling chain analysis.
- `preconditions_missing`: What conditions are NOT currently met but could be created by another vulnerability.
- `depth_verdicts`: History of depth worker re-analysis results (agent, verdict, reasoning, confidence).
- `chain_ids` / `chain_role` / `chain_severity_upgrade`: Multi-step exploit chain metadata.
- `root_cause_group`: Unique identifiers determining how bugs should be consolidated across multiple entry points.
- `jury_decision` / `jury_vote_summary` / `jury_reasoning`: Full Jury deliberation record.
