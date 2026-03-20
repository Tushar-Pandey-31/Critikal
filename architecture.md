# Critikal Architecture

Critikal is a multi-agent smart contract security system designed for high-signal vulnerability detection. Its architecture is built around a hybrid approach: **Pattern Scanning** seeds initial signals, a deterministic **Knowledge Graph** filters out noise and calculates exploitability, and **LLM Agents** reason over the resulting high-risk hotspots to generate and prove exploits via live execution.

---

## The End-to-End Pipeline

The entire system is orchestrated programmatically via a central Lead Coordinator using a stateful LangGraph workflow. Execute the pipeline via `python -m src.main --repo <target>`.

### Phase 1: Ingestion & Analysis
- **Framework Detection & Repository Management:** Automatically detects framework types (Foundry, Hardhat, Brownie) and clones repositories.
- **`AnalysisEngine`:** Compiles the smart contracts using Slither to generate an Intermediate Representation (IR).

### Phase 2: Structural Intelligence (The Knowledge Graph)
- **Titan Pattern Engine (`pattern_scanner.py`)**: A static regex-based engine (30+ vulnerability categories) scans source code for known anti-patterns (e.g., reentrancy CEI violations, unprotected tx.origin, flash loan inflation).
- **`GraphBuilder`**: Constructs a massive **NetworkX DiGraph** from the Slither IR. Nodes represent `Contract`, `Function`, `StateVariable`, and `Modifier` elements. It enriches the graph with:
  - Taint Analysis & Data Flow
  - Privilege & Access Control Extraction
  - Economic Amplification Multipliers
  - Validated Pattern Hits (from Titan)
- **`hotspot_engine.py`**: A deterministic gate. It evaluates graph nodes computing a `structural_score`, `exploitability_score`, and `final_score`. Functions only pass if they exceed strict thresholds (e.g., `final_score >= 70`) and bypass view/pure/constructor and test-file filters.

### Phase 3: Multi-Agent Orchestration (LangGraph Flow)
Specialized "Worker" LLM agents execute on the filtered hotspots.

1. **`ReconWorker`**: Runs globally. Analyzes the entire codebase to understand protocol architecture, intent, and tier (e.g., Vault, DEX Router, Periphery).
2. **`AttackHypothesisWorker`**: Runs in **parallel** for every Hotspot. Using the Recon dossier and Graph node data, it attempts to formulate an attack.
   - **Outputs**: Vulnerability Class, Exploit Hypothesis, Confidence Score, **Preconditions**, and **Postconditions**.
   - **Anti-Dismissal Logic**: Forced to evaluate non-standard impacts via strict prompt engineering rules preventing premature bug dismissal.

### Phase 4: Validation (RAG & Jury)
- **RAG Batch Validation (`rag_system.py`)**: Before synthesizing findings, Critikal queries a ChromaDB vector database containing historical exploits.
  - Matches dynamically **boost** the Attack Worker's confidence (+5).
  - Lack of precedent dynamically **penalizes** the confidence (-10).
- **Jury Validation** (Optional): A multi-agent debate (Judge & Jurors) adversarially dissects the findings to eliminate false positives.

### Phase 5: Synthesis
The `LeadAgent` synthesizes the validated findings from the Attack Workers into a structured JSON pipeline state.

### Phase 6: Exploit Proof Layer (Phoenix Loop)
For every synthesized high-confidence lead, the **`TestWriterWorker`** attempts to prove the vulnerability by writing executable Foundry tests.
- **Sandbox Manager**: Isolates the testing environment utilizing `tempfile`.
- **Iterative Refinement**: The agent reads the Forge compiler output. If an error occurs (e.g., Error 6160 or 5883), it uses explicit prompt taxonomy to self-correct `import` paths and constructor arguments.
- **Variant Exploration**: If a PoC test compiles but the assertion fails, the TestWriter analyzes the execution trace and generates **relaxed variants** (mutating amounts, timing, balances) to uncover edge-case triggers.
- **Tags**: Assigns definitive Evidence Badges to the finding (`[POC-PASS]`, `[POC-PASS-VARIANT]`, `[POC-FAIL]`, `[CODE-TRACE]`).

### Phase 7: Reporting
The `ReportGenerator` ingests the graph, leads, and proven exploit artifacts (`.t.sol` files).
- Outputs `report.html` (comprehensive UI with interactive evidence/verdict badges and root cause tracking).
- Outputs `report.md` (formatted for Immunefi/HackerOne submission).
- Visualizes the NetworkX execution logic into `graph.html`.

---

## Agent Details & Multi-Provider Support

Critikal utilizes a "Mixture of Experts" framework where different models can be designated for specialized tasks via `.env`:

- **Coordinator LLM**: Synthesizes the overall state. (Default: `gemini-2.5-pro`)
- **`ReconWorker`**: Fast context aggregation. (Default: `gemini-2.5-flash`)
- **`AttackHypothesisWorker`**: Deep reasoning and lateral thinking. (Default: `grok-3`)
- **`TestWriterWorker`**: Heavy coding and prompt adherence. (Default: `claude-3.5-sonnet`)

Critikal implements robust thread-safe **API Key Pooling**. The system automatically manages rotation, 429 backoff strategies, and cooldown periods.

## Finding Taxonomy

A `Finding` in Critikal is not merely a string. It is a highly structured Pydantic object containing:
- `FindingVerdict`: Explicit determination (`CONFIRMED`, `PARTIAL`, `CONTESTED`, `REFUTED`).
- `confidence_decomposition`: Broken down by Evidence, Consensus (Jury), and RAG match.
- `evidence_tag`: Identifies how the bug was validated (`[POC-PASS]`, `[CODE-TRACE]`, etc.).
- `preconditions` / `postconditions`: Tracks precisely what state must exist to exploit the bug, enabling advanced multi-step chain analysis.
- `root_cause_group`: Unique identifiers determining how bugs should be consolidated across multiple entry points.
