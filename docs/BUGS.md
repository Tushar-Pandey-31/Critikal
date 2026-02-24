# Penteam Bug Documentation

**Generated**: February 22, 2026  
**Purpose**: Exhaustive catalog of identified bugs with exact citations for verification before fixes.  
**Status**: Partially remediated (updated February 24, 2026).

## Remediation Update (February 24, 2026)

The following items have been addressed in code:

- Node-ID normalization is now enforced for attack paths and evidence IDs.
- Coordinator synthesis rules now match runtime behavior (final synthesis is no-tool).
- `.git` repository URL normalization is handled in coordinator repo path resolution.
- Optional contract-address mapping was added to CLI/env for recon enrichment.
- Test Writer now enforces exact `test_exploit()` naming and uses exit-code-first success checks.
- Sandbox has Windows fallback when symlink creation fails.
- Chroma DB pathing is centralized via `src/knowledge/paths.py` across ingest/runtime.
- Timestamp generation in `Finding` now uses timezone-aware UTC API.

Open items should be interpreted against current code state; several original entries describe pre-fix behavior.

---

## Table of Contents

1. [Critical Bugs](#critical-bugs)
2. [High Severity Bugs](#high-severity-bugs)
3. [Medium Severity Bugs](#medium-severity-bugs)
4. [Low Severity Bugs](#low-severity-bugs)
5. [Verification Checklist](#verification-checklist)

---

## Critical Bugs

### BUG-001: `code` vs `source_code` Key Mismatch — GraphQueries API

**Severity**: Critical  
**Impact**: Attack Hypothesis Worker never receives source code. Lead Agent never populates `relevant_code` for Test Writer. The LLM analyzes hotspots without seeing the actual source.

#### Location 1 — Producer (returns `code`)

| File | Line(s) | Snippet |
|------|---------|---------|
| `src/utils/graph_queries.py` | 33-37 | See below |

```python
return {
    "node_id": node_id,
    "code": node_data.get("source_code", ""),   # <-- KEY IS "code"
    "callers": callers,
    "callees": callees
}
```

**Note**: `GraphQueries.get_function_context()` returns a dict with key `"code"`. The graph node stores `source_code` (see `src/graph_builder.py` line 116), but the query API exposes it as `"code"`.

#### Location 2 — Consumer (expects `source_code`)

| File | Line(s) | Snippet |
|------|---------|---------|
| `src/agents/workers/attack_hypothesis_worker.py` | 259 | See below |

```python
{fn_ctx.get("source_code", "Source code not available — rely on graph signals")}
```

**Root cause**: `fn_ctx` comes from `get_function_context(graph, node_id)` which returns `{"code": ...}`. The key `"source_code"` is never present, so the fallback string is always used.

**Verification**: Add a debug print in `_build_prompt` and observe that `fn_ctx.get("source_code")` is always `None` while `fn_ctx.get("code")` contains the actual code.

#### Location 3 — Lead Agent (checks `source_code`)

| File | Line(s) | Snippet |
|------|---------|---------|
| `src/agents/lead_agent.py` | 469-491 | See below |

```python
for node_id in finding.attack_path:
    try:
        ctx = get_function_context(state["graph"], node_id)
        if "source_code" in ctx:                    # <-- NEVER TRUE
            relevant_code[node_id] = ctx["source_code"]
    except Exception:
        pass

if not relevant_code:
    for ep in finding.evidence_nodes:
        try:
            ctx = get_function_context(state["graph"], ep.node_id)
            if "source_code" in ctx:                # <-- NEVER TRUE
                relevant_code[ep.node_id] = ctx["source_code"]
        except Exception:
            pass

if not relevant_code and finding.hotspot_node_id:
    try:
        ctx = get_function_context(state["graph"], finding.hotspot_node_id)
        if "source_code" in ctx:                    # <-- NEVER TRUE
            relevant_code[finding.hotspot_node_id] = ctx["source_code"]
    except Exception:
        pass
```

**Result**: `relevant_code` is always `{}` when built from the graph. Test Writer falls back to `_find_real_source()` only when a matching `.sol` file is found on disk.

---

### BUG-002: Node ID Format Mismatch — Dot vs Double Colon

**Severity**: Critical  
**Impact**: Even if BUG-001 were fixed, `relevant_code` would remain empty because `get_function_context()` is called with node IDs that do not exist in the graph.

#### Graph Convention (double colon)

| File | Line(s) | Snippet |
|------|---------|---------|
| `src/graph_builder.py` | 68-70, 124 | See below |

```python
# Line 68-70 (_add_function_node)
# Unique ID: ContractName::FunctionName
node_id = f"{contract.name}::{function.name}"

# Line 124 (_add_edge_defines)
function_id = f"{contract.name}::{function.name}"
```

**Graph node IDs**: `Vault::deposit`, `Token::transfer`, etc.

#### Attack Worker Convention (dot)

| File | Line(s) | Snippet |
|------|---------|---------|
| `src/agents/workers/attack_hypothesis_worker.py` | 50, 59-62, 132, 161 | See below |

```python
# Line 50 - JSON schema instructs LLM
"attack_path": ["ContractName.functionName", "ContractName.otherFunction"],

# Lines 59-62 - Explicit instruction
## attack_path Rules
- Use the format "ContractName.functionName" (dot notation, not ::)
- ...
- Do NOT use :: notation.

# Line 132 - Fallback when parse fails
attack_path=[f"{hotspot.contract}.{hotspot.function}"],

# Lines 160-161 - Fallback when attack_path is empty
if not attack_path:
    attack_path = [f"{hotspot.contract}.{hotspot.function}"]
```

**Attack path format**: `Vault.deposit`, `Token.transfer`, etc.

#### Lead Agent Usage

| File | Line(s) | Snippet |
|------|---------|---------|
| `src/agents/lead_agent.py` | 469-471 | See below |

```python
for node_id in finding.attack_path:
    try:
        ctx = get_function_context(state["graph"], node_id)  # node_id = "Vault.deposit"
```

**Result**: `graph.has_node("Vault.deposit")` is `False`. `get_function_context()` returns `{"error": "Node not found"}` (see `src/utils/graph_queries.py` lines 14-15). No context is ever returned.

**Verification**: Call `get_function_context(graph, "Vault.deposit")` vs `get_function_context(graph, "Vault::deposit")`; only the second returns valid data.

---

### BUG-003: Lead–Finding Mismatch for Proven Exploits

**Severity**: Critical  
**Impact**: When Test Writer proves an exploit, the corresponding lead in the final output may not be updated with `[PROVEN]`, `test_code`, or `exploit_success` because the equality check fails.

#### Location

| File | Line(s) | Snippet |
|------|---------|---------|
| `src/agents/lead_agent.py` | 530-532 | See below |

```python
for lead in leads:
    if lead.get("affected_function_node_id") == finding.hotspot_node_id:
        lead.update({
            "confidence": finding.confidence,
            "test_code": raw.get("test_code"),
            "exploit_success": raw.get("exploit_success"),
            ...
        })
```

**Root cause**:
- `finding.hotspot_node_id` always uses graph format: `Contract::function` (set from `hotspot.node_id` in `Finding.from_worker_output`, which comes from `get_high_risk_hotspots`).
- `lead.get("affected_function_node_id")` comes from the Coordinator LLM's JSON output. The prompt specifies `"<ContractName::functionName>"` (line 108), but LLMs may output `ContractName.functionName`.
- If the LLM uses dot notation, `"Vault.deposit" == "Vault::deposit"` is `False`, so the update never runs.

**Verification**: Inspect `lead["affected_function_node_id"]` vs `finding.hotspot_node_id` in a run where Test Writer succeeds; if formats differ, the update is skipped.

---

## High Severity Bugs

### BUG-004: `contract_addresses` Never Populated

**Severity**: High  
**Impact**: Etherscan-based recon (exploit history, flash loan interactions, proxy detection, contract age) never runs. Recon always receives stub data.

#### Location 1 — Initialization

| File | Line(s) | Snippet |
|------|---------|---------|
| `src/main.py` | 141 | See below |

```python
"contract_addresses": {},  # Initialize empty if recon not done yet
```

#### Location 2 — Recon Consumption

| File | Line(s) | Snippet |
|------|---------|---------|
| `src/agents/lead_agent.py` | 291-292 | See below |

```python
context={
    ...
    "contract_addresses": state.get("contract_addresses", {}),
    ...
}
```

| File | Line(s) | Snippet |
|------|---------|---------|
| `src/agents/workers/recon_worker.py` | 94, 101, 222-232 | See below |

```python
# Line 94
contract_addresses: dict = input_data.get("contract_addresses", {})

# Line 101
self._gather_onchain_intel(contract_addresses),

# Lines 222-232 - Early return when empty
async def _gather_onchain_intel(self, contract_addresses: dict) -> dict:
    if not contract_addresses:
        return {
            "contract_age_days": None,
            "previous_exploits_detected": False,
            ...
            "data_source": "stub",
        }
```

**Root cause**: No code ever populates `contract_addresses`. There is no extraction from `repo_url`, config, or user input.

**Verification**: Run the pipeline; check `recon_context["onchain_risk_signals"]["data_source"]` — it will always be `"stub"`.

---

### BUG-005: Symlink Creation Fails on Windows

**Severity**: High  
**Impact**: On Windows without Developer Mode or admin privileges, `Path.symlink_to()` raises `OSError`. Sandbox setup fails for any repo that has a `lib/` directory (typical for Foundry projects).

#### Location

| File | Line(s) | Snippet |
|------|---------|---------|
| `src/agents/workers/test_writer_sandbox.py` | 43-48 | See below |

```python
# Symlink lib/ — works because repo_path is now on /tmp/ (Linux fs)
original_lib = self.repo_path / "lib"
sandbox_lib = self.tmp_dir / "lib"
if original_lib.exists():
    sandbox_lib.symlink_to(original_lib.resolve())   # <-- OSError on Windows without Developer Mode
```

**Note**: The comment assumes Linux. On Windows, `tempfile.mkdtemp()` returns a path under `%TEMP%`, and `symlink_to` requires special permissions.

**Verification**: Run Test Writer with a Foundry repo on Windows without Developer Mode; observe `OSError` during `_setup_from_real_repo`.

---

### BUG-006: Repo Path Resolution Fails for `.git` URLs

**Severity**: High  
**Impact**: When `repo_url` ends with `.git`, `repo_path` is resolved incorrectly, so `repo_path` stays `None`. Test Writer never receives a valid `repo_path` and cannot use real sources.

#### Location 1 — RepoManager (strips `.git`)

| File | Line(s) | Snippet |
|------|---------|---------|
| `src/repo_manager.py` | 28-32 | See below |

```python
repo_name = os.path.basename(os.path.normpath(url))
if repo_name.endswith(".git"):
    repo_name = repo_name[:-4]

target_path = os.path.join(self.workspace_dir, repo_name)
# Clone creates: ./data/scratch/repo  (folder name = "repo")
```

**Clone result**: Folder is named `repo` (without `.git`).

#### Location 2 — Lead Agent (does not strip `.git`)

| File | Line(s) | Snippet |
|------|---------|---------|
| `src/agents/lead_agent.py` | 297-304 | See below |

```python
repo_url = state.get("repo_url", "")
repo_name = repo_url.rstrip("/").split("/")[-1] if repo_url else ""   # "repo.git" for URL ending in .git
repo_path = None
if repo_name:
    candidate = Path("data/scratch") / repo_name   # Path("data/scratch/repo.git")
    if candidate.exists():                         # FALSE - actual folder is "repo"
        repo_path = str(candidate)
```

**Root cause**: `repo_name` from URL parsing keeps `.git`; RepoManager strips it when creating the folder. The candidate path `data/scratch/repo.git` does not exist; the real path is `data/scratch/repo`.

**Verification**: Run with `--repo https://github.com/org/repo.git`; `repo_path` will be `None`, and Test Writer will use mock mode instead of real sources.

---

## Medium Severity Bugs

### BUG-007: ChromaDB Path Inconsistency

**Severity**: Medium  
**Impact**: Tools and RAG/ingest may use different ChromaDB directories if CWD differs between runs or entry points.

#### Locations

| File | Line(s) | Path Used |
|------|---------|-----------|
| `src/agents/tools.py` | 19 | `"./data/chroma_db"` |
| `src/knowledge/rag_system.py` | 6 | `os.path.join(os.getcwd(), "data", "chroma_db")` |
| `src/knowledge/ingest.py` | 9 | `os.path.join(os.getcwd(), "data", "chroma_db")` |

**Snippet from `src/agents/tools.py`**:
```python
DB_PATH = "./data/chroma_db"
...
vector_db = Chroma(persist_directory=DB_PATH, ...)
```

**Root cause**: `"./data/chroma_db"` is relative to CWD. If the process is started from a different directory (e.g. `python -m src.main` from project root vs `python src/main.py` from another folder), tools and RAG may point to different DBs.

**Verification**: Run ingest from one CWD, then run main from another; RAG queries in tools may return no results if the paths differ.

---

### BUG-008: Exploit Success Uses String Match Instead of Return Code

**Severity**: Medium  
**Impact**: A test run that fails (non-zero exit) could still be marked as success if `[PASS]` appears in logs (e.g. from another test or from compiler output). Conversely, a successful run with no `[PASS]` in captured output could be marked as failure.

#### Location

| File | Line(s) | Snippet |
|------|---------|---------|
| `src/agents/workers/test_writer_worker.py` | 202-204 | See below |

```python
test_res = sandbox.run("forge test --match-test test_exploit -vvv")
test_logs = (test_res.stdout or "") + "\n" + (test_res.stderr or "")
exploit_success = "[PASS]" in test_logs or "exploit succeeded" in test_logs.lower()
```

**Note**: `test_res.success` (from `Result.success` which checks `returncode == 0`) is not used. Foundry exits with 0 on all tests pass, non-zero on failure.

**Verification**: Compare `test_res.success` with `exploit_success` in edge cases; they should be equivalent for correct behavior.

---

### BUG-009: EvidenceNode `node_id` Format Ambiguity

**Severity**: Medium  
**Impact**: If Attack Worker LLM returns `evidence_node_ids` in dot notation, those IDs will not match graph nodes. Any later lookup (e.g. in Lead Agent's `relevant_code` loop over `finding.evidence_nodes`) will fail.

#### Location

| File | Line(s) | Snippet |
|------|---------|---------|
| `src/models/finding.py` | 63-71 | See below |

```python
evidence_nodes=[
    EvidenceNode(
        node_id=nid,   # nid from output.evidence_node_ids - may be "Vault.deposit"
        ...
    )
    for nid in output.evidence_node_ids
],
```

**Root cause**: `evidence_node_ids` comes from the LLM; prompt leaves it as `[]` and does not supply graph node IDs. If the LLM fills it, it may use dot notation. Graph uses `::`.

**Verification**: Manually set `evidence_node_ids = ["Vault.deposit"]` in a WorkerOutput; observe `get_function_context(graph, "Vault.deposit")` returning `{"error": "Node not found"}`.

---

### BUG-010: Test Writer Prompts Do Not Enforce `test_exploit` Name

**Severity**: Medium  
**Impact**: The pipeline runs `forge test --match-test test_exploit`. If the LLM generates `test_exploit_reentrancy` or `test_vuln` instead of `test_exploit`, the filter matches nothing and the test is effectively skipped.

#### Location 1 — Command

| File | Line(s) | Snippet |
|------|---------|---------|
| `src/agents/workers/test_writer_worker.py` | 202 | See below |

```python
test_res = sandbox.run("forge test --match-test test_exploit -vvv")
```

#### Location 2 — Prompts

| File | Line(s) | Snippet |
|------|---------|---------|
| `src/agents/workers/test_writer_prompts.py` | 23-24, 65 | See below |

```python
# Mock prompt - mentions test_exploit but does not say "MUST be named exactly test_exploit"
- `test_exploit()` function containing the attack logic

# Real source prompt - same
- `test_exploit()` with the attack
```

**Root cause**: Prompts say to include `test_exploit()` but do not state that the function name must be exactly `test_exploit` for the command to match.

---

## Low Severity Bugs

### BUG-011: RAG Ingest Not Part of Main Flow

**Severity**: Low  
**Impact**: ChromaDB is populated only by a separate ingest script. If ingest is never run, RAG queries return empty results with no explicit error. Recon and tools run without RAG context.

**Location**: `src/knowledge/ingest.py` is a standalone script; no code in the main pipeline calls it.

---

### BUG-012: Coordinator Tool Loop Re-runs Full Pipeline

**Severity**: Low  
**Impact**: If the Coordinator LLM returns tool calls (e.g. `get_high_risk_hotspots`) instead of synthesis JSON, execution goes to the Tool node and then back to Coordinator. The Coordinator node re-runs Recon, Attack workers, and Test Writer from scratch, causing duplicate work and potential inconsistency.

**Relevant code**: `src/agents/lead_agent.py` lines 391-393 — early return when `response.tool_calls` is truthy.

---

## Verification Checklist

Before fixing, verify each bug as follows:

| Bug ID | Verification Step |
|--------|-------------------|
| BUG-001 | Add `print("code" in ctx, "source_code" in ctx)` in Attack Worker `_build_prompt`; run and confirm `source_code` is always missing |
| BUG-002 | Call `graph.has_node("Vault.deposit")` vs `graph.has_node("Vault::deposit")` on a real graph; only second is True |
| BUG-003 | Log `lead.get("affected_function_node_id")` and `finding.hotspot_node_id` when Test Writer succeeds; check format match |
| BUG-004 | Log `state["contract_addresses"]` at Recon run; confirm always `{}` |
| BUG-005 | Run Test Writer on Windows with a Foundry repo that has `lib/`; observe OSError if Developer Mode off |
| BUG-006 | Run with `--repo https://github.com/user/repo.git`; log `repo_path` in Coordinator; confirm `None` |
| BUG-007 | Run ingest from `./`, then main from `src/`; check if RAG returns results |
| BUG-008 | Inspect `Result.success` vs string-based `exploit_success` in test runs |
| BUG-009 | Create Finding with `evidence_node_ids=["Contract.func"]`; run relevant_code loop; confirm empty |
| BUG-010 | Manually generate a test with `test_exploit_reentrancy`; run forge test; confirm no match |
| BUG-011 | Run main without ever running ingest; confirm RAG returns [] |
| BUG-012 | Force Coordinator to return tool_calls; observe duplicate worker execution |

---

## Cross-Reference Summary

| Concept | Files Involved |
|---------|----------------|
| Function context / source code | `graph_queries.py`, `attack_hypothesis_worker.py`, `lead_agent.py`, `graph_builder.py` |
| Node ID format | `graph_builder.py`, `attack_hypothesis_worker.py`, `lead_agent.py`, `graph_queries.py` |
| Contract addresses | `main.py`, `lead_agent.py`, `recon_worker.py` |
| Repo path | `main.py`, `repo_manager.py`, `lead_agent.py`, `test_writer_worker.py` |
| ChromaDB path | `agents/tools.py`, `knowledge/rag_system.py`, `knowledge/ingest.py` |
| Sandbox / symlink | `test_writer_sandbox.py` |
| Exploit success | `test_writer_worker.py` |

---

*End of BUGS.md*
