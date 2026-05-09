"""
ExecutionTraceWorker — Forward execution trace agent.

Maps execution flow across function boundaries to find bugs that exist
in the INTERACTION between functions, not within any single function.

Methodology:
1. Build the call sequence graph: who calls whom, in what order
2. Track state changes through the full sequence
3. Find where assumptions made by function A are violated by function B
4. Identify incomplete code paths (early returns, error branches that skip cleanup)

This catches bugs like:
- Function A updates variable X but function B reads stale X
- Deposit updates balance but withdraw doesn't update the same counter
- Error path in function A skips updating variable Y that function B depends on
- Symmetric function pairs (mint/burn) with asymmetric state changes
"""

from __future__ import annotations

import asyncio
import json
import logging
import os

from src.pipeline.base_worker import WorkerAgent, WorkerOutput, WorkerTask

logger = logging.getLogger(__name__)

EXECUTION_TRACE_TIMEOUT = int(os.getenv("EXECUTION_TRACE_LLM_TIMEOUT", "300"))

EXECUTION_TRACE_SYSTEM_PROMPT = """\
You are an attacker that exploits gaps between functions. Single-function analysis
found nothing wrong — the bug lives in the INTERACTION between two or more functions.

## Your Only Job
Find bugs by tracing execution across function boundaries. Map every state change
in function A, then check if function B handles ALL of those changes correctly.

## Methodology

### Step 1 — Build the Function Family Map
Group all functions by what they DO (not by name):
- **Entry functions**: deposit, mint, stake, create, open
- **Exit functions**: withdraw, burn, unstake, close, cancel
- **Update functions**: claim, harvest, compound, rebalance, sync
- **Admin functions**: setFee, updateOracle, pause, migrate

### Step 2 — The Symmetry Test (highest-value check)
For every Entry/Exit function pair:
1. List ALL state variables modified by the Entry function
2. List ALL state variables modified by the Exit function
3. For each variable in list 1: does list 2 contain the REVERSE operation?
4. For each event in Entry: does Exit emit the corresponding reverse event?
5. For each token transfer in Entry: does Exit have the corresponding refund?

**If Entry does X but Exit doesn't undo X → BUG.** This is the function family
comparison test. It catches accounting desyncs, orphaned rewards, and leaked state.

### Step 3 — Incomplete Code Paths
For every function with multiple return paths (if/else, try/catch, require):
1. Trace the "happy path" — what state changes occur?
2. Trace EVERY "sad path" (early return, revert, error branch)
3. For each state change in the happy path: is it ALSO cleaned up in sad paths?
4. If a sad path leaves partial state → bug. An attacker triggers the sad path
   to accumulate corrupted state.

### Step 4 — Cross-Function State Staleness
For every state variable read by 2+ functions:
1. Can function A write the variable, then function B read a stale value?
2. Is there a time window between A's write and B's read where an attacker acts?
3. Can an attacker call function C between A and B to change the variable?

### Step 5 — Construct the Attack
For each gap found:
- Build the MINIMAL call sequence that exploits the gap
- Show concrete values: state before, state after, what the attacker extracts
- Identify the threat actor (unprivileged, semi-trusted, or privileged)

## Output Format
Return ONLY valid JSON:
{
  "function_families": {
    "entry": ["deposit", "mint"],
    "exit": ["withdraw", "burn"],
    "update": ["claim", "sync"],
    "admin": ["setFee", "pause"]
  },
  "symmetry_gaps": [
    {
      "entry_function": "ContractName::deposit",
      "exit_function": "ContractName::withdraw",
      "state_change_in_entry": "totalDeposited += amount",
      "missing_reverse_in_exit": "totalDeposited is never decremented in withdraw",
      "exploitable": true/false
    }
  ],
  "findings": [
    {
      "vulnerability_class": "symmetry_gap | incomplete_path | stale_cross_read |
        orphaned_state | missing_cleanup",
      "title": "Short descriptive title",
      "affected_contract": "ContractName",
      "entry_function": "functionA",
      "exit_function": "functionB",
      "hypothesis": "How the gap between these functions is exploitable",
      "proof": "Concrete values: step-by-step call sequence showing state corruption",
      "attack_path": ["ContractName::funcA", "ContractName::funcB"],
      "threat_actor": "unprivileged | semi_trusted_role | privileged",
      "confidence": <integer 0-100>,
      "impact": "What the attacker extracts — with specific numbers",
      "severity_estimate": "CRITICAL | HIGH | MEDIUM | LOW"
    }
  ]
}

## Critical Rules
- Every finding needs TWO functions: the one that creates the gap and the one that exploits it.
- Concrete values are MANDATORY. No proof with values = not a finding.
- The symmetry test is your highest-value check — do it first, do it thoroughly.
- If you find nothing, return empty findings. Do NOT hallucinate.
"""


class ExecutionTraceWorker(WorkerAgent):
    """
    Forward execution trace agent.

    Runs after AttackHypothesisWorker for every hotspot. Focuses on
    cross-function interactions rather than single-function analysis.
    """

    MAX_ATTEMPTS: int = 3

    def __init__(self, graph, llm_client):
        self.graph = graph
        self.llm = llm_client

    def get_worker_type(self) -> str:
        return "execution_trace"

    async def run(self, task: WorkerTask) -> WorkerOutput:
        hotspot = task.hotspot
        if hotspot is None:
            return WorkerOutput(
                worker_type="execution_trace",
                task_id=task.task_id,
                confidence=0,
                raw_output={"error": "No hotspot provided"},
            )

        node_id = hotspot.node_id
        prompt = self._build_prompt(hotspot)
        raw_response = await self._call_llm(prompt)
        parsed = self._parse_response(raw_response, node_id)

        if not parsed:
            return WorkerOutput(
                worker_type="execution_trace",
                task_id=task.task_id,
                confidence=0,
                raw_output={
                    "vulnerability_class": "execution_trace",
                    "error": "LLM returned unparseable response",
                    "raw": raw_response[:500],
                },
            )

        # Extract the best finding from the response
        findings_list = parsed.get("findings", [])
        if not findings_list:
            return WorkerOutput(
                worker_type="execution_trace",
                task_id=task.task_id,
                confidence=0,
                raw_output={
                    "vulnerability_class": "execution_trace",
                    "title": "No cross-function gaps found",
                    "symmetry_gaps": parsed.get("symmetry_gaps", []),
                    "function_families": parsed.get("function_families", {}),
                },
            )

        # Take the highest-confidence finding
        best = max(findings_list, key=lambda f: f.get("confidence", 0))
        confidence = int(best.get("confidence", 0))

        attack_path = best.get("attack_path", [])
        if not attack_path:
            attack_path = [f"{hotspot.contract}::{hotspot.function}"]

        return WorkerOutput(
            worker_type="execution_trace",
            task_id=task.task_id,
            hypothesis=best.get("hypothesis"),
            evidence_node_ids=[],
            attack_path=attack_path,
            confidence=confidence,
            raw_output={
                "vulnerability_class": best.get("vulnerability_class", "symmetry_gap"),
                "title": best.get("title", f"Cross-function gap in {hotspot.contract}"),
                "proof": best.get("proof", ""),
                "impact": best.get("impact", ""),
                "preconditions": [],
                "preconditions_missing": [],
                "postconditions": [],
                "verdict": "CONFIRMED" if confidence >= 70 else "PARTIAL" if confidence >= 40 else "CONTESTED",
                "affected_contract": hotspot.contract,
                "affected_function": hotspot.function,
                "severity_estimate": best.get("severity_estimate", hotspot.priority),
                "symmetry_gaps": parsed.get("symmetry_gaps", []),
                "function_families": parsed.get("function_families", {}),
                "all_findings": findings_list,
            },
        )

    def _build_prompt(self, hotspot) -> list[dict]:
        """Build the user prompt with full contract source code and call graph."""
        from src.utils.graph_queries import get_callers, get_function_context, get_internal_calls

        source_code = "Source code not available"
        callers = []
        callees = []
        sibling_functions = []

        try:
            fn_ctx = get_function_context(self.graph, hotspot.node_id)
            source_code = fn_ctx.get("source_code") or fn_ctx.get("code", "Source code not available")
        except Exception:
            pass

        # Disk fallback
        if source_code == "Source code not available":
            source_code = self._read_source_from_disk(hotspot.contract)

        try:
            callers = get_callers(self.graph, hotspot.node_id)
        except Exception:
            pass

        try:
            callees = get_internal_calls(self.graph, hotspot.node_id)
        except Exception:
            pass

        # Find sibling functions in the same contract
        try:
            for node_id, data in self.graph.nodes(data=True):
                if (data.get("contract_name") == hotspot.contract and
                    node_id != hotspot.node_id and
                    data.get("node_type") == "function"):
                    sibling_functions.append({
                        "name": data.get("function_name", node_id),
                        "visibility": data.get("visibility", "unknown"),
                        "writes_state": data.get("writes_state", False),
                        "state_vars_written": data.get("state_variables_written", []),
                    })
        except Exception:
            pass

        siblings_text = ""
        if sibling_functions:
            siblings_text = "\n## Sibling Functions in Same Contract\n"
            for sf in sibling_functions[:20]:  # Cap at 20
                vars_written = ", ".join(sf["state_vars_written"][:5]) if sf["state_vars_written"] else "none"
                siblings_text += f"- {sf['name']} ({sf['visibility']}) → writes: [{vars_written}]\n"

        user_content = f"""\
## Target Function
Contract: {hotspot.contract}
Function: {hotspot.function}

## Source Code
```solidity
{source_code}
```

## Call Graph
Functions that call this function:
{self._format_list(callers) if callers else "None (entry point)"}

Functions this function calls:
{self._format_list(callees) if callees else "None (leaf)"}
{siblings_text}
## Your Task
Apply the execution trace methodology:
1. Build the function family map for {hotspot.contract}
2. Run the symmetry test on all entry/exit pairs
3. Check for incomplete code paths
4. Find cross-function state staleness
5. If you find gaps, construct concrete attacks with specific values

Return ONLY the JSON object.
"""
        return [
            {"role": "system", "content": EXECUTION_TRACE_SYSTEM_PROMPT},
            {"role": "user", "content": user_content},
        ]

    async def _call_llm(self, messages: list[dict]) -> str:
        _FALLBACK = '{"function_families":{},"symmetry_gaps":[],"findings":[]}'

        for attempt in range(1, self.MAX_ATTEMPTS + 1):
            try:
                response = await asyncio.wait_for(
                    self.llm.ainvoke(messages),
                    timeout=EXECUTION_TRACE_TIMEOUT,
                )
                content = response.content if hasattr(response, "content") else str(response)
                if isinstance(content, list):
                    content = "".join(
                        c.get("text", "") if isinstance(c, dict) else str(c)
                        for c in content
                    )

                # Token tracking
                try:
                    from src.utils.token_counter import get_token_counter
                    model_name = os.getenv("EXECUTION_TRACE_MODEL_NAME", "gpt-5.4-mini")
                    input_text = "\n".join(
                        m.get("content", "") if isinstance(m, dict) else str(m)
                        for m in messages
                    )
                    get_token_counter().record(
                        "ExecutionTraceWorker", model_name,
                        input_text, str(content),
                        getattr(response, "response_metadata", None),
                    )
                except Exception:
                    pass

                return str(content)

            except TimeoutError:
                wait = 2 ** (attempt - 1)
                logger.warning(f"[ExecutionTrace] Attempt {attempt} timeout. Retrying in {wait}s...")
                if attempt < self.MAX_ATTEMPTS:
                    await asyncio.sleep(wait)
                continue

            except Exception as e:
                wait = 2 ** (attempt - 1)
                logger.warning(f"[ExecutionTrace] Attempt {attempt} error: {str(e)[:100]}")
                if attempt < self.MAX_ATTEMPTS:
                    await asyncio.sleep(wait)
                continue

        logger.warning(f"[ExecutionTrace] All {self.MAX_ATTEMPTS} attempts failed.")
        return _FALLBACK

    def _parse_response(self, raw: str, node_id: str) -> dict | None:
        try:
            cleaned = raw.strip()
            if cleaned.startswith("```"):
                lines = cleaned.split("\n")
                cleaned = "\n".join(lines[1:-1]).strip()
            parsed = json.loads(cleaned)
            return parsed
        except Exception as e:
            logger.info(f"[ExecutionTrace] JSON parse error for {node_id}: {e}")
            return None

    def _read_source_from_disk(self, contract_name: str) -> str:
        """Fallback: read source from disk when graph has no source data."""
        import glob
        repo_path = getattr(self.graph, '_repo_path', None) or os.getcwd()
        exclude_dirs = {"test", "tests", "mock", "mocks", "lib", "node_modules",
                        "script", "scripts", "echidna", "fuzz", "fuzzing"}
        sol_files = glob.glob(os.path.join(repo_path, "**", "*.sol"), recursive=True)
        for f in sol_files:
            parts = f.replace("\\", "/").split("/")
            if any(p.lower() in exclude_dirs for p in parts):
                continue
            basename = os.path.basename(f).replace(".sol", "")
            if basename.lower() == contract_name.lower():
                try:
                    with open(f, encoding="utf-8", errors="replace") as fh:
                        content = fh.read()
                    if len(content) > 30000:
                        content = content[:30000] + "\n// ... truncated ..."
                    return content
                except Exception:
                    pass
        return "Source code not available"

    def _format_list(self, items: list) -> str:
        if not items:
            return "None"
        if items and isinstance(items[0], dict):
            return json.dumps(items, indent=2)
        return "\n".join(f"  - {item}" for item in items)
