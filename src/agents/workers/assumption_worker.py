"""
AssumptionWorker — First-Principles Zero-Day Discovery Agent (Story 6.1)

Unlike AttackHypothesisWorker which injects pattern hints (reentrancy, oracle,
etc.) and tells the LLM WHAT class of bug to look for, this worker deliberately
suppresses all named vulnerability patterns. It gives the LLM raw source code +
graph structure and instructs it to enumerate and VIOLATE implicit assumptions.

This is the closest thing to a true zero-day methodology: bugs with no name,
found by systematically breaking what the code assumes to be true.

Inspired by pashov/skills first-principles-agent.md.
"""

import asyncio
import json
import logging
import os
import time

from src.agents.base_worker import WorkerAgent, WorkerOutput, WorkerTask

logger = logging.getLogger(__name__)

ASSUMPTION_LLM_TIMEOUT = int(os.getenv("ASSUMPTION_WORKER_LLM_TIMEOUT", "300"))

# ─────────────────────────────────────────────────────────────────────────────
#  SYSTEM PROMPT
#
#  Key design decisions:
#  1. ZERO pattern hints — no mention of reentrancy, oracle, access control, etc.
#  2. Assumption enumeration + violation loop is the ONLY methodology.
#  3. Output includes assumption/violation/proof fields, not just hypothesis.
#  4. Confidence floor 0 allowed — better to say "no violations found" than
#     hallucinate a pattern-matched false positive.
# ─────────────────────────────────────────────────────────────────────────────

ASSUMPTION_SYSTEM_PROMPT = """\
You are a first-principles security researcher.

## Your Only Job
Find bugs that have no name by violating what the code assumes to be true.

## MANDATORY: Do NOT pattern-match.
Forget every named vulnerability class you know.
Do not think about "reentrancy", "oracle manipulation", "access control", or
any other named security concept. For every line of code, ask only:
"this assumes X — can I break X?"

## Methodology (apply to EVERY state-changing function in scope)

### Step 1 — Extract every assumption the code makes
For each function, list ALL implicit assumptions:
- **Values**: "balance is current and reflects actual state", "price is fresh"
- **Ordering**: "function A ran before B", "variable was initialized before use"
- **Identity**: "msg.sender is who the protocol thinks it is"
- **Arithmetic**: "intermediate result fits in type", "denominator is nonzero"
- **State**: "flag was set by a prior call", "mapping entry exists", "invariant holds across calls"
- **Timing**: "this executes atomically with the next call", "state doesn't change between reads"
- **Scope**: "the collection I iterate contains ALL relevant items" (check queues, lists, mappings)

### Step 2 — Violate an assumption
For each assumption:
- Who controls the inputs that could break it?
- Construct a multi-transaction sequence that reaches the function with the assumption broken.
- Consider: direct calls, flash loans, MEV reordering, governance actions, natural protocol growth,
  a SEMI-TRUSTED role (allocator, keeper, operator) acting maliciously.

### Step 3 — Exploit the break
- Trace execution with the violated assumption active.
- Where does corrupted storage accumulate?
- Who can extract value from that corruption?
- Build a concrete step-by-step attack sequence.

## Design Intent Check (apply carefully before calling anything CONTESTED)
Before classifying a function as vulnerable, check Design Context:
1. Does natspec say this behaviour is intentional AND no external party is harmed?
2. Does the caller PAY their own tokens AND the "victim" only benefits?
3. Is overflow the claimed mechanism AND Solidity >= 0.8.0 without `unchecked {}`?

If ALL THREE checks pass: set verdict CONTESTED, confidence ≤ 40.
If only some pass: Do NOT reduce severity. The pattern may be "by design" yet still enable fund loss.

NEVER invoke design-intent reduction when:
- A semi-trusted role can cause harm to third parties via the "by design" path
- The mechanism allows arbitrary asset extraction by a non-owner
- The "intent" of the function and the attack path diverge

## Output Format
Return ONLY valid JSON. No markdown. No preamble.

{
  "assumption": "<the specific assumption that is broken — one sentence, precise>",
  "violation": "<how you broke it and exactly who controls the input to do so>",
  "proof": "<concrete multi-tx trace: call sequence, storage state, value extracted>",
  "confidence": <integer 0-100>,
  "title": "<short descriptive title — describe the mechanism, not a pattern name>",
  "impact": "<what the attacker gains if this succeeds>",
  "vulnerability_class": "invariant_violation | unprotected_mutator | privilege_escalation | flash_loan_amplification | accounting_scope | unknown",
  "severity_estimate": "CRITICAL | HIGH | MEDIUM | LOW",
  "attack_path": ["ContractName::functionName", ...],
  "preconditions": ["<what must be true before the attack>"],
  "preconditions_missing": ["<conditions needed but not currently met>"],
  "postconditions": ["<what state changes after the attack>"],
  "verdict": "CONFIRMED | PARTIAL | CONTESTED"
}

## Confidence Guidelines
- Concrete exploitable assumption + full self-contained call trace = 75–95
- Assumption violated + call trace established + SEMI-TRUSTED ROLE as threat actor = 65–80
  (do NOT reduce confidence because of role requirement — role-gated bugs are real and high-severity)
- Assumption violated, call trace indirect (depends on external state not in source) = 50–70
- Assumption breakable, extraction path unclear = 30–50
- No violation found: return confidence=0

## Semi-Trusted Role Rule
If the assumption violation requires a malicious allocator, keeper, guardian, operator, relayer, or
strategist:
- This is a VALID and IMPORTANT finding. Do NOT reduce confidence because of role.
- Set confidence based on the severity of the violation, not the role required.
- Set severity_estimate = CRITICAL if depositor/LP/lender funds can be drained.
- Set verdict = CONFIRMED if you can trace the full attack without needing live on-chain state.

## If no violations found
Return confidence=0 with:
{
  "assumption": "NONE_FOUND",
  "violation": "No assumption violations found",
  "proof": "<list the assumptions you checked and why each is upheld>",
  "confidence": 0,
  "vulnerability_class": "unknown",
  "severity_estimate": "LOW",
  ...
}

This is more valuable than a hallucinated false positive.

## Hard Rules
- NEVER invent a named vulnerability class as your title.
- The finding stands on its own proof, not on pattern recognition.
- If your proof requires knowing contract state that isn't in the source, mark it PARTIAL.
"""


class AssumptionWorker(WorkerAgent):
    """
    First-principles assumption-violation depth agent.

    Runs in parallel with AttackHypothesisWorker for every hotspot.
    Receives raw source + call graph. No graph signals. No pattern hints.
    """

    MAX_ATTEMPTS: int = 3

    def __init__(self, graph, llm_client):
        self.graph = graph
        self.llm = llm_client

    def get_worker_type(self) -> str:
        return "assumption_violation"

    async def run(self, task: WorkerTask) -> WorkerOutput:
        hotspot = task.hotspot
        if hotspot is None:
            return WorkerOutput(
                worker_type="assumption_violation",
                task_id=task.task_id,
                confidence=0,
                raw_output={"error": "No hotspot provided"},
            )

        node_id = hotspot.node_id
        prompt = self._build_prompt(hotspot)
        raw_response = await self._call_llm(prompt)
        parsed = self._parse_response(raw_response, node_id)

        if not parsed:
            logger.info(f"[AssumptionWorker] Parse failed for {node_id}")
            return WorkerOutput(
                worker_type="assumption_violation",
                task_id=task.task_id,
                confidence=0,
                raw_output={
                    "vulnerability_class": "first_principles",
                    "error": "LLM returned unparseable response",
                    "raw": raw_response[:500],
                },
            )

        confidence = parsed.get("confidence", 0)
        attack_path = parsed.get("attack_path", [])
        if not attack_path:
            attack_path = [f"{hotspot.contract}::{hotspot.function}"]

        return WorkerOutput(
            worker_type="assumption_violation",
            task_id=task.task_id,
            hypothesis=parsed.get("violation"),
            evidence_node_ids=[],   # no graph nodes — assumption violations are source-derived
            attack_path=attack_path,
            confidence=confidence,
            raw_output={
                "vulnerability_class": "first_principles",
                "title": parsed.get("title", f"Assumption violation in {hotspot.function}"),
                "assumption": parsed.get("assumption"),
                "violation": parsed.get("violation"),
                "proof": parsed.get("proof"),
                "impact": parsed.get("impact"),
                "preconditions": parsed.get("preconditions", []),
                "postconditions": parsed.get("postconditions", []),
                "verdict": parsed.get("verdict", "CONTESTED"),
                "affected_contract": hotspot.contract,
                "affected_function": hotspot.function,
                "severity_estimate": hotspot.priority,
            },
        )

    def _build_prompt(self, hotspot) -> list[dict]:
        """
        Build the user prompt. Inject ONLY:
        - Full source code
        - Function callers (who calls this)
        - Function callees (what this calls)
        - State variables written

        Deliberately OMIT all graph signals (reentrancy_risk, is_unprotected_mutator, etc.)
        to prevent pattern-matching bias.

        Falls back to reading source from disk when the graph is empty (semantic_only mode).
        """
        # Get source code and call graph — no signals
        from src.utils.graph_queries import get_function_context, get_internal_calls, get_callers

        source_code = "Source code not available"
        callers = []
        callees = []
        state_vars_written = []

        try:
            fn_ctx = get_function_context(self.graph, hotspot.node_id)
            source_code = fn_ctx.get("source_code") or fn_ctx.get("code", "Source code not available")
        except Exception:
            pass

        # Disk fallback: when graph is empty (semantic_only mode), read source from disk
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

        try:
            node_data = self.graph.nodes.get(hotspot.node_id, {})
            state_vars_written = node_data.get("state_variables_written", [])
        except Exception:
            pass

        user_content = f"""\
## Target Function
Contract: {hotspot.contract}
Function: {hotspot.function}

## Source Code
```solidity
{source_code}
```

## Call Graph (structural context only — no security signals)
Functions that call this function:
{self._format_list(callers) if callers else "None (this may be an entry point)"}

Functions this function calls internally:
{self._format_list(callees) if callees else "None (leaf function)"}

State variables written by this function:
{', '.join(state_vars_written) if state_vars_written else "None detected"}

## Your Task
Apply the assumption-violation methodology to this function.
Enumerate ALL assumptions the code makes. Violate them.
If you find a violation — prove it with a concrete call sequence.
If you find nothing — return confidence=0 with the assumptions you checked.

Return ONLY the JSON object.
"""
        return [
            {"role": "system", "content": ASSUMPTION_SYSTEM_PROMPT},
            {"role": "user", "content": user_content},
        ]

    async def _call_llm(self, messages: list[dict]) -> str:
        _FALLBACK = '{"assumption":"LLM_FAILED","violation":"LLM call failed","proof":"N/A","confidence":0,"title":"LLM failure","impact":"Unknown"}'

        for attempt in range(1, self.MAX_ATTEMPTS + 1):
            logger.info(
                f"[AssumptionWorker] LLM call attempt {attempt}/{self.MAX_ATTEMPTS} "
                f"at {time.strftime('%H:%M:%S')} (timeout={ASSUMPTION_LLM_TIMEOUT}s)..."
            )
            try:
                response = await asyncio.wait_for(
                    self.llm.ainvoke(messages),
                    timeout=ASSUMPTION_LLM_TIMEOUT,
                )
                content = response.content if hasattr(response, "content") else str(response)
                if isinstance(content, list):
                    content = "".join(
                        c.get("text", "") if isinstance(c, dict) else str(c)
                        for c in content
                    )

                # Token tracking (non-fatal)
                try:
                    from src.utils.token_counter import get_token_counter
                    model_name = os.getenv("ASSUMPTION_MODEL_NAME", "claude-sonnet-4-5")
                    input_text = "\n".join(
                        m.get("content", "") if isinstance(m, dict) else str(m)
                        for m in messages
                    )
                    get_token_counter().record(
                        "AssumptionWorker", model_name,
                        input_text, str(content),
                        getattr(response, "response_metadata", None),
                    )
                except Exception:
                    pass

                return str(content)

            except asyncio.TimeoutError:
                wait = 2 ** (attempt - 1)
                logger.warning(f"[AssumptionWorker] Attempt {attempt} timeout. Retrying in {wait}s...")
                if attempt < self.MAX_ATTEMPTS:
                    await asyncio.sleep(wait)
                continue

            except Exception as e:
                err_str = str(e)
                is_transient = any(kw in err_str for kw in ["504", "Deadline", "DEADLINE_EXCEEDED", "503", "CANCELLED"])
                wait = 2 ** (attempt - 1)
                logger.warning(f"[AssumptionWorker] Attempt {attempt} {'transient' if is_transient else 'non-transient'} error: {err_str[:100]}")
                if attempt < self.MAX_ATTEMPTS:
                    await asyncio.sleep(wait)
                continue

        logger.warning(f"[AssumptionWorker] All {self.MAX_ATTEMPTS} attempts failed — returning fallback.")
        return _FALLBACK

    def _parse_response(self, raw: str, node_id: str) -> dict | None:
        try:
            cleaned = raw.strip()
            if cleaned.startswith("```"):
                lines = cleaned.split("\n")
                cleaned = "\n".join(lines[1:-1]).strip()
            parsed = json.loads(cleaned)
            parsed["confidence"] = int(parsed.get("confidence", 0))
            if not isinstance(parsed.get("attack_path"), list):
                parsed["attack_path"] = []
            if not isinstance(parsed.get("preconditions"), list):
                parsed["preconditions"] = []
            if not isinstance(parsed.get("postconditions"), list):
                parsed["postconditions"] = []
            return parsed
        except Exception as e:
            logger.info(f"[AssumptionWorker] JSON parse error for {node_id}: {e}")
            return None

    def _read_source_from_disk(self, contract_name: str) -> str:
        """Fallback: read source from disk when graph has no source data (semantic_only mode)."""
        import glob
        # Try to find repo_path from the graph's metadata or fall back to cwd
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
                    with open(f, "r", encoding="utf-8", errors="replace") as fh:
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
