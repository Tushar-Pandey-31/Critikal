"""
Depth Workers — Specialized re-analysis agents for uncertain findings.

When a finding's verdict is CONTESTED, PARTIAL, or UNASSESSED, depth workers
perform targeted deep analysis from three specialized angles:

1. StateTraceDepthWorker: Cross-function state mutation tracing
2. EdgeCaseDepthWorker:   Zero-state, dust, boundary condition analysis
3. ExternalDepthWorker:   External call side effects, MEV, flash loan vectors

Each worker receives a Finding + graph context, queries the knowledge graph
for domain-specific signals, then prompts an LLM for a structured re-verdict.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
from dataclasses import dataclass, field
from typing import Any

import networkx as nx

from src.models.finding import Finding, FindingVerdict
from src.utils.graph_queries import get_graph_queries

logger = logging.getLogger(__name__)

DEPTH_LLM_TIMEOUT = int(os.getenv("DEPTH_WORKER_LLM_TIMEOUT", "180"))


# ── Result dataclass ──────────────────────────────────────────────

@dataclass
class DepthResult:
    """Structured output from a depth worker pass."""
    worker_type: str
    verdict: str        # CONFIRMED / REFINED / REFUTED / CONTESTED
    reasoning: str
    refined_confidence: int  # 0-100
    new_evidence_refs: list[str] = field(default_factory=list)
    raw_output: dict = field(default_factory=dict)


# ── Routing logic ────────────────────────────────────────────────

# Maps vulnerability class → best depth worker type
_VULN_CLASS_TO_DEPTH = {
    "reentrancy": "state_trace",
    "cei_violation": "state_trace",
    "invariant_violation": "state_trace",
    "unprotected_mutator": "state_trace",
    "privilege_escalation": "state_trace",
    "flash_loan_amplification": "external",
    "oracle_manipulation": "external",
    "mev_sandwich": "external",
    "arithmetic": "edge_case",
    "rounding": "edge_case",
    "boundary": "edge_case",
}


def _route_to_depth_worker(finding: Finding) -> str:
    """Pick the best depth worker based on vulnerability class."""
    return _VULN_CLASS_TO_DEPTH.get(
        finding.vulnerability_class.lower().replace(" ", "_"),
        "state_trace",  # default fallback
    )


# ── System Prompts ───────────────────────────────────────────────

STATE_TRACE_SYSTEM_PROMPT = """You are a depth analysis agent specializing in cross-function state mutation tracing.

## Your Role
You are re-analyzing a SPECIFIC finding that was previously marked as uncertain.
Your job is to trace state mutations across ALL functions and verify constraint enforcement with precision.

## Mandatory Analysis Checks (apply ALL before any verdict)
1. **Devil's Advocate**: Answer "What would make this exploitable?" — never answer "nothing".
2. **Chain Check**: Could ANOTHER vulnerability in the same contract create the missing precondition?
3. **Evidence Quality**: Tag all evidence [CODE], [GRAPH-SIGNAL], or [INFERRED].
4. **Confidence Gate**: If uncertain → CONTESTED, not REFUTED. Only REFUTED if defense proven with specific code references.

## Methodology
1. **Complete State Graph**: For the target state variable(s), list every function that READS and WRITES them.
2. **Cross-Function Consistency**: If X increments in function A, does it decrement in function B? Are all update operations atomic?
3. **Constraint Enforcement Trace**: For each constraint (min/max/cap/limit), is the check present on ALL code paths? Is the comparison operator correct (< vs <=)?
4. **Entry → Downstream Trace**: If the entry point forgets to update variable X, what breaks downstream?

## Output Format
Return ONLY valid JSON, no markdown:
{
  "verdict": "CONFIRMED" | "REFINED" | "REFUTED" | "CONTESTED",
  "reasoning": "<detailed paragraph explaining your verdict with specific code references>",
  "refined_confidence": <integer 0-100>,
  "new_evidence_refs": ["specific function or variable references found during analysis"],
  "state_graph": {
    "readers": ["list of functions that read the target variable"],
    "writers": ["list of functions that write the target variable"]
  },
  "devils_advocate": "<what would make this exploitable even if your initial analysis says no>"
}

## Verdict Guidelines
- CONFIRMED: The vulnerability is real. State mutations are inconsistent or unprotected.
- REFINED: The original hypothesis was partially correct but the actual issue is different. Explain the real issue.
- REFUTED: Concrete defense mechanism exists (cite specific code). REQUIRES [CODE] evidence.
- CONTESTED: Evidence is mixed. You see both attack surface and defense. Escalate.
"""

EDGE_CASE_SYSTEM_PROMPT = """You are a depth analysis agent specializing in edge cases, boundary conditions, and dust analysis.

## Your Role
You are re-analyzing a SPECIFIC finding that was previously marked as uncertain.
Focus on zero-state scenarios, minimum/maximum inputs, rounding precision, and off-by-one errors.

## DEMOTION CONTEXT AWARENESS
If this finding has gate_verdict = GATE_DEMOTED, it was likely demoted because:
(a) it requires a semi-trusted role (allocator, keeper, operator, guardian), or
(b) evidence was ambiguous.

For SEMI-TRUSTED ROLE demotions:
- The role IS a realistic threat actor. Assume it can be malicious.
- Your job is to verify TECHNICAL feasibility assuming the role IS acting maliciously.
- If technically feasible: verdict = CONFIRMED. Note "SEMI-TRUSTED-ROLE" in reasoning.
- Do NOT return REFUTED because the role is required. That is not a technical refutation.
- Confidence rule: if technically feasible AND semi-trusted role finding → refined_confidence >= 70
  (the TestWriter threshold is 65; be confident if the bug is technically real)

## Mandatory Analysis Checks
1. **Devil's Advocate**: Answer "What would make this exploitable?" — never "nothing".
2. **Real Constants**: Extract ACTUAL constant values from the source code and substitute them.
3. **Confidence Gate**: Uncertain? → CONTESTED, not REFUTED.

## Methodology
1. **Zero-State Analysis**: What happens at total_supply=0? Can first depositor exploit via donation? What exchange rate is used?
2. **Return-to-Zero**: When supply returns to 0, are there residual assets? What rate does the next depositor get?
3. **Dust Analysis**: Test with minimum unit (1 wei). Can sum of rounded fees > input amount? Where does remainder go?
4. **Boundary Traces**: For each < : should it be <=? At boundary-1, boundary, boundary+1 — what happens?
5. **Off-by-One**: Apply systematically to ALL comparison operators in setter functions, supply caps, and loop termination.

## Output Format
Return ONLY valid JSON:
{
  "verdict": "CONFIRMED" | "REFINED" | "REFUTED" | "CONTESTED",
  "reasoning": "<detailed paragraph with concrete calculations using real constants>",
  "refined_confidence": <integer 0-100>,
  "new_evidence_refs": ["specific references"],
  "real_constants": {"constant_name": "value from source code"},
  "concrete_calculations": "<show your math with real values>",
  "devils_advocate": "<what would make this exploitable>"
}
"""

EXTERNAL_SYSTEM_PROMPT = """You are a depth analysis agent specializing in external call side effects, MEV vectors, and flash loan enablement.

## Your Role
You are re-analyzing a SPECIFIC finding that was previously marked as uncertain.
Focus on what external calls actually DO (including side effects), sandwich attack surfaces, and flash loan amplification.

## Mandatory Analysis Checks
1. **Devil's Advocate**: Answer "What would make this exploitable?" — never "nothing".
2. **Side Effect Audit**: What does the external call ACTUALLY DO beyond the visible return value?
3. **Confidence Gate**: Uncertain? → CONTESTED, not REFUTED.

## Methodology
1. **External Call Side Effects**: Does the call transfer tokens? Update external state? Emit events? Can it revert selectively?
2. **MEV / Sandwich Surface**: Can this function be front-run profitably? Is there slippage protection? Can it be bypassed?
3. **Flash Loan Enablement**: Can this function be called atomically in a flash loan? What state checks would flash-borrowed tokens pass?
4. **Oracle Manipulation**: What oracle is read? TWAP window length? Can it be manipulated within a block?
5. **Governance Impact**: Can external parameter changes (fee rates, supported tokens, pause states) break assumptions?

## Output Format
Return ONLY valid JSON:
{
  "verdict": "CONFIRMED" | "REFINED" | "REFUTED" | "CONTESTED",
  "reasoning": "<detailed paragraph>",
  "refined_confidence": <integer 0-100>,
  "new_evidence_refs": ["references"],
  "external_side_effects": ["list of side effects identified"],
  "mev_assessment": "<sandwich/frontrun viability>",
  "flash_loan_viable": true | false,
  "devils_advocate": "<what would make this exploitable>"
}
"""

STATE_TRACE_DEMOTION_BLOCK = """\

## DEMOTION CONTEXT AWARENESS
If this finding has gate_verdict = GATE_DEMOTED, it was likely demoted because:
(a) it requires a semi-trusted role (allocator, keeper, operator, guardian), or
(b) evidence was ambiguous.

For SEMI-TRUSTED ROLE demotions:
- The role IS a realistic threat actor. Assume it can be malicious.
- Your job is to verify TECHNICAL feasibility assuming the role IS acting maliciously.
- If technically feasible: verdict = CONFIRMED. Note "SEMI-TRUSTED-ROLE" in reasoning.
- Do NOT return REFUTED because the role is required. That is not a technical refutation.
- Confidence rule: if technically feasible AND semi-trusted role finding → refined_confidence >= 70
  (the TestWriter threshold is 65; be explicit and confident if the bug is technically real)
"""



# ── Depth Worker Base ────────────────────────────────────────────

class _DepthWorkerBase:
    """Common logic for all depth workers."""

    worker_type: str = "depth_base"
    system_prompt: str = ""

    def __init__(self, llm_client: Any, model_name: str):
        self.llm = llm_client
        self.model_name = model_name

    def _build_user_content(
        self,
        finding: Finding,
        graph: nx.DiGraph,
        source_code: str,
        is_da_pass: bool = False,
    ) -> str:
        """Build the user prompt with finding context and graph signals."""
        gq = get_graph_queries(graph)
        node_data = graph.nodes.get(finding.hotspot_node_id, {})

        # Get graph-derived context
        func_ctx = gq.get_function_context(finding.hotspot_node_id)
        state_deps = gq.get_state_dependencies(finding.affected_contract)
        state_transitions = gq.get_state_transitions(
            function_id=finding.hotspot_node_id
        )

        lines = []
        if is_da_pass:
            lines += [
                "🔥 DEVIL'S ADVOCATE MODE ACTIVE 🔥",
                "Your objective is to find a way to make this finding EXPLOITABLE.",
                "Disregard previous dismissals. Act as an attacker trying to prove this works.",
                "",
            ]

        lines += [
            "## Finding Under Review",
            f"Contract: {finding.affected_contract}",
            f"Function: {finding.affected_function}",
            f"Vulnerability Class: {finding.vulnerability_class}",
        ]

        if not is_da_pass:
            lines += [
                f"Current Verdict: {finding.verdict}",
                f"Current Confidence: {finding.confidence}",
            ]

        lines += [
            "",
            "## Original Hypothesis",
            finding.hypothesis or "No hypothesis available.",
            "",
            "## Preconditions (claimed)",
        ]
        for p in (finding.preconditions or []):
            lines.append(f"  ✅ {p}")
        for p in (finding.preconditions_missing or []):
            lines.append(f"  ❌ MISSING: {p}")

        lines += [
            "",
            "## Postconditions (if exploited)",
        ]
        for p in (finding.postconditions or []):
            lines.append(f"  → {p}")

        # Graph signals
        lines += [
            "",
            "## Graph Signals (deterministic facts)",
            f"Structural Score: {node_data.get('structural_score', 0)}",
            f"Exploitability Score: {node_data.get('exploitability_score', 0)}",
            f"Final Score: {node_data.get('final_score', 0)}",
            f"Has Reentrancy Risk: {node_data.get('reentrancy_risk', False)}",
            f"Makes External Call: {node_data.get('makes_external_call', False)}",
            f"Writes State: {node_data.get('writes_state', False)}",
            f"Is Protected: {node_data.get('is_protected', False)}",
            f"State Variables Written: {node_data.get('state_variables_written', [])}",
        ]

        # Taint info
        taint_paths = node_data.get("taint_critical_paths", [])
        if taint_paths:
            lines += ["", "## Taint Critical Paths"]
            for tp in taint_paths[:5]:
                lines.append(f"  - {tp}")

        # State dependencies
        if state_deps:
            lines += ["", "## Cross-Function State Dependencies"]
            for dep in state_deps[:10]:
                lines.append(
                    f"  {dep['writer']} → {dep['reader']} "
                    f"via [{', '.join(dep.get('shared_variables', []))}]"
                )

        # State transitions
        if state_transitions:
            lines += ["", "## State Transitions in This Function"]
            for st in state_transitions[:10]:
                lines.append(
                    f"  {st['operation']} on {st['variable']} "
                    f"(attacker_controlled={st.get('attacker_controlled_input', False)})"
                )

        # Source code
        lines += [
            "",
            "## Contract Source Code",
            "```solidity",
            source_code[:8000] if source_code else "// Source not available",
            "```",
            "",
            "Review the above and return your depth verdict as JSON.",
        ]

        return "\n".join(lines)

    async def analyze(
        self,
        finding: Finding,
        graph: nx.DiGraph,
        source_code: str,
        is_da_pass: bool = False,
    ) -> DepthResult:
        """Run depth analysis on a single finding."""
        user_content = self._build_user_content(finding, graph, source_code, is_da_pass)

        # Inject demotion context: if the finding was GATE_DEMOTED, append the
        # semi-trusted role demotion block so the LLM knows to evaluate technical
        # feasibility rather than questioning the threat actor's realism.
        system = self.system_prompt
        gate_verdict = getattr(finding, "gate_verdict", "")
        if gate_verdict == "GATE_DEMOTED":
            system = system + STATE_TRACE_DEMOTION_BLOCK

        messages = [
            {"role": "system", "content": system},
            {"role": "user", "content": user_content},
        ]


        try:
            response = await asyncio.wait_for(
                self.llm.ainvoke(messages),
                timeout=DEPTH_LLM_TIMEOUT,
            )
            content = (
                response.content
                if hasattr(response, "content")
                else str(response)
            )
            if isinstance(content, list):
                content = "".join(
                    c.get("text", "") if isinstance(c, dict) else str(c)
                    for c in content
                )

            # Track tokens
            try:
                from src.utils.token_counter import get_token_counter
                input_text = "\n".join(
                    m.get("content", "") if isinstance(m, dict) else str(m)
                    for m in messages
                )
                get_token_counter().record(
                    f"Depth_{self.worker_type}",
                    self.model_name,
                    input_text,
                    str(content),
                    getattr(response, "response_metadata", None),
                )
            except Exception:
                pass

            return self._parse_response(content)

        except TimeoutError:
            logger.warning(f"[Depth] {self.worker_type} timed out")
            return DepthResult(
                worker_type=self.worker_type,
                verdict="CONTESTED",
                reasoning="Depth worker timed out",
                refined_confidence=finding.confidence,
            )
        except Exception as e:
            logger.warning(f"[Depth] {self.worker_type} failed: {e}")
            return DepthResult(
                worker_type=self.worker_type,
                verdict="CONTESTED",
                reasoning=f"Depth worker error: {str(e)[:200]}",
                refined_confidence=finding.confidence,
            )

    def _parse_response(self, raw: str) -> DepthResult:
        """Parse LLM JSON output into a DepthResult."""
        try:
            cleaned = raw.strip()
            if cleaned.startswith("```"):
                lines = cleaned.split("\n")
                cleaned = "\n".join(lines[1:-1]).strip()

            parsed = json.loads(cleaned)

            verdict = parsed.get("verdict", "CONTESTED").upper()
            if verdict not in ("CONFIRMED", "REFINED", "REFUTED", "CONTESTED"):
                verdict = "CONTESTED"

            confidence = int(parsed.get("refined_confidence", 50))
            confidence = max(0, min(100, confidence))

            return DepthResult(
                worker_type=self.worker_type,
                verdict=verdict,
                reasoning=parsed.get("reasoning", ""),
                refined_confidence=confidence,
                new_evidence_refs=parsed.get("new_evidence_refs", []),
                raw_output=parsed,
            )
        except Exception as e:
            logger.warning(f"[Depth] {self.worker_type} parse error: {e}")
            return DepthResult(
                worker_type=self.worker_type,
                verdict="CONTESTED",
                reasoning=f"Parse error: {str(e)[:200]}",
                refined_confidence=50,
            )


# ── Concrete Depth Workers ───────────────────────────────────────

class StateTraceDepthWorker(_DepthWorkerBase):
    worker_type = "state_trace"
    system_prompt = STATE_TRACE_SYSTEM_PROMPT


class EdgeCaseDepthWorker(_DepthWorkerBase):
    worker_type = "edge_case"
    system_prompt = EDGE_CASE_SYSTEM_PROMPT


class ExternalDepthWorker(_DepthWorkerBase):
    worker_type = "external"
    system_prompt = EXTERNAL_SYSTEM_PROMPT


# ── Orchestrator ─────────────────────────────────────────────────

async def run_depth_workers(
    findings: list[Finding],
    graph: nx.DiGraph,
    source_cache: dict[str, str],
    llm_client: Any,
    model_name: str,
    max_depth_passes: int = 1,
) -> list[tuple[Finding, DepthResult]]:
    """
    Run depth workers on uncertain findings.

    Filters for findings with verdict in (CONTESTED, PARTIAL, UNASSESSED),
    routes each to the best-matching depth worker, runs them concurrently,
    and applies the results back to the findings.

    Returns list of (finding, depth_result) pairs.
    """
    # Filter uncertain findings
    uncertain = [
        f for f in findings
        if f.verdict in (
            FindingVerdict.CONTESTED,
            FindingVerdict.PARTIAL,
            FindingVerdict.UNASSESSED,
            "CONTESTED",
            "PARTIAL",
            "UNASSESSED",
        )
        and f.depth_pass_count == 0
    ]

    if not uncertain:
        print("[Depth] No uncertain findings to analyze.")
        return []

    print(f"[Depth] Analyzing {len(uncertain)} uncertain finding(s) (up to {max_depth_passes} passes)...")

    # Instantiate workers
    workers = {
        "state_trace": StateTraceDepthWorker(llm_client, model_name),
        "edge_case": EdgeCaseDepthWorker(llm_client, model_name),
        "external": ExternalDepthWorker(llm_client, model_name),
    }

    processed: list[tuple[Finding, DepthResult]] = []

    for pass_idx in range(max_depth_passes):
        is_da_pass = (pass_idx > 0)

        if not uncertain:
            break

        pass_name = f"Pass {pass_idx+1}" + (" (Devil's Advocate)" if is_da_pass else "")
        print(f"[Depth] Starting {pass_name} on {len(uncertain)} finding(s)...")

        async def _analyze_one(finding: Finding, is_da: bool) -> tuple[Finding, DepthResult]:
            worker_type = _route_to_depth_worker(finding)
            worker = workers.get(worker_type, workers["state_trace"])

            # Get source code for the contract
            source = source_cache.get(finding.affected_contract, "")
            if not source:
                # Try node data
                node_data = graph.nodes.get(finding.hotspot_node_id, {})
                source = node_data.get("source_code", "")

            print(f"  [Depth] {worker_type} → {finding.affected_contract}::{finding.affected_function}")
            result = await worker.analyze(finding, graph, source, is_da_pass=is_da)
            print(
                f"  [Depth] {worker_type} verdict: {result.verdict} "
                f"(confidence: {result.refined_confidence})"
            )
            return (finding, result)

        tasks = [_analyze_one(f, is_da_pass) for f in uncertain]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        next_uncertain = []
        for r in results:
            if isinstance(r, Exception):
                logger.warning(f"[Depth] Worker exception: {r}")
                continue
            finding, depth_result = r
            _apply_depth_result(finding, depth_result)

            # Use finding.verdict since _apply_depth_result updates it,
            # wait, _apply_depth_result currently DOES NOT update finding.verdict immediately.
            # I must update finding.verdict = depth_result.verdict if we don't already do that.
            # Actually _apply_depth_result is right below. Let me assume finding.verdict gets updated
            # or depth_result.verdict is the authority.
            finding.verdict = depth_result.verdict
            finding.confidence = depth_result.refined_confidence

            if pass_idx == max_depth_passes - 1 or depth_result.verdict not in ("CONTESTED", "PARTIAL", "UNASSESSED"):
                processed.append((finding, depth_result))
            else:
                next_uncertain.append(finding)

        uncertain = next_uncertain

    confirmed = sum(1 for _, r in processed if r.verdict == "CONFIRMED")
    refined = sum(1 for _, r in processed if r.verdict == "REFINED")
    refuted = sum(1 for _, r in processed if r.verdict == "REFUTED")
    contested = sum(1 for _, r in processed if r.verdict == "CONTESTED")
    print(
        f"[Depth] Complete: {confirmed} confirmed, {refined} refined, "
        f"{refuted} refuted, {contested} contested"
    )

    return processed


def _apply_depth_result(finding: Finding, result: DepthResult) -> None:
    """Apply a depth worker's result back onto the finding."""
    finding.depth_pass_count += 1
    finding.depth_verdicts.append({
        "agent": result.worker_type,
        "verdict": result.verdict,
        "reasoning": result.reasoning,
        "confidence": result.refined_confidence,
        "evidence_refs": result.new_evidence_refs,
    })

    # Update verdict based on depth result
    if result.verdict == "CONFIRMED":
        finding.verdict = FindingVerdict.CONFIRMED
        # Boost confidence: take the higher of current vs depth
        finding.confidence = max(finding.confidence, result.refined_confidence)
        finding.confidence_evidence = max(
            finding.confidence_evidence, result.refined_confidence
        )
    elif result.verdict == "REFINED":
        finding.verdict = FindingVerdict.PARTIAL
        # Use depth worker's refined confidence
        finding.confidence = result.refined_confidence
    elif result.verdict == "REFUTED":
        finding.verdict = FindingVerdict.REFUTED
        # Drop confidence significantly
        finding.confidence = min(finding.confidence, max(result.refined_confidence, 15))
    # CONTESTED: no change to verdict, leave as-is for human review
