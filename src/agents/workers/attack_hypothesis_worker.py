import json
from src.agents.base_worker import WorkerAgent, WorkerOutput, WorkerTask
from src.utils.graph_queries import (
    get_function_context,
    get_internal_calls,
    get_callers,
    get_privilege_escalation_risks,
    get_external_call_functions,
)

CONFIDENCE_THRESHOLDS = {
    "reentrancy": 35,
    "privilege_escalation": 35,
    "unprotected_mutator": 30,
    "cei_violation": 35,
    "unknown": 40,
}

CATEGORY_TO_CLASS = {
    "reentrancy": "reentrancy",
    "unprotected_mutator": "unprotected_mutator",
    "can_escalate_privileges": "privilege_escalation",
    "state_write_after_external_call": "cei_violation",
}

# ─────────────────────────────────────────────────────────────
#  SYSTEM PROMPT
#
#  Key fixes vs old prompt:
#  1. No longer demands node IDs in attack_path — LLM doesn't have
#     them so it was always returning []. Now accepts function names.
#  2. No "confidence=0 if not sure" — instead always produce a best
#     guess with appropriate confidence, never null.
#  3. Explicit DVDeFi vulnerability patterns listed.
# ─────────────────────────────────────────────────────────────

ATTACK_WORKER_SYSTEM_PROMPT = """You are an elite smart contract security researcher specializing in finding exploitable bugs.

## Your Job
Analyze ONE suspicious function (a "hotspot") and determine if it contains a real vulnerability.
You MUST always produce a hypothesis — never return confidence=0 unless the function is a pure getter with zero state access.

## Output Format
Return ONLY valid JSON. No markdown fences, no preamble, no explanation.

{
  "vulnerability_class": "reentrancy" | "unprotected_mutator" | "privilege_escalation" | "cei_violation" | "unknown",
  "title": "Short one-line title of the vulnerability",
  "hypothesis": "2-4 sentence narrative of HOW to exploit this. Be specific about the attack steps.",
  "attack_path": ["ContractName.functionName", "ContractName.otherFunction"],
  "evidence_node_ids": [],
  "confidence": <integer 35-100>,
  "impact": "What an attacker gains if this succeeds",
  "preconditions": ["What must be true for this exploit to work"],
  "reasoning": "Why this confidence score"
}

## attack_path Rules
- Use the format "ContractName.functionName" (dot notation, not ::)
- Start with the external entry point, end with the vulnerable function
- Minimum 1 element. If only one function is involved, just list that one.
- Do NOT use :: notation. Do NOT leave this empty. Always include at least the target function.

## Common Vulnerability Patterns (trust graph signals heavily)

**REENTRANCY** (state_write_after_external_call=True OR reentrancy_risk=True):
- External call happens BEFORE state update (CEI violation)
- Attacker deploys malicious contract, calls victim, victim calls attacker's fallback, attacker re-enters
- confidence >= 80 if state_write_after_external_call=True and makes_external_call=True

**UNPROTECTED_MUTATOR** (is_unprotected_mutator=True):
- Admin function (setOwner, setMigrator, addToken, initialize, etc.) with no onlyOwner/access control
- Any address can call and hijack the protocol
- confidence >= 85 if is_unprotected_mutator=True on a clearly admin function

**PRIVILEGE_ESCALATION** (can_escalate_privileges=True):
- Function overwrites owner/admin variable without checking caller
- confidence >= 75

**CEI_VIOLATION** (state_write_after_external_call=True):
- Balance/accounting updated AFTER external transfer
- Can be exploited with flash loans or re-entrance
- confidence >= 70

## Confidence Guidelines
- Graph signal confirmed + source code confirms = 85-98
- Graph signal confirmed, source code ambiguous = 60-80
- Graph signal only, no source code = 45-65
- Speculative based on function name alone = 35-50
- NEVER return confidence < 35 (use 35 as floor if any signal exists)
"""


class AttackHypothesisWorker(WorkerAgent):
    model_name: str = "gemini-2.5-flash"

    def __init__(self, graph, llm_client):
        self.graph = graph
        self.llm = llm_client

    def get_worker_type(self) -> str:
        return "attack_hypothesis"

    async def run(self, task: WorkerTask) -> WorkerOutput:
        print(f"[AttackWorker debug] Starting task {task.task_id}", flush=True)
        hotspot = task.hotspot
        if hotspot is None:
            return WorkerOutput(
                worker_type="attack_hypothesis",
                task_id=task.task_id,
                confidence=0,
                raw_output={"error": "No hotspot provided"}
            )

        recon_context = task.context.get("recon_context", {})
        node_id = hotspot.node_id

        graph_context = self._gather_graph_context(node_id, hotspot)
        prompt = self._build_prompt(hotspot, graph_context, recon_context)

        raw_response = await self._call_llm(prompt)
        parsed = self._parse_response(raw_response, node_id)

        if not parsed:
            print(f"[AttackWorker] Parse failed for {node_id}. Raw: {raw_response[:200]}")
            # Return minimum viable output instead of silent 0
            return WorkerOutput(
                worker_type="attack_hypothesis",
                task_id=task.task_id,
                confidence=35,
                hypothesis=f"Static analysis flagged {hotspot.function} as high-risk but LLM response was unparseable.",
                attack_path=[f"{hotspot.contract}.{hotspot.function}"],
                raw_output={
                    "vulnerability_class": "unknown",
                    "title": f"Suspected issue in {hotspot.function}",
                    "impact": "Unknown — requires manual review",
                    "error": "LLM returned unparseable response",
                    "raw": raw_response[:500],
                }
            )

        vulnerability_class = parsed.get("vulnerability_class", "unknown")
        confidence = parsed.get("confidence", 0)
        threshold = CONFIDENCE_THRESHOLDS.get(vulnerability_class, 40)

        # Boost confidence if graph signals are strong but LLM was conservative
        signals = graph_context.get("signals_summary", {})
        strong_signal = (
            signals.get("reentrancy_risk") or
            signals.get("is_unprotected_mutator") or
            signals.get("can_escalate_privileges") or
            signals.get("state_write_after_external_call")
        )
        if strong_signal and confidence < 35:
            confidence = 45
            print(f"[AttackWorker] Graph signal strong → boosting confidence to 45 for {node_id}")

        # Fix empty attack_path — LLM often returns [] even with a valid hypothesis
        attack_path = parsed.get("attack_path", [])
        if not attack_path:
            attack_path = [f"{hotspot.contract}.{hotspot.function}"]
            print(f"[AttackWorker] attack_path was empty → defaulting to [{attack_path[0]}]")

        if confidence < threshold:
            print(f"[AttackWorker] Confidence {confidence} below threshold {threshold} for {vulnerability_class} on {node_id}")
            return WorkerOutput(
                worker_type="attack_hypothesis",
                task_id=task.task_id,
                confidence=0,
                raw_output={
                    "reason": f"Confidence {confidence} below threshold {threshold}",
                    "parsed": parsed,
                }
            )

        return WorkerOutput(
            worker_type="attack_hypothesis",
            task_id=task.task_id,
            hypothesis=parsed.get("hypothesis"),
            evidence_node_ids=parsed.get("evidence_node_ids", []),
            attack_path=attack_path,
            confidence=confidence,
            raw_output={
                "vulnerability_class": vulnerability_class,
                "title": parsed.get("title"),
                "impact": parsed.get("impact"),
                "preconditions": parsed.get("preconditions", []),
                "graph_signals_used": signals,
                "affected_contract": hotspot.contract,
                "affected_function": hotspot.function,
                "severity_estimate": hotspot.priority,
            }
        )

    def _gather_graph_context(self, node_id: str, hotspot) -> dict:
        context = {}

        try:
            fn_context = get_function_context(self.graph, node_id)
            context["function_context"] = fn_context
        except Exception:
            context["function_context"] = {}

        try:
            context["internal_calls"] = get_internal_calls(self.graph, node_id)
        except Exception:
            context["internal_calls"] = []

        try:
            context["callers"] = get_callers(self.graph, node_id)
        except Exception:
            context["callers"] = []

        context["signals_summary"] = {
            "reentrancy_risk": hotspot.signals.get("reentrancy_risk", False),
            "is_unprotected_mutator": hotspot.signals.get("is_unprotected_mutator", False),
            "can_escalate_privileges": hotspot.signals.get("can_escalate_privileges", False),
            "state_write_after_external_call": hotspot.signals.get("state_write_after_external_call", False),
            "makes_external_call": hotspot.signals.get("makes_external_call", False),
            "reachable_from_external_entry": hotspot.signals.get("reachable_from_external_entry", True),
        }

        if hotspot.signals.get("can_escalate_privileges"):
            try:
                context["escalation_detail"] = get_privilege_escalation_risks(self.graph, hotspot.contract)
            except Exception:
                context["escalation_detail"] = {}

        if hotspot.signals.get("makes_external_call"):
            try:
                ext = get_external_call_functions(self.graph)
                context["external_call_detail"] = [e for e in ext if e.get("node_id") == node_id]
            except Exception:
                context["external_call_detail"] = []

        return context

    def _build_prompt(self, hotspot, graph_context: dict, recon_context: dict) -> list[dict]:
        fn_ctx = graph_context.get("function_context", {})
        signals = graph_context.get("signals_summary", {})

        # Determine expected vulnerability class from signals
        expected_class = "unknown"
        if signals.get("state_write_after_external_call") or signals.get("reentrancy_risk"):
            expected_class = "reentrancy or cei_violation"
        elif signals.get("is_unprotected_mutator"):
            expected_class = "unprotected_mutator"
        elif signals.get("can_escalate_privileges"):
            expected_class = "privilege_escalation"

        user_content = f"""## Target Hotspot
Contract: {hotspot.contract}
Function: {hotspot.function}
Node ID (for reference): {hotspot.node_id}
Risk Score: {hotspot.risk_score}
Expected Vulnerability Class (from static analysis): {expected_class}

## Source Code
{fn_ctx.get("source_code", "Source code not available — rely on graph signals")}

## Graph Signals (deterministic — trust these completely)
- reentrancy_risk: {signals.get("reentrancy_risk")}
- state_write_after_external_call: {signals.get("state_write_after_external_call")}
- is_unprotected_mutator: {signals.get("is_unprotected_mutator")}
- can_escalate_privileges: {signals.get("can_escalate_privileges")}
- makes_external_call: {signals.get("makes_external_call")}
- reachable_from_external_entry: {signals.get("reachable_from_external_entry")}

## Internal Calls Made by This Function
{self._format_list(graph_context.get("internal_calls", []))}

## Functions That Call This Function
{self._format_list(graph_context.get("callers", []))}

## Protocol Context (from Recon)
Protocol Type: {recon_context.get("protocol_type", "unknown")}
Known Attack Patterns: {recon_context.get("known_attack_patterns", [])}

## Instructions
1. The graph signals above are from deterministic static analysis — treat them as ground truth.
2. If state_write_after_external_call=True, assume CEI violation is real.
3. If is_unprotected_mutator=True, assume access control is missing.
4. Generate the strongest exploit hypothesis you can based on available evidence.
5. attack_path must use dot notation: "ContractName.functionName"
6. Return ONLY the JSON object, no markdown, no prose."""

        return [
            {"role": "system", "content": ATTACK_WORKER_SYSTEM_PROMPT},
            {"role": "user", "content": user_content}
        ]

    async def _call_llm(self, messages: list[dict]) -> str:
        try:
            response = await self.llm.ainvoke(messages)
            content = response.content if hasattr(response, "content") else str(response)
            if isinstance(content, list):
                content = "".join([c.get("text", "") if isinstance(c, dict) else str(c) for c in content])
            return str(content)
        except Exception as e:
            print(f"[AttackWorker] LLM call failed: {e}")
            return '{"vulnerability_class":"unknown","confidence":35,"hypothesis":"LLM call failed","attack_path":[],"evidence_node_ids":[]}'

    def _parse_response(self, raw: str, node_id: str) -> dict | None:
        try:
            cleaned = raw.strip()
            if cleaned.startswith("```"):
                lines = cleaned.split("\n")
                # Strip opening fence line and closing fence line
                cleaned = "\n".join(lines[1:-1]).strip()

            parsed = json.loads(cleaned)
            parsed["confidence"] = int(parsed.get("confidence", 0))

            if not isinstance(parsed.get("attack_path"), list):
                parsed["attack_path"] = []
            if not isinstance(parsed.get("evidence_node_ids"), list):
                parsed["evidence_node_ids"] = []

            return parsed
        except Exception as e:
            print(f"[AttackWorker] JSON parse error for {node_id}: {e}")
            return None

    def _format_list(self, items: list) -> str:
        if not items:
            return "None"
        if items and isinstance(items[0], dict):
            return json.dumps(items, indent=2)
        return "\n".join(f"  - {item}" for item in items)