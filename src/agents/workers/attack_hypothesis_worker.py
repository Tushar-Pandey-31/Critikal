import json
from src.agents.base_worker import WorkerAgent, WorkerOutput, WorkerTask
from src.utils.graph_queries import (
    get_function_context,
    get_internal_calls,
    get_callers,
    get_reentrancy_risks,
    get_unprotected_mutators,
    get_privilege_escalation_risks,
    get_external_call_functions,
)


# Maps vulnerability class → minimum confidence threshold to report
# Below these thresholds the worker returns confidence=0 (no finding)
CONFIDENCE_THRESHOLDS = {
    "reentrancy": 60,
    "privilege_escalation": 55,
    "unprotected_mutator": 50,
    "cei_violation": 60,
    "unknown": 70,   # Unknown class requires higher bar
}

# Maps risk_category from HotspotEngine → vulnerability_class name
CATEGORY_TO_CLASS = {
    "reentrancy": "reentrancy",
    "unprotected_mutator": "unprotected_mutator",
    "can_escalate_privileges": "privilege_escalation",
    "state_write_after_external_call": "cei_violation",
}


class AttackHypothesisWorker(WorkerAgent):
    """
    Generates structured vulnerability hypotheses for a single hotspot.

    Reads recon_context from WorkerTask.context — does NOT re-query
    graph-level data that Recon already collected.

    Tools available:
        get_function_context()          — source code + callers/callees
        get_internal_calls()            — internal call chain from this function
        get_callers()                   — who calls this function
        get_reentrancy_risks()          — pre-computed reentrancy signals
        get_unprotected_mutators()      — pre-computed unprotected mutator signals
        get_privilege_escalation_risks() — pre-computed escalation signals
        get_external_call_functions()   — CEI status

    Does NOT have access to:
        get_high_risk_hotspots()        — Coordinator only
        search_security_knowledge()     — Recon already did this
        get_access_control_summary()    — too broad, use specific tools
    """

    model_name: str = "gemini-2.5-flash"

    def __init__(self, graph, llm_client):
        self.graph = graph
        self.llm = llm_client

    def get_worker_type(self) -> str:
        return "attack_hypothesis"

    async def run(self, task: WorkerTask) -> WorkerOutput:
        hotspot = task.hotspot
        if hotspot is None:
            return WorkerOutput(
                worker_type="attack_hypothesis",
                confidence=0,
                raw_output={"error": "No hotspot provided"}
            )

        recon_context = task.context.get("recon_context", {})
        node_id = hotspot.node_id

        # Step 1 — Gather deterministic graph context for this hotspot
        graph_context = self._gather_graph_context(node_id, hotspot)

        # Step 2 — Build LLM prompt with all context
        prompt = self._build_prompt(hotspot, graph_context, recon_context)

        # Step 3 — Call LLM, get structured JSON hypothesis
        raw_response = await self._call_llm(prompt)

        # Step 4 — Parse and validate the response
        parsed = self._parse_response(raw_response, node_id)

        if not parsed:
            return WorkerOutput(
                worker_type="attack_hypothesis",
                confidence=0,
                raw_output={"error": "LLM returned unparseable response", "raw": raw_response}
            )

        # Step 5 — Confidence threshold check
        vulnerability_class = parsed.get("vulnerability_class", "unknown")
        confidence = parsed.get("confidence", 0)
        threshold = CONFIDENCE_THRESHOLDS.get(vulnerability_class, 70)

        if confidence < threshold:
            return WorkerOutput(
                worker_type="attack_hypothesis",
                confidence=0,
                raw_output={
                    "reason": f"Confidence {confidence} below threshold {threshold} for {vulnerability_class}",
                    "parsed": parsed
                }
            )

        # Step 6 — Build final output
        return WorkerOutput(
            worker_type="attack_hypothesis",
            hypothesis=parsed.get("hypothesis"),
            evidence_node_ids=parsed.get("evidence_node_ids", []),
            attack_path=parsed.get("attack_path", []),
            confidence=confidence,
            raw_output={
                "vulnerability_class": vulnerability_class,
                "title": parsed.get("title"),
                "impact": parsed.get("impact"),
                "preconditions": parsed.get("preconditions", []),
                "graph_signals_used": graph_context.get("signals_summary", {}),
            }
        )

    # ------------------------------------------------------------------ #
    #  Graph Context Gathering                                              #
    # ------------------------------------------------------------------ #

    def _gather_graph_context(self, node_id: str, hotspot) -> dict:
        """
        Pull all graph intelligence for this specific hotspot node.
        Returns a structured dict the LLM prompt builder will use.
        """
        context = {}

        # Core function context — source code, callers, callees
        try:
            fn_context = get_function_context(self.graph, node_id)
            context["function_context"] = fn_context
        except Exception:
            context["function_context"] = {}

        # Internal call chain — who does this function call?
        try:
            internal_calls = get_internal_calls(self.graph, node_id)
            context["internal_calls"] = internal_calls
        except Exception:
            context["internal_calls"] = []

        # Reverse lookup — who calls this function?
        try:
            callers = get_callers(self.graph, node_id)
            context["callers"] = callers
        except Exception:
            context["callers"] = []

        # Pre-computed risk signals from Phase 3
        context["signals_summary"] = {
            "reentrancy_risk": hotspot.signals.get("reentrancy_risk", False),
            "reentrancy_risk_score": hotspot.signals.get("reentrancy_risk_score", 0),
            "is_unprotected_mutator": hotspot.signals.get("is_unprotected_mutator", False),
            "unprotected_risk_level": hotspot.signals.get("unprotected_risk_level", None),
            "can_escalate_privileges": hotspot.signals.get("can_escalate_privileges", False),
            "state_write_after_external_call": hotspot.signals.get("state_write_after_external_call", False),
            "makes_external_call": hotspot.signals.get("makes_external_call", False),
            "propagated_state_variables": hotspot.signals.get("propagated_state_variables", []),
            "reachable_from_external_entry": hotspot.signals.get("reachable_from_external_entry", True),
            "entry_points": hotspot.signals.get("entry_points", []),
        }

        # For privilege escalation hotspots — get escalation path detail
        if hotspot.signals.get("can_escalate_privileges"):
            try:
                escalation = get_privilege_escalation_risks(self.graph, hotspot.contract)
                context["escalation_detail"] = escalation
            except Exception:
                context["escalation_detail"] = {}

        # For CEI/reentrancy hotspots — get external call detail
        if hotspot.signals.get("makes_external_call"):
            try:
                ext_calls = get_external_call_functions(self.graph)
                # Filter to just this function's entry
                context["external_call_detail"] = [
                    e for e in ext_calls
                    if e.get("node_id") == node_id
                ]
            except Exception:
                context["external_call_detail"] = []

        return context

    # ------------------------------------------------------------------ #
    #  Prompt Construction                                                  #
    # ------------------------------------------------------------------ #

    def _build_prompt(self, hotspot, graph_context: dict, recon_context: dict) -> list[dict]:
        """
        Builds the full message list for the LLM call.
        System prompt sets behavioral rules.
        User prompt contains all context.
        """

        system_prompt = """You are a specialized smart contract vulnerability researcher.

Your job: Given ONE suspicious function (a "hotspot"), determine if it contains a real, exploitable vulnerability.

## Rules

1. ONLY cite node IDs that appear in the graph context provided. Never invent node IDs.
2. attack_path MUST be an ordered list of node IDs representing the execution sequence from entry point to the vulnerability. Minimum 1 node, typically 2-5.
3. If you cannot find a clear, credible exploit path using only the provided context, set confidence=0 and hypothesis=null.
4. Do not speculate beyond what the graph signals confirm. If state_write_after_external_call is False, do not claim a CEI violation.
5. evidence_node_ids must be a SUBSET of node IDs that appear in the graph context.

## Output Format

Return ONLY valid JSON. No explanation, no markdown fences, no preamble.

{
  "vulnerability_class": "reentrancy" | "unprotected_mutator" | "privilege_escalation" | "cei_violation" | "unknown",
  "title": "One-line summary of the vulnerability",
  "hypothesis": "2-4 sentence narrative of the exploit. Must reference specific function names.",
  "attack_path": ["NodeId.entryPoint", "NodeId.intermediary", "NodeId.vulnerableFunction"],
  "evidence_node_ids": ["NodeId.vulnerableFunction", "NodeId.stateVar"],
  "confidence": 0-100,
  "impact": "What an attacker gains if this succeeds",
  "preconditions": ["What must be true for this exploit to work"],
  "reasoning": "Why you chose this confidence score"
}"""

        # Build the user message with all context
        fn_ctx = graph_context.get("function_context", {})
        signals = graph_context.get("signals_summary", {})

        user_content = f"""## Target Hotspot

Node ID: {hotspot.node_id}
Contract: {hotspot.contract}
Function: {hotspot.function}
Risk Score: {hotspot.risk_score}
Risk Categories: {hotspot.risk_categories}

## Source Code
{fn_ctx.get("source_code", "Not available")}

## Graph Signals (Deterministic — trust these)
- reentrancy_risk: {signals.get("reentrancy_risk")}
- state_write_after_external_call: {signals.get("state_write_after_external_call")}
- is_unprotected_mutator: {signals.get("is_unprotected_mutator")}
- unprotected_risk_level: {signals.get("unprotected_risk_level")}
- can_escalate_privileges: {signals.get("can_escalate_privileges")}
- makes_external_call: {signals.get("makes_external_call")}
- propagated_state_variables: {signals.get("propagated_state_variables")}
- reachable_from_external_entry: {signals.get("reachable_from_external_entry")}
- entry_points (external entries that reach this function): {signals.get("entry_points")}

## Internal Calls Made by This Function
{self._format_list(graph_context.get("internal_calls", []))}

## Functions That Call This Function (Callers)
{self._format_list(graph_context.get("callers", []))}

## External Call Detail (if applicable)
{json.dumps(graph_context.get("external_call_detail", []), indent=2)}

## Escalation Detail (if applicable)
{json.dumps(graph_context.get("escalation_detail", {}), indent=2)}

## Recon Context (from Recon Worker — do not re-derive this)
Protocol Type: {recon_context.get("protocol_type", "unknown")}
Known Attack Patterns for This Protocol: {recon_context.get("known_attack_patterns", [])}
Recommended Focus Areas: {recon_context.get("recommended_focus_areas", [])}
Prior Exploit Detected On-chain: {recon_context.get("onchain_risk_signals", {}).get("previous_exploits_detected", False)}

## Your Task

Analyze the hotspot above. Determine if this is a real vulnerability.
Build your attack_path starting from one of the entry_points listed in graph signals.
Return JSON only."""

        return [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_content}
        ]

    # ------------------------------------------------------------------ #
    #  LLM Call + Response Parsing                                         #
    # ------------------------------------------------------------------ #

    async def _call_llm(self, messages: list[dict]) -> str:
        """
        Calls the configured LLM. Adapt this to your LLM client interface.
        Returns raw string response.
        """
        try:
            response = await self.llm.ainvoke(messages)
            # Handle both string responses and message objects
            if hasattr(response, "content"):
                return response.content
            return str(response)
        except Exception as e:
            return f'{{"error": "{str(e)}", "confidence": 0}}'

    def _parse_response(self, raw: str, node_id: str) -> dict | None:
        """
        Parse LLM JSON response. Returns None on parse failure.
        Also validates that attack_path and evidence_node_ids
        are lists of strings (node IDs), not narrative text.
        """
        try:
            # Strip accidental markdown fences if LLM adds them
            cleaned = raw.strip()
            if cleaned.startswith("```"):
                lines = cleaned.split("\n")
                if len(lines) > 2:
                    cleaned = "\n".join(lines[1:-1])
                else:
                    cleaned = lines[0].replace("```json", "").replace("```", "")

            parsed = json.loads(cleaned)

            # Validate required fields exist
            required = ["vulnerability_class", "confidence", "attack_path", "evidence_node_ids"]
            for field in required:
                if field not in parsed:
                    return None

            # Validate attack_path is a list of strings
            if not isinstance(parsed["attack_path"], list):
                return None
            if parsed["attack_path"] and not isinstance(parsed["attack_path"][0], str):
                return None

            # Validate confidence is numeric
            try:
                parsed["confidence"] = int(parsed.get("confidence", 0))
            except (ValueError, TypeError):
                parsed["confidence"] = 0

            return parsed

        except (json.JSONDecodeError, ValueError, TypeError):
            return None

    # ------------------------------------------------------------------ #
    #  Helpers                                                              #
    # ------------------------------------------------------------------ #

    def _format_list(self, items: list) -> str:
        if not items:
            return "None"
        if isinstance(items[0], dict):
            return json.dumps(items, indent=2)
        return "\n".join(f"  - {item}" for item in items)
