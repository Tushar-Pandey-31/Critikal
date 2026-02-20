"""
Lead Agent — Pure Coordinator.

The Lead Agent no longer performs direct analysis. It:
  1. Maintains global state & strategy
  2. Calls get_high_risk_hotspots() to identify targets
  3. Spawns specialist workers (via pending_workers state)
  4. Synthesizes worker outputs into prioritised vulnerability leads
  5. Decides human escalation when confidence is ambiguous
"""

import os
import json
from datetime import datetime
from typing import List, Any, Optional
import uuid
from dotenv import load_dotenv

load_dotenv()

from langchain_core.messages import SystemMessage, HumanMessage
from src.agents.state import AgentState
from src.agents.base_worker import WorkerOutput, WorkerTask
from src.agents.workers.recon_worker import ReconWorker
from src.agents.workers.attack_hypothesis_worker import AttackHypothesisWorker
from src.agents.workers.test_writer_worker import TestWriterWorker
from src.models.finding import Finding, FindingStatus
from src.utils.graph_queries import get_high_risk_hotspots, get_function_context
from src.tools.etherscan_client import EtherscanClient
import asyncio

try:
    from langchain_google_genai import ChatGoogleGenerativeAI
except ImportError:
    ChatGoogleGenerativeAI = None


# ════════════════════════════════════════════════════════════
#  COORDINATOR SYSTEM PROMPT
# ════════════════════════════════════════════════════════════

COORDINATOR_SYSTEM_PROMPT = """You are the Lead Security Coordinator for Penteam, an AI-assisted smart contract vulnerability hunting system.

You are NOT an analyst. You are the ORCHESTRATOR. You do not read source code directly. Instead you:
  1. Assess risk signals from the Knowledge Graph
  2. Formulate analysis strategy
  3. Delegate detailed work to specialist workers
  4. Synthesize results into a prioritised vulnerability report
  5. Decide when human review is needed

═══════════════════════════════════════════════════════════
SECTION 1: YOUR TOOLS
═══════════════════════════════════════════════════════════

  - get_high_risk_hotspots()
      → Returns a consolidated risk summary: reentrancy risks, unprotected
        state mutators, privilege escalation vectors, external calls.
      → THIS IS YOUR PRIMARY TOOL. Call it first to understand the landscape.

  - search_security_knowledge(query)
      → Search audit reports and docs for known vulnerability patterns.
      → Use AFTER reviewing hotspot data to validate patterns.

═══════════════════════════════════════════════════════════
SECTION 2: THE COORDINATION PROTOCOL (MANDATORY)
═══════════════════════════════════════════════════════════

─── STEP 1: ASSESS RISK LANDSCAPE ─────────────────────────

Call get_high_risk_hotspots() to get the full risk map.
From the results, identify:
  - Functions with reentrancy risk (external call + state mutation)
  - Unprotected state mutators (no access control)
  - Privilege escalation vectors (writable admin variables)
  - High-value external call targets

─── STEP 2: FORMULATE STRATEGY ────────────────────────────

Based on the risk map, formulate your analysis strategy:
  - Rank targets by severity (CRITICAL > HIGH > MEDIUM > LOW)
  - Group related risks (e.g., multiple functions sharing a variable)
  - Identify which specialist workers to deploy

─── STEP 3: SYNTHESIZE & REPORT ───────────────────────────

If worker_outputs are present in the conversation, synthesize them.
Otherwise, produce your own assessment based on the hotspot data.

Output ONLY valid JSON with this exact structure:

{
  "analysis_summary": {
    "contracts_analyzed": ["ContractName1"],
    "total_risks_identified": <integer>,
    "strategy": "<brief strategy description>"
  },
  "vulnerability_leads": [
    {
      "id": "LEAD-001",
      "title": "<Short title>",
      "vulnerability_class": "<REENTRANCY | ACCESS_CONTROL | PRIVILEGE_ESCALATION | ARITHMETIC | LOGIC | OTHER>",
      "severity_estimate": "<CRITICAL | HIGH | MEDIUM | LOW>",
      "affected_contract": "<ContractName>",
      "affected_function": "<functionName>",
      "affected_function_node_id": "<ContractName::functionName>",
      "root_cause": "<One sentence: the exact condition that enables this>",
      "impact": "<One sentence: what an attacker achieves if exploited>",
      "confidence": <integer 0-100>,
      "confidence_rationale": "<Why this confidence level>",
      "source": "<hotspot_analysis | worker_output | synthesis>",
      "test_code": null,
      "exploit_success": null
    }
  ],
  "escalation_needed": <true|false>,
  "escalation_reason": "<Why human review is needed, or null>",
  "investigation_gaps": [
    "<Anything that could not be verified>"
  ]
}

═══════════════════════════════════════════════════════════
SECTION 3: BEHAVIOR RULES
═══════════════════════════════════════════════════════════

1. ALWAYS call get_high_risk_hotspots() as your first tool.
2. NEVER attempt to read source code. That is the workers' job.
3. Report ALL leads that workers flagged with confidence > 0, even if confidence is low.
4. Do NOT filter out leads. More leads is better than fewer. The user can triage.
5. IF the hotspot data shows zero risks, report 0 leads honestly.
6. Output ONLY the JSON block. No prose, no markdown fences, no preamble.
"""

SYSTEM_PROMPT = COORDINATOR_SYSTEM_PROMPT


# ════════════════════════════════════════════════════════════
#  LLM SETUP
# ════════════════════════════════════════════════════════════

_TOOLS: List[Any] = []


def set_tools(tools: List[Any]):
    global _TOOLS
    _TOOLS = tools


def get_llm(
    model_name: str = os.getenv("MODEL_NAME", "gemini-2.5-flash"),
    temperature: float = 0.0,
    bind_tools: bool = True,
):
    """Returns a configured coordinator LLM (tool-bound by default)."""
    if not ChatGoogleGenerativeAI:
        raise ImportError("langchain-google-genai is not installed.")
    if "GOOGLE_API_KEY" not in os.environ:
        print("WARNING: GOOGLE_API_KEY not found in environment.")
    llm = ChatGoogleGenerativeAI(model=model_name, temperature=temperature)
    print(f"[get_llm] Created LLM: {llm.model} (bind_tools={bind_tools})", flush=True)
    if bind_tools and _TOOLS:
        return llm.bind_tools(_TOOLS)
    return llm


def get_worker_llm(
    model_name: str = os.getenv("WORKER_MODEL_NAME", os.getenv("MODEL_NAME", "gemini-2.5-flash")),
    temperature: float = 0.0,
):
    """
    Returns a CLEAN LLM with NO tools bound.
    Workers MUST use this. Never pass coordinator_llm to workers.
    """
    if not ChatGoogleGenerativeAI:
        raise ImportError("langchain-google-genai is not installed.")
    llm = ChatGoogleGenerativeAI(model=model_name, temperature=temperature)
    print(f"[get_worker_llm] Created worker LLM: {llm.model} (no tools)", flush=True)
    return llm


# ════════════════════════════════════════════════════════════
#  SYNTHESIS & ESCALATION
# ════════════════════════════════════════════════════════════

def synthesize_worker_outputs(worker_outputs: List[Any]) -> List[dict]:
    """Merge worker outputs into deduplicated, prioritised vulnerability leads."""
    if not worker_outputs:
        return []

    leads_by_target: dict[str, dict] = {}

    for i, wo in enumerate(worker_outputs):
        wo_dict = wo.model_dump() if hasattr(wo, "model_dump") else wo

        lead_id = f"LEAD-{i + 1:03d}"
        evidence = wo_dict.get("evidence_node_ids", [])
        # Use task_id as key if evidence is empty (prevents all empty-evidence outputs colliding)
        key = "|".join(sorted(evidence)) if evidence else wo_dict.get("task_id", f"__worker_{i}")

        wo_confidence = wo_dict.get("confidence", 0)
        if wo_confidence == 0:
            continue

        raw = wo_dict.get("raw_output", {})
        existing = leads_by_target.get(key)

        if existing is None or wo_confidence > existing.get("confidence", 0):
            leads_by_target[key] = {
                "id": lead_id,
                "title": raw.get("title", "Unnamed Lead"),
                "vulnerability_class": raw.get("vulnerability_class", "unknown"),
                "severity_estimate": raw.get("severity_estimate", "HIGH"),
                "affected_contract": raw.get("affected_contract", "Unknown"),
                "affected_function": raw.get("affected_function", "Unknown"),
                "worker_type": wo_dict.get("worker_type", "unknown"),
                "hypothesis": wo_dict.get("hypothesis"),
                "impact": raw.get("impact", "Unknown"),
                "evidence_node_ids": evidence,
                "attack_path": wo_dict.get("attack_path", []),
                "confidence": wo_confidence,
                "raw_output": raw,
                "test_code": wo_dict.get("test_code"),
                "exploit_success": wo_dict.get("exploit_success"),
                "compiled": wo_dict.get("compiled"),
                "attempts": wo_dict.get("attempts"),
            }

    leads = sorted(leads_by_target.values(), key=lambda x: x["confidence"], reverse=True)
    for i, lead in enumerate(leads):
        lead["id"] = f"LEAD-{i + 1:03d}"

    return leads


def should_escalate_to_human(
    worker_outputs: List[dict],
    low_threshold: int = 30,
    high_threshold: int = 70,
) -> tuple[bool, str | None]:
    if not worker_outputs:
        return False, None

    confidences = [
        wo.get("confidence", 0) if isinstance(wo, dict) else getattr(wo, "confidence", 0)
        for wo in worker_outputs
    ]

    ambiguous = [c for c in confidences if low_threshold <= c <= high_threshold]
    if ambiguous:
        return True, (
            f"{len(ambiguous)} worker(s) returned ambiguous confidence "
            f"(range {low_threshold}–{high_threshold}). Human review recommended."
        )

    if len(confidences) >= 2:
        conf_range = max(confidences) - min(confidences)
        if conf_range > 50:
            return True, (
                f"Workers show high disagreement (confidence range: {conf_range}). "
                f"Human review recommended."
            )

    return False, None


# ════════════════════════════════════════════════════════════
#  COORDINATOR NODE
# ════════════════════════════════════════════════════════════

async def coordinator_node(state: AgentState):
    messages = state.get("messages", [])
    worker_outputs = state.get("worker_outputs", [])

    # ── LLM instances ──────────────────────────────────────
    coordinator_llm = get_llm()       # tool-bound, for LangGraph routing + synthesis
    worker_llm = get_worker_llm()     # clean, for all workers

    # ── Step 1: Recon ──────────────────────────────────────
    etherscan = EtherscanClient()
    recon_worker = ReconWorker(
        graph=state["graph"],
        llm_client=worker_llm,
        etherscan_client=etherscan,
    )
    recon_task = WorkerTask(
        task_id="recon_protocol",
        task_type="recon",
        context={
            "contract_names": state.get("contract_names", []),
            "contract_addresses": state.get("contract_addresses", {}),
            "repo_url": state.get("repo_url"),
        }
    )
    recon_output = await recon_worker.run(recon_task)
    recon_context = recon_output.raw_output
    state["recon_context"] = recon_context

    if recon_context.get("onchain_risk_signals", {}).get("previous_exploits_detected"):
        print("[Coordinator] ⚠️  Prior exploit detected by Recon. Escalating priority.")

    # ── Step 2: Hotspots ───────────────────────────────────
    hotspots = get_high_risk_hotspots(state["graph"], min_score=70)
    findings = []

    if not hotspots:
        state["findings"] = []
        state["escalate"] = False
    else:
        # ── Step 3: Attack Workers ─────────────────────────
        attack_worker = AttackHypothesisWorker(
            graph=state["graph"],
            llm_client=worker_llm,
        )

        def _budget_for_priority(priority: str) -> int:
            return {"CRITICAL": 8000, "HIGH": 5000, "MEDIUM": 3000}.get(priority, 3000)

        tasks = [
            WorkerTask(
                task_id=f"attack_{hotspot.node_id}",
                task_type="attack_analysis",
                hotspot=hotspot,
                context={"recon_context": state.get("recon_context", {})},
                budget_tokens=_budget_for_priority(hotspot.priority),
            )
            for hotspot in hotspots
        ]

        worker_outputs_parallel = await asyncio.gather(
            *[attack_worker.run(task) for task in tasks],
            return_exceptions=True
        )

        print(f"[Debug] Total attack worker outputs: {len(worker_outputs_parallel)}")
        for i, o in enumerate(worker_outputs_parallel):
            if isinstance(o, Exception):
                print(f"  [{i}] EXCEPTION: {o}")
            else:
                print(f"  [{i}] confidence={o.confidence} attack_path={o.attack_path} hypothesis={str(o.hypothesis)[:80] if o.hypothesis else None}")

        # ── Step 4: Build Findings ─────────────────────────
        # FIX: removed `and output.attack_path` — attack_path is always [] because
        # the LLM can't reference graph node IDs it hasn't seen. Confidence is enough.
        for output, hotspot in zip(worker_outputs_parallel, hotspots):
            if isinstance(output, Exception):
                print(f"[Coordinator] Worker error on {hotspot.node_id}: {output}")
                continue
            if output.confidence > 0:  # <-- FIXED: was: output.confidence > 0 and output.attack_path
                finding = Finding.from_worker_output(output, hotspot)
                findings.append(finding)

            if not isinstance(output, Exception):
                wo_dict = output.model_dump() if hasattr(output, "model_dump") else output
                worker_outputs.append(wo_dict)

        print(f"[Debug] Findings that passed filter: {len(findings)}")

    # ── Step 5: Coordinator LLM Synthesis ─────────────────
    prompt = [SystemMessage(content=COORDINATOR_SYSTEM_PROMPT)]

    if worker_outputs:
        synthesis = synthesize_worker_outputs(worker_outputs)
        escalate_human, reason = should_escalate_to_human(worker_outputs)

        worker_context = (
            f"\n\n=== WORKER RESULTS ===\n"
            f"Received {len(worker_outputs)} worker output(s).\n"
            f"Synthesised into {len(synthesis)} unique lead(s).\n"
            f"Escalation needed: {escalate_human}"
        )
        if reason:
            worker_context += f"\nEscalation reason: {reason}"
        worker_context += f"\n\nSynthesised leads:\n{json.dumps(synthesis, indent=2)}"
        prompt.append(HumanMessage(content=worker_context))

    if messages:
        prompt.extend(messages)
    else:
        prompt.append(HumanMessage(content="Assess the risk landscape using get_high_risk_hotspots()."))

    response = coordinator_llm.invoke(prompt)

    if response.tool_calls:
        return {"messages": [response], "worker_outputs": worker_outputs}

    # ── Parse final response ───────────────────────────────
    leads = []
    target_nodes = []
    strategy = ""
    escalation = False
    try:
        content = response.content
        if isinstance(content, list):
            content = "".join([c.get("text", "") if isinstance(c, dict) else str(c) for c in content])

        if "```json" in content:
            content = content.split("```json")[1].split("```")[0].strip()
        elif "```" in content:
            content = content.split("```")[1].split("```")[0].strip()

        data = json.loads(content)
        leads = data.get("vulnerability_leads", [])
        target_nodes = data.get("target_nodes", [])
        strategy = data.get("analysis_summary", {}).get("strategy", "")
        escalation = data.get("escalation_needed", False)
    except Exception as e:
        print(f"[Coordinator] Parse error: {e}")
        leads = synthesize_worker_outputs(worker_outputs) if worker_outputs else []
        strategy = "Failed to parse LLM response"

    # ── Step 5b: Synthetic Fallback for TestWriter ─────────
    # If workers returned findings but LLM didn't produce leads, or
    # if findings list is empty but LLM leads exist at high confidence
    if not findings and leads:
        for lead in leads:
            if (lead.get("confidence", 0) >= 65 and
                    lead.get("severity_estimate") in ("CRITICAL", "HIGH")):
                synthetic_finding = Finding(
                    id=str(uuid.uuid4()),
                    hotspot_node_id=lead.get("affected_function_node_id", ""),
                    vulnerability_class=lead.get("vulnerability_class", "UNKNOWN"),
                    title=lead.get("title", "Unnamed Lead"),
                    hypothesis=lead.get("root_cause", ""),
                    evidence_nodes=[],
                    attack_path=[lead.get("affected_function_node_id", "")],
                    status=FindingStatus.DRAFT,
                    confidence=lead.get("confidence", 65),
                    impact=lead.get("impact", "Unknown"),
                    preconditions=[],
                    affected_contract=lead.get("affected_contract", "Unknown"),
                    affected_function=lead.get("affected_function", "Unknown"),
                    severity_estimate=lead.get("severity_estimate", "HIGH"),
                    severity=lead.get("severity_estimate", "HIGH"),
                )
                findings.append(synthetic_finding)

        if findings:
            print(f"[Coordinator] Synthesized {len(findings)} findings from LLM leads for TestWriter")

    # ── Step 6: TestWriter ────────────────────────────────
    test_tasks = []
    target_findings = []
    for finding in findings:
        if finding.confidence >= 65 and finding.severity_estimate in ("CRITICAL", "HIGH"):
            relevant_code = {}
            for node_id in finding.attack_path:
                try:
                    ctx = get_function_context(state["graph"], node_id)
                    if "source_code" in ctx:
                        relevant_code[node_id] = ctx["source_code"]
                except Exception:
                    pass

            if not relevant_code:
                for ep in finding.evidence_nodes:
                    try:
                        ctx = get_function_context(state["graph"], ep.node_id)
                        if "source_code" in ctx:
                            relevant_code[ep.node_id] = ctx["source_code"]
                    except Exception:
                        pass

            # Fallback: use hotspot_node_id directly
            if not relevant_code and finding.hotspot_node_id:
                try:
                    ctx = get_function_context(state["graph"], finding.hotspot_node_id)
                    if "source_code" in ctx:
                        relevant_code[finding.hotspot_node_id] = ctx["source_code"]
                except Exception:
                    pass

            task = WorkerTask(
                task_id=f"test_{finding.id}",
                task_type="test_writer",
                context={
                    "finding": finding,
                    "relevant_code": relevant_code,
                    "recon_context": state.get("recon_context", {})
                }
            )
            test_tasks.append(task)
            target_findings.append(finding)

    if test_tasks:
        print(f"[Coordinator] Spawning TestWriter for {len(test_tasks)} finding(s)...")
        test_writer = TestWriterWorker(llm_client=worker_llm, graph=state["graph"])
        test_outputs = await asyncio.gather(
            *[test_writer.run(task) for task in test_tasks],
            return_exceptions=True
        )

        for output, finding in zip(test_outputs, target_findings):
            if isinstance(output, Exception):
                print(f"[Coordinator] TestWriterWorker error on {finding.hotspot_node_id}: {output}")
                continue

            finding.confidence = output.confidence
            raw = output.raw_output or {}

            if raw.get("exploit_success"):
                finding.status = FindingStatus.PROVEN
                print(f"[Coordinator] ✅ EXPLOIT PROVEN: {finding.hotspot_node_id}")
            else:
                print(f"[Coordinator] TestWriter result for {finding.hotspot_node_id}: "
                      f"compiled={raw.get('compiled')}, success=False, attempts={raw.get('attempts')}")

            for lead in leads:
                if lead.get("affected_function_node_id") == finding.hotspot_node_id:
                    lead.update({
                        "confidence": finding.confidence,
                        "test_code": raw.get("test_code"),
                        "exploit_success": raw.get("exploit_success"),
                        "compiled": raw.get("compiled"),
                        "attempts": raw.get("attempts"),
                    })
                    title = lead.get("title", "")
                    if raw.get("exploit_success") and not title.startswith("[PROVEN]"):
                        lead.update({"title": f"[PROVEN] {title}"})
                    break

    state["findings"] = findings
    state["escalate"] = len(findings) > 0 or escalation

    return {
        "vulnerability_leads": leads,
        "target_nodes": target_nodes,
        "strategy": strategy,
        "messages": [response],
        "findings": findings,
        "worker_outputs": worker_outputs,
        "escalate": state["escalate"]
    }


import warnings

async def lead_researcher_node(state: AgentState):
    """DEPRECATED ALIAS — use coordinator_node() directly."""
    warnings.warn(
        "lead_researcher_node is a deprecated alias for coordinator_node.",
        DeprecationWarning,
        stacklevel=2
    )
    return await coordinator_node(state)