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
from dotenv import load_dotenv

load_dotenv()

from langchain_core.messages import SystemMessage, HumanMessage
from src.agents.state import AgentState
from src.agents.base_worker import WorkerOutput, WorkerTask
from src.agents.workers.recon_worker import ReconWorker
from src.agents.workers.attack_hypothesis_worker import AttackHypothesisWorker
from src.agents.workers.test_writer_worker import TestWriterWorker
from src.models.finding import Finding
from src.utils.graph_queries import get_high_risk_hotspots
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

Output ONLY the following JSON:

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
      "confidence": "<HIGH | MEDIUM | LOW>",
      "confidence_rationale": "<Why this confidence level>",
      "source": "<hotspot_analysis | worker_output | synthesis>"
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
3. PREFER fewer, high-confidence leads over many low-confidence ones.
4. RECOMMEND human escalation when confidence is ambiguous (30-70 range).
5. IF the hotspot data shows zero risks, report 0 leads honestly.
"""

# Keep the old prompt around for backward compat reference
SYSTEM_PROMPT = COORDINATOR_SYSTEM_PROMPT


# ════════════════════════════════════════════════════════════
#  LLM SETUP
# ════════════════════════════════════════════════════════════

_TOOLS: List[Any] = []


def set_tools(tools: List[Any]):
    """Sets the tools available to the Lead Agent."""
    global _TOOLS
    _TOOLS = tools


def get_llm(
    model_name: str = os.getenv("MODEL_NAME", "gemini-2.5-flash"),
    temperature: float = 0.0,
):
    """Returns a configured LLM instance."""
    if not ChatGoogleGenerativeAI:
        raise ImportError("langchain-google-genai is not installed.")

    if "GOOGLE_API_KEY" not in os.environ:
        print("WARNING: GOOGLE_API_KEY not found in environment. LLM calls may fail.")

    llm = ChatGoogleGenerativeAI(model=model_name, temperature=temperature)
    if _TOOLS:
        return llm.bind_tools(_TOOLS)
    return llm


# ════════════════════════════════════════════════════════════
#  SYNTHESIS & ESCALATION
# ════════════════════════════════════════════════════════════

def synthesize_worker_outputs(worker_outputs: List[Any]) -> List[dict]:
    """
    Merge worker outputs into a deduplicated, prioritised list of
    vulnerability leads.
    """
    if not worker_outputs:
        return []

    # Index by evidence node IDs for deduplication
    leads_by_target: dict[str, dict] = {}

    for i, wo in enumerate(worker_outputs):
        # Convert Pydantic model to dict if necessary
        wo_dict = wo.model_dump() if hasattr(wo, "model_dump") else wo
        
        lead_id = f"LEAD-{i + 1:03d}"
        evidence = wo_dict.get("evidence_node_ids", [])
        key = "|".join(sorted(evidence)) if evidence else f"__worker_{i}"

        existing = leads_by_target.get(key)
        wo_confidence = wo_dict.get("confidence", 0)

        if existing is None or wo_confidence > existing.get("confidence", 0):
            leads_by_target[key] = {
                "id": lead_id,
                "worker_type": wo_dict.get("worker_type", "unknown"),
                "hypothesis": wo_dict.get("hypothesis"),
                "evidence_node_ids": evidence,
                "attack_path": wo_dict.get("attack_path", []),
                "confidence": wo_confidence,
                "raw_output": wo_dict.get("raw_output", {}),
            }

    # Sort by confidence descending
    leads = sorted(leads_by_target.values(), key=lambda x: x["confidence"], reverse=True)

    # Re-number after sort
    for i, lead in enumerate(leads):
        lead["id"] = f"LEAD-{i + 1:03d}"

    return leads


def should_escalate_to_human(
    worker_outputs: List[dict],
    low_threshold: int = 30,
    high_threshold: int = 70,
) -> tuple[bool, str | None]:
    """
    Decide whether the coordinator should request human review.

    Escalation is recommended when:
      - Any worker confidence is in the ambiguous zone (30–70)
      - Workers disagree (high variance in confidence)
      - Zero findings despite non-trivial codebase

    Returns:
        (should_escalate, reason)
    """
    if not worker_outputs:
        return False, None

    confidences = [
        wo.get("confidence", 0) if isinstance(wo, dict) else getattr(wo, "confidence", 0)
        for wo in worker_outputs
    ]
    avg_conf = sum(confidences) / len(confidences) if confidences else 0

    # Ambiguous confidence zone
    ambiguous = [c for c in confidences if low_threshold <= c <= high_threshold]
    if ambiguous:
        return True, (
            f"{len(ambiguous)} worker(s) returned ambiguous confidence "
            f"(range {low_threshold}–{high_threshold}). Human review recommended."
        )

    # High variance — workers disagree
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
    """
    The Coordinator (Lead Agent) node.

    Reads global state, invokes summary tools, synthesizes worker outputs,
    and produces the final vulnerability report.
    """
    messages = state.get("messages", [])
    worker_outputs = state.get("worker_outputs", [])

    llm = get_llm()

    # Step 1 — Always run Recon first
    etherscan = EtherscanClient()  # Auto-stubs if no ETHERSCAN_API_KEY in env
    recon_worker = ReconWorker(
        graph=state["graph"],
        llm_client=llm,
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

    # Store recon context — Attack Workers receive this
    recon_context = recon_output.raw_output
    state["recon_context"] = recon_context

    # Step 2 — Log what Recon found
    if recon_context.get("onchain_risk_signals", {}).get("previous_exploits_detected"):
        print("[Coordinator] ⚠️  Prior exploit detected by Recon. Escalating priority.")

    # Step 2 — Get hotspots (Coordinator-only query)
    hotspots = get_high_risk_hotspots(state["graph"], min_score=70)

    if not hotspots:
        state["findings"] = []
        state["escalate"] = False
        # (Optional: continue to Synthesis even if no hotspots)
    else:
        # Step 3 — Spawn Attack Workers in parallel (one per hotspot)
        attack_worker = AttackHypothesisWorker(
            graph=state["graph"],
            llm_client=llm,
        )

        def _budget_for_priority(priority: str) -> int:
            """Token budget per worker based on hotspot priority."""
            return {"CRITICAL": 8000, "HIGH": 5000, "MEDIUM": 3000}.get(priority, 3000)

        # Build tasks — inject recon_context into each
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

        # Run all in parallel
        worker_outputs_parallel = await asyncio.gather(
            *[attack_worker.run(task) for task in tasks],
            return_exceptions=True
        )

        # Step 4 — Convert non-zero outputs to Findings
        findings = []
        for output, hotspot in zip(worker_outputs_parallel, hotspots):
            if isinstance(output, Exception):
                print(f"[Coordinator] Worker error on {hotspot.node_id}: {output}")
                continue
            if output.confidence > 0 and output.attack_path:
                finding = Finding.from_worker_output(output, hotspot)
                findings.append(finding)
            
            # Add to global worker_outputs for synthesis
            if not isinstance(output, Exception):
                wo_dict = output.model_dump() if hasattr(output, "model_dump") else output
                worker_outputs.append(wo_dict)

        state["findings"] = findings
        state["escalate"] = len(findings) > 0

    # Step 5 — Synthesis & Final Response
    # Build prompt
    prompt = [SystemMessage(content=COORDINATOR_SYSTEM_PROMPT)]

    # Inject worker results context if available
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
        prompt.append(
            HumanMessage(content="Assess the risk landscape using get_high_risk_hotspots().")
        )

    # Invoke LLM
    response = llm.invoke(prompt)

    # Tool call → let LangGraph route
    if response.tool_calls:
        return {"messages": [response], "worker_outputs": worker_outputs}

    # Parse final answer
    try:
        content = response.content
        if "```json" in content:
            content = content.split("```json")[1].split("```")[0].strip()
        elif "```" in content:
            content = content.split("```")[1].split("```")[0].strip()

        data = json.loads(content)

        leads = data.get("vulnerability_leads", [])
        target_nodes = data.get("target_nodes", [])
        strategy = data.get("analysis_summary", {}).get("strategy", "")
        escalation = data.get("escalation_needed", False)

        return {
            "vulnerability_leads": leads,
            "target_nodes": target_nodes,
            "strategy": strategy,
            "messages": [response],
            "findings": state.get("findings", []),
            "worker_outputs": worker_outputs,
            "escalate": escalation or state.get("escalate", False)
        }
    except Exception:
        return {"messages": [response], "worker_outputs": worker_outputs}


import warnings

async def lead_researcher_node(state: AgentState):
    """
    DEPRECATED ALIAS — scheduled for removal at Phase 6 merge.
    Use coordinator_node() directly.
    """
    warnings.warn(
        "lead_researcher_node is a deprecated alias for coordinator_node. "
        "Remove all calls to lead_researcher_node before Phase 6.",
        DeprecationWarning,
        stacklevel=2
    )
    return await coordinator_node(state)
