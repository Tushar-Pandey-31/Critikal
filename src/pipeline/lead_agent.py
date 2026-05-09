"""
Lead Agent — Pure Coordinator.

The Lead Agent no longer performs direct analysis. It:
  1. Maintains global state & strategy
  2. Calls get_high_risk_hotspots() to identify targets
  3. Spawns specialist workers (via pending_workers state)
  4. Synthesizes worker outputs into prioritised vulnerability leads
  5. Decides human escalation when confidence is ambiguous
"""

import json
import logging
import os
import shutil
import tempfile
from pathlib import Path
from typing import Any

from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)
import asyncio

from langchain_core.messages import HumanMessage, SystemMessage

from src.models.finding import Finding, FindingStatus, FindingVerdict
from src.pipeline.base_worker import WorkerOutput, WorkerTask
from src.pipeline.state import AgentState
from src.pipeline.workers.attack_hypothesis_worker import AttackHypothesisWorker
from src.pipeline.workers.recon_worker import ReconWorker
from src.pipeline.workers.test_writer_worker import TestWriterWorker
from src.pipeline_config import get_config
from src.tools.etherscan_client import EtherscanClient
from src.utils.graph_queries import get_callers, get_contract_signatures, get_function_context, get_high_risk_hotspots
from src.utils.node_ids import normalize_node_id

# P0: Threat Intelligence
try:
    from src.intelligence.attack_vector_db import AttackVectorDB
    from src.intelligence.threat_profiler import ThreatProfiler

    _THREAT_INTEL_AVAILABLE = True
except ImportError:
    _THREAT_INTEL_AVAILABLE = False
    logger.warning("Threat intelligence module not available")


# Jury system — config is authoritative, env var kept for backward compat
def _jury_enabled() -> bool:
    return get_config().jury_enabled


JURY_CONCURRENCY = int(os.getenv("JURY_CONCURRENCY", "5"))
JURY_SKEPTIC_MODEL = os.getenv("JURY_SKEPTIC_MODEL", "gpt-5.5")
JURY_ATTACKER_MODEL = os.getenv("JURY_ATTACKER_MODEL", "grok-4-1-fast-reasoning")
JURY_AUDITOR_MODEL = os.getenv("JURY_AUDITOR_MODEL", "gpt-5.4-mini")
JURY_JUDGE_MODEL = os.getenv("JURY_JUDGE_MODEL", "grok-4-1-fast-reasoning")

try:
    from langchain_google_genai import ChatGoogleGenerativeAI
except ImportError:
    ChatGoogleGenerativeAI = None

try:
    from langchain_anthropic import ChatAnthropic
except ImportError:
    ChatAnthropic = None

try:
    from langchain_openai import ChatOpenAI
except ImportError:
    ChatOpenAI = None

# Provider detection + worker LLM construction moved to src/llm/providers.py.
# Re-exported here for backward compatibility with existing call sites.
from src.llm.providers import detect_provider as _detect_provider
from src.llm.providers import get_worker_llm


def _finding_priority(f: Finding) -> tuple:
    """Sort key: highest confidence first, tie-break by severity (CRITICAL > HIGH > MEDIUM > LOW)."""
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    return (-f.confidence, sev_order.get(f.severity_estimate, 4))


# BUG-009 fix: deduplicated — shared with test_writer_sandbox.py
from src.utils.foundry_root import resolve_foundry_root as _get_foundry_project_root


def _exploit_target_eligible(finding: Finding, graph) -> bool:
    """Check if the finding's target is eligible for an exploit test."""
    if not graph:
        return True  # fail open
    target = finding.hotspot_node_id
    if not target or not graph.has_node(target):
        return True  # fail open

    data = graph.nodes[target]
    # FIX-4: View/pure functions CAN be exploited via read-only reentrancy,
    # oracle manipulation, or stale data. Only drop if vuln class is
    # clearly incompatible with a view/pure target.
    if data.get("is_view") or data.get("is_pure"):
        vuln = (finding.vulnerability_class or "").lower()
        is_read_only_vuln = any(
            kw in vuln
            for kw in (
                "oracle",
                "stale",
                "read-only",
                "price",
                "manipulation",
                "inflation",
                "accounting",
                "fee",
                "readonly",
            )
        )
        if not is_read_only_vuln:
            return False
    if data.get("node_type") == "interface_function":
        return False
    vis = data.get("visibility", "")
    if vis in ("internal", "private"):
        return False
    return True


# ════════════════════════════════════════════════════════════
#  COORDINATOR SYSTEM PROMPT
# ════════════════════════════════════════════════════════════

COORDINATOR_SYSTEM_PROMPT = """You are the Lead Security Coordinator for Critikal, an AI-assisted smart contract vulnerability hunting system.

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

1. Use the provided hotspot and worker context from the programmatic pipeline.
2. NEVER attempt to read source code. That is the workers' job.
3. Report ALL leads that workers flagged with confidence > 0, even if confidence is low.
4. Do NOT filter out leads. More leads is better than fewer. The user can triage.
5. IF the hotspot data shows zero risks, report 0 leads honestly.
6. Do NOT call tools in this final synthesis step.
7. Output ONLY the JSON block. No prose, no markdown fences, no preamble.
"""

SYSTEM_PROMPT = COORDINATOR_SYSTEM_PROMPT


# ════════════════════════════════════════════════════════════
#  LLM SETUP
# ════════════════════════════════════════════════════════════

_TOOLS: list[Any] = []


def _repo_name_from_url(repo_url: str) -> str:
    if not repo_url:
        return ""
    repo_name = repo_url.rstrip("/").split("/")[-1]
    if repo_name.endswith(".git"):
        repo_name = repo_name[:-4]  # Pyre doesn't like str slicing here for some reason, ignore
    return repo_name


def set_tools(tools: list[Any]):
    global _TOOLS
    _TOOLS = tools


def get_llm(
    model_name: str = os.getenv("MODEL_NAME", "gpt-5.4-mini"),
    temperature: float = 0.0,
    bind_tools: bool = True,
):
    """Returns a configured coordinator LLM (tool-bound by default)."""
    provider = _detect_provider(model_name)
    if provider == "openrouter":
        clean_model = (
            model_name.removeprefix("openrouter/") if model_name.lower().startswith("openrouter/") else model_name
        )
        llm = ChatOpenAI(
            model=clean_model,
            temperature=temperature,
            openai_api_key=os.getenv("OPENROUTER_API_KEY"),
            openai_api_base="https://openrouter.ai/api/v1",
        )
    else:
        llm = ChatGoogleGenerativeAI(model=model_name, temperature=temperature)

    logger.info(f"[get_llm] Created LLM: {model_name} (bind_tools={bind_tools})")
    if bind_tools and _TOOLS:
        return llm.bind_tools(_TOOLS)
    return llm


# get_worker_llm and _detect_provider now live in src/llm/providers.py
# and are re-exported at the top of this file for backward compatibility.


# ════════════════════════════════════════════════════════════
#  SYNTHESIS & ESCALATION
# ════════════════════════════════════════════════════════════


def deduplicate_leads(worker_outputs: list[Any]) -> list[dict]:
    """Deduplicate worker outputs by contract::function, keeping highest confidence per target."""
    if not worker_outputs:
        return []

    leads_by_target: dict[str, dict] = {}

    for i, wo in enumerate(worker_outputs):
        wo_dict = wo.model_dump() if hasattr(wo, "model_dump") else wo

        lead_id = f"LEAD-{i + 1:03d}"
        evidence = wo_dict.get("evidence_node_ids", [])
        raw = wo_dict.get("raw_output", {})
        func_key = f"{raw.get('affected_contract', '')}::{raw.get('affected_function', '')}"
        vuln_class = raw.get("vulnerability_class", "unknown")

        # Story 6.7: ALWAYS use contract::function as primary dedup key.
        # evidence_node_ids can be shared across DIFFERENT hotspots (e.g., both
        # reference a shared internal helper) causing silent collision — one valid
        # finding would be overwritten. Identity = what function is being attacked,
        # not what evidence was cited.
        #
        # Story 6.8: first_principles findings are a SEPARATE identity dimension.
        # An assumption-violation finding and a reentrancy finding on the same
        # function are NOT duplicates — they describe different attacks.
        #
        # P2-J FIX: include vuln_class so distinct vulnerability classes on the
        # same function are NOT collapsed. An invariant_violation and a reentrancy
        # on the same function are two separate bugs.
        if vuln_class == "first_principles":
            key = f"fp_{func_key}_{i}"  # always unique — never collapse FP findings
        elif func_key != "::":
            key = f"{func_key}::{vuln_class}"  # contract::function::vuln_class
        else:
            key = wo_dict.get("task_id", f"__worker_{i}")

        wo_confidence = wo_dict.get("confidence", 0)
        if wo_confidence == 0:
            continue

        raw = raw  # already extracted above for dedup key
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
    worker_outputs: list[dict],
    low_threshold: int = 30,
    high_threshold: int = 70,
) -> tuple[bool, str | None]:
    if not worker_outputs:
        return False, None

    confidences = [
        wo.get("confidence", 0) if isinstance(wo, dict) else getattr(wo, "confidence", 0) for wo in worker_outputs
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
            return True, (f"Workers show high disagreement (confidence range: {conf_range}). Human review recommended.")

    return False, None


# ════════════════════════════════════════════════════════════
#  HELPERS
# ════════════════════════════════════════════════════════════


def _build_caller_context(graph, hotspot_node_id: str) -> list[dict]:
    """Extract all callers of a hotspot and their access control status."""
    if not graph or not hotspot_node_id:
        return []
    try:
        callers = get_callers(graph, hotspot_node_id)
        result = []
        for caller_id in callers:
            node_data = graph.nodes.get(caller_id, {})
            result.append(
                {
                    "caller": caller_id,
                    "is_protected": node_data.get("is_protected", False),
                    "access_control_type": node_data.get("access_control_type", "none"),
                }
            )
        return result
    except Exception:
        return []


# ════════════════════════════════════════════════════════════
#  COORDINATOR NODE
# ════════════════════════════════════════════════════════════


async def coordinator_node(state: AgentState):
    config = get_config()
    messages = state.get("messages", [])
    worker_outputs = state.get("worker_outputs", [])

    # Per-worker model routing
    recon_model = os.getenv("RECON_MODEL_NAME", os.getenv("WORKER_MODEL_NAME", "gpt-5.4-mini"))
    attack_model = os.getenv("ATTACK_MODEL_NAME", os.getenv("WORKER_MODEL_NAME", "grok-4-1-fast-reasoning"))
    test_writer_model = os.getenv("TEST_WRITER_MODEL_NAME", os.getenv("WORKER_MODEL_NAME", "grok-code-fast-1"))

    recon_llm = get_worker_llm(model_name=recon_model)
    attack_llm = get_worker_llm(model_name=attack_model)

    # ── Step 1: Recon ──────────────────────────────────────
    etherscan = EtherscanClient() if config.etherscan_enabled else None

    # Resolve repo_path BEFORE recon so it can read docs/natspec/compiler info
    repo_url = state.get("repo_url", "")
    repo_name = _repo_name_from_url(repo_url)
    repo_path = None
    if repo_name:
        candidate = Path("data/scratch") / repo_name
        if candidate.exists():
            repo_path = str(candidate)
    # Also check if repo_url is itself a local path (e.g. --repo data/morpho-workspace)
    if not repo_path and repo_url and Path(repo_url).exists():
        repo_path = str(Path(repo_url))

    recon_worker = ReconWorker(
        graph=state["graph"],
        llm_client=recon_llm,
        etherscan_client=etherscan,
    )
    recon_task = WorkerTask(
        task_id="recon_protocol",
        task_type="recon",
        context={
            "contract_names": state.get("contract_names", []),
            "contract_addresses": state.get("contract_addresses", {}),
            "repo_url": state.get("repo_url"),
            "repo_path": repo_path,
        },
    )
    recon_output = await recon_worker.run(recon_task)
    if repo_path:
        print(f"[Step 1] Recon complete. Repo path: {repo_path}")

    recon_context = recon_output.raw_output
    # BUG-008 fix: don't directly mutate state["recon_context"] here.
    # It's now returned via the return dict at the end of the function (LOGIC-004).

    if recon_context.get("onchain_risk_signals", {}).get("previous_exploits_detected"):
        print("[Step 1] Prior exploit detected by Recon. Escalating priority.")

    # ── Step 1.5: Semantic Discovery (Slither-independent) ──
    _semantic_findings: list[Finding] = []
    if config.semantic_discovery_enabled and repo_path:
        print("[Step 1.5] Semantic discovery enabled — launching LLM-native agents...")
        try:
            from src.pipeline.workers.semantic_discovery import run_semantic_discovery

            semantic_model = os.getenv("SEMANTIC_MODEL_NAME", os.getenv("WORKER_MODEL_NAME", "gpt-5.4-mini"))
            semantic_llm = get_worker_llm(model_name=semantic_model)
            semantic_outputs = await run_semantic_discovery(
                repo_path=repo_path,
                llm_client=semantic_llm,
                model_name=semantic_model,
                recon_context=recon_context,
            )
            print(f"[Step 1.5] Semantic discovery complete: {len(semantic_outputs)} agent output(s)")
            # Convert semantic outputs to Finding objects (no Hotspot required)
            for so in semantic_outputs:
                primary = Finding.from_semantic_output(so)
                primary._seed_semantic_score()  # P2-K: seed plausibility from confidence
                _semantic_findings.append(primary)
                # Also include multi-finding output from agents that return all_findings
                all_raw = so.raw_output.get("all_findings", [])
                if len(all_raw) > 1:
                    for extra in all_raw:
                        if extra == so.raw_output.get("best_finding"):
                            continue  # already handled above
                        extra_conf = int(extra.get("confidence", 0))
                        if extra_conf > 0:
                            extra_output = WorkerOutput(
                                worker_type=so.worker_type,
                                task_id=so.task_id,
                                hypothesis=extra.get("hypothesis", ""),
                                confidence=min(100, max(0, extra_conf)),
                                attack_path=extra.get("attack_path", []),
                                raw_output={
                                    "vulnerability_class": extra.get("vulnerability_class", "semantic_discovery"),
                                    "affected_contract": extra.get("affected_contract", ""),
                                    "affected_function": extra.get("affected_function", ""),
                                    "title": extra.get("title", ""),
                                    "impact": extra.get("impact", ""),
                                    "severity_estimate": extra.get("severity_estimate", "MEDIUM"),
                                    "evidence": extra.get("evidence", ""),
                                },
                            )
                            ef = Finding.from_semantic_output(extra_output)
                            ef._seed_semantic_score()  # P2-K: seed plausibility
                            _semantic_findings.append(ef)
            print(f"[Step 1.5] Total semantic findings: {len(_semantic_findings)}")
        except Exception as e:
            print(f"[Step 1.5] Semantic discovery failed (non-fatal): {e}")
    elif not config.semantic_discovery_enabled:
        print("[Step 1.5] Semantic discovery disabled (SEMANTIC_DISCOVERY_ENABLED=false)")
    else:
        print("[Step 1.5] No repo path — skipping semantic discovery")

    # ── Step 2: Hotspots ───────────────────────────────────
    findings: list[Finding] = list(_semantic_findings)  # seed with semantic findings
    hotspots = []

    if _semantic_findings:
        print(f"[Step 2] Seeded findings with {len(_semantic_findings)} semantic finding(s)")

    if config.slither_enabled and state["graph"].number_of_nodes() > 0:
        hotspots = get_high_risk_hotspots(state["graph"])
        # v2 E2E TESTING: fallback to relaxed gate if no hotspots found (single-contract repos)
        if not hotspots:
            from src.utils.graph_queries import get_graph_queries as _gq

            hotspots = _gq(state["graph"]).get_high_risk_hotspots(require_exploit_target=False)
        # BUG-1 FIX: Adaptive threshold for small graphs — single-file SCONE
        # contracts produce low signal density. Auto-retry at lower threshold.
        if not hotspots and state["graph"].number_of_nodes() < 50:
            _current_min = int(os.getenv("HOTSPOT_MIN_SCORE", "40"))
            _lowered = max(25, _current_min - 15)
            print(
                f"[Step 2] Small graph ({state['graph'].number_of_nodes()} nodes), retrying hotspots at min_score={_lowered}"
            )
            from src.utils.graph_queries import get_graph_queries as _gq2

            hotspots = _gq2(state["graph"]).get_high_risk_hotspots(
                min_score=_lowered,
                min_structural=10,
                min_exploitability=5,
                require_exploit_target=False,
            )
        print(f"[Step 2] Found {len(hotspots)} high-risk hotspot(s)")
    else:
        print("[Step 2] Slither disabled or empty graph — skipping hotspot-based workers")

    # ── Step 2.5: Threat Intelligence ──────────────────────
    _threat_context: dict = {}  # per-pipeline threat intel
    _matched_vectors: list = []
    _protocol_types: list = []
    _profiler = None
    _vector_db = None

    if _THREAT_INTEL_AVAILABLE and config.threat_profiler_enabled and state["graph"].number_of_nodes() > 0:
        try:
            _profiler = ThreatProfiler()
            _protocol_types = _profiler.classify(state["graph"])
            _primary_type = _protocol_types[0].get("type", "unknown") if _protocol_types else "unknown"
            _primary_confidence = _protocol_types[0].get("confidence", 0) if _protocol_types else 0
            print(f"[Step 2.5] Protocol classified: {_primary_type} (confidence: {_primary_confidence})")
            if len(_protocol_types) > 1:
                _secondary = [p["type"] for p in _protocol_types[1:3]]
                print(f"[Step 2.5] Secondary types: {_secondary}")

            # Load threat profile for primary type
            _threat_profile = _profiler.get_threat_profile(_primary_type)
            _threat_context = {
                "protocol_type": _primary_type,
                "protocol_confidence": _primary_confidence,
                "adversaries": [a.__dict__ for a in _threat_profile.adversaries],
                "invariants": _threat_profile.invariants,
                "composability_risks": _threat_profile.composability_risks,
                "threat_prompt": _threat_profile.format_for_prompt(),
            }
            print(
                f"[Step 2.5] Loaded threat profile: {len(_threat_profile.adversaries)} adversaries, {len(_threat_profile.invariants)} invariants"
            )
        except Exception as e:
            print(f"[Step 2.5] Threat profiler failed (non-fatal): {e}")
    elif not config.threat_profiler_enabled:
        print("[Step 2.5] Threat profiler disabled (THREAT_PROFILER_ENABLED=false)")

    if _THREAT_INTEL_AVAILABLE and config.attack_vector_db_enabled:
        try:
            _vector_db = AttackVectorDB()
            _proto_list = [p.get("type", "unknown") for p in _protocol_types] if _protocol_types else []
            _matched_vectors = _vector_db.match_vectors(state["graph"], _proto_list)
            print(f"[Step 2.5] Matched {len(_matched_vectors)} attack vectors for {_proto_list}")
        except Exception as e:
            print(f"[Step 2.5] Attack vector DB failed (non-fatal): {e}")
    elif not config.attack_vector_db_enabled:
        print("[Step 2.5] Attack vector DB disabled (ATTACK_VECTOR_DB_ENABLED=false)")

    if not hotspots:
        print("[Step 2] No hotspots above threshold — skipping attack workers")
        state["findings"] = []
        state["escalate"] = False
    else:
        # ── Step 3: Attack Workers + Assumption Workers ────
        attack_worker = AttackHypothesisWorker(
            graph=state["graph"],
            llm_client=attack_llm,
        )

        # Story 6.1: AssumptionWorker runs in parallel with AttackHypothesisWorker.
        # It receives NO graph signals or pattern hints — only raw source + call graph.
        # Separate model recommended: claude-sonnet for lateral/creative reasoning.
        assumption_worker = None
        if config.assumption_worker_enabled:
            from src.pipeline.workers.assumption_worker import AssumptionWorker

            assumption_model = os.getenv(
                "ASSUMPTION_MODEL_NAME", os.getenv("WORKER_MODEL_NAME", "grok-4-1-fast-reasoning")
            )
            assumption_llm = get_worker_llm(model_name=assumption_model)
            assumption_worker = AssumptionWorker(
                graph=state["graph"],
                llm_client=assumption_llm,
            )
        else:
            print("[Step 3] Assumption worker disabled (ASSUMPTION_WORKER_ENABLED=false)")

        # ExecutionTraceWorker: cross-function symmetry tests and execution path analysis
        execution_trace_worker = None
        _execution_trace_enabled = os.getenv("EXECUTION_TRACE_ENABLED", "true").lower() in ("true", "1", "yes")
        if _execution_trace_enabled:
            try:
                from src.pipeline.workers.execution_trace_worker import ExecutionTraceWorker

                exec_trace_model = os.getenv(
                    "EXECUTION_TRACE_MODEL_NAME", os.getenv("WORKER_MODEL_NAME", "gpt-5.4-mini")
                )
                exec_trace_llm = get_worker_llm(model_name=exec_trace_model)
                execution_trace_worker = ExecutionTraceWorker(
                    graph=state["graph"],
                    llm_client=exec_trace_llm,
                )
                print(f"[Step 3] ExecutionTraceWorker enabled (model={exec_trace_model})")
            except Exception as e:
                print(f"[Step 3] ExecutionTraceWorker init failed (non-fatal): {e}")
        else:
            print("[Step 3] ExecutionTraceWorker disabled (EXECUTION_TRACE_ENABLED=false)")

        def _budget_for_priority(priority: str) -> int:
            return {"CRITICAL": 8000, "HIGH": 5000, "MEDIUM": 3000}.get(priority, 3000)

        # Build per-hotspot threat context bundles
        def _build_attack_context(hotspot) -> dict:
            ctx = {"recon_context": recon_context}
            if _threat_context:
                ctx["threat_context"] = _threat_context
            if _vector_db and _matched_vectors:
                # Get hotspot source code for vector relevance filtering
                hs_source = ""
                if state["graph"].has_node(hotspot.node_id):
                    hs_source = state["graph"].nodes[hotspot.node_id].get("source_code", "")
                vector_bundle = _vector_db.build_agent_bundle(_matched_vectors, hs_source)
                ctx["vector_bundle"] = vector_bundle
                ctx["matched_vector_count"] = len(_matched_vectors)
            return ctx

        attack_tasks = [
            WorkerTask(
                task_id=f"attack_{hotspot.node_id}",
                task_type="attack_analysis",
                hotspot=hotspot,
                context=_build_attack_context(hotspot),
                budget_tokens=_budget_for_priority(hotspot.priority),
            )
            for hotspot in hotspots
        ]
        assumption_tasks = (
            [
                WorkerTask(
                    task_id=f"assumption_{hotspot.node_id}",
                    task_type="assumption_analysis",
                    hotspot=hotspot,
                    context={},  # deliberately empty — no hints
                    budget_tokens=_budget_for_priority(hotspot.priority),
                )
                for hotspot in hotspots
            ]
            if assumption_worker
            else []
        )
        execution_trace_tasks = (
            [
                WorkerTask(
                    task_id=f"exec_trace_{hotspot.node_id}",
                    task_type="execution_trace",
                    hotspot=hotspot,
                    context={},  # uses graph internally for sibling lookup
                    budget_tokens=_budget_for_priority(hotspot.priority),
                )
                for hotspot in hotspots
            ]
            if execution_trace_worker
            else []
        )

        total_tasks = len(attack_tasks) + len(assumption_tasks) + len(execution_trace_tasks)
        print(
            f"[Step 3] Launching {len(attack_tasks)} attack + {len(assumption_tasks)} assumption + {len(execution_trace_tasks)} exec_trace worker(s) in parallel ({total_tasks} total)..."
        )
        for t in attack_tasks:
            print(f"  [attack]      - {t.task_id}")
        for t in assumption_tasks:
            print(f"  [assumption]  - {t.task_id}")
        for t in execution_trace_tasks:
            print(f"  [exec_trace]  - {t.task_id}")

        _attack_concurrency = int(os.getenv("ATTACK_WORKER_CONCURRENCY", "15"))
        _attack_sem = asyncio.Semaphore(_attack_concurrency)
        _assumption_sem = asyncio.Semaphore(_attack_concurrency)
        _exec_trace_sem = asyncio.Semaphore(_attack_concurrency)

        async def _run_attack_with_timeout(task, timeout=300):
            async with _attack_sem:
                try:
                    return await asyncio.wait_for(attack_worker.run(task), timeout=timeout)
                except TimeoutError:
                    print(f"  TIMEOUT: {task.task_id} (>{timeout}s)")
                    return None

        async def _run_assumption_with_timeout(task, timeout=300):
            async with _assumption_sem:
                try:
                    return await asyncio.wait_for(assumption_worker.run(task), timeout=timeout)
                except TimeoutError:
                    print(f"  TIMEOUT: {task.task_id} (>{timeout}s)")
                    return None

        async def _run_exec_trace_with_timeout(task, timeout=300):
            async with _exec_trace_sem:
                try:
                    return await asyncio.wait_for(execution_trace_worker.run(task), timeout=timeout)
                except TimeoutError:
                    print(f"  TIMEOUT: {task.task_id} (>{timeout}s)")
                    return None

        # Gather ALL workers in parallel — attack, assumption, and exec_trace run simultaneously
        all_outputs = await asyncio.gather(
            *[_run_attack_with_timeout(t) for t in attack_tasks],
            *[_run_assumption_with_timeout(t) for t in assumption_tasks],
            *[_run_exec_trace_with_timeout(t) for t in execution_trace_tasks],
            return_exceptions=True,
        )
        _split_1 = len(attack_tasks)
        _split_2 = _split_1 + len(assumption_tasks)
        worker_outputs_parallel = all_outputs[:_split_1]
        assumption_outputs_parallel = all_outputs[_split_1:_split_2]
        exec_trace_outputs_parallel = all_outputs[_split_2:]

        print(f"[Step 3] Attack workers complete: {len(worker_outputs_parallel)} result(s)")
        print(f"[Step 3] Assumption workers complete: {len(assumption_outputs_parallel)} result(s)")
        for i, o in enumerate(worker_outputs_parallel):
            if isinstance(o, Exception):
                print(f"  [attack][{i}] EXCEPTION: {o}")
            elif o is None:
                print(f"  [attack][{i}] TIMEOUT (no result)")
            else:
                o_conf = getattr(o, "confidence", 0)
                o_hyp = str(getattr(o, "hypothesis", "")) or None
                print(f"  [attack][{i}] confidence={o_conf} hypothesis={o_hyp}")

        for i, o in enumerate(assumption_outputs_parallel):
            if isinstance(o, Exception):
                print(f"  [assumption][{i}] EXCEPTION: {o}")
            elif o is None:
                print(f"  [assumption][{i}] TIMEOUT (no result)")
            else:
                o_conf = getattr(o, "confidence", 0)
                print(f"  [assumption][{i}] confidence={o_conf}")

        for i, o in enumerate(exec_trace_outputs_parallel):
            if isinstance(o, Exception):
                print(f"  [exec_trace][{i}] EXCEPTION: {o}")
            elif o is None:
                print(f"  [exec_trace][{i}] TIMEOUT (no result)")
            else:
                o_conf = getattr(o, "confidence", 0)
                print(f"  [exec_trace][{i}] confidence={o_conf}")

        # ── Step 4: Build Findings ─────────────────────────
        for output, hotspot in zip(worker_outputs_parallel, hotspots):
            if output is None or isinstance(output, Exception):
                print(f"  Skipping {hotspot.node_id} — no output")
                continue

            out_conf = getattr(output, "confidence", 0)
            # F3: Attack worker confidence gate with SPECULATIVE tier
            # >= 50: normal Finding  (was 65 — lowered to allow more candidates)
            # 30-49: SPECULATIVE Finding (goes through depth but flagged in report)
            # < 30:  true noise floor — drop
            attack_conf_floor = int(os.getenv("ATTACK_CONFIDENCE_FLOOR", "50"))
            speculative_floor = int(os.getenv("ATTACK_SPECULATIVE_FLOOR", "30"))
            if out_conf >= attack_conf_floor:
                finding = Finding.from_worker_output(output, hotspot)
                # BUG-4 FIX: Old seed (conf//5 = 10-16) was too low to ever
                # reach PROMOTE_THRESHOLD=50 with gate PASS (+20). Now conf//3
                # gives 16-33, so gate PASS pushes to 36-53 — reachable.
                finding.contribute_score("attack_worker", out_conf // 3, f"attack confidence {out_conf}")
                findings.append(finding)
            elif out_conf >= speculative_floor:
                finding = Finding.from_worker_output(output, hotspot)
                finding.is_speculative = True
                finding.contribute_score("attack_worker", out_conf // 5, f"speculative attack confidence {out_conf}")
                findings.append(finding)

            if not isinstance(output, Exception):
                model_dump_func = getattr(output, "model_dump", None)
                wo_dict = model_dump_func() if callable(model_dump_func) else output
                worker_outputs.append(wo_dict)

        # Story 6.1: Assumption findings use a lower confidence threshold (25).
        # First-principles findings are inherently more speculative but can surface
        # bugs that the pattern-based attack worker completely misses. They go
        # through the same jury + depth pipeline as regular findings.
        assumption_conf_threshold = int(os.getenv("ASSUMPTION_CONFIDENCE_THRESHOLD", "25"))
        assumption_finding_count = 0
        for output, hotspot in zip(assumption_outputs_parallel, hotspots):
            if output is None or isinstance(output, Exception):
                continue
            out_conf = getattr(output, "confidence", 0)
            if out_conf >= assumption_conf_threshold:
                finding = Finding.from_worker_output(output, hotspot)
                # BUG-4 FIX: Assumption findings also need a plausibility seed
                finding.contribute_score("assumption_worker", out_conf // 4, f"assumption confidence {out_conf}")
                findings.append(finding)
                assumption_finding_count += 1

            if not isinstance(output, Exception):
                model_dump_func = getattr(output, "model_dump", None)
                wo_dict = model_dump_func() if callable(model_dump_func) else output
                worker_outputs.append(wo_dict)

        # ExecutionTraceWorker findings — cross-function symmetry gaps
        exec_trace_conf_threshold = int(os.getenv("EXEC_TRACE_CONFIDENCE_THRESHOLD", "35"))
        exec_trace_finding_count = 0
        for output, hotspot in zip(exec_trace_outputs_parallel, hotspots):
            if output is None or isinstance(output, Exception):
                continue
            out_conf = getattr(output, "confidence", 0)
            if out_conf >= exec_trace_conf_threshold:
                finding = Finding.from_worker_output(output, hotspot)
                finding.contribute_score("execution_trace", out_conf // 4, f"exec_trace confidence {out_conf}")
                findings.append(finding)
                exec_trace_finding_count += 1

            if not isinstance(output, Exception):
                model_dump_func = getattr(output, "model_dump", None)
                wo_dict = model_dump_func() if callable(model_dump_func) else output
                worker_outputs.append(wo_dict)

        print(
            f"[Step 4] Findings that passed filter: {len(findings)} ({assumption_finding_count} from assumption, {exec_trace_finding_count} from exec_trace)"
        )

    # ── Step 4.25: Synthetic Fallback for Semantic Leads (P2-K) ──────────
    # If attack + assumption workers produced ZERO promoted findings but semantic
    # discovery found high-confidence leads, directly promote the best N semantic
    # findings by marking them _jury_confirmed=True.
    #
    # Rationale: semantic agents reason about source code at a protocol level and
    # can surface Morpho-class bugs that attack workers miss because they require
    # semi-trusted role conditions. We should not silently drop these.
    SEMANTIC_FALLBACK_N = int(os.getenv("SEMANTIC_FALLBACK_N", "3"))
    SEMANTIC_FALLBACK_THRESHOLD = int(os.getenv("SEMANTIC_FALLBACK_THRESHOLD", "55"))

    _attack_derived = [
        f
        for f in findings
        if not (
            f.hotspot_node_id
            and "::" in f.hotspot_node_id
            and f.vulnerability_class
            in (
                "semantic_discovery",
                "invariant_violation",
                "accounting_scope_mismatch",
                "keeper_drain",
                "cross_contract_reentrancy",
                "flash_loan_manipulation",
                "oracle_manipulation",
                "role_delegation_abuse",
                "privilege_escalation",
                "first_principles",
            )
        )
    ]
    _semantic_only = [f for f in findings if f not in _attack_derived]

    if not _attack_derived and _semantic_only and _semantic_findings:
        # No attack-worker findings survived — try semantic fallback
        high_conf_semantic = sorted(
            [f for f in _semantic_only if f.confidence >= SEMANTIC_FALLBACK_THRESHOLD],
            key=lambda f: f.confidence,
            reverse=True,
        )
        if high_conf_semantic:
            promoted = high_conf_semantic[:SEMANTIC_FALLBACK_N]
            for f in promoted:
                f._jury_confirmed = True  # bypass PROMOTE_THRESHOLD at TestWriter
                f.contribute_score(
                    "semantic_fallback", +40, f"synthetic promotion: no attack-worker findings, conf={f.confidence}"
                )
                print(
                    f"  [P2-K] Synthetic fallback: promoted {f.hotspot_node_id} "
                    f"(conf={f.confidence}, score→{f.plausibility_score})"
                )
            print(f"[Step 4.25] Synthetic fallback: {len(promoted)} semantic finding(s) force-promoted to TestWriter")
        else:
            print(
                f"[Step 4.25] Synthetic fallback: no semantic findings >= {SEMANTIC_FALLBACK_THRESHOLD} confidence — nothing to promote"
            )
    else:
        if _attack_derived:
            print(f"[Step 4.25] Attack-derived findings exist ({len(_attack_derived)}) — skipping semantic fallback")

    # ── Step 4.45: 4-Gate Pre-Filter (gated by config.gate_enabled) ──────
    # ── Step 4.5: Jury Validation (gated by config.jury_enabled) ─────────
    jury_briefs: dict[str, dict] = {}
    confirmed_findings: list = []  # BUG FIX: defined before gate block to prevent NameError

    if (config.gate_enabled or config.jury_enabled) and findings:
        print(f"[Step 4.5] Gate/Jury enabled — evaluating {len(findings)} finding(s)...")

        from src.pipeline.workers.jury_context import build_jury_context_package
        from src.pipeline.workers.jury_worker import JuryCoordinator, gate_evaluate

        # ── Story 6.2: 4-Gate Pre-Filter (only if gate_enabled) ───────
        state.setdefault("jury_rejected_findings", [])

        if config.gate_enabled:
            gate_model = os.getenv("GATE_MODEL_NAME", "gpt-5.4-mini")
            gate_llm = get_worker_llm(model_name=gate_model)

            print(f"[Step 4.45] Running fast 4-gate pre-filter on {len(findings)} finding(s)...")

            # Semaphore: max 5 concurrent gate calls — prevents thundering-herd
            # rate-limit timeouts when evaluating 20+ findings at once.
            _GATE_CONCURRENCY = int(os.getenv("GATE_CONCURRENCY", "5"))
            _gate_sem = asyncio.Semaphore(_GATE_CONCURRENCY)

            async def _run_gate(finding):
                async with _gate_sem:
                    try:
                        raw_source = ""
                        try:
                            ctx = get_function_context(state["graph"], finding.hotspot_node_id)
                            raw_source = ctx.get("source_code") or ctx.get("code") or ""
                        except Exception:
                            pass
                        return finding, await gate_evaluate(finding, raw_source, gate_llm)
                    except Exception as e:
                        logger.warning(f"[Gate] Failed for {finding.hotspot_node_id}: {e}")
                        from src.pipeline.workers.jury_worker import GateResult

                        return finding, GateResult(verdict="PASS", gate=0, quote="error")

            gate_results = await asyncio.gather(*[_run_gate(f) for f in findings])

            pre_filtered_findings = []

            for finding, gate_res in gate_results:
                finding.gate_verdict = gate_res.verdict
                finding.gate_failed = gate_res.gate
                finding.gate_quote = gate_res.quote

                if gate_res.verdict == "GATE_REFUTED":
                    finding.jury_decision = "GATE_REFUTED"
                    finding.jury_rejection_reason = f"Failed Gate {gate_res.gate}: {gate_res.quote}"
                    finding.status = FindingStatus.REJECTED
                    # Plausibility: hard code refutation is strong negative evidence but not permanent
                    finding.contribute_score("gate", -40, f"GATE_REFUTED gate={gate_res.gate}: {gate_res.quote[:50]}")
                    state["jury_rejected_findings"].append(finding)
                    pre_filtered_findings.append(finding)  # keep in pool for depth resurrection
                    print(f"  [Gate] ✗ REFUTED Gate {gate_res.gate}: {finding.hotspot_node_id} ({gate_res.quote[:60]})")
                elif gate_res.verdict == "GATE_DEMOTED":
                    finding.verdict = FindingVerdict.PARTIAL
                    finding.jury_decision = "GATE_DEMOTED"
                    finding.jury_reasoning = f"Demoted at Gate {gate_res.gate}: {gate_res.quote}"
                    finding.contribute_score(
                        "gate", +5, f"GATE_DEMOTED gate={gate_res.gate}: real but restricted/partial"
                    )
                    pre_filtered_findings.append(finding)
                    print(f"  [Gate] ↓ DEMOTED Gate {gate_res.gate}: {finding.hotspot_node_id} (sent to depth)")
                else:  # PASS
                    finding.contribute_score("gate", +20, "all 4 gates cleared")
                    pre_filtered_findings.append(finding)
                    print(f"  [Gate] ✓ PASSED: {finding.hotspot_node_id}")

            findings = pre_filtered_findings
            jury_candidates = [f for f in findings if f.gate_verdict == "PASS"]
        else:
            # Gate disabled — all findings pass through unfiltered
            print(f"[Step 4.45] Gate disabled — all {len(findings)} finding(s) pass to jury unfiltered")
            for f in findings:
                f.gate_verdict = "PASS"
            jury_candidates = list(findings)

        if not jury_candidates:
            print("[Step 4.5] No findings passed the gate pre-filter. Skipping full jury.")
            for f in findings:
                # the ones left in findings are GATE_DEMOTED (PARTIAL)
                confirmed_findings.append(f)
        elif not config.jury_enabled:
            # Gate ran but jury is disabled (e.g. standard mode) — pass gate-survived findings through
            print(f"[Step 4.5] Jury disabled — {len(jury_candidates)} finding(s) passed gate, skipping debate")
            for f in findings:
                confirmed_findings.append(f)
        else:
            print(f"[Step 4.5] Full jury evaluating {len(jury_candidates)} finding(s) that passed gates...")

            skeptic_llm = get_worker_llm(model_name=JURY_SKEPTIC_MODEL)
            attacker_llm = get_worker_llm(model_name=JURY_ATTACKER_MODEL)
            auditor_llm = get_worker_llm(model_name=JURY_AUDITOR_MODEL)
            judge_llm = get_worker_llm(model_name=JURY_JUDGE_MODEL)

            jury = JuryCoordinator(
                skeptic_llm=skeptic_llm,
                attacker_llm=attacker_llm,
                auditor_llm=auditor_llm,
                judge_llm=judge_llm,
                skeptic_model=JURY_SKEPTIC_MODEL,
                attacker_model=JURY_ATTACKER_MODEL,
                auditor_model=JURY_AUDITOR_MODEL,
                judge_model=JURY_JUDGE_MODEL,
            )

            _jury_sem = asyncio.Semaphore(JURY_CONCURRENCY)

            async def _run_jury_for_finding(finding, hotspot):
                async with _jury_sem:
                    raw_source = ""
                    try:
                        ctx = get_function_context(state["graph"], finding.hotspot_node_id)
                        raw_source = ctx.get("source_code") or ctx.get("code") or ""
                    except Exception:
                        pass

                    context_package = build_jury_context_package(
                        finding=finding,
                        hotspot=hotspot,
                        graph=state["graph"],
                        raw_source_code=raw_source,
                    )

                    try:
                        return finding, await asyncio.wait_for(
                            jury.evaluate(context_package),
                            timeout=150,
                        )
                    except TimeoutError:
                        logger.warning(f"[Jury] Timeout (150s) for {finding.hotspot_node_id} — skipping jury")
                        return finding, None
                    except Exception as e:
                        logger.warning(f"[Jury] Failed for {finding.hotspot_node_id}: {e}")
                        return finding, None

        hotspot_map = {h.node_id: h for h in hotspots}
        jury_tasks = []
        confirmed_findings = []

        for finding in jury_candidates:
            hotspot = hotspot_map.get(finding.hotspot_node_id)
            # BUG-3 FIX: Semantic findings use "Contract::function" node IDs
            # but hotspot_map keys are "Contract.function". Don't skip findings
            # without a hotspot match — build a synthetic hotspot from the finding.
            if not hotspot:
                from src.hotspot_engine import Hotspot

                hotspot = Hotspot(
                    node_id=finding.hotspot_node_id,
                    contract=finding.affected_contract,
                    function=finding.affected_function,
                    risk_score=finding.risk_score or finding.confidence,
                    risk_categories=[finding.vulnerability_class],
                    signals={},
                    priority=finding.severity_estimate or "MEDIUM",
                )
            jury_tasks.append(_run_jury_for_finding(finding, hotspot))

        if jury_tasks:
            jury_results = await asyncio.gather(*jury_tasks, return_exceptions=True)
        else:
            jury_results = []

        for result in jury_results:
            if isinstance(result, Exception):
                continue
            finding, judge_output = result
            if judge_output is None:
                # Jury timed out: keep finding but don't give jury score
                confirmed_findings.append(finding)
                continue

            decision = judge_output.decision

            if decision == "CONFIRMED":
                confirmed_findings.append(finding)
                jury_briefs[finding.hotspot_node_id] = judge_output.testwriter_brief
                finding.jury_decision = "CONFIRMED"
                finding.jury_vote_summary = judge_output.vote_summary
                finding.jury_reasoning = judge_output.reasoning
                finding.confidence_consensus = 100
                # Jury CONFIRMED: strong evidence — and pinned to TestWriter bypass
                finding.contribute_score("jury", +30, "CONFIRMED: 2+/3 jurors agreed")
                finding._jury_confirmed = True  # bypass plausibility threshold
                print(f"  [Jury] ✓ CONFIRMED: {finding.hotspot_node_id}")

            elif decision == "CONFIRMED_UNPROVABLE":
                confirmed_findings.append(finding)
                finding.jury_unprovable = True
                finding.jury_unprovable_reason = judge_output.unprovable_reason
                finding.jury_decision = "CONFIRMED_UNPROVABLE"
                finding.jury_vote_summary = judge_output.vote_summary
                finding.jury_reasoning = judge_output.reasoning
                finding.confidence_consensus = 75
                finding.contribute_score("jury", +20, "CONFIRMED_UNPROVABLE: real but can't prove in isolation")
                finding._jury_confirmed = True  # still confirmed — always to TestWriter
                print(
                    f"  [Jury] ~ CONFIRMED_UNPROVABLE: {finding.hotspot_node_id} — {judge_output.unprovable_reason[:80]}"
                )

                # Downgrade severity if preconditions require privileged role compromise
                _privilege_keywords = [
                    "admin",
                    "router",
                    "owner",
                    "compromise",
                    "malicious",
                    "privileged",
                    "operator",
                    "governance",
                    "multisig",
                ]
                if finding.preconditions_missing:
                    _pre_text = " ".join(finding.preconditions_missing).lower()
                    if any(kw in _pre_text for kw in _privilege_keywords):
                        _sev_map = {"CRITICAL": "HIGH", "HIGH": "MEDIUM", "MEDIUM": "MEDIUM", "LOW": "LOW"}
                        _orig_sev = finding.severity_estimate
                        finding.severity_estimate = _sev_map.get(_orig_sev, _orig_sev)
                        logger.info(
                            f"[Jury] Severity downgraded {_orig_sev} → {finding.severity_estimate} (unmet privilege precondition)"
                        )
                        print(
                            f"  [Jury] ↓ Severity {_orig_sev} → {finding.severity_estimate} (requires privileged role)"
                        )

            elif decision == "ESCALATE":
                confirmed_findings.append(finding)
                finding.jury_escalate = True
                finding.jury_decision = "ESCALATE"
                finding.jury_vote_summary = judge_output.vote_summary
                finding.jury_reasoning = judge_output.reasoning
                finding.confidence_consensus = 50
                finding.contribute_score("jury", +10, "ESCALATE: mixed jury, needs human review")
                # FIX-2: ESCALATE = benefit of the doubt → always try TestWriter.
                # If jury couldn't agree, a PoC attempt is the best tiebreaker.
                finding._jury_confirmed = True
                print(f"  [Jury] ? ESCALATE: {finding.hotspot_node_id}")

            else:  # REJECTED
                finding.jury_decision = "REJECTED"
                finding.jury_vote_summary = judge_output.vote_summary
                finding.jury_reasoning = judge_output.reasoning
                finding.jury_rejection_reason = judge_output.rejection_reason
                finding.confidence_consensus = 10
                # Penalize but DON'T drop — depth workers can still resurrect this
                finding.contribute_score("jury", -25, f"REJECTED: {judge_output.rejection_reason[:60]}")
                state.setdefault("jury_rejected_findings", [])
                state["jury_rejected_findings"].append(finding)
                # Keep in pool so depth workers can evaluate and potentially resurrect
                confirmed_findings.append(finding)
                print(f"  [Jury] ✗ REJECTED: {finding.hotspot_node_id} — kept in pool (depth may resurrect)")

        rejected_count = sum(1 for f in confirmed_findings if f.jury_decision == "REJECTED")
        print(
            f"[Step 4.5] Jury complete: {len(confirmed_findings) - rejected_count} confirmed/escalated, {rejected_count} jury-rejected (in pool)"
        )
        findings = confirmed_findings

        # Apply chain severity upgrades AFTER jury — only confirmed findings get upgraded
        from src.pipeline.chain_analyzer import apply_chain_severity_upgrades

        apply_chain_severity_upgrades(findings)
        print("[Step 4.55] Applied post-jury chain severity upgrades")

    else:
        if not config.jury_enabled:
            print("[Step 4.5] Jury disabled (set JURY_ENABLED=true or AUDIT_MODE=deep to enable)")

    # ── Step 4.6: RAG Batch Validation & Scoring ──────────
    if config.rag_enabled and findings:
        from src.knowledge.rag_system import rag_mandatory_sweep

        findings = await rag_mandatory_sweep(findings)

        # Apply Mechanical Confidence Scoring
        for f in findings:
            f.confidence = f.compute_mechanical_confidence()
    elif not config.rag_enabled:
        print("[Step 4.6] RAG disabled (RAG_ENABLED=false)")

    # ── Step 4.7: Depth Worker Pass ──────────────────────
    # Re-analyze uncertain findings from specialized angles.
    # DEPTH_ON_REJECTED: also run depth on jury-rejected findings (costs more, optional).
    DEPTH_ON_REJECTED = os.getenv("DEPTH_ON_REJECTED", "false").lower() == "true"
    depth_eligible = [
        f
        for f in findings
        if f.verdict in ("CONTESTED", "PARTIAL", "UNASSESSED")
        or (DEPTH_ON_REJECTED and f.jury_decision == "REJECTED")
        or f.gate_verdict == "GATE_DEMOTED"  # always depth gate-demoted findings
    ]
    uncertain_count = len(depth_eligible)
    if config.depth_workers_enabled and uncertain_count > 0:
        print(
            f"[Step 4.7] Running depth workers on {uncertain_count} finding(s) (DEPTH_ON_REJECTED={DEPTH_ON_REJECTED})..."
        )
        try:
            from src.pipeline.workers.depth_workers import run_depth_workers

            depth_model = os.getenv("DEPTH_MODEL_NAME", os.getenv("MODEL_NAME", "gpt-5.4-mini"))
            depth_llm = get_worker_llm(model_name=depth_model)
            depth_results = await run_depth_workers(
                findings=depth_eligible,
                graph=state["graph"],
                source_cache={},
                llm_client=depth_llm,
                model_name=depth_model,
                max_depth_passes=2,
            )

            # Wire depth results into plausibility scores
            DEPTH_SCORE_MAP = {
                "CONFIRMED": +20,
                "REFINED": +10,
                "CONTESTED": +5,
                "REFUTED": -15,
            }
            for dr in depth_results or []:
                finding = getattr(dr, "finding", None) or getattr(dr, "_finding", None)
                if finding is None:
                    continue
                verdict = getattr(dr, "verdict", "") or ""
                delta = DEPTH_SCORE_MAP.get(verdict.upper(), 0)
                if delta != 0:
                    finding.contribute_score("depth", delta, f"depth verdict={verdict}")

            print(f"[Step 4.7] Depth pass complete: {len(depth_results or [])} finding(s) re-analyzed")
        except Exception as e:
            print(f"[Step 4.7] Depth workers failed (non-fatal): {e}")

    elif not config.depth_workers_enabled:
        print("[Step 4.7] Depth workers disabled (DEPTH_WORKERS_ENABLED=false)")
    else:
        print("[Step 4.7] No uncertain findings — skipping depth pass")

    # ── Step 4.8: Chain Analysis ──────────────────────────
    # Link findings by matching postconditions → preconditions_missing
    if config.chain_analysis_enabled and len(findings) >= 2:
        print("[Step 4.8] Running chain analysis...")
        try:
            from src.pipeline.chain_analyzer import run_chain_analysis

            chain_hypotheses = run_chain_analysis(findings)
            # Store chains on state for report consumption
            state["chain_hypotheses"] = chain_hypotheses
            print(f"[Step 4.8] Chain analysis complete: {len(chain_hypotheses)} chain(s) found")
        except Exception as e:
            print(f"[Step 4.8] Chain analysis failed (non-fatal): {e}")
            state["chain_hypotheses"] = []
    elif not config.chain_analysis_enabled:
        print("[Step 4.8] Chain analysis disabled (CHAIN_ANALYSIS_ENABLED=false)")
        state["chain_hypotheses"] = []
    else:
        print("[Step 4.8] Not enough findings for chain analysis")
        state["chain_hypotheses"] = []

    # ── Step 5: Coordinator LLM Synthesis ─────────────────
    # The programmatic pipeline (Recon → Hotspots → Attack → TestWriter) has
    # already run above. The LLM's ONLY job here is to produce the final JSON
    # report. NEVER bind tools — avoids Gemini thought_signature errors and
    # prevents the LangGraph tool loop from re-running the entire pipeline.
    print("[Step 5] Starting Coordinator LLM synthesis...")
    coordinator_llm = get_llm(bind_tools=False)

    prompt = [SystemMessage(content=COORDINATOR_SYSTEM_PROMPT)]

    # Build context for LLM: either worker results or hotspot summary
    hotspot_summary = ""
    if hotspots:
        hotspot_summary = "\n\n=== HOTSPOT DATA (from programmatic analysis) ===\n"
        hotspot_summary += f"Found {len(hotspots)} high-risk function(s):\n"
        for h in hotspots[:15]:
            hotspot_summary += (
                f"  - {h.node_id} | final={h.risk_score} "
                f"struct={h.structural_score} exploit={h.exploitability_score} "
                f"impact={h.impact_score} | priority={h.priority}\n"
            )

    if worker_outputs:
        synthesis = deduplicate_leads(worker_outputs)
        escalate_human, reason = should_escalate_to_human(worker_outputs)

        worker_context = (
            f"\n\n=== WORKER RESULTS ===\n"
            f"Received {len(worker_outputs)} worker output(s).\n"
            f"Synthesised into {len(synthesis)} unique lead(s).\n"
            f"Escalation needed: {escalate_human}"
        )
        if reason:
            worker_context += f"\nEscalation reason: {reason}"
        worker_context += (
            f"\n\nSynthesised leads:\n{json.dumps(synthesis, indent=2)}\n\n"
            "Your task: Output the JSON block only. Do NOT call any tools."
        )
        prompt.append(HumanMessage(content=worker_context))
    else:
        no_findings_context = (
            f"{hotspot_summary}\n\n"
            f"No high-risk hotspots exceeded the threshold (min_score=70). "
            f"The Knowledge Graph has {state['graph'].number_of_nodes()} nodes "
            f"and {state['graph'].number_of_edges()} edges across "
            f"{len(state.get('contract_names', []))} contract(s).\n\n"
            "Produce the JSON report. If no risks were found, report 0 vulnerability_leads honestly."
        )
        prompt.append(HumanMessage(content=no_findings_context))

    if messages:
        prompt.extend(messages)

    SYNTHESIS_TIMEOUT = int(os.getenv("COORDINATOR_SYNTHESIS_TIMEOUT", "180"))
    print(f"[Step 5] Calling Coordinator LLM (timeout={SYNTHESIS_TIMEOUT}s)...")
    try:
        response = await asyncio.wait_for(
            asyncio.to_thread(coordinator_llm.invoke, prompt),
            timeout=SYNTHESIS_TIMEOUT,
        )

        # ── Token tracking for Coordinator synthesis ──
        try:
            from src.utils.token_counter import get_token_counter

            _model = os.getenv("MODEL_NAME", "gpt-5.4-mini")
            _input_text = "\n".join(m.content if hasattr(m, "content") else str(m) for m in prompt)
            _resp_content = response.content if hasattr(response, "content") else str(response)
            if isinstance(_resp_content, list):
                _resp_content = "".join([c.get("text", "") if isinstance(c, dict) else str(c) for c in _resp_content])
            get_token_counter().record(
                "CoordinatorSynthesis",
                _model,
                _input_text,
                str(_resp_content),
                getattr(response, "response_metadata", None),
            )
        except Exception:
            pass  # Never let tracking break the pipeline

    except TimeoutError:
        print(f"[Step 5] WARNING: Coordinator LLM timed out after {SYNTHESIS_TIMEOUT}s — using worker outputs directly")
        response = None
    except Exception as e:
        print(f"[Step 5] WARNING: Coordinator LLM failed: {e} — using worker outputs directly")
        response = None

    # With tools disabled, the LLM should never make tool_calls.
    # If it does, strip them to prevent LangGraph routing to ToolNode
    # which would re-run the entire pipeline (BUG-012).
    if response and getattr(response, "tool_calls", None):
        logger.warning("Coordinator LLM returned tool_calls despite bind_tools=False — stripping")
        response.tool_calls = []
        if hasattr(response, "additional_kwargs"):
            getattr(response, "additional_kwargs", {}).pop("tool_calls", None)

    # ── Parse final response ───────────────────────────────
    leads = []
    target_nodes = []
    strategy = ""
    escalation = False
    if response is None:
        print("[Step 5] No LLM response — falling back to worker synthesis")
        leads = deduplicate_leads(worker_outputs) if worker_outputs else []
        strategy = "LLM synthesis skipped (timeout or error)"
        # Build a dummy response for the return dict
        from langchain_core.messages import AIMessage

        response = AIMessage(
            content=json.dumps(
                {
                    "analysis_summary": {"strategy": strategy},
                    "vulnerability_leads": leads,
                }
            )
        )
    else:
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
            print(f"[Step 5] LLM synthesis complete: {len(leads)} lead(s)")
        except Exception as e:
            print(f"[Step 5] Parse error: {e}")
            leads = deduplicate_leads(worker_outputs) if worker_outputs else []
            strategy = "Failed to parse LLM response"

    # ── Step 5b: DISABLED (Epic 2, Story 2.1) ───────────────
    # Synthetic finding creation from LLM leads has been removed.
    # Only Attack Workers (Step 3→4) can produce findings, ensuring
    # every finding is grounded in a graph hotspot — the LLM cannot
    # invent vulnerabilities without structural evidence.
    if not findings and leads:
        print(
            f"[Step 5b] {len(leads)} LLM lead(s) present but synthetic fallback is disabled. "
            f"Only Attack Worker findings are accepted."
        )

    # ── Step 6: TestWriter ─────────────────────────────────
    test_tasks = []
    target_findings = []
    if not config.testwriter_enabled:
        print("[Step 6] TestWriter disabled (TESTWRITER_ENABLED=false)")
    else:
        print(f"[Step 6] Preparing TestWriter: {len(findings)} finding(s) to process")

    # ── Copy repo to Linux fs ONCE before spawning all TestWriters ──
    # This avoids N parallel copies of the repo (one per finding).
    # All sandboxes will symlink lib/ from this shared Linux-fs copy.
    linux_repo_path = None
    tmp_base = None  # track for cleanup
    try:
        if repo_path:
            try:
                tmp_base = tempfile.mkdtemp()
                repo_copy_root = os.path.join(tmp_base, Path(repo_path).name)
                print(f"[Step 6] Copying repo to Linux fs: {repo_copy_root}")
                shutil.copytree(repo_path, repo_copy_root, symlinks=False)
                print("[Step 6] Repo copy complete.")

                # Default fallback root
                foundry_root = _get_foundry_project_root(Path(repo_copy_root))
                linux_repo_path = str(foundry_root)
                if str(foundry_root) != repo_copy_root:
                    print(
                        f"[Step 6] Global Foundry project root resolved: {linux_repo_path} (will be overriden per finding if multi-repo)"
                    )
            except Exception as e:
                print(f"[Step 6] Failed to copy repo to Linux fs: {e}, falling back to original path")
                linux_repo_path = repo_path

        # ── Plausibility-based Promotion Gate (P2-I) ──────────────────────
        # Replaces the raw `confidence >= 45` hard floor.
        # Each pipeline stage has contributed to finding.plausibility_score.
        # Jury-CONFIRMED findings bypass this via _jury_confirmed=True.
        PROMOTE_THRESHOLD = int(os.getenv("PROMOTE_THRESHOLD", "50"))

        def _eligible_for_testwriter(f) -> bool:
            jury_confirmed = getattr(f, "_jury_confirmed", False)
            if jury_confirmed:
                return True  # jury CONFIRMED always gets a PoC attempt
            if f.plausibility_score >= PROMOTE_THRESHOLD:
                return True
            return False

        # BUG-7 FIX: Removed `jury_unprovable` filter — CONFIRMED_UNPROVABLE
        # findings have _jury_confirmed=True and should still get a TW attempt.
        # The TW might find a way to prove them in isolation.
        sorted_findings = sorted(
            [
                f
                for f in findings
                if _eligible_for_testwriter(f)
                and f.severity_estimate in ("CRITICAL", "HIGH", "MEDIUM")
                and _exploit_target_eligible(f, state.get("graph"))
            ],
            key=_finding_priority,
        )

        for finding in sorted_findings:
            # Permanent filter — never waste time on test helpers
            skip_list = {"balancesum", "riskycontract", "test", "mock", "dstest", "invariant", "fuzz"}
            if finding.affected_contract and any(kw in finding.affected_contract.lower() for kw in skip_list):
                print(f"  Skipping test/mock helper: {finding.affected_contract}")
                continue

            # Skip findings whose source lives in lib/ or node_modules/
            _node_data = state["graph"].nodes.get(finding.affected_contract, {}) if state.get("graph") else {}
            _src_file = (_node_data.get("source_file", "") or "").replace("\\", "/")
            if "/lib/" in _src_file or "/node_modules/" in _src_file:
                print(f"  Skipping library contract: {finding.affected_contract} ({_src_file})")
                continue

            # === FIXED: Robust relevant_code lookup (fixes BUG-001, 002, 003) ===
            relevant_code = {}

            # 1. From attack_path
            for raw_id in finding.attack_path:
                norm_id = normalize_node_id(raw_id)
                try:
                    ctx = get_function_context(state["graph"], norm_id)
                    code = ctx.get("source_code") or ctx.get("code")
                    if code:
                        relevant_code[norm_id] = code
                except Exception:
                    pass

            # 2. From evidence nodes
            for ep in finding.evidence_nodes:
                norm_id = normalize_node_id(ep.node_id)
                try:
                    ctx = get_function_context(state["graph"], norm_id)
                    code = ctx.get("source_code") or ctx.get("code")
                    if code and norm_id not in relevant_code:
                        relevant_code[norm_id] = code
                except Exception:
                    pass

            # 3. Fallback to hotspot
            if not relevant_code and finding.hotspot_node_id:
                norm_id = normalize_node_id(finding.hotspot_node_id)
                try:
                    ctx = get_function_context(state["graph"], norm_id)
                    code = ctx.get("source_code") or ctx.get("code")
                    if code:
                        relevant_code[norm_id] = code
                except Exception:
                    pass

            contract_signatures = get_contract_signatures(state["graph"], finding.affected_contract)

            # Improvement 4: Pass exploit sequence to TestWriter
            _node_data = (
                state["graph"].nodes.get(finding.hotspot_node_id, {})
                if finding.hotspot_node_id and state.get("graph")
                else {}
            )
            exploit_seq = _node_data.get("exploit_sequence", [])

            # Multi-repo fix: resolve the specific foundry.toml root for THIS finding's file
            finding_repo_path = linux_repo_path
            if _src_file and tmp_base and repo_path:
                workspace_name = Path(repo_path).name
                if workspace_name in Path(_src_file).parts:
                    try:
                        idx = Path(_src_file).parts.index(workspace_name)
                        sub_parts = Path(_src_file).parts[idx + 1 :]
                        current_check = Path(repo_copy_root)
                        best_root = (
                            current_check if (current_check / "foundry.toml").exists() else Path(linux_repo_path)
                        )
                        for part in sub_parts:
                            current_check = current_check / part
                            if (current_check / "foundry.toml").exists():
                                best_root = current_check
                        finding_repo_path = str(best_root)
                    except ValueError:
                        pass

            task = WorkerTask(
                task_id=f"test_{finding.id}",
                task_type="test_writer",
                context={
                    "finding": finding,
                    "relevant_code": relevant_code,
                    "recon_context": state.get("recon_context", {}),
                    "repo_path": finding_repo_path,  # Use the finding-specific linux repo path!
                    "contract_signatures": contract_signatures,
                    "exploit_sequence": exploit_seq,
                    "jury_brief": jury_briefs.get(finding.hotspot_node_id, {}),
                    "jury_unprovable": getattr(finding, "jury_unprovable", False),
                    "caller_context": _build_caller_context(state.get("graph"), finding.hotspot_node_id),
                },
            )
            test_tasks.append(task)
            target_findings.append(finding)

        test_outputs = []  # Initialize before conditional — avoids UnboundLocalError
        if test_tasks:
            _tw_concurrency = int(os.getenv("TEST_WRITER_CONCURRENCY", "3"))
            _tw_sem = asyncio.Semaphore(_tw_concurrency)
            print(
                f"[Step 6] Spawning TestWriter for {len(test_tasks)} finding(s) "
                f"(parallel, concurrency={_tw_concurrency}, highest confidence first)..."
            )
            test_writer_model = os.getenv("TEST_WRITER_MODEL_NAME", os.getenv("WORKER_MODEL_NAME", "grok-code-fast-1"))
            test_writer_llm = get_worker_llm(model_name=test_writer_model)
            test_writer = TestWriterWorker(llm_client=test_writer_llm, graph=state["graph"])

            async def _run_test_writer(idx, task, finding):
                async with _tw_sem:
                    print(
                        f"[Step 6] TestWriter {idx + 1}/{len(test_tasks)}: {finding.hotspot_node_id} (confidence={finding.confidence})"
                    )
                    try:
                        return await test_writer.run(task)
                    except Exception as e:
                        print(f"[Step 6] TestWriter error on {finding.hotspot_node_id}: {e}")
                        return e

            test_outputs = await asyncio.gather(
                *[
                    _run_test_writer(i, task, finding)
                    for i, (task, finding) in enumerate(zip(test_tasks, target_findings))
                ]
            )

            print(f"[Step 6] Validation sweep complete: {len(test_tasks)} attempted")
            proven = []
            for finding, output in zip(target_findings, test_outputs):
                if isinstance(output, Exception):
                    print(f"  TestWriter error on {finding.hotspot_node_id}: {output}")
                    continue

                raw_result = getattr(output, "raw_output", {}) or {}
                if not raw_result.get("exploit_success", False):
                    compiled = raw_result.get("compiled", False)
                    print(
                        f"  [x] {finding.hotspot_node_id} — PoC {'compiled but failed' if compiled else 'did not compile'}"
                    )
                    # Don't override Jury-confirmed findings to REJECTED —
                    # a failed PoC doesn't mean the vulnerability is a false positive
                    if finding.verdict != "CONFIRMED":
                        finding.status = FindingStatus.REJECTED
                    # For jury-confirmed findings, don't let a failed PoC lower confidence
                    tw_conf = getattr(output, "confidence", getattr(finding, "confidence", 0))
                    if finding.verdict == "CONFIRMED" or finding.jury_decision == "CONFIRMED":
                        finding.confidence = max(finding.confidence, tw_conf)
                    else:
                        finding.confidence = tw_conf

                    # Keep the false-positive in the list, just update status
                    # finding is passed by reference inside `findings`
                else:
                    score = getattr(output, "confidence", 100)
                    print(f"  [v] {finding.hotspot_node_id} — PROVEN (confidence {score})")
                    finding.status = FindingStatus.PROVEN
                    finding.confidence = score

                    # v2: Set evidence tag and verdict from TestWriter output
                    raw = getattr(output, "raw_output", {}) or {}
                    evidence_tag = raw.get("evidence_tag", "[POC-PASS]")
                    finding.evidence_tag = evidence_tag
                    finding.verdict = "CONFIRMED"
                    finding.confidence_evidence = score
                    if raw.get("variant_success"):
                        print(f"  [v] {finding.hotspot_node_id} — proven via VARIANT exploration")

                    if output and hasattr(output, "model_dump"):
                        proven.append(
                            {
                                "finding_id": finding.id,
                                "hotspot": finding.hotspot_node_id,
                                "confidence": finding.confidence,
                                "test_code": getattr(output, "test_code", None),
                                "test_output": getattr(output, "compiler_output", None),
                            }
                        )

                # Update leads with TestWriter results
                for lead in leads:
                    lead_id = normalize_node_id(lead.get("affected_function_node_id", ""))
                    finding_id = normalize_node_id(finding.hotspot_node_id)

                    if lead_id == finding_id:
                        raw = getattr(output, "raw_output", {}) or {}
                        lead.update(
                            {
                                "confidence": finding.confidence,
                                "test_code": raw.get("test_code"),
                                "exploit_success": raw.get("exploit_success", False),
                                "compiled": raw.get("compiled"),
                                "attempts": raw.get("attempts"),
                                "evidence_tag": raw.get("evidence_tag", ""),
                                "variant_success": raw.get("variant_success", False),
                            }
                        )
                        if raw.get("exploit_success", False) and not lead.get("title", "").startswith("[PROVEN]"):
                            lead["title"] = f"[PROVEN] {lead.get('title', '')}"
                        break

        if not test_tasks:
            print("[Step 6] No findings qualified for TestWriter.")

        if config.fuzz_generator_enabled:
            fuzz_targets = []
            fuzz_tasks = []
            for finding, output in zip(sorted_findings, test_outputs):
                if (
                    finding.status == FindingStatus.PROVEN
                    and finding.severity_estimate == "CRITICAL"
                    and not isinstance(output, Exception)
                ):
                    fuzz_targets.append(finding)
                    fuzz_tasks.append(
                        WorkerTask(
                            task_id=f"fuzz_{finding.id}",
                            task_type="fuzz_generator",
                            context={
                                "finding": finding,
                                "poc_code": getattr(output, "test_code", ""),
                                "repo_path": linux_repo_path,
                            },
                        )
                    )

            if fuzz_tasks:
                print(f"[Step 6.5] Spawning FuzzGenerator for {len(fuzz_tasks)} CRITICAL finding(s)...")
                from src.pipeline.workers.fuzz_generator import FuzzGeneratorWorker

                fuzzer_model = os.getenv(
                    "FUZZ_MODEL_NAME",
                    os.getenv("TEST_WRITER_MODEL_NAME", os.getenv("WORKER_MODEL_NAME", "grok-code-fast-1")),
                )
                fuzzer_llm = get_worker_llm(model_name=fuzzer_model)
                fuzzer = FuzzGeneratorWorker(llm_client=fuzzer_llm, graph=state["graph"])

                fuzz_outputs = await asyncio.gather(*[fuzzer.run(task) for task in fuzz_tasks], return_exceptions=True)

                for finding, output in zip(fuzz_targets, fuzz_outputs):
                    if isinstance(output, Exception):
                        print(f"  Fuzzer error on {finding.hotspot_node_id}: {output}")
                        continue

                    raw = getattr(output, "raw_output", {}) or {}
                    if raw.get("violation_found"):
                        print(f"  [!] {finding.hotspot_node_id} — INVARIANT BROKEN (Fuzzing successful)")
                        finding.confidence = getattr(output, "confidence", finding.confidence)
                        for lead in leads:
                            lead_id = normalize_node_id(lead.get("affected_function_node_id", ""))
                            if lead_id == normalize_node_id(finding.hotspot_node_id):
                                lead["fuzz_code"] = raw.get("fuzz_code")
                                lead["fuzz_logs"] = raw.get("logs")
                                if not lead.get("title", "").endswith("[FUZZED]"):
                                    lead["title"] = f"{lead.get('title', '')} [FUZZED]"
                                break

    finally:
        # Cleanup shared Linux-fs repo copy — always runs even on exception
        if tmp_base and os.path.exists(tmp_base):
            try:
                shutil.rmtree(tmp_base)
            except Exception:
                pass

    proven_count = sum(1 for f in findings if f.status == FindingStatus.PROVEN)
    print(f"[Pipeline] All steps complete: {len(findings)} finding(s), {proven_count} proven, {len(leads)} lead(s)")

    state["findings"] = findings
    # LOGIC-003 fix: escalate only when should_escalate_to_human() says so,
    # not when ANY finding exists (a proven exploit doesn't need human triage).
    state["escalate"] = escalation

    # ── Phase 7: Generate Report & Visualization ───────────────
    # Collect token usage for the report
    token_usage = None
    try:
        from src.utils.token_counter import get_token_counter

        token_usage = get_token_counter().get_summary()
        total = token_usage.get("total", {})
        print(
            f"[TokenCounter] Total: {total.get('call_count', 0)} calls, "
            f"{total.get('total_tokens', 0)} tokens, "
            f"${total.get('estimated_cost_usd', 0):.4f} est. cost"
        )
    except Exception:
        pass

    try:
        from src.reporting.report_generator import ReportGenerator

        reporter = ReportGenerator(
            repo_url=state.get("repo_url", ""),
            repo_name=repo_name or "unknown",
            findings=findings,
            leads=leads,
            graph=state["graph"],
            token_usage=token_usage,
            jury_rejected=state.get("jury_rejected_findings", []),
        )
        report_paths = reporter.generate()
        print(f"\n{'=' * 60}")
        print(f"  Report:     {report_paths['report_html']}")
        print(f"  Graph:      {report_paths['graph_html']}")
        print(f"  Exploits:   {report_paths['exploits_dir']}")
        print(f"{'=' * 60}\n")
    except Exception as e:
        print(f"[Reporter] Warning: report generation failed: {e}")

    return {
        "vulnerability_leads": leads,
        "target_nodes": target_nodes,
        "strategy": strategy,
        "messages": [response],
        "findings": findings,
        "worker_outputs": worker_outputs,
        "recon_context": recon_context,  # LOGIC-004 fix: include so LangGraph state is updated
        "escalate": state["escalate"],
        "jury_rejected_findings": state.get("jury_rejected_findings", []),
    }


import warnings


async def lead_researcher_node(state: AgentState):
    """DEPRECATED ALIAS — use coordinator_node() directly."""
    warnings.warn("lead_researcher_node is a deprecated alias for coordinator_node.", DeprecationWarning, stacklevel=2)
    return await coordinator_node(state)
