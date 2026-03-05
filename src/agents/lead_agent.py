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
import logging
import json
import shutil
import tempfile
from datetime import datetime
from typing import List, Any, Optional
import uuid
from dotenv import load_dotenv
from pathlib import Path

load_dotenv()

logger = logging.getLogger(__name__)
from langchain_core.messages import SystemMessage, HumanMessage
from src.agents.state import AgentState
from src.agents.base_worker import WorkerOutput, WorkerTask
from src.agents.workers.recon_worker import ReconWorker
from src.agents.workers.attack_hypothesis_worker import AttackHypothesisWorker
from src.agents.workers.test_writer_worker import TestWriterWorker
from src.models.finding import Finding, FindingStatus
from src.utils.graph_queries import get_high_risk_hotspots, get_function_context, get_contract_signatures
from src.utils.node_ids import normalize_node_id
from src.tools.etherscan_client import EtherscanClient
import asyncio

try:
    from langchain_google_genai import ChatGoogleGenerativeAI
except ImportError:
    ChatGoogleGenerativeAI = None


def _finding_priority(f: Finding) -> tuple:
    """Sort key: highest confidence first, tie-break by severity (CRITICAL > HIGH > MEDIUM > LOW)."""
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    return (-f.confidence, sev_order.get(f.severity_estimate, 4))

# BUG-009 fix: deduplicated — shared with test_writer_sandbox.py
from src.utils.foundry_root import resolve_foundry_root as _get_foundry_project_root


def _exploit_target_eligible(finding: Finding, graph) -> bool:
    """Check if the finding's target is eligible for an exploit test."""
    if not graph:
        return True # fail open
    target = finding.hotspot_node_id
    if not target or not graph.has_node(target):
         return True # fail open
    
    data = graph.nodes[target]
    # Drop external view functions, interface placeholders, and internal functions
    if data.get("is_view") or data.get("is_pure"):
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

_TOOLS: List[Any] = []


def _repo_name_from_url(repo_url: str) -> str:
    if not repo_url:
        return ""
    repo_name = repo_url.rstrip("/").split("/")[-1]
    if repo_name.endswith(".git"):
        repo_name = repo_name[:-4] # Pyre doesn't like str slicing here for some reason, ignore
    return repo_name


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
        logger.info("WARNING: GOOGLE_API_KEY not found in environment.")
    llm = ChatGoogleGenerativeAI(model=model_name, temperature=temperature)
    logger.info(f"[get_llm] Created LLM: {llm.model} (bind_tools={bind_tools})")
    if bind_tools and _TOOLS:
        return llm.bind_tools(_TOOLS)
    return llm


def _detect_provider(model_name: str) -> str:
    """Detect LLM provider from model name string."""
    m = model_name.lower()
    if m.startswith("gemini") or m.startswith("models/gemini"):
        return "gemini"
    if m.startswith("gpt") or m.startswith("o1") or m.startswith("o3"):
        return "openai"
    if m.startswith("claude"):
        return "anthropic"
    return "gemini"  # default


def get_worker_llm(
    model_name: str = os.getenv("WORKER_MODEL_NAME", os.getenv("MODEL_NAME", "gemini-2.5-flash")),
    temperature: float = 0.0,
):
    """
    Returns a rate-limited LLM with NO tools bound.
    Workers MUST use this. Never pass coordinator_llm to workers.

    The returned object is a RateLimitedLLM wrapper that transparently
    handles RPM throttling and API key rotation.
    """
    if not ChatGoogleGenerativeAI:
        raise ImportError("langchain-google-genai is not installed.")

    from src.utils.rate_limiter import get_rate_limiter, RateLimitedLLM
    from src.utils.key_pool import get_key_pool

    timeout = float(os.getenv("WORKER_LLM_TIMEOUT", "180"))
    max_retries = int(os.getenv("WORKER_LLM_MAX_RETRIES", "0"))
    transport = os.getenv("WORKER_LLM_TRANSPORT", "rest")
    provider = _detect_provider(model_name)
    key_pool = get_key_pool()

    # Get the next available API key from the pool
    try:
        api_key = key_pool.get_key(provider)
    except ValueError:
        # No keys in pool — fall back to default env var behavior
        api_key = None

    kwargs: dict[str, Any] = {
        "model": model_name,
        "temperature": temperature,
        "timeout": timeout,
        "request_timeout": timeout,
        "max_retries": max_retries,
        "transport": transport,
    }
    if api_key:
        kwargs["google_api_key"] = api_key

    llm = ChatGoogleGenerativeAI(**kwargs)

    # Wrap with rate limiter
    limiter = get_rate_limiter()
    wrapped = RateLimitedLLM(
        llm=llm,
        limiter=limiter,
        key_pool=key_pool,
        provider=provider,
        model_name=model_name,
    )
    if api_key:
        wrapped.set_key(api_key)

    logger.info(
        f"[get_worker_llm] Created rate-limited worker LLM: {model_name} "
        f"(provider={provider}, timeout={timeout}s, transport={transport}, "
        f"key=...{api_key[-4:] if api_key else 'default'})"
    )
    return wrapped


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
        # LOGIC-006 fix: use the hotspot function node_id as dedup key.
        # evidence_node_ids is almost always empty (attack workers don't populate it),
        # so falling back to task_id made dedup useless.
        raw = wo_dict.get("raw_output", {})
        func_key = f"{raw.get('affected_contract', '')}::{raw.get('affected_function', '')}"
        key = "|".join(sorted(evidence)) if evidence else (func_key if func_key != "::" else wo_dict.get("task_id", f"__worker_{i}"))

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
    worker_llm = get_worker_llm()

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
    repo_url = state.get("repo_url", "")
    repo_name = _repo_name_from_url(repo_url)
    repo_path = None
    if repo_name:
        candidate = Path("data/scratch") / repo_name
        if candidate.exists():
            repo_path = str(candidate)
            print(f"[Step 1] Recon complete. Repo path: {repo_path}")

    recon_context = recon_output.raw_output
    # BUG-008 fix: don't directly mutate state["recon_context"] here.
    # It's now returned via the return dict at the end of the function (LOGIC-004).

    if recon_context.get("onchain_risk_signals", {}).get("previous_exploits_detected"):
        print("[Step 1] Prior exploit detected by Recon. Escalating priority.")

    # ── Step 2: Hotspots ───────────────────────────────────
    hotspots = get_high_risk_hotspots(state["graph"], min_score=70)
    print(f"[Step 2] Found {len(hotspots)} high-risk hotspot(s)")
    findings = []

    if not hotspots:
        print("[Step 2] No hotspots above threshold — skipping attack workers")
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
        print(f"[Step 3] Launching {len(tasks)} attack worker(s) in parallel (timeout=300s each)...")
        for t in tasks:
            print(f"  - {t.task_id}")

        _attack_concurrency = int(os.getenv("ATTACK_WORKER_CONCURRENCY", "15"))
        _attack_sem = asyncio.Semaphore(_attack_concurrency)

        async def _run_with_timeout(task, timeout=300):
            async with _attack_sem:
                try:
                    return await asyncio.wait_for(attack_worker.run(task), timeout=timeout)
                except asyncio.TimeoutError:
                    print(f"  TIMEOUT: {task.task_id} (>{timeout}s)")
                    return None

        worker_outputs_parallel = await asyncio.gather(
            *[_run_with_timeout(task) for task in tasks],
            return_exceptions=True
        )

        print(f"[Step 3] Attack workers complete: {len(worker_outputs_parallel)} result(s)")
        for i, o in enumerate(worker_outputs_parallel):
            if isinstance(o, Exception):
                print(f"  [{i}] EXCEPTION: {o}")
            elif o is None:
                print(f"  [{i}] TIMEOUT (no result)")
            else:
                o_conf = getattr(o, "confidence", 0)
                o_hyp = str(getattr(o, "hypothesis", "")) or None
                print(f"  [{i}] confidence={o_conf} hypothesis={o_hyp}")

        # ── Step 4: Build Findings ─────────────────────────
        for output, hotspot in zip(worker_outputs_parallel, hotspots):
            if output is None or isinstance(output, Exception):
                print(f"  Skipping {hotspot.node_id} — no output")
                continue
            
            out_conf = getattr(output, "confidence", 0)
            if out_conf > 0:
                finding = Finding.from_worker_output(output, hotspot)
                findings.append(finding)

            if not isinstance(output, Exception):
                model_dump_func = getattr(output, "model_dump", None)
                wo_dict = model_dump_func() if callable(model_dump_func) else output
                worker_outputs.append(wo_dict)

        print(f"[Step 4] Findings that passed filter: {len(findings)}")

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
        hotspot_summary = f"\n\n=== HOTSPOT DATA (from programmatic analysis) ===\n"
        hotspot_summary += f"Found {len(hotspots)} high-risk function(s):\n"
        for h in hotspots[:15]:
            hotspot_summary += (
                f"  - {h.node_id} | final={h.risk_score} "
                f"struct={h.structural_score} exploit={h.exploitability_score} "
                f"impact={h.impact_score} | priority={h.priority}\n"
            )

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
            _model = os.getenv("MODEL_NAME", "gemini-2.5-flash")
            _input_text = "\n".join(
                m.content if hasattr(m, "content") else str(m) for m in prompt
            )
            _resp_content = response.content if hasattr(response, "content") else str(response)
            if isinstance(_resp_content, list):
                _resp_content = "".join([c.get("text", "") if isinstance(c, dict) else str(c) for c in _resp_content])
            get_token_counter().record(
                "CoordinatorSynthesis", _model,
                _input_text, str(_resp_content),
                getattr(response, "response_metadata", None),
            )
        except Exception:
            pass  # Never let tracking break the pipeline

    except asyncio.TimeoutError:
        print(f"[Step 5] WARNING: Coordinator LLM timed out after {SYNTHESIS_TIMEOUT}s — using worker outputs directly")
        response = None
    except Exception as e:
        print(f"[Step 5] WARNING: Coordinator LLM failed: {e} — using worker outputs directly")
        response = None

    # With tools disabled, the LLM should never make tool_calls.
    # If it does, strip them to prevent LangGraph routing to ToolNode
    # which would re-run the entire pipeline (BUG-012).
    if response and getattr(response, "tool_calls", None):
        logger.warning(
            "Coordinator LLM returned tool_calls despite bind_tools=False — stripping"
        )
        setattr(response, "tool_calls", [])
        if hasattr(response, "additional_kwargs"):
            getattr(response, "additional_kwargs", {}).pop("tool_calls", None)

    # ── Parse final response ───────────────────────────────
    leads = []
    target_nodes = []
    strategy = ""
    escalation = False
    if response is None:
        print("[Step 5] No LLM response — falling back to worker synthesis")
        leads = synthesize_worker_outputs(worker_outputs) if worker_outputs else []
        strategy = "LLM synthesis skipped (timeout or error)"
        # Build a dummy response for the return dict
        from langchain_core.messages import AIMessage
        response = AIMessage(content=json.dumps({
            "analysis_summary": {"strategy": strategy},
            "vulnerability_leads": leads,
        }))
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
            leads = synthesize_worker_outputs(worker_outputs) if worker_outputs else []
            strategy = "Failed to parse LLM response"

    # ── Step 5b: DISABLED (Epic 2, Story 2.1) ───────────────
    # Synthetic finding creation from LLM leads has been removed.
    # Only Attack Workers (Step 3→4) can produce findings, ensuring
    # every finding is grounded in a graph hotspot — the LLM cannot
    # invent vulnerabilities without structural evidence.
    if not findings and leads:
        print(f"[Step 5b] {len(leads)} LLM lead(s) present but synthetic fallback is disabled. "
              f"Only Attack Worker findings are accepted.")

    # ── Step 6: TestWriter ─────────────────────────────────
    print(f"[Step 6] Preparing TestWriter: {len(findings)} finding(s) to process")
    test_tasks = []
    target_findings = []

    # ── Copy repo to Linux fs ONCE before spawning all TestWriters ──
    # This avoids N parallel copies of the repo (one per finding).
    # All sandboxes will symlink lib/ from this shared Linux-fs copy.
    linux_repo_path = None
    tmp_base = None  # track for cleanup
    if repo_path:
        try:
            tmp_base = tempfile.mkdtemp()
            repo_copy_root = os.path.join(tmp_base, Path(repo_path).name)
            print(f"[Step 6] Copying repo to Linux fs: {repo_copy_root}")
            shutil.copytree(repo_path, repo_copy_root, symlinks=False)
            print(f"[Step 6] Repo copy complete.")

            # KEY FIX: resolve the actual Foundry project root within the copy.
            # Many repos have foundry.toml in a subdirectory (e.g. ethernaut/contracts/).
            # Passing the repo root causes SandboxManager to look for lib/ in the wrong place.
            foundry_root = _get_foundry_project_root(Path(repo_copy_root))
            linux_repo_path = str(foundry_root)
            if str(foundry_root) != repo_copy_root:
                print(f"[Step 6] Foundry project root resolved: {linux_repo_path}")
        except Exception as e:
            print(f"[Step 6] Failed to copy repo to Linux fs: {e}, falling back to original path")
            linux_repo_path = repo_path

    # Sort findings by confidence descending; tie-break by severity (highest first)
    sorted_findings = sorted(
        [f for f in findings if f.confidence >= 65 and f.severity_estimate in ("CRITICAL", "HIGH", "MEDIUM") and _exploit_target_eligible(f, state.get("graph"))],
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
        _node_data = state["graph"].nodes.get(finding.hotspot_node_id, {}) if finding.hotspot_node_id and state.get("graph") else {}
        exploit_seq = _node_data.get("exploit_sequence", [])

        task = WorkerTask(
            task_id=f"test_{finding.id}",
            task_type="test_writer",
            context={
                "finding": finding,
                "relevant_code": relevant_code,
                "recon_context": state.get("recon_context", {}),
                "repo_path": linux_repo_path,  # shared Linux-fs copy
                "contract_signatures": contract_signatures,
                "exploit_sequence": exploit_seq,
            }
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
        test_writer_model = os.getenv("TEST_WRITER_MODEL_NAME", os.getenv("WORKER_MODEL_NAME", "gemini-2.5-flash"))
        test_writer_llm = get_worker_llm(model_name=test_writer_model)
        test_writer = TestWriterWorker(llm_client=test_writer_llm, graph=state["graph"])

        async def _run_test_writer(idx, task, finding):
            async with _tw_sem:
                print(f"[Step 6] TestWriter {idx+1}/{len(test_tasks)}: {finding.hotspot_node_id} (confidence={finding.confidence})")
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
        for finding, output in zip(sorted_findings, test_outputs):
            if isinstance(output, Exception):
                print(f"  TestWriter error on {finding.hotspot_node_id}: {output}")
                continue

            if not getattr(output, "validation_passed", False):
                print(f"  [x] {finding.hotspot_node_id} — Validation FAILED")
                finding.status = FindingStatus.REJECTED
                setattr(finding, "confidence", getattr(output, "confidence", getattr(finding, "confidence", 0)))
                
                # Keep the false-positive in the list, just update status
                # finding is passed by reference inside `findings`
            else:
                score = getattr(output, "confidence", 100)
                print(f"  [v] {finding.hotspot_node_id} — PROVEN (confidence {score})")
                finding.status = FindingStatus.PROVEN
                setattr(finding, "confidence", score)
                
                if output and hasattr(output, "model_dump"):
                    proven.append({
                        "finding_id": finding.id,
                        "hotspot": finding.hotspot_node_id,
                        "confidence": finding.confidence,
                        "test_code": getattr(output, "test_code", None),
                        "test_output": getattr(output, "compiler_output", None)
                    })
            
            # Update leads with TestWriter results
            for lead in leads:
                lead_id = normalize_node_id(lead.get("affected_function_node_id", ""))
                finding_id = normalize_node_id(finding.hotspot_node_id)

                if lead_id == finding_id:
                    raw = getattr(output, "raw_output", {}) or {} # Use getattr for raw_output
                    lead.update({
                        "confidence": finding.confidence,
                        "test_code": getattr(output, "test_code", None), # Use getattr
                        "exploit_success": getattr(output, "exploit_success", False), # Use getattr
                        "compiled": raw.get("compiled"),
                        "attempts": raw.get("attempts"),
                    })
                    if getattr(output, "exploit_success", False) and not lead.get("title", "").startswith("[PROVEN]"): # Use getattr
                        lead["title"] = f"[PROVEN] {lead.get('title', '')}"
                    break

    if not test_tasks:
        print(f"[Step 6] No findings qualified for TestWriter.")

    # ── Step 6.5: Fuzz Generator (Medusa Layer) ───────────────
    fuzz_targets = []
    fuzz_tasks = []
    for finding, output in zip(sorted_findings, test_outputs):
        if finding.status == FindingStatus.PROVEN and finding.severity_estimate == "CRITICAL" and not isinstance(output, Exception):
            fuzz_targets.append(finding)
            fuzz_tasks.append(
                WorkerTask(
                    task_id=f"fuzz_{finding.id}",
                    task_type="fuzz_generator",
                    context={
                        "finding": finding,
                        "poc_code": getattr(output, "test_code", ""),
                        "repo_path": linux_repo_path,
                    }
                )
            )
            
    if fuzz_tasks:
        print(f"[Step 6.5] Spawning FuzzGenerator for {len(fuzz_tasks)} CRITICAL finding(s)...")
        from src.agents.workers.fuzz_generator import FuzzGeneratorWorker
        fuzzer_model = os.getenv("TEST_WRITER_MODEL_NAME", os.getenv("WORKER_MODEL_NAME", "gemini-2.5-flash"))
        fuzzer_llm = get_worker_llm(model_name=fuzzer_model)
        fuzzer = FuzzGeneratorWorker(llm_client=fuzzer_llm, graph=state["graph"])
        
        fuzz_outputs = await asyncio.gather(
            *[fuzzer.run(task) for task in fuzz_tasks],
            return_exceptions=True
        )
        
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

    # Cleanup shared Linux-fs repo copy
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
        print(f"[TokenCounter] Total: {total.get('call_count', 0)} calls, "
              f"{total.get('total_tokens', 0)} tokens, "
              f"${total.get('estimated_cost_usd', 0):.4f} est. cost")
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
        )
        report_paths = reporter.generate()
        print(f"\n{'='*60}")
        print(f"  Report:     {report_paths['report_html']}")
        print(f"  Graph:      {report_paths['graph_html']}")
        print(f"  Exploits:   {report_paths['exploits_dir']}")
        print(f"{'='*60}\n")
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