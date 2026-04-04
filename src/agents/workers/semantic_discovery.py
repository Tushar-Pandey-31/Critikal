"""
Semantic Discovery — LLM-native vulnerability discovery agents.

These agents read raw source files directly, with NO dependency on Slither
graph signals. They discover bugs from first principles by reasoning about
protocol invariants, economic attack surfaces, and trust boundaries.

Activated when SEMANTIC_DISCOVERY_ENABLED=true.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import glob
from typing import Any

from src.agents.base_worker import WorkerAgent, WorkerTask, WorkerOutput

logger = logging.getLogger(__name__)

SEMANTIC_LLM_TIMEOUT = int(os.getenv("SEMANTIC_LLM_TIMEOUT", "300"))


# ── InvariantHunter System Prompt ────────────────────────────────

INVARIANT_HUNTER_SYSTEM_PROMPT = """\
You are an elite smart contract security researcher. Your specialty is finding
protocol invariant violations — bugs where the contract's internal accounting
or state becomes inconsistent in a way that can be exploited.

## Methodology

### Step 1: Derive Invariants
Read the entire contract source code and derive what invariants MUST always hold.
Format each as: "In [Contract], [variable/relationship] must always [condition]."

Common invariant classes:
- Balance: totalSupply == sum(balances[user]) for all users
- Share/asset consistency: converting shares→assets→shares gives same result
- Monotonicity: accumulator variables can only increase
- Conservation: tokens in == tokens out (no creation/destruction without explicit mint/burn)
- Access: only specific role can change critical state
- Ordering: state A must be updated before state B is read
- CEI compliance: state is consistent BEFORE any external call (this IS an invariant)
- Accounting completeness: totalAssets/totalDebt/totalSupply iterates ALL relevant positions without gaps
- Queue integrity: if a function tracks items in a list/queue, every item in reality must be in the list

### Step 2: Check Every Function
For each invariant, find every function that could violate it.
Check: is the invariant re-established BEFORE the function returns on ALL paths?
Pay special attention to:
- Functions that modify a tracking list/queue — does the data structure stay consistent with reality?
- Functions that compute aggregates (totalAssets, totalSupply, totalDebt) — is every element counted?
- Functions that allow partial removal of tracked items while leaving underlying positions
- External calls that could change state the function assumes is stable

### Step 3: Accounting Scope Analysis (catches queue-gap class bugs)
For any function that computes an aggregate value from a collection:
- What COLLECTION does it iterate? (withdrawQueue, markets[], positions[], allocations[])
- What INVARIANT must hold between that collection and reality?
  ("queue must contain ALL markets with allocated assets")
- Is there any function that removes an item from the collection WITHOUT ensuring the invariant?
- Specifically: can items be removed from the tracked set while the underlying asset position remains?
- If yes: any call that reads the aggregate will underreport, enabling share price manipulation.

### Step 4: Threat Actor Analysis
For each invariant violation found, ask:
- Can an UNPRIVILEGED external attacker trigger this?
- Can a SEMI-TRUSTED ROLE (allocator, keeper, operator, guardian, strategist) trigger this?
  → This is a VALID and HIGH-SEVERITY finding. Do NOT downgrade because of role requirement.
- Does the violation enable asset extraction even if triggered by a permissioned function?

### Step 5: Construct Attack
For violations found, build a minimal attacker-controlled call sequence that breaks the invariant
and extracts value. Be explicit about which actor calls which function in what order.

## CRITICAL RULES
- Derive invariants from THIS code. Do not just list generic vulnerability names.
- CEI (Checks-Effects-Interactions) compliance IS an invariant. Include violations.
- Every claim must reference a specific function and line context.
- Semi-trusted role findings are HIGH/CRITICAL priority. Do NOT downgrade because of role requirement.
- If you find nothing, return an empty findings list. Do NOT hallucinate.

## Output Format
Return ONLY valid JSON:
{
  "invariants_derived": [
    {"invariant": "description", "contract": "name", "variables": ["var1", "var2"]}
  ],
  "findings": [
    {
      "vulnerability_class": "invariant_violation | accounting_mismatch | orphaned_assets | queue_inconsistency | cei_violation | economic_attack | logic_inversion",
      "affected_contract": "ContractName",
      "affected_function": "functionName",
      "hypothesis": "detailed explanation of the bug",
      "attack_path": ["ContractName::functionName as threat actor", "ContractName::vulnerableFunction"],
      "threat_actor": "unprivileged | semi_trusted_role | privileged",
      "confidence": <integer 0-100>,
      "severity_estimate": "CRITICAL | HIGH | MEDIUM | LOW",
      "invariant_violated": "which invariant from step 1",
      "evidence": "specific code reference proving the violation"
    }
  ]
}
"""


class InvariantHunterWorker(WorkerAgent):
    """
    Derives protocol invariants from source code, then checks every function
    against them. No graph signals required — pure LLM reasoning.

    Produces WorkerOutput objects compatible with the existing finding pipeline.
    """

    model_name: str = "gemini-2.5-flash"

    def __init__(self, llm_client: Any, model_name: str = "gemini-2.5-flash"):
        self.llm = llm_client
        self.model_name = model_name

    def get_worker_type(self) -> str:
        return "invariant_hunter"

    async def run(self, task: WorkerTask) -> WorkerOutput:
        """
        Run invariant hunting on provided source files.

        task.context should contain:
            sol_files: list[str]  — absolute paths to .sol files
            recon_context: dict   — protocol type info from ReconWorker
        """
        sol_files = task.context.get("sol_files", [])
        recon_context = task.context.get("recon_context", {})

        if not sol_files:
            return WorkerOutput(
                worker_type=self.get_worker_type(),
                task_id=task.task_id,
                hypothesis="No source files provided for semantic analysis.",
                confidence=0,
            )

        # Read source files (cap at ~30k chars to stay within context window)
        source_text = self._read_source_files(sol_files, max_chars=30000)

        # Build prompt
        protocol_type = recon_context.get("protocol_type", "unknown")
        user_content = self._build_prompt(source_text, protocol_type)

        messages = [
            {"role": "system", "content": INVARIANT_HUNTER_SYSTEM_PROMPT},
            {"role": "user", "content": user_content},
        ]

        try:
            response = await asyncio.wait_for(
                self.llm.ainvoke(messages),
                timeout=SEMANTIC_LLM_TIMEOUT,
            )
            content = response.content if hasattr(response, "content") else str(response)
            if isinstance(content, list):
                content = "".join(
                    c.get("text", "") if isinstance(c, dict) else str(c) for c in content
                )

            # Track tokens
            try:
                from src.utils.token_counter import get_token_counter
                input_text = "\n".join(
                    m.get("content", "") if isinstance(m, dict) else str(m)
                    for m in messages
                )
                get_token_counter().record(
                    "InvariantHunter",
                    self.model_name,
                    input_text,
                    str(content),
                    getattr(response, "response_metadata", None),
                )
            except Exception:
                pass

            return self._parse_response(content, task.task_id)

        except asyncio.TimeoutError:
            logger.warning("[InvariantHunter] LLM timed out")
            return WorkerOutput(
                worker_type=self.get_worker_type(),
                task_id=task.task_id,
                hypothesis="InvariantHunter timed out during analysis.",
                confidence=0,
            )
        except Exception as e:
            logger.warning(f"[InvariantHunter] Error: {e}")
            return WorkerOutput(
                worker_type=self.get_worker_type(),
                task_id=task.task_id,
                hypothesis=f"InvariantHunter error: {str(e)[:200]}",
                confidence=0,
            )

    def _read_source_files(self, sol_files: list[str], max_chars: int = 30000) -> str:
        """Read and concatenate source files up to max_chars."""
        parts = []
        total = 0
        for path in sol_files:
            try:
                with open(path, "r", encoding="utf-8", errors="replace") as f:
                    content = f.read()
                header = f"\n// ══════ FILE: {os.path.basename(path)} ══════\n"
                if total + len(content) + len(header) > max_chars:
                    remaining = max_chars - total - len(header)
                    if remaining > 500:
                        parts.append(header + content[:remaining] + "\n// ... truncated ...")
                    break
                parts.append(header + content)
                total += len(content) + len(header)
            except Exception as e:
                logger.debug(f"[InvariantHunter] Could not read {path}: {e}")
        return "\n".join(parts)

    def _build_prompt(self, source_text: str, protocol_type: str) -> str:
        return f"""## Protocol Context
Protocol type: {protocol_type}

## Source Code (all in-scope contracts)
```solidity
{source_text}
```

Analyze the above contracts. Derive invariants, check them, and report violations as JSON."""

    def _parse_response(self, raw: str, task_id: str) -> WorkerOutput:
        """Parse LLM JSON response into WorkerOutput."""
        try:
            cleaned = raw.strip()
            if cleaned.startswith("```"):
                lines = cleaned.split("\n")
                cleaned = "\n".join(lines[1:-1]).strip()

            parsed = json.loads(cleaned)
            findings_list = parsed.get("findings", [])

            if not findings_list:
                return WorkerOutput(
                    worker_type=self.get_worker_type(),
                    task_id=task_id,
                    hypothesis="No invariant violations found by semantic analysis.",
                    confidence=0,
                    raw_output=parsed,
                )

            # Return the highest-confidence finding as the primary output.
            # Additional findings are in raw_output for downstream consumption.
            best = max(findings_list, key=lambda f: f.get("confidence", 0))

            return WorkerOutput(
                worker_type=self.get_worker_type(),
                task_id=task_id,
                hypothesis=best.get("hypothesis", ""),
                confidence=min(100, max(0, int(best.get("confidence", 50)))),
                attack_path=best.get("attack_path", []),
                raw_output={
                    "invariants_derived": parsed.get("invariants_derived", []),
                    "all_findings": findings_list,
                    "best_finding": best,
                    "vulnerability_class": best.get("vulnerability_class", "invariant_violation"),
                    "affected_contract": best.get("affected_contract", ""),
                    "affected_function": best.get("affected_function", ""),
                },
            )
        except Exception as e:
            logger.warning(f"[InvariantHunter] Parse error: {e}")
            return WorkerOutput(
                worker_type=self.get_worker_type(),
                task_id=task_id,
                hypothesis=f"InvariantHunter parse error: {str(e)[:200]}",
                confidence=0,
            )


# ── Orchestrator ─────────────────────────────────────────────────

def _collect_sol_files(repo_path: str, max_files: int = 50) -> list[str]:
    """Collect .sol files from a repo, excluding tests/mocks/libs."""
    exclude_dirs = {"test", "tests", "mock", "mocks", "lib", "node_modules",
                    "script", "scripts", "echidna", "fuzz", "fuzzing"}

    sol_files = glob.glob(os.path.join(repo_path, "**", "*.sol"), recursive=True)
    filtered = []
    for f in sol_files:
        parts = f.replace("\\", "/").split("/")
        if any(p.lower() in exclude_dirs for p in parts):
            continue
        filtered.append(f)

    # Sort by file size (larger = more interesting) and cap
    filtered.sort(key=lambda f: os.path.getsize(f), reverse=True)
    return filtered[:max_files]


async def run_semantic_discovery(
    repo_path: str,
    llm_client: Any,
    model_name: str = "gemini-2.5-flash",
    recon_context: dict | None = None,
) -> list[WorkerOutput]:
    """
    Entry point for semantic discovery. Called by coordinator_node when
    SEMANTIC_DISCOVERY_ENABLED=true.

    Runs four parallel agents, each specializing in a different 0-day class:
    1. InvariantHunterWorker — protocol invariant violations
    2. EconomicAttackerWorker — flash loan / sandwich / price manipulation
    3. TrustBoundaryAnalyzer — privilege escalation / proxy abuse
    4. CrossContractStateChecker — cross-contract reentrancy / stale state

    Returns list of WorkerOutput objects (one per agent that found something).
    """
    sol_files = _collect_sol_files(repo_path)
    if not sol_files:
        print("[Semantic] No .sol files found in repo — skipping semantic discovery")
        return []

    print(f"[Semantic] Found {len(sol_files)} .sol file(s) for semantic analysis")

    context = {
        "sol_files": sol_files,
        "recon_context": recon_context or {},
    }

    # Instantiate all agents
    hunter = InvariantHunterWorker(llm_client=llm_client, model_name=model_name)

    from src.agents.workers.economic_attacker import EconomicAttackerWorker
    from src.agents.workers.trust_boundary import TrustBoundaryAnalyzer
    from src.agents.workers.cross_contract import CrossContractStateChecker

    economic = EconomicAttackerWorker(llm_client=llm_client, model_name=model_name)
    trust = TrustBoundaryAnalyzer(llm_client=llm_client, model_name=model_name)
    cross = CrossContractStateChecker(llm_client=llm_client, model_name=model_name)

    # Build tasks
    tasks = [
        ("InvariantHunter", hunter, WorkerTask(
            task_id="semantic_invariant_hunt",
            task_type="semantic_discovery",
            context=context,
        )),
        ("EconomicAttacker", economic, WorkerTask(
            task_id="semantic_economic_attack",
            task_type="semantic_discovery",
            context=context,
        )),
        ("TrustBoundary", trust, WorkerTask(
            task_id="semantic_trust_boundary",
            task_type="semantic_discovery",
            context=context,
        )),
        ("CrossContract", cross, WorkerTask(
            task_id="semantic_cross_contract",
            task_type="semantic_discovery",
            context=context,
        )),
    ]

    print(f"[Semantic] Launching {len(tasks)} semantic agent(s) in parallel...")

    async def _run_agent(name: str, agent, task):
        try:
            result = await asyncio.wait_for(agent.run(task), timeout=SEMANTIC_LLM_TIMEOUT + 30)
            print(f"[Semantic] {name} complete: confidence={result.confidence}")
            return result
        except asyncio.TimeoutError:
            print(f"[Semantic] {name} timed out")
            return None
        except Exception as e:
            print(f"[Semantic] {name} error: {e}")
            return None

    results = await asyncio.gather(
        *[_run_agent(name, agent, task) for name, agent, task in tasks],
        return_exceptions=True,
    )

    outputs = []
    for result in results:
        if isinstance(result, Exception) or result is None:
            continue
        if isinstance(result, WorkerOutput) and result.confidence > 0:
            outputs.append(result)

    print(f"[Semantic] Total findings across all agents: {len(outputs)}")
    return outputs
