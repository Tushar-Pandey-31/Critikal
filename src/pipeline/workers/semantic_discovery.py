"""
Semantic Discovery — LLM-native vulnerability discovery agents.

These agents read raw source files directly, with NO dependency on Slither
graph signals. They discover bugs from first principles by reasoning about
protocol invariants, economic attack surfaces, and trust boundaries.

Activated when SEMANTIC_DISCOVERY_ENABLED=true.
"""

from __future__ import annotations

import asyncio
import glob
import json
import logging
import os
from typing import Any

from src.pipeline.base_worker import WorkerAgent, WorkerOutput, WorkerTask

logger = logging.getLogger(__name__)

SEMANTIC_LLM_TIMEOUT = int(os.getenv("SEMANTIC_LLM_TIMEOUT", "300"))


# ── InvariantHunter System Prompt ────────────────────────────────

INVARIANT_HUNTER_SYSTEM_PROMPT = """\
You are an attacker that breaks conservation laws. Every protocol has rules that must
ALWAYS hold — balances that must sum, ratios that must be consistent, states that must
be coupled. Find the path that breaks these rules and extract value from the break.

Other agents cover permissions, economics, and cross-contract interactions.
You break the protocol's own internal consistency.

## Methodology

### Step 1 — Map Every Conservation Law
Read the entire contract and derive what MUST always hold:
- **Balance conservation**: totalSupply == sum(balances[user]) for all users
- **Share/asset round-trip**: converting shares→assets→shares gives the same result (within 1 wei)
- **Monotonicity**: accumulator variables (totalDeposited, rewardIndex) can only increase
- **Token conservation**: tokens in == tokens out (no creation/destruction except mint/burn)
- **Ordering invariant**: state A is always updated before state B is read
- **Completeness**: totalAssets/totalDebt iterates ALL relevant positions without gaps
- **Queue integrity**: every item in reality is tracked in the data structure
- **State coupling**: if variable A changes, variable B MUST also change in the same tx

For each invariant, write: "In [Contract], [relationship] must always hold."

### Step 2 — Break Round-Trips
For every pair of inverse operations (deposit/withdraw, mint/redeem, stake/unstake):
- Does `deposit(X) → withdraw(all)` return exactly X? Test with 1 wei, max uint, first/last.
- Does `mint(shares) → redeem(shares)` return the same assets? At different exchange rates?
- If the round-trip is profitable → CRITICAL. If there's leakage → HIGH.

### Step 3 — Exploit Path Divergence
Find multiple routes to the same outcome that produce different states:
- `deposit()` vs `mint()` — do they arrive at the same share balance?
- Direct transfer + `sync()` vs `deposit()` — does accounting match?
- Normal flow vs error-recovery flow — is cleanup symmetric with setup?
Take the profitable path.

### Step 4 — The Function Family Comparison Test
For every pair of functions that do SIMILAR things:
1. List all state changes in function A (deposit/place/create)
2. List all state changes in function B (withdraw/update/cancel)
3. For each state change in A: does B have the corresponding reverse?
4. For each token transfer in A: does B have the corresponding refund?
5. For each event emitted in A: does B emit the corresponding event?
**If A does X but B doesn't do the reverse of X → BUG.**

### Step 5 — Check Every Function Against Every Invariant
For each invariant, find EVERY function that could violate it.
Does the function re-establish the invariant before returning on ALL paths?
Pay special attention to:
- Early returns that skip cleanup
- Error paths that leave state half-updated
- Functions that modify a tracking list — does the data structure stay consistent?
- External calls that could change state between two invariant-related updates

### Step 6 — Construct the Attack
For each invariant violation found:
- Build the MINIMAL call sequence that breaks the invariant
- Show the concrete values before and after: `balance was X, now Y, but should be Z`
- Show who extracts value and how much

## Proof Rules (MANDATORY)
Every finding MUST include:
- `invariant`: the conservation law you broke — stated precisely
- `violation_path`: minimal sequence of calls that breaks it
- `proof`: concrete values showing the invariant broken before and after
No proof with concrete values = not a finding. Set confidence ≤ 30.

## Kill Signals
- Share inflation: Virtual shares/offset present (`_decimalsOffset()`, `VIRTUAL_AMOUNT`) → mitigated
- Balance desync with fee-on-transfer: Code uses `balanceOf(this) - balanceBefore` pattern → mitigated
- CEI violation: `nonReentrant` on affected function → reentrancy path blocked
If kill signal exists → confidence ≤ 30.

## Output Format
Return ONLY valid JSON:
{
  "invariants_derived": [
    {"invariant": "description", "contract": "name", "variables": ["var1", "var2"]}
  ],
  "findings": [
    {
      "vulnerability_class": "invariant_violation | accounting_mismatch | orphaned_assets |
        queue_inconsistency | cei_violation | path_divergence | incomplete_roundtrip |
        state_coupling_break",
      "affected_contract": "ContractName",
      "affected_function": "functionName",
      "hypothesis": "detailed explanation of the bug",
      "proof": "concrete values showing invariant broken: before=[X], after=[Y], expected=[Z]",
      "invariant_violated": "the specific conservation law broken",
      "violation_path": ["Contract::funcA(args)", "Contract::funcB(args)"],
      "attack_path": ["ContractName::functionName as threat actor", "ContractName::vulnerableFunction"],
      "threat_actor": "unprivileged | semi_trusted_role | privileged",
      "confidence": <integer 0-100>,
      "severity_estimate": "CRITICAL | HIGH | MEDIUM | LOW",
      "evidence": "specific code reference proving the violation",
      "kill_signal_check": "what mitigations you checked for"
    }
  ]
}

## Critical Rules
- Derive invariants from THIS code. Do not just list generic vulnerability names.
- Every finding needs the full trace: invariant → violation path → concrete values → extraction.
- Semi-trusted role findings are HIGH/CRITICAL. Do NOT downgrade because of role requirement.
- If you find nothing, return an empty findings list. Do NOT hallucinate.
"""


class InvariantHunterWorker(WorkerAgent):
    """
    Derives protocol invariants from source code, then checks every function
    against them. No graph signals required — pure LLM reasoning.

    Produces WorkerOutput objects compatible with the existing finding pipeline.
    """

    def __init__(self, llm_client: Any, model_name: str | None = None):
        self.llm = llm_client
        self.model_name = model_name or os.getenv(
            "SEMANTIC_MODEL_NAME",
            os.getenv("WORKER_MODEL_NAME", "gpt-5.4-mini"),
        )

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
        max_chars = int(task.context.get("max_chars", 30000))

        if not sol_files:
            return WorkerOutput(
                worker_type=self.get_worker_type(),
                task_id=task.task_id,
                hypothesis="No source files provided for semantic analysis.",
                confidence=0,
            )

        source_text = self._read_source_files(sol_files, max_chars=max_chars)

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

        except TimeoutError:
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
                with open(path, encoding="utf-8", errors="replace") as f:
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
    model_name: str | None = None,
    recon_context: dict | None = None,
    sol_files: list[str] | None = None,
    agents: list[str] | None = None,
    max_chars: int | None = None,
) -> list[WorkerOutput]:
    """
    Entry point for semantic discovery.

    Args:
      sol_files: Explicit list of .sol files to analyze. When the caller (the
        agent brain) has already done recon and knows which contracts matter,
        pass them here — the workers will focus ONLY on these files. Paths
        may be absolute or repo-relative.
        When None, falls back to auto-collecting up to 50 largest non-test
        files from the repo (legacy behavior).
      agents: Subset of agents to run. Options: invariant_hunter,
        economic_attacker, trust_boundary, cross_contract. None = run all.
      max_chars: Override per-worker source-budget cap. Auto-selected based
        on whether files were curated (more budget) or auto-collected (less).

    Runs up to four parallel agents, each specializing in a different 0-day class.
    Returns list of WorkerOutput objects (one per agent that produced a finding).
    """
    focused_mode = bool(sol_files)

    if sol_files:
        # Caller supplied an explicit file list. Resolve any relative paths
        # against repo_path and drop missing files (with a warning).
        resolved: list[str] = []
        missing: list[str] = []
        for f in sol_files:
            abs_path = f if os.path.isabs(f) else os.path.join(repo_path, f)
            if os.path.isfile(abs_path):
                resolved.append(os.path.abspath(abs_path))
            else:
                missing.append(f)
        if missing:
            print(f"[Semantic] Ignoring {len(missing)} missing file(s): {missing[:3]}...")
        sol_files = resolved

    if not sol_files:
        sol_files = _collect_sol_files(repo_path)

    if not sol_files:
        print("[Semantic] No .sol files found in repo — skipping semantic discovery")
        return []

    mode = "FOCUSED" if focused_mode else "AUTO"
    print(f"[Semantic] {mode} mode: {len(sol_files)} .sol file(s) for analysis")

    # Focused mode = curated inputs; workers get a larger per-call budget so
    # the brain's selected files are read in full instead of truncated.
    if max_chars is None:
        max_chars = 80000 if focused_mode else 30000

    context = {
        "sol_files": sol_files,
        "recon_context": recon_context or {},
        "max_chars": max_chars,
    }

    # Instantiate all agents
    hunter = InvariantHunterWorker(llm_client=llm_client, model_name=model_name)

    from src.pipeline.workers.cross_contract import CrossContractStateChecker
    from src.pipeline.workers.economic_attacker import EconomicAttackerWorker
    from src.pipeline.workers.trust_boundary import TrustBoundaryAnalyzer

    economic = EconomicAttackerWorker(llm_client=llm_client, model_name=model_name)
    trust = TrustBoundaryAnalyzer(llm_client=llm_client, model_name=model_name)
    cross = CrossContractStateChecker(llm_client=llm_client, model_name=model_name)

    all_tasks = [
        ("invariant_hunter", "InvariantHunter", hunter, "semantic_invariant_hunt"),
        ("economic_attacker", "EconomicAttacker", economic, "semantic_economic_attack"),
        ("trust_boundary", "TrustBoundary", trust, "semantic_trust_boundary"),
        ("cross_contract", "CrossContract", cross, "semantic_cross_contract"),
    ]

    if agents:
        selected = {a.strip().lower() for a in agents}
        all_tasks = [t for t in all_tasks if t[0] in selected]

    tasks = [
        (display_name, worker, WorkerTask(
            task_id=task_id,
            task_type="semantic_discovery",
            context=context,
        ))
        for _, display_name, worker, task_id in all_tasks
    ]

    if not tasks:
        print("[Semantic] No agents selected — returning early")
        return []

    print(f"[Semantic] Launching {len(tasks)} semantic agent(s) in parallel...")

    async def _run_agent(name: str, agent, task):
        try:
            result = await asyncio.wait_for(agent.run(task), timeout=SEMANTIC_LLM_TIMEOUT + 30)
            print(f"[Semantic] {name} complete: confidence={result.confidence}")
            return result
        except TimeoutError:
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
