"""
CrossContractStateChecker — Cross-contract reentrancy / stale state 0-day discovery.

Reads raw source code (no Slither required). Focuses on:
- Read-after-external-call bugs where callee mutates shared state
- Cross-contract reentrancy via callback interfaces
- Stale return value usage from external calls
- View function reliance on mutable external state
- Storage poisoning via permissionless external setup functions

Runs as part of the semantic discovery pipeline.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
from typing import Any

from src.pipeline.base_worker import WorkerAgent, WorkerOutput, WorkerTask

logger = logging.getLogger(__name__)

CROSS_CONTRACT_LLM_TIMEOUT = int(os.getenv("CROSS_CONTRACT_LLM_TIMEOUT", "300"))

CROSS_CONTRACT_SYSTEM_PROMPT = """\
You are an attacker that exploits the boundary between contracts. Core contracts trust
external calls, callbacks, and return values implicitly. One stale read, one mid-update
callback, one unvalidated return value — and you extract everything.

Other agents cover single-function logic. You exploit what happens BETWEEN contracts
and ACROSS transactions.

## Attack Surfaces

### Within a Transaction
**Parameter divergence.** Feed mismatched inputs: claimed amount ≠ actual sent. Token
amount parameter vs msg.value. Length of array parameter vs actual array contents.

**Stale reads.** Contract A reads value V from contract B. Another call modifies V.
Contract A still uses the old V. Exploit the gap between read and use.

**Callback exploitation.** For every function that could be called as a callback
(ERC777 tokensReceived, ERC1155 onReceived, flash loan callbacks, Uniswap hooks):
- What state is "mid-update" when the callback fires?
- Can the callback re-enter the caller with a different function?
- Can the callback call a THIRD contract that reads the mid-update state?

**Return value corruption.** External calls that return values: What if the callee
returns zero when non-zero is expected? Truncated addresses? Mismatched lengths?
Every caller trusting this return value inherits the bug.

### Across Transactions
**Wrong-state execution.** Execute functions in protocol states they were never designed
for: paused but unguarded, mid-migration, post-upgrade with stale storage.

**Operation interleaving.** Corrupt multi-step operations by acting between the steps.
Approve → transferFrom: act between them. Create position → configure position: hijack
configuration. The gap between two user transactions is your attack surface.

**Mid-operation config mutation.** Fire a setter (updateFee, changeOracle, setRecipient)
while a multi-block operation is in-flight. The operation started with old config but
finishes with new config — exploit the inconsistency.

### Accounting Scope (catches Morpho-class queue bugs)
**Collection completeness.** For any function that computes an aggregate (totalAssets,
totalDebt, totalSupply) by iterating a collection:
- Is the collection stored in this contract or another?
- Can the other contract modify the collection (remove items) while underlying assets remain?
- If yes: aggregate underreports reality → share price manipulation → extraction.
- Who has permission to modify the collection? Semi-trusted roles are valid attackers.

**Hidden state side effects.** Find storage writes, approval changes, balance updates
in external calls that the caller doesn't account for.

## Kill Signals
- Cross-contract reentrancy: `nonReentrant` on ALL functions that make external calls
  AND read shared state → mitigated
- Stale reads: Value is re-fetched after external call (not cached) → mitigated
- Callback: `ReentrancyGuard` covers the callback entry point → mitigated
If kill signal exists → confidence ≤ 30.

## Proof Rules (MANDATORY)
Every finding MUST specify:
- BOTH the caller contract/function AND the callee contract/function
- The specific state that becomes stale or corrupt
- A concrete transaction sequence (who calls what, in what order)
No concrete sequence = not a finding.

## Output Format
Return ONLY valid JSON:
{
  "external_calls_mapped": [
    {"caller": "Contract.func", "callee": "IInterface.method", "state_read_after": true/false}
  ],
  "findings": [
    {
      "vulnerability_class": "cross_contract_reentrancy | stale_state | callback_exploitation |
        storage_poisoning | view_manipulation | accounting_scope_mismatch | operation_interleaving |
        parameter_divergence",
      "affected_contract": "ContractName",
      "affected_function": "functionName",
      "callee_contract": "TargetContractName",
      "callee_function": "targetFunction",
      "hypothesis": "detailed explanation",
      "proof": "concrete transaction sequence showing the exploit",
      "attack_path": ["step1", "step2", "step3"],
      "threat_actor": "unprivileged | semi_trusted_role | privileged",
      "confidence": <integer 0-100>,
      "evidence": "specific code reference",
      "impact": "what the attacker gains — with concrete numbers if possible",
      "severity_estimate": "CRITICAL | HIGH | MEDIUM | LOW",
      "kill_signal_check": "what mitigations you checked for"
    }
  ]
}
"""


class CrossContractStateChecker(WorkerAgent):
    """
    Cross-contract reentrancy and stale state agent.
    No graph signals — pure LLM reasoning over raw source.
    """

    def __init__(self, llm_client: Any, model_name: str | None = None):
        self.llm = llm_client
        self.model_name = model_name or os.getenv(
            "SEMANTIC_MODEL_NAME",
            os.getenv("WORKER_MODEL_NAME", "gpt-5.4-mini"),
        )

    def get_worker_type(self) -> str:
        return "cross_contract"

    async def run(self, task: WorkerTask) -> WorkerOutput:
        sol_files = task.context.get("sol_files", [])
        recon_context = task.context.get("recon_context", {})
        # Cross-contract needs more context than siblings to trace calls across
        # multiple contracts. Scale the shared budget by ~1.6x, but never below
        # the legacy 50k floor when in auto mode.
        base = int(task.context.get("max_chars", 30000))
        max_chars = max(int(base * 1.6), 50000 if base <= 30000 else base)

        if not sol_files:
            return WorkerOutput(
                worker_type=self.get_worker_type(),
                task_id=task.task_id,
                hypothesis="No source files provided.",
                confidence=0,
            )

        source_text = self._read_source_files(sol_files, max_chars=max_chars)
        protocol_type = recon_context.get("protocol_type", "unknown")

        messages = [
            {"role": "system", "content": CROSS_CONTRACT_SYSTEM_PROMPT},
            {
                "role": "user",
                "content": f"## Protocol Context\nProtocol type: {protocol_type}\n\n## Source Code (ALL in-scope contracts)\n```solidity\n{source_text}\n```\n\nAnalyze ALL cross-contract interactions. Map external calls, check for stale state, callback bugs, and storage poisoning. Return JSON.",
            },
        ]

        try:
            response = await asyncio.wait_for(
                self.llm.ainvoke(messages),
                timeout=CROSS_CONTRACT_LLM_TIMEOUT,
            )
            content = response.content if hasattr(response, "content") else str(response)
            if isinstance(content, list):
                content = "".join(c.get("text", "") if isinstance(c, dict) else str(c) for c in content)
            return self._parse_response(content, task.task_id)
        except TimeoutError:
            logger.warning("[CrossContract] LLM timed out")
            return WorkerOutput(worker_type=self.get_worker_type(), task_id=task.task_id, confidence=0)
        except Exception as e:
            logger.warning(f"[CrossContract] Error: {e}")
            return WorkerOutput(worker_type=self.get_worker_type(), task_id=task.task_id, confidence=0)

    def _read_source_files(self, sol_files: list[str], max_chars: int = 50000) -> str:
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
                logger.debug(f"[CrossContract] Could not read {path}: {e}")
        return "\n".join(parts)

    def _parse_response(self, raw: str, task_id: str) -> WorkerOutput:
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
                    hypothesis="No cross-contract vulnerabilities found.",
                    confidence=0,
                    raw_output=parsed,
                )

            best = max(findings_list, key=lambda f: f.get("confidence", 0))
            return WorkerOutput(
                worker_type=self.get_worker_type(),
                task_id=task_id,
                hypothesis=best.get("hypothesis", ""),
                confidence=min(100, max(0, int(best.get("confidence", 50)))),
                attack_path=best.get("attack_path", []),
                raw_output={
                    "external_calls_mapped": parsed.get("external_calls_mapped", []),
                    "all_findings": findings_list,
                    "best_finding": best,
                    "vulnerability_class": best.get("vulnerability_class", "cross_contract_reentrancy"),
                    "affected_contract": best.get("affected_contract", ""),
                    "affected_function": best.get("affected_function", ""),
                    "severity_estimate": best.get("severity_estimate", "HIGH"),
                    "impact": best.get("impact", ""),
                },
            )
        except Exception as e:
            logger.warning(f"[CrossContract] Parse error: {e}")
            return WorkerOutput(worker_type=self.get_worker_type(), task_id=task_id, confidence=0)
