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

from src.agents.base_worker import WorkerAgent, WorkerTask, WorkerOutput

logger = logging.getLogger(__name__)

CROSS_CONTRACT_LLM_TIMEOUT = int(os.getenv("CROSS_CONTRACT_LLM_TIMEOUT", "300"))

CROSS_CONTRACT_SYSTEM_PROMPT = """\
You are an elite smart contract security researcher specializing in cross-contract
interaction bugs. Your job is to find vulnerabilities arising from the interaction
between multiple contracts, NOT bugs within a single function.

## Threat Actor Model
- SEMI-TRUSTED ROLES (keeper, operator, allocator, guardian) are VALID attackers.
  If a keeper can call a function in Contract A that changes state Contract B reads,
  this IS a valid attack vector.
- Cross-contract bugs often require a semi-trusted role to initiate the corruption.
  Do NOT dismiss because of role requirement.

## Methodology

### Step 1: Map All External Calls
For every `IFoo(addr).bar()`, `addr.call(...)`, or `.delegatecall(...)`:
- What does the callee write to storage?
- Does the caller re-read any shared state after the external call?
- Can the callee's state be poisoned before this call?

### Step 2: Callback Analysis
For every function that could be called as a callback (ERC777, ERC1155, flash loan
callbacks, Uniswap hooks):
- Is there any state that is "mid-update" when the callback fires?
- Can the callback re-enter the caller?
- Can the callback call a different function that reads the mid-update state?

### Step 3: View Function Dependency
For every view/pure function that reads external state:
- Can that external state change between the view call and its consumer?
- Is the return value cached or re-fetched?
- Can a MEV bot manipulate the external state between reads?

### Step 4: Storage Poisoning
For permissionless functions that set up state:
- Can an attacker front-run initialization to set malicious addresses?
- Can external contracts be deployed at predictable addresses?
- Can CREATE2 be used to place attacker code at expected addresses?

### Step 5: Cross-Contract Accounting Scope (catches Morpho-class queue bugs)
For any function in Contract A that computes an aggregate (totalAssets, totalDebt,
assetBalance) by iterating a collection (a queue, list, or mapping of positions):
- Is that collection stored in Contract A or Contract B?
- Can Contract B modify the collection in a way that removes a position while the
  underlying assets remain?
- If yes: Contract A's aggregate underreports reality, enabling share price manipulation.
- Who has permission to remove items from the collection? Is this a semi-trusted role?
- Specifically: after the removal, can an attacker deposit/withdraw at the deflated price
  and then cause the position to be re-added, restoring the real asset value?

## CRITICAL RULES
- Read ALL contracts together to trace cross-contract flows.
- Every finding must specify BOTH the caller and callee contract/function.
- Semi-trusted role findings are HIGH/CRITICAL severity if funds are extractable.
- If no vulnerabilities found, return empty findings. Do NOT hallucinate.

## Output Format
Return ONLY valid JSON:
{
  "external_calls_mapped": [
    {"caller": "Contract.func", "callee": "IInterface.method", "state_read_after": true/false}
  ],
  "findings": [
    {
      "vulnerability_class": "cross_contract_reentrancy | stale_state | callback_exploitation | storage_poisoning | view_manipulation | accounting_scope_mismatch",
      "affected_contract": "ContractName",
      "affected_function": "functionName",
      "callee_contract": "TargetContractName",
      "callee_function": "targetFunction",
      "hypothesis": "detailed explanation",
      "attack_path": ["step1", "step2", "step3"],
      "threat_actor": "unprivileged | semi_trusted_role | privileged",
      "confidence": <integer 0-100>,
      "evidence": "specific code reference",
      "impact": "what the attacker gains",
      "severity_estimate": "CRITICAL | HIGH | MEDIUM | LOW"
    }
  ]
}
"""


class CrossContractStateChecker(WorkerAgent):
    """
    Cross-contract reentrancy and stale state agent.
    No graph signals — pure LLM reasoning over raw source.
    """

    model_name: str = "gemini-2.5-flash"

    def __init__(self, llm_client: Any, model_name: str = "gemini-2.5-flash"):
        self.llm = llm_client
        self.model_name = model_name

    def get_worker_type(self) -> str:
        return "cross_contract"

    async def run(self, task: WorkerTask) -> WorkerOutput:
        sol_files = task.context.get("sol_files", [])
        recon_context = task.context.get("recon_context", {})

        if not sol_files:
            return WorkerOutput(
                worker_type=self.get_worker_type(), task_id=task.task_id,
                hypothesis="No source files provided.", confidence=0,
            )

        # Read MORE files than other agents since cross-contract needs full picture
        source_text = self._read_source_files(sol_files, max_chars=50000)
        protocol_type = recon_context.get("protocol_type", "unknown")

        messages = [
            {"role": "system", "content": CROSS_CONTRACT_SYSTEM_PROMPT},
            {"role": "user", "content": f"## Protocol Context\nProtocol type: {protocol_type}\n\n## Source Code (ALL in-scope contracts)\n```solidity\n{source_text}\n```\n\nAnalyze ALL cross-contract interactions. Map external calls, check for stale state, callback bugs, and storage poisoning. Return JSON."},
        ]

        try:
            response = await asyncio.wait_for(
                self.llm.ainvoke(messages), timeout=CROSS_CONTRACT_LLM_TIMEOUT,
            )
            content = response.content if hasattr(response, "content") else str(response)
            if isinstance(content, list):
                content = "".join(
                    c.get("text", "") if isinstance(c, dict) else str(c) for c in content
                )
            return self._parse_response(content, task.task_id)
        except asyncio.TimeoutError:
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
                    worker_type=self.get_worker_type(), task_id=task_id,
                    hypothesis="No cross-contract vulnerabilities found.", confidence=0,
                    raw_output=parsed,
                )

            best = max(findings_list, key=lambda f: f.get("confidence", 0))
            return WorkerOutput(
                worker_type=self.get_worker_type(), task_id=task_id,
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
