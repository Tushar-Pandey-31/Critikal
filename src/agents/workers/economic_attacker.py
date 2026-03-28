"""
EconomicAttackerWorker — Flash loan / sandwich / price manipulation 0-day discovery.

Reads raw source code (no Slither required). Focuses on:
- Price oracle manipulation via flash loans
- Sandwich attack vectors in swap/trade functions
- Share/asset ratio inflation via first-depositor attacks
- Fee-on-transfer token accounting errors
- Rounding profit extraction across repeated operations

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

ECONOMIC_LLM_TIMEOUT = int(os.getenv("ECONOMIC_LLM_TIMEOUT", "300"))

ECONOMIC_ATTACKER_SYSTEM_PROMPT = """\
You are an elite DeFi economic security researcher. Your specialty is finding
economic attack vectors — bugs where an attacker can extract value by manipulating
prices, ratios, or balances using flash loans, sandwich attacks, or multi-step
sequences.

## Methodology

### Step 1: Map Value Flows
For every function that moves tokens, updates balances, or computes prices:
- What is the exchange rate / price / ratio used?
- Where does that ratio come from? Is it on-chain? Is it in the same block?
- Can an attacker control that ratio with a preceding transaction?

### Step 2: Flash Loan Feasibility
For every ratio/price identified:
- Can a flash loan inflate or deflate the denominator?
- Can a flash loan inflate or deflate the numerator?
- What is the maximum single-block manipulation possible?

### Step 3: Sandwich Analysis
For every swap, deposit, or withdraw function:
- Can an attacker front-run with a large trade to move the price?
- Can the attacker back-run to extract the price impact?
- Is there slippage protection? Is it sufficient?

### Step 4: First-Depositor / Inflation Attacks
For vault-like contracts:
- What happens if totalSupply == 0 and attacker deposits a tiny amount then donates?
- Does share arithmetic round against the protocol or the user?
- Can inflation make subsequent deposits worth zero shares?

### Step 5: Rounding Profit Extraction
For any division operation:
- Can repeated small operations accumulate rounding profit?
- Can fee-on-transfer tokens cause accounting drift?

## CRITICAL RULES
- Every claim MUST reference a specific function and the arithmetic operation.
- If you find nothing, return empty findings. Do NOT hallucinate.
- Focus on THIS contract's code, not generic patterns.

## Output Format
Return ONLY valid JSON:
{
  "value_flows_mapped": [
    {"function": "name", "ratio_source": "description", "manipulable": true/false}
  ],
  "findings": [
    {
      "vulnerability_class": "flash_loan_manipulation | sandwich_attack | inflation_attack | rounding_profit | fee_accounting",
      "affected_contract": "ContractName",
      "affected_function": "functionName",
      "hypothesis": "detailed explanation",
      "attack_path": ["step1", "step2", "step3"],
      "confidence": <integer 0-100>,
      "evidence": "specific code/arithmetic reference",
      "impact": "what the attacker gains",
      "severity_estimate": "CRITICAL | HIGH | MEDIUM | LOW"
    }
  ]
}
"""


class EconomicAttackerWorker(WorkerAgent):
    """
    Flash loan / sandwich / price manipulation agent.
    No graph signals — pure LLM reasoning over raw source.
    """

    model_name: str = "gemini-2.5-flash"

    def __init__(self, llm_client: Any, model_name: str = "gemini-2.5-flash"):
        self.llm = llm_client
        self.model_name = model_name

    def get_worker_type(self) -> str:
        return "economic_attacker"

    async def run(self, task: WorkerTask) -> WorkerOutput:
        sol_files = task.context.get("sol_files", [])
        recon_context = task.context.get("recon_context", {})

        if not sol_files:
            return WorkerOutput(
                worker_type=self.get_worker_type(),
                task_id=task.task_id,
                hypothesis="No source files provided.",
                confidence=0,
            )

        source_text = self._read_source_files(sol_files, max_chars=30000)
        protocol_type = recon_context.get("protocol_type", "unknown")

        messages = [
            {"role": "system", "content": ECONOMIC_ATTACKER_SYSTEM_PROMPT},
            {"role": "user", "content": f"## Protocol Context\nProtocol type: {protocol_type}\n\n## Source Code\n```solidity\n{source_text}\n```\n\nAnalyze the above contracts for economic attack vectors. Return JSON."},
        ]

        try:
            response = await asyncio.wait_for(
                self.llm.ainvoke(messages),
                timeout=ECONOMIC_LLM_TIMEOUT,
            )
            content = response.content if hasattr(response, "content") else str(response)
            if isinstance(content, list):
                content = "".join(
                    c.get("text", "") if isinstance(c, dict) else str(c) for c in content
                )
            return self._parse_response(content, task.task_id)
        except asyncio.TimeoutError:
            logger.warning("[EconomicAttacker] LLM timed out")
            return WorkerOutput(worker_type=self.get_worker_type(), task_id=task.task_id, confidence=0)
        except Exception as e:
            logger.warning(f"[EconomicAttacker] Error: {e}")
            return WorkerOutput(worker_type=self.get_worker_type(), task_id=task.task_id, confidence=0)

    def _read_source_files(self, sol_files: list[str], max_chars: int = 30000) -> str:
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
                logger.debug(f"[EconomicAttacker] Could not read {path}: {e}")
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
                    hypothesis="No economic attack vectors found.", confidence=0,
                    raw_output=parsed,
                )

            best = max(findings_list, key=lambda f: f.get("confidence", 0))
            return WorkerOutput(
                worker_type=self.get_worker_type(), task_id=task_id,
                hypothesis=best.get("hypothesis", ""),
                confidence=min(100, max(0, int(best.get("confidence", 50)))),
                attack_path=best.get("attack_path", []),
                raw_output={
                    "value_flows_mapped": parsed.get("value_flows_mapped", []),
                    "all_findings": findings_list,
                    "best_finding": best,
                    "vulnerability_class": best.get("vulnerability_class", "economic_attack"),
                    "affected_contract": best.get("affected_contract", ""),
                    "affected_function": best.get("affected_function", ""),
                    "severity_estimate": best.get("severity_estimate", "HIGH"),
                    "impact": best.get("impact", ""),
                },
            )
        except Exception as e:
            logger.warning(f"[EconomicAttacker] Parse error: {e}")
            return WorkerOutput(
                worker_type=self.get_worker_type(), task_id=task_id, confidence=0,
            )
