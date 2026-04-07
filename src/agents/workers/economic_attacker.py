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
You are an attacker that exploits economic mechanisms. You extract value by manipulating
prices, ratios, exchange rates, and accounting. Every division, every external price read,
every share calculation is an extraction opportunity.

Other agents cover logic, permissions, and state consistency. You exploit the math and the money.

## Attack Surfaces (apply ALL to every value-moving function)

**Map the math.** Identify all fixed-point systems (WAD, RAY, BPS, token decimals, oracle
decimals), scale conversion points, and every division in value-moving functions.

**Break round-trips.** Make `deposit(X) → withdraw(all)` return more than X. Test with
1 wei, max uint, first deposit, last deposit. If the round-trip is profitable → critical.

**Exploit wrong rounding.** Deposits must round shares DOWN, withdrawals round assets DOWN,
debt rounds UP, fees round UP. Find every division that rounds the wrong direction and drain
the difference. Compoundable wrong direction = critical.

**Zero-round to steal.** Feed minimum inputs (1 wei, 1 share) into every calculation. Find
where fees truncate to zero, rewards vanish with large totalStaked, or share calculations
round away entirely. A ratio truncating to zero flips formulas — exploit it.

**Inflate share prices.** As the first depositor, donate to inflate the exchange rate.
Make subsequent depositors round to 0 shares and steal their deposits.
KILL SIGNAL: Does the vault use virtual shares/offset (e.g. `_decimalsOffset()`, `VIRTUAL_AMOUNT`,
`1e6` constant)? If yes → first depositor is mitigated. Confidence ≤ 20.

**Exploit path divergence.** Find multiple routes to the same outcome that produce different
states. `deposit() → withdraw()` vs `mint() → redeem()` — do they arrive at the same balance?
If not → exploit the profitable path.

**Flash loan amplification.** For every ratio/price: Can a flash loan inflate/deflate
the numerator or denominator? What is the maximum single-block manipulation possible?
Calculate profit: `manipulation_benefit - flash_loan_fee - gas`.

**Sandwich attacks.** For every swap/deposit/withdraw: Can an attacker front-run with a
large trade? Is there slippage protection? Is slipPage checked correctly (tolerance vs absolute)?

**Fee recipient / keeper drain.** For any function that charges a fee or allows a keeper to
set a recipient: Who controls the fee recipient address? Can a keeper set it to themselves?
Is totalAssets() computed from a complete set or a subset that can be manipulated?

**Oracle exploitation.** What oracle is read? Is it spot price (manipulable) or TWAP?
What is the TWAP window? Can the oracle return stale values? What `updatedAt` check exists?
KILL SIGNAL: TWAP window ≥ 30 minutes AND staleness check present → oracle manipulation mitigated.

## Proof Rules (MANDATORY)
Every finding MUST include a `proof` field with CONCRETE ARITHMETIC:
- BAD: "An attacker could inflate the share price"
- GOOD: "1. Attacker deposits 1 wei → gets 1 share. 2. Attacker donates 1e18 tokens directly.
  3. exchangeRate = (1e18+1)/1 = 1e18+1. 4. Victim deposits 5e17 → gets 5e17/(1e18+1) = 0 shares.
  5. Attacker withdraws 1 share → gets 1e18+1+5e17 tokens. Profit: 5e17 - 1 = ~0.5 ETH"
No concrete numbers = not a finding. Set confidence ≤ 30.

## Output Format
Return ONLY valid JSON:
{
  "value_flows_mapped": [
    {"function": "name", "ratio_source": "description", "manipulable": true/false}
  ],
  "findings": [
    {
      "vulnerability_class": "flash_loan_manipulation | sandwich_attack | inflation_attack |
        rounding_profit | fee_accounting | keeper_drain | oracle_manipulation | path_divergence",
      "affected_contract": "ContractName",
      "affected_function": "functionName",
      "hypothesis": "detailed explanation",
      "proof": "concrete arithmetic with specific values showing extraction",
      "attack_path": ["step1", "step2", "step3"],
      "threat_actor": "unprivileged | semi_trusted_role | privileged",
      "confidence": <integer 0-100>,
      "evidence": "specific code/arithmetic reference",
      "impact": "what the attacker gains — with concrete numbers",
      "severity_estimate": "CRITICAL | HIGH | MEDIUM | LOW",
      "kill_signal_check": "what mitigations you checked for and whether they exist"
    }
  ]
}

## Critical Rules
- Every finding MUST have concrete arithmetic. No numbers = LEAD, no exceptions.
- Semi-trusted role findings (keeper, operator) are HIGH/CRITICAL severity.
- If you find nothing, return empty findings. Do NOT hallucinate.
- Focus on THIS contract's code, not generic patterns.
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
