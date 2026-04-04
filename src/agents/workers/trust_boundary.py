"""
TrustBoundaryAnalyzer — Privilege escalation / proxy / delegatecall 0-day discovery.

Reads raw source code (no Slither required). Focuses on:
- msg.sender check bypasses via contract deployment
- Proxy admin overlap and storage collision
- delegatecall destination control
- Ownership transfer race conditions
- Multi-sig threshold manipulation
- Initializer replay attacks on upgradeable contracts

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

TRUST_LLM_TIMEOUT = int(os.getenv("TRUST_LLM_TIMEOUT", "300"))

TRUST_BOUNDARY_SYSTEM_PROMPT = """\
You are an elite smart contract security researcher specializing in trust boundary
analysis. Your job is to find privilege escalation paths, proxy abuse vectors, and
access control bypasses.

## Threat Actor Model
- SEMI-TRUSTED ROLES (keeper, operator, allocator, guardian, relayer, strategist) can be
  malicious. If a role-holder can extract funds, manipulate storage, or grant themselves
  elevated privileges, this is a VALID HIGH-severity finding. Do NOT skip it.
- PRIVILEGED ROLES (owner, multisig, DAO) require higher evidence — but still report if
  the privilege escalation can be triggered without a governance vote.
- UNPRIVILEGED callers can trigger public functions.

## Methodology

### Step 1: Map Every Trust Boundary
Identify every msg.sender / tx.origin check. For each:
- What role does this guard? (owner, admin, operator, minter, etc.)
- Is the role stored as an address? Can a contract be deployed at that address?
- Is there a timelock or multi-sig protection?

### Step 2: Analyze Ownership Transitions
For every transferOwnership, revokeRole, renounceOwnership:
- Can ownership be transferred to address(0) accidentally?
- Can two transactions race to both claim ownership?
- What happens if the new owner is a contract that reverts on callback?

### Step 3: Proxy & Upgrade Analysis
For contracts using delegatecall, proxy patterns, or initializers:
- Is the implementation slot readable by anyone?
- Can the proxy admin also call user functions? (selector clash)
- Is the initializer protected against re-initialization?
- Can storage layout collisions corrupt cross-slot state?

### Step 4: Cross-Function Privilege Paths
Map call chains where a low-privilege entry leads to high-privilege state change:
- User function → internal function → writes admin slot
- Callback from external contract → re-enters with elevated context

### Step 5: Delegation Attack Surface (catches role-delegation bugs)
For semi-trusted roles (keeper, operator, allocator):
- Can a keeper/operator delegate their role to another address they control?
- Is role delegation subject to a timelock or approval? If not, can it escalate instantly?
- Can a keeper execute arbitrary calls on behalf of the protocol (e.g. via execute() or
  perform() functions with unconstrained calldata)?
- Is there a grant/revoke mechanism that can be triggered without proper authorization?
- Can a semi-trusted actor remove themselves from tracking while keeping their privileges?
  (e.g., deallocate from a queue but retain an allocation that generates fees)

## CRITICAL RULES
- Reference specific functions and access control patterns.
- Semi-trusted role findings are HIGH/CRITICAL severity if funds are extractable.
- Confidence 65-80 for semi-trusted findings with clear code path.
- If no vulnerabilities found, return empty findings. Do NOT hallucinate.

## Output Format
Return ONLY valid JSON:
{
  "trust_boundaries": [
    {"function": "name", "guard": "onlyOwner/require(msg.sender==...)", "role": "description"}
  ],
  "findings": [
    {
      "vulnerability_class": "privilege_escalation | proxy_abuse | initializer_replay | ownership_race | delegatecall_injection | role_delegation_abuse",
      "affected_contract": "ContractName",
      "affected_function": "functionName",
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


class TrustBoundaryAnalyzer(WorkerAgent):
    """
    Privilege escalation and trust boundary agent.
    No graph signals — pure LLM reasoning over raw source.
    """

    model_name: str = "gemini-2.5-flash"

    def __init__(self, llm_client: Any, model_name: str = "gemini-2.5-flash"):
        self.llm = llm_client
        self.model_name = model_name

    def get_worker_type(self) -> str:
        return "trust_boundary"

    async def run(self, task: WorkerTask) -> WorkerOutput:
        sol_files = task.context.get("sol_files", [])
        recon_context = task.context.get("recon_context", {})

        if not sol_files:
            return WorkerOutput(
                worker_type=self.get_worker_type(), task_id=task.task_id,
                hypothesis="No source files provided.", confidence=0,
            )

        source_text = self._read_source_files(sol_files, max_chars=30000)
        protocol_type = recon_context.get("protocol_type", "unknown")

        messages = [
            {"role": "system", "content": TRUST_BOUNDARY_SYSTEM_PROMPT},
            {"role": "user", "content": f"## Protocol Context\nProtocol type: {protocol_type}\n\n## Source Code\n```solidity\n{source_text}\n```\n\nAnalyze trust boundaries, access control, proxy patterns, and privilege escalation vectors. Return JSON."},
        ]

        try:
            response = await asyncio.wait_for(
                self.llm.ainvoke(messages), timeout=TRUST_LLM_TIMEOUT,
            )
            content = response.content if hasattr(response, "content") else str(response)
            if isinstance(content, list):
                content = "".join(
                    c.get("text", "") if isinstance(c, dict) else str(c) for c in content
                )
            return self._parse_response(content, task.task_id)
        except asyncio.TimeoutError:
            logger.warning("[TrustBoundary] LLM timed out")
            return WorkerOutput(worker_type=self.get_worker_type(), task_id=task.task_id, confidence=0)
        except Exception as e:
            logger.warning(f"[TrustBoundary] Error: {e}")
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
                logger.debug(f"[TrustBoundary] Could not read {path}: {e}")
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
                    hypothesis="No trust boundary violations found.", confidence=0,
                    raw_output=parsed,
                )

            best = max(findings_list, key=lambda f: f.get("confidence", 0))
            return WorkerOutput(
                worker_type=self.get_worker_type(), task_id=task_id,
                hypothesis=best.get("hypothesis", ""),
                confidence=min(100, max(0, int(best.get("confidence", 50)))),
                attack_path=best.get("attack_path", []),
                raw_output={
                    "trust_boundaries": parsed.get("trust_boundaries", []),
                    "all_findings": findings_list,
                    "best_finding": best,
                    "vulnerability_class": best.get("vulnerability_class", "privilege_escalation"),
                    "affected_contract": best.get("affected_contract", ""),
                    "affected_function": best.get("affected_function", ""),
                    "severity_estimate": best.get("severity_estimate", "HIGH"),
                    "impact": best.get("impact", ""),
                },
            )
        except Exception as e:
            logger.warning(f"[TrustBoundary] Parse error: {e}")
            return WorkerOutput(worker_type=self.get_worker_type(), task_id=task_id, confidence=0)
