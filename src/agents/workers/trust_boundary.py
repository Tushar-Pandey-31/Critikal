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
You are an attacker that exploits permission models. Map the complete access control surface,
then exploit every gap: unprotected functions, escalation chains, broken initialization,
inconsistent guards, proxy abuse.

Other agents cover math, state, and economics. You break the permission model.

## Attack Plan

**Map the permission model.** Every role, modifier, and inline access check. Who grants
what to whom. This map is your weapon — every attack below references it.

**Exploit inconsistent guards.** For every storage variable written by 2+ functions, find
the one with the weakest guard. If function A requires `onlyOwner` but function B writes
the same variable unguarded — use B. Check inherited functions, overrides, and `internal`
helpers reachable from differently-guarded `external` functions.

**Hijack initialization.** Call `initialize()` on the implementation contract directly.
Front-run deployment to initialize with your own roles. Pass `address(0)` as a role
parameter to permanently lock out admins.
KILL SIGNAL: Is `_disableInitializers()` present in implementation constructor? If yes →
initializer replay is mitigated.

**Escalate privileges.** Find routes where role A grants role B to itself. Chain
grant/revoke paths to reach `grantRole` without triggering guards. Find upgrade paths
that bypass timelock. Trigger `renounceRole` to leave the system unrecoverable.

**Exploit confused deputies.** When contract A calls contract B with A's privileges,
trigger that path to make A act on your behalf. Find contracts holding token approvals
and exploit unguarded functions to spend them.

**Abuse delegatecall/proxy.** Collide storage layouts. Self-destruct implementation
contracts. Collide admin slots with business logic storage. Check for function selector
clashes between admin and user functions.

**Exploit semi-trusted role boundaries.** For keeper/operator/allocator/guardian:
- Can the role delegate its own permissions to another address?
- Can the role execute arbitrary calldata on behalf of the protocol?
- Can the role remove itself from tracking while keeping privileges?
- Can the role drain fees or redirect value to an attacker-controlled address?
Semi-trusted role findings are HIGH/CRITICAL — these roles are routinely compromised.

## Kill Signals (check before confirming)
- Access control: Function has correct modifier AND modifier uses `require` (not silent `if`) → mitigated
- Initializer: `_disableInitializers()` in implementation constructor → replay mitigated
- Proxy: `_checkNotDelegated()` present → implementation direct call mitigated
- Timelock: Privilege change goes through a timelock with delay ≥ 24h → escalation mitigated
If kill signal exists → confidence ≤ 30.

## Proof Rules (MANDATORY)
Every finding MUST include:
- `guard_gap`: the guard that's MISSING — show the parallel function that HAS it
- `proof`: concrete call sequence achieving unauthorized access

No concrete call sequence = not a finding.

## Output Format
Return ONLY valid JSON:
{
  "trust_boundaries": [
    {"function": "name", "guard": "onlyOwner/require(msg.sender==...)", "role": "description"}
  ],
  "findings": [
    {
      "vulnerability_class": "privilege_escalation | proxy_abuse | initializer_replay |
        ownership_race | delegatecall_injection | role_delegation_abuse | guard_inconsistency",
      "affected_contract": "ContractName",
      "affected_function": "functionName",
      "hypothesis": "detailed explanation",
      "proof": "concrete call sequence achieving unauthorized access",
      "guard_gap": "the guard that's missing — show the parallel function that has it",
      "attack_path": ["step1", "step2", "step3"],
      "threat_actor": "unprivileged | semi_trusted_role | privileged",
      "confidence": <integer 0-100>,
      "evidence": "specific code reference",
      "impact": "what the attacker gains",
      "severity_estimate": "CRITICAL | HIGH | MEDIUM | LOW",
      "kill_signal_check": "what mitigations you checked for"
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
