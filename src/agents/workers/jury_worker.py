"""
Jury System — Adversarial multi-model validation for vulnerability hypotheses.

Three independent jurors review each finding from different adversarial angles.
A Judge arbitrates and produces a TestWriter Brief for confirmed findings.

Juror roles:
- Claude Sonnet (Skeptic): finds reasons the hypothesis is wrong
- Grok (Attacker): finds the most realistic attack scenario
- GPT-4o (Auditor): applies professional audit standards

Judge: Gemini Pro — arbitrates, writes TestWriter Brief
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
from dataclasses import dataclass, field
from typing import Any, Literal

logger = logging.getLogger(__name__)

# ── Verdict types ────────────────────────────────────────────────────

JuryVerdict = Literal["CONFIRM", "REJECT", "UNCERTAIN"]

JudgeDecision = Literal[
    "CONFIRMED",
    "REJECTED",
    "ESCALATE",
    "CONFIRMED_UNPROVABLE",
]


@dataclass
class JurorOutput:
    juror_id: str
    model: str
    verdict: JuryVerdict
    confidence: int
    reasoning: str
    key_concern: str
    raw_output: dict = field(default_factory=dict)


@dataclass
class JudgeOutput:
    decision: JudgeDecision
    vote_summary: str
    reasoning: str
    testwriter_brief: dict = field(default_factory=dict)
    unprovable_reason: str = ""
    rejection_reason: str = ""


# ── System Prompts ───────────────────────────────────────────────────

SKEPTIC_SYSTEM_PROMPT = """You are a senior smart contract security auditor acting as a SKEPTIC reviewer.

Your job is to find every possible reason why the vulnerability hypothesis you are reviewing is WRONG, OVERSTATED, or NOT EXPLOITABLE.

You are the last line of defense against false positives. Assume the hypothesis worker made a mistake. Only confirm if you genuinely cannot find a reason to reject.

## What you are reviewing
You will receive:
1. Raw source code of the contract
2. Deterministic graph signals (these are facts from static analysis)
3. A vulnerability hypothesis (this is LLM output — treat it skeptically)
4. Titan pattern hits (regex-based detectors — these are facts)

## Your job
- Read the source code carefully
- Check every precondition the hypothesis claims
- Look for access control you might have missed
- Look for reentrancy guards, initializer guards, require statements
- Check if the graph signals actually support the hypothesis
- Ask: could a real attacker actually execute these steps?

## Output format
Return ONLY valid JSON, no markdown, no preamble:
{
  "verdict": "CONFIRM" | "REJECT" | "UNCERTAIN",
  "confidence": <integer 0-100>,
  "reasoning": "<one paragraph explaining your verdict>",
  "key_concern": "<the single most important thing — what would change your verdict>"
}

## Verdict guidelines
- CONFIRM only if you genuinely cannot find a reason to reject
- REJECT if any precondition is false, access control exists, or the attack is physically impossible
- UNCERTAIN if you need more information (live state, deployment details, etc.)
- Never CONFIRM just because graph signals are positive — verify in the source code
"""

ATTACKER_SYSTEM_PROMPT = """You are an elite smart contract exploit developer acting as an ATTACKER reviewer.

Your job is to find the most realistic, concrete attack scenario for the vulnerability hypothesis you are reviewing. Think like someone who wants to profit from this vulnerability.

## What you are reviewing
You will receive:
1. Raw source code of the contract
2. Deterministic graph signals (facts from static analysis)
3. A vulnerability hypothesis (your starting point)
4. Titan pattern hits (regex detectors)

## Your job
- Build the most concrete attack scenario you can
- Specify exact function calls, arguments, and order
- Identify what the attacker needs to start the attack
- Calculate what the attacker gains if successful
- Be honest about whether this requires mainnet state, signatures, or other external dependencies

## Critical: Provability Assessment
You MUST assess whether this exploit can be proven in an isolated Foundry test:
- Can all dependencies be mocked or deployed fresh?
- Does it require valid signatures from specific private keys you don't have?
- Does it require specific mainnet state (oracle prices, pool liquidity)?
- Does it require a specific deployment sequence you don't know?

## Output format
Return ONLY valid JSON, no markdown, no preamble:
{
  "verdict": "CONFIRM" | "REJECT" | "UNCERTAIN",
  "confidence": <integer 0-100>,
  "reasoning": "<one paragraph — your attack narrative>",
  "key_concern": "<the single most important thing>",
  "attack_steps": ["step 1", "step 2", "step 3"],
  "what_attacker_needs": ["list of prerequisites"],
  "what_success_looks_like": "<concrete assertion>",
  "provability": {
    "can_prove_in_isolation": true | false,
    "reason_if_not": "<why it cannot be proven in an isolated test>",
    "recommendation": "forge_test" | "mainnet_fork" | "manual_review"
  }
}
"""

AUDITOR_SYSTEM_PROMPT = """You are a senior smart contract auditor from a top-tier audit firm acting as an AUDITOR reviewer.

Your job is to evaluate this vulnerability finding as if you were writing a professional audit report. Apply the standards you would use at Trail of Bits, Spearbit, or Cyfrin.

## What you are reviewing
You will receive:
1. Raw source code of the contract
2. Deterministic graph signals (facts from static analysis)
3. A vulnerability hypothesis (evaluate its quality and accuracy)
4. Titan pattern hits (regex detectors)

## Your job
- Would you include this finding in a professional audit report?
- Is the severity accurately assessed?
- Is the impact realistic or overstated?
- Are there mitigating factors the hypothesis missed?
- What additional context would a developer need to understand and fix this?

## Output format
Return ONLY valid JSON, no markdown, no preamble:
{
  "verdict": "CONFIRM" | "REJECT" | "UNCERTAIN",
  "confidence": <integer 0-100>,
  "reasoning": "<one paragraph — your professional assessment>",
  "key_concern": "<the single most important thing>",
  "severity_assessment": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW",
  "mitigating_factors": ["any factors that reduce severity"],
  "recommended_fix": "<one sentence describing the fix>"
}
"""

JUDGE_SYSTEM_PROMPT = """You are the Judge in a multi-model vulnerability validation system called Critikal.

You have received verdicts from 3 independent jurors who reviewed the same vulnerability finding. Your job is to:
1. Count the votes and make a final decision
2. If confirmed, write a concrete TestWriter Brief that gives the exploit developer everything they need

## Voting rules
- 3/3 CONFIRM → CONFIRMED
- 2/3 CONFIRM → CONFIRMED
- 2/3 REJECT → REJECTED
- 3/3 REJECT → REJECTED
- 1 CONFIRM, 1 REJECT, 1 UNCERTAIN → ESCALATE
- Any other split → ESCALATE
- 2/3+ CONFIRM but attacker says can_prove_in_isolation=false → CONFIRMED_UNPROVABLE

## TestWriter Brief (write this ONLY for CONFIRMED decisions)
The brief must be so concrete and complete that a developer can write the exploit without reading the source code themselves. Include:
- Exact attack steps from the attacker juror's output
- Verified preconditions (cross-check skeptic and auditor)
- What success looks like (exact assertion)
- Specific gotchas from skeptic's key_concern
- Whether to use mainnet fork or isolated test

## Output format
Return ONLY valid JSON, no markdown, no preamble:
{
  "decision": "CONFIRMED" | "REJECTED" | "ESCALATE" | "CONFIRMED_UNPROVABLE",
  "vote_summary": "<e.g. 2/3 CONFIRM: skeptic=REJECT confidence=45, attacker=CONFIRM confidence=90, auditor=CONFIRM confidence=80>",
  "reasoning": "<why you made this decision>",
  "testwriter_brief": {
    "what_to_prove": "<one sentence: the exact vulnerable condition>",
    "attack_steps": ["step 1", "step 2", "step 3"],
    "preconditions_verified": ["precondition 1 — CONFIRMED in source", "precondition 2 — CONFIRMED by graph"],
    "what_success_looks_like": "<exact Foundry assertion>",
    "watch_out_for": "<skeptic's key concern>",
    "deployment_notes": "<what contracts need to be deployed and in what order>",
    "suggested_approach": "forge_test" | "mainnet_fork",
    "attacker_scenario": "<full attack narrative from attacker juror>"
  },
  "unprovable_reason": "<only if CONFIRMED_UNPROVABLE>",
  "rejection_reason": "<only if REJECTED>"
}
"""


# ── Juror Worker ─────────────────────────────────────────────────────

class JurorWorker:
    """
    Single juror — reviews a finding from one adversarial angle.
    Instantiated 3 times with different role prompts and LLM clients.
    """

    def __init__(
        self,
        juror_id: str,
        system_prompt: str,
        llm_client: Any,
        model_name: str,
    ):
        self.juror_id = juror_id
        self.system_prompt = system_prompt
        self.llm = llm_client
        self.model_name = model_name

    async def review(self, context_package: dict) -> JurorOutput:
        user_content = self._build_user_content(context_package)
        messages = [
            {"role": "system", "content": self.system_prompt},
            {"role": "user", "content": user_content},
        ]

        try:
            response = await asyncio.wait_for(
                self.llm.ainvoke(messages),
                timeout=120,
            )
            content = response.content if hasattr(response, "content") else str(response)
            if isinstance(content, list):
                content = "".join(
                    [c.get("text", "") if isinstance(c, dict) else str(c) for c in content]
                )

            # Track token usage
            try:
                from src.utils.token_counter import get_token_counter
                input_text = "\n".join(
                    m.get("content", "") if isinstance(m, dict) else str(m)
                    for m in messages
                )
                get_token_counter().record(
                    f"Jury_{self.juror_id}",
                    self.model_name,
                    input_text,
                    str(content),
                    getattr(response, "response_metadata", None),
                )
            except Exception:
                pass  # Never let tracking break the pipeline

            return self._parse_response(content)

        except asyncio.TimeoutError:
            logger.warning(f"[Jury] {self.juror_id} timed out")
            return JurorOutput(
                juror_id=self.juror_id,
                model=self.model_name,
                verdict="UNCERTAIN",
                confidence=0,
                reasoning="Juror timed out",
                key_concern="Timeout — could not complete review",
            )
        except Exception as e:
            logger.warning(f"[Jury] {self.juror_id} failed: {e}")
            return JurorOutput(
                juror_id=self.juror_id,
                model=self.model_name,
                verdict="UNCERTAIN",
                confidence=0,
                reasoning=f"Juror error: {str(e)[:100]}",
                key_concern="Error — could not complete review",
            )

    def _build_user_content(self, ctx: dict) -> str:
        signals = ctx.get("signals", {})
        scores = ctx.get("scores", {})
        hypothesis = ctx.get("hypothesis", {})
        pattern_hits = ctx.get("pattern_hits", [])

        lines = [
            "## Target Function",
            f"Contract: {ctx.get('contract', 'Unknown')}",
            f"Function: {ctx.get('function', 'Unknown')}",
            f"Node ID: {ctx.get('node_id', 'Unknown')}",
            "",
            "## Graph Scores (deterministic)",
            f"Structural: {scores.get('structural', 0)} | Exploitability: {scores.get('exploitability', 0)} | Final: {scores.get('final', 0)}",
            "",
            "## Graph Signals (deterministic facts from static analysis)",
        ]

        for key, val in signals.items():
            if val and val != "none" and val != [] and val is not False:
                lines.append(f"- {key}: {val}")

        if pattern_hits:
            lines += [
                "",
                "## Titan Pattern Hits (regex detectors — deterministic)",
            ]
            for hit in pattern_hits[:10]:
                lines.append(
                    f"- [{hit.get('severity', '?')}] {hit.get('id', '?')}: "
                    f"{hit.get('title', '?')} (line {hit.get('line', '?')})"
                )

        lines += [
            "",
            "## Vulnerability Hypothesis (LLM output — treat skeptically)",
            f"Class: {hypothesis.get('vulnerability_class', 'unknown')}",
            f"Confidence claimed: {hypothesis.get('confidence', 0)}",
            f"Narrative: {hypothesis.get('narrative', '')}",
            f"Attack path: {' → '.join(hypothesis.get('attack_path', []))}",
            f"Impact: {hypothesis.get('impact', '')}",
        ]

        preconditions = hypothesis.get("preconditions", [])
        if preconditions:
            lines.append("Preconditions claimed:")
            for p in preconditions:
                lines.append(f"  - {p}")

        lines += [
            "",
            "## Contract Source Code",
            "```solidity",
            ctx.get("source_code", "// Source not available"),
            "```",
            "",
            "Review the above and return your verdict as JSON.",
        ]

        return "\n".join(lines)

    def _parse_response(self, raw: str) -> JurorOutput:
        try:
            cleaned = raw.strip()
            if cleaned.startswith("```"):
                lines = cleaned.split("\n")
                cleaned = "\n".join(lines[1:-1]).strip()

            parsed = json.loads(cleaned)

            verdict = parsed.get("verdict", "UNCERTAIN")
            if verdict not in ("CONFIRM", "REJECT", "UNCERTAIN"):
                verdict = "UNCERTAIN"

            return JurorOutput(
                juror_id=self.juror_id,
                model=self.model_name,
                verdict=verdict,
                confidence=int(parsed.get("confidence", 0)),
                reasoning=parsed.get("reasoning", ""),
                key_concern=parsed.get("key_concern", ""),
                raw_output=parsed,
            )
        except Exception as e:
            logger.warning(f"[Jury] {self.juror_id} parse error: {e}")
            return JurorOutput(
                juror_id=self.juror_id,
                model=self.model_name,
                verdict="UNCERTAIN",
                confidence=0,
                reasoning=f"Parse error: {str(e)[:100]}",
                key_concern="Could not parse juror response",
            )


# ── Judge Worker ─────────────────────────────────────────────────────

class JudgeWorker:
    """
    Judge — receives all 3 juror verdicts, arbitrates, writes TestWriter Brief.
    Uses Gemini Pro for cheap arbitration.
    """

    def __init__(self, llm_client: Any, model_name: str):
        self.llm = llm_client
        self.model_name = model_name

    async def arbitrate(
        self,
        juror_outputs: list[JurorOutput],
        context_package: dict,
    ) -> JudgeOutput:
        user_content = self._build_judge_content(juror_outputs, context_package)
        messages = [
            {"role": "system", "content": JUDGE_SYSTEM_PROMPT},
            {"role": "user", "content": user_content},
        ]

        try:
            response = await asyncio.wait_for(
                self.llm.ainvoke(messages),
                timeout=120,
            )
            content = response.content if hasattr(response, "content") else str(response)
            if isinstance(content, list):
                content = "".join(
                    [c.get("text", "") if isinstance(c, dict) else str(c) for c in content]
                )

            # Track token usage
            try:
                from src.utils.token_counter import get_token_counter
                input_text = "\n".join(
                    m.get("content", "") if isinstance(m, dict) else str(m)
                    for m in messages
                )
                get_token_counter().record(
                    "Jury_Judge",
                    self.model_name,
                    input_text,
                    str(content),
                    getattr(response, "response_metadata", None),
                )
            except Exception:
                pass

            return self._parse_judge_response(content, juror_outputs)

        except Exception as e:
            logger.warning(f"[Jury] Judge failed: {e}")
            return self._fallback_arbitration(juror_outputs)

    def _build_judge_content(
        self,
        juror_outputs: list[JurorOutput],
        ctx: dict,
    ) -> str:
        hypothesis = ctx.get("hypothesis", {})
        lines = [
            "## Finding",
            f"Contract: {ctx.get('contract')} | Function: {ctx.get('function')}",
            f"Vulnerability class: {hypothesis.get('vulnerability_class')}",
            "",
            "## Juror Verdicts",
        ]

        for jo in juror_outputs:
            lines += [
                "",
                f"### {jo.juror_id.upper()} ({jo.model})",
                f"Verdict: {jo.verdict} | Confidence: {jo.confidence}",
                f"Reasoning: {jo.reasoning}",
                f"Key concern: {jo.key_concern}",
            ]

            if jo.juror_id == "attacker":
                raw = jo.raw_output
                if raw.get("attack_steps"):
                    lines.append(f"Attack steps: {json.dumps(raw.get('attack_steps', []))}")
                if raw.get("what_success_looks_like"):
                    lines.append(f"Success looks like: {raw.get('what_success_looks_like')}")
                provability = raw.get("provability", {})
                if provability:
                    lines.append(f"Can prove in isolation: {provability.get('can_prove_in_isolation')}")
                    if not provability.get("can_prove_in_isolation"):
                        lines.append(f"Reason cannot prove: {provability.get('reason_if_not')}")

            if jo.juror_id == "auditor":
                raw = jo.raw_output
                if raw.get("severity_assessment"):
                    lines.append(f"Severity: {raw.get('severity_assessment')}")
                if raw.get("recommended_fix"):
                    lines.append(f"Fix: {raw.get('recommended_fix')}")

        lines += ["", "Now arbitrate and return your decision as JSON."]
        return "\n".join(lines)

    def _parse_judge_response(
        self,
        raw: str,
        juror_outputs: list[JurorOutput],
    ) -> JudgeOutput:
        try:
            cleaned = raw.strip()
            if cleaned.startswith("```"):
                lines = cleaned.split("\n")
                cleaned = "\n".join(lines[1:-1]).strip()

            parsed = json.loads(cleaned)

            decision = parsed.get("decision", "ESCALATE")
            if decision not in ("CONFIRMED", "REJECTED", "ESCALATE", "CONFIRMED_UNPROVABLE"):
                decision = "ESCALATE"

            return JudgeOutput(
                decision=decision,
                vote_summary=parsed.get("vote_summary", ""),
                reasoning=parsed.get("reasoning", ""),
                testwriter_brief=parsed.get("testwriter_brief", {}),
                unprovable_reason=parsed.get("unprovable_reason", ""),
                rejection_reason=parsed.get("rejection_reason", ""),
            )
        except Exception as e:
            logger.warning(f"[Jury] Judge parse error: {e}")
            return self._fallback_arbitration(juror_outputs)

    def _fallback_arbitration(
        self,
        juror_outputs: list[JurorOutput],
    ) -> JudgeOutput:
        confirms = sum(1 for j in juror_outputs if j.verdict == "CONFIRM")
        rejects = sum(1 for j in juror_outputs if j.verdict == "REJECT")

        if confirms >= 2:
            decision = "CONFIRMED"
        elif rejects >= 2:
            decision = "REJECTED"
        else:
            decision = "ESCALATE"

        vote_str = " | ".join(
            f"{j.juror_id}={j.verdict}({j.confidence})" for j in juror_outputs
        )

        return JudgeOutput(
            decision=decision,
            vote_summary=f"Fallback count: {vote_str}",
            reasoning="Judge LLM failed — using vote count fallback",
            testwriter_brief={},
        )


# ── Jury Coordinator ─────────────────────────────────────────────────

class JuryCoordinator:
    """
    Orchestrates the full jury process for a single finding.
    Runs 3 jurors in parallel, then runs Judge.
    """

    def __init__(
        self,
        skeptic_llm: Any,
        attacker_llm: Any,
        auditor_llm: Any,
        judge_llm: Any,
        skeptic_model: str,
        attacker_model: str,
        auditor_model: str,
        judge_model: str,
    ):
        self.skeptic = JurorWorker(
            juror_id="skeptic",
            system_prompt=SKEPTIC_SYSTEM_PROMPT,
            llm_client=skeptic_llm,
            model_name=skeptic_model,
        )
        self.attacker = JurorWorker(
            juror_id="attacker",
            system_prompt=ATTACKER_SYSTEM_PROMPT,
            llm_client=attacker_llm,
            model_name=attacker_model,
        )
        self.auditor = JurorWorker(
            juror_id="auditor",
            system_prompt=AUDITOR_SYSTEM_PROMPT,
            llm_client=auditor_llm,
            model_name=auditor_model,
        )
        self.judge = JudgeWorker(
            llm_client=judge_llm,
            model_name=judge_model,
        )

    async def evaluate(self, context_package: dict) -> JudgeOutput:
        node_id = context_package.get("node_id", "unknown")
        print(f"  [Jury] Evaluating {node_id}...")

        juror_outputs = await asyncio.gather(
            self.skeptic.review(context_package),
            self.attacker.review(context_package),
            self.auditor.review(context_package),
            return_exceptions=True,
        )

        clean_outputs = []
        for i, output in enumerate(juror_outputs):
            if isinstance(output, Exception):
                juror_id = ["skeptic", "attacker", "auditor"][i]
                logger.warning(f"[Jury] {juror_id} raised exception: {output}")
                clean_outputs.append(JurorOutput(
                    juror_id=juror_id,
                    model="unknown",
                    verdict="UNCERTAIN",
                    confidence=0,
                    reasoning=f"Exception: {str(output)[:100]}",
                    key_concern="Juror failed with exception",
                ))
            else:
                clean_outputs.append(output)

        for jo in clean_outputs:
            print(f"  [Jury] {jo.juror_id}: {jo.verdict} (confidence={jo.confidence})")

        print(f"  [Jury] Judge arbitrating...")
        judge_output = await self.judge.arbitrate(clean_outputs, context_package)
        print(f"  [Jury] Decision: {judge_output.decision} — {judge_output.vote_summary}")

        return judge_output
