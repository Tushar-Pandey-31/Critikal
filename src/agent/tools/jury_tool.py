"""
JuryTool — Multi-model adversarial debate on findings.

Wraps: JuryCoordinator from jury_worker.py (3 jurors + 1 judge)
Reads: ctx.findings, ctx.graph
Writes: updates finding.jury_decision, jury_vote_summary, jury_reasoning
"""

import asyncio
import logging
import os

from src.agent.context import ToolContext
from src.agent.tool import PermissionLevel, Tool, ToolResult

logger = logging.getLogger(__name__)


class JuryTool(Tool):

    def name(self) -> str:
        return "run_jury_debate"

    def description(self) -> str:
        return (
            "Run multi-model adversarial jury debate on findings. "
            "3 jurors (Skeptic, Attacker, Auditor) debate each finding, "
            "then a Judge synthesizes the verdict. Each role uses a different "
            "LLM for diversity of reasoning. Findings are updated with jury "
            "decisions: CONFIRMED, PARTIAL, CONTESTED, or REFUTED."
        )

    def permission_level(self) -> PermissionLevel:
        return PermissionLevel.EXECUTE

    def input_schema(self) -> dict:
        return {
            "type": "object",
            "properties": {
                "finding_indices": {
                    "type": "array",
                    "items": {"type": "integer"},
                    "description": "Indices of specific findings to debate. Omit for all gate-passed findings.",
                },
            },
        }

    def is_available(self, ctx: ToolContext) -> bool:
        return len(ctx.findings) > 0

    async def execute(self, params: dict, ctx: ToolContext) -> ToolResult:
        from src.hotspot_engine import Hotspot
        from src.llm.providers import get_worker_llm
        from src.pipeline.workers.jury_context import build_jury_context_package
        from src.pipeline.workers.jury_worker import JuryCoordinator
        from src.utils.graph_queries import get_function_context

        ctx.ensure_config()
        if not ctx.config.jury_enabled:
            return ToolResult.success("Jury system is disabled in config.")

        # Select findings
        indices = params.get("finding_indices")
        if indices:
            target_findings = [ctx.findings[i] for i in indices if i < len(ctx.findings)]
        else:
            # Default: gate-passed findings only
            target_findings = [
                f for f in ctx.findings
                if getattr(f, "gate_verdict", None) == "PASS" or getattr(f, "gate_verdict", None) is None
            ]

        if not target_findings:
            return ToolResult.success("No findings eligible for jury debate.")

        # Jury models
        skeptic_model = os.getenv("JURY_SKEPTIC_MODEL", "gpt-5.5")
        attacker_model = os.getenv("JURY_ATTACKER_MODEL", "grok-4-1-fast-reasoning")
        auditor_model = os.getenv("JURY_AUDITOR_MODEL", "gpt-5.4-mini")
        judge_model = os.getenv("JURY_JUDGE_MODEL", "grok-4-1-fast-reasoning")

        jury_coordinator = JuryCoordinator(
            skeptic_llm=get_worker_llm(model_name=skeptic_model),
            attacker_llm=get_worker_llm(model_name=attacker_model),
            auditor_llm=get_worker_llm(model_name=auditor_model),
            judge_llm=get_worker_llm(model_name=judge_model),
            skeptic_model=skeptic_model,
            attacker_model=attacker_model,
            auditor_model=auditor_model,
            judge_model=judge_model,
        )

        concurrency = int(os.getenv("JURY_CONCURRENCY", "5"))
        sem = asyncio.Semaphore(concurrency)

        confirmed = 0
        contested = 0
        refuted = 0

        async def _debate(finding):
            nonlocal confirmed, contested, refuted
            async with sem:
                try:
                    # JuryCoordinator.evaluate expects a context_package dict,
                    # not a Finding — build it the same way the legacy pipeline does.
                    raw_source = ""
                    try:
                        fc = get_function_context(ctx.graph, finding.hotspot_node_id)
                        raw_source = fc.get("source_code") or fc.get("code") or ""
                    except Exception:
                        pass

                    hotspot = Hotspot(
                        node_id=finding.hotspot_node_id,
                        contract=getattr(finding, "affected_contract", "") or "",
                        function=getattr(finding, "affected_function", "") or "",
                        risk_score=getattr(finding, "risk_score", 0) or getattr(finding, "confidence", 0),
                        risk_categories=[getattr(finding, "vulnerability_class", "unknown")],
                        signals={},
                        priority=getattr(finding, "severity_estimate", "MEDIUM") or "MEDIUM",
                    )

                    context_package = build_jury_context_package(
                        finding=finding,
                        hotspot=hotspot,
                        graph=ctx.graph,
                        raw_source_code=raw_source,
                    )

                    judge_output = await asyncio.wait_for(
                        jury_coordinator.evaluate(context_package),
                        timeout=300,
                    )
                    # JudgeOutput is a dataclass, not a dict.
                    decision = judge_output.decision
                    finding.jury_decision = decision
                    finding.jury_vote_summary = judge_output.vote_summary
                    finding.jury_reasoning = judge_output.reasoning

                    if decision == "CONFIRMED":
                        finding.contribute_score("jury_confirmed", 25, "Jury confirmed")
                        confirmed += 1
                    elif decision in ("ESCALATE", "CONFIRMED_UNPROVABLE"):
                        finding.contribute_score("jury_contested", 5, f"Jury: {decision}")
                        contested += 1
                    elif decision == "REJECTED":
                        finding.contribute_score("jury_refuted", -20, "Jury rejected")
                        finding.jury_rejection_reason = judge_output.rejection_reason or judge_output.reasoning
                        refuted += 1
                except TimeoutError:
                    logger.warning(f"Jury timeout for: {finding.title}")
                except Exception as e:
                    logger.error(f"Jury error: {e}")

        await asyncio.gather(*[_debate(f) for f in target_findings])

        return ToolResult.success(
            f"Jury debate complete.\n"
            f"Debated: {len(target_findings)}\n"
            f"Confirmed: {confirmed}\n"
            f"Contested/Partial: {contested}\n"
            f"Refuted: {refuted}",
            confirmed=confirmed,
            contested=contested,
            refuted=refuted,
        )
