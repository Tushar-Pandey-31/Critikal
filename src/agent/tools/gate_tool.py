"""
GateFilterTool — 4-gate pre-filter to kill obvious false positives.

Wraps: gate_evaluate() from jury_worker.py
Reads: ctx.findings, ctx.graph
Writes: updates finding.gate_verdict, finding.plausibility_score
"""

import asyncio
import logging
import os

from src.agent.context import ToolContext
from src.agent.tool import PermissionLevel, Tool, ToolResult

logger = logging.getLogger(__name__)


class GateFilterTool(Tool):

    def name(self) -> str:
        return "run_gate_filter"

    def description(self) -> str:
        return (
            "Run 4-gate pre-filter on current findings to kill obvious false positives. "
            "Gates: (1) Refutation — can the hypothesis be trivially disproven? "
            "(2) Reachability — is the vulnerable function reachable from external entry? "
            "(3) Trigger — does a realistic trigger condition exist? "
            "(4) Impact — is the impact meaningful? "
            "Findings that pass get a plausibility boost. Findings that fail are demoted."
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
                    "description": "Indices of specific findings to gate. Omit to gate all.",
                },
            },
        }

    def is_available(self, ctx: ToolContext) -> bool:
        return len(ctx.findings) > 0

    async def execute(self, params: dict, ctx: ToolContext) -> ToolResult:
        from src.llm.providers import get_worker_llm
        from src.pipeline.workers.jury_worker import gate_evaluate
        from src.utils.graph_queries import get_function_context

        ctx.ensure_config()
        if not ctx.config.gate_enabled:
            return ToolResult.success("Gate filter is disabled in config.")

        gate_model = os.getenv("GATE_MODEL_NAME", "gpt-5.4-mini")
        gate_llm = get_worker_llm(model_name=gate_model)

        indices = params.get("finding_indices")
        findings_to_gate = (
            [ctx.findings[i] for i in indices if i < len(ctx.findings)]
            if indices
            else list(ctx.findings)
        )

        if not findings_to_gate:
            return ToolResult.success("No findings to gate.")

        concurrency = int(os.getenv("JURY_CONCURRENCY", "5"))
        sem = asyncio.Semaphore(concurrency)

        passed = 0
        refuted = 0
        demoted = 0

        async def _gate_one(finding):
            nonlocal passed, refuted, demoted
            async with sem:
                try:
                    # gate_evaluate signature: (finding, source_code: str, llm_client)
                    source_code = ""
                    try:
                        fc = get_function_context(ctx.graph, finding.hotspot_node_id)
                        source_code = fc.get("source_code") or fc.get("code") or ""
                    except Exception:
                        pass

                    result = await asyncio.wait_for(
                        gate_evaluate(finding, source_code, gate_llm),
                        timeout=120,
                    )
                    finding.gate_verdict = result.verdict
                    finding.gate_failed = result.gate if result.verdict != "PASS" else None
                    finding.gate_quote = result.quote

                    if result.verdict == "PASS":
                        finding.contribute_score("gate_pass", 20, "Passed 4-gate filter")
                        passed += 1
                    elif result.verdict == "GATE_REFUTED":
                        finding.contribute_score("gate_refuted", -30, f"Refuted at gate {result.gate}")
                        refuted += 1
                    elif result.verdict == "GATE_DEMOTED":
                        finding.contribute_score("gate_demoted", -15, f"Demoted at gate {result.gate}")
                        demoted += 1
                except TimeoutError:
                    logger.warning(f"Gate timeout for finding: {finding.title}")
                except Exception as e:
                    logger.error(f"Gate error: {e}")

        await asyncio.gather(*[_gate_one(f) for f in findings_to_gate])

        return ToolResult.success(
            f"Gate filter complete.\n"
            f"Processed: {len(findings_to_gate)}\n"
            f"Passed: {passed}\n"
            f"Refuted: {refuted}\n"
            f"Demoted: {demoted}",
            passed=passed,
            refuted=refuted,
            demoted=demoted,
        )
