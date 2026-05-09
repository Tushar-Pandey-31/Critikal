"""
DepthAnalysisTool — Re-analyze uncertain findings with specialized depth workers.

Wraps: StateTraceDepthWorker, EdgeCaseDepthWorker, ExternalDepthWorker
Reads: ctx.findings, ctx.graph
Writes: updates finding confidence and evidence
"""

import asyncio
import logging
import os

from src.agent.context import ToolContext
from src.agent.tool import PermissionLevel, Tool, ToolResult

logger = logging.getLogger(__name__)


class DepthAnalysisTool(Tool):
    def name(self) -> str:
        return "run_depth_analysis"

    def description(self) -> str:
        return (
            "Re-analyze uncertain or contested findings with specialized depth workers. "
            "Three worker types: StateTrace (state variable tracking), EdgeCase (boundary "
            "conditions), External (cross-protocol interactions). Automatically routes "
            "each finding to the most appropriate worker based on vulnerability class."
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
                    "description": "Indices of findings to re-analyze. Omit for all uncertain findings.",
                },
            },
        }

    def is_available(self, ctx: ToolContext) -> bool:
        return len(ctx.findings) > 0

    async def execute(self, params: dict, ctx: ToolContext) -> ToolResult:
        from src.llm.providers import get_worker_llm
        from src.pipeline.workers.depth_workers import (
            EdgeCaseDepthWorker,
            ExternalDepthWorker,
            StateTraceDepthWorker,
            _route_to_depth_worker,
        )
        from src.utils.graph_queries import get_function_context

        ctx.ensure_config()
        if not ctx.config.depth_workers_enabled:
            return ToolResult.success("Depth workers are disabled in config.")

        depth_model = os.getenv("DEPTH_MODEL_NAME", os.getenv("WORKER_MODEL_NAME", "gpt-5.4-mini"))
        depth_llm = get_worker_llm(model_name=depth_model)

        workers = {
            "state_trace": StateTraceDepthWorker(llm_client=depth_llm, model_name=depth_model),
            "edge_case": EdgeCaseDepthWorker(llm_client=depth_llm, model_name=depth_model),
            "external": ExternalDepthWorker(llm_client=depth_llm, model_name=depth_model),
        }

        indices = params.get("finding_indices")
        if indices:
            target = [ctx.findings[i] for i in indices if i < len(ctx.findings)]
        else:
            target = [
                f
                for f in ctx.findings
                if getattr(f, "jury_decision", None) in ("CONTESTED", "PARTIAL", None)
                and getattr(f, "gate_verdict", None) != "GATE_REFUTED"
            ]

        if not target:
            return ToolResult.success("No uncertain findings to re-analyze.")

        sem = asyncio.Semaphore(5)
        improved = 0

        async def _depth(finding):
            nonlocal improved
            async with sem:
                try:
                    # analyze signature: (finding, graph, source_code, is_da_pass=False)
                    source_code = ""
                    try:
                        fc = get_function_context(ctx.graph, finding.hotspot_node_id)
                        source_code = fc.get("source_code") or fc.get("code") or ""
                    except Exception:
                        pass

                    worker_type = _route_to_depth_worker(finding)
                    worker = workers.get(worker_type, workers["state_trace"])
                    is_da_pass = getattr(finding, "gate_verdict", None) == "GATE_DEMOTED"
                    result = await asyncio.wait_for(
                        worker.analyze(finding, ctx.graph, source_code, is_da_pass),
                        timeout=180,
                    )
                    if result and result.refined_confidence > getattr(finding, "confidence", 0):
                        finding.contribute_score(
                            "depth_worker",
                            10,
                            f"Depth {worker_type}: confidence raised to {result.refined_confidence}",
                        )
                        improved += 1
                    finding.depth_pass_count = getattr(finding, "depth_pass_count", 0) + 1
                except TimeoutError:
                    logger.warning(f"Depth timeout for: {finding.title}")
                except Exception as e:
                    logger.error(f"Depth error: {e}")

        await asyncio.gather(*[_depth(f) for f in target])

        return ToolResult.success(
            f"Depth analysis complete.\nAnalyzed: {len(target)}\nConfidence improved: {improved}",
            analyzed=len(target),
            improved=improved,
        )
