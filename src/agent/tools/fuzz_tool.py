"""
FuzzGeneratorTool — Generate Foundry invariant fuzz tests.

Wraps: FuzzGeneratorWorker.run()
EVM-only, for CRITICAL proven findings.
"""

import asyncio
import logging
import os

from src.agent.context import ToolContext
from src.agent.tool import PermissionLevel, Tool, ToolResult

logger = logging.getLogger(__name__)


class FuzzGeneratorTool(Tool):
    def name(self) -> str:
        return "generate_fuzz_tests"

    def description(self) -> str:
        return (
            "Generate Foundry invariant fuzz tests for findings. Targets CRITICAL "
            "findings that have proven exploits. Creates property-based tests that "
            "Foundry's fuzzer can run to find edge cases."
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
                    "description": "Indices of findings to fuzz. Omit for all critical proven.",
                },
            },
        }

    def is_available(self, ctx: ToolContext) -> bool:
        return ctx.repo_path is not None and len(ctx.findings) > 0

    async def execute(self, params: dict, ctx: ToolContext) -> ToolResult:
        from src.llm.providers import get_worker_llm
        from src.pipeline.base_worker import WorkerTask
        from src.pipeline.workers.fuzz_generator import FuzzGeneratorWorker

        ctx.ensure_config()
        if not ctx.config.fuzz_generator_enabled:
            return ToolResult.success("Fuzz generator is disabled in config.")

        indices = params.get("finding_indices")
        if indices:
            eligible = [ctx.findings[i] for i in indices if i < len(ctx.findings)]
        else:
            eligible = [
                f
                for f in ctx.findings
                if getattr(f, "exploit_success", False) and getattr(f, "severity_estimate", "").upper() == "CRITICAL"
            ]

        if not eligible:
            return ToolResult.success("No critical proven findings eligible for fuzz generation.")

        fuzz_model = os.getenv("FUZZ_MODEL_NAME", os.getenv("WORKER_MODEL_NAME", "grok-code-fast-1"))
        fuzz_llm = get_worker_llm(model_name=fuzz_model)

        generated = 0
        for finding in eligible:
            try:
                worker = FuzzGeneratorWorker(
                    llm_client=fuzz_llm,
                    graph=ctx.graph,
                )
                task = WorkerTask(
                    task_id=f"fuzz_{finding.id}",
                    task_type="fuzz_generator",
                    context={
                        "finding": finding,
                        "repo_path": str(ctx.repo_path),
                    },
                )
                output = await asyncio.wait_for(worker.run(task), timeout=300)
                if output:
                    generated += 1
            except Exception as e:
                logger.error(f"Fuzz generation error: {e}")

        return ToolResult.success(
            f"Fuzz generation complete. Generated {generated}/{len(eligible)} fuzz tests.",
            generated=generated,
        )
