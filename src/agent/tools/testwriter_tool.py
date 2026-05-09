"""
TestWriterTool — Generate Foundry PoC exploit tests.

Wraps: TestWriterWorker.run() — Phoenix loop with self-correction
EVM-only.
Reads: ctx.findings, ctx.repo_path
Writes: updates finding.exploit_success, finding.test_code
"""

import asyncio
import logging
import os

from src.agent.context import ToolContext
from src.agent.tool import PermissionLevel, Tool, ToolResult

logger = logging.getLogger(__name__)


class TestWriterTool(Tool):
    def name(self) -> str:
        return "write_exploit_test"

    def description(self) -> str:
        return (
            "Generate Foundry .t.sol proof-of-concept exploit tests for findings. "
            "Uses a Phoenix loop with self-correction: generates test, compiles, "
            "runs, and iterates on failures up to N attempts. EVM-only. "
            "Requires a cloned repo with Foundry setup."
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
                    "description": "Indices of findings to write PoCs for. Omit for all eligible.",
                },
                "max_concurrent": {
                    "type": "integer",
                    "description": "Max parallel test writers (default: 3)",
                    "default": 3,
                },
            },
        }

    def is_available(self, ctx: ToolContext) -> bool:
        return ctx.repo_path is not None and len(ctx.findings) > 0

    async def execute(self, params: dict, ctx: ToolContext) -> ToolResult:
        from src.llm.providers import get_worker_llm
        from src.pipeline.base_worker import WorkerTask
        from src.pipeline.workers.test_writer_worker import TestWriterWorker

        ctx.ensure_config()
        if not ctx.config.testwriter_enabled:
            return ToolResult.success("TestWriter is disabled in config.")

        test_model = os.getenv("TEST_WRITER_MODEL_NAME", os.getenv("WORKER_MODEL_NAME", "grok-code-fast-1"))
        test_llm = get_worker_llm(model_name=test_model)

        indices = params.get("finding_indices")
        promote_threshold = int(os.getenv("PROMOTE_THRESHOLD", "50"))

        if indices:
            eligible = [ctx.findings[i] for i in indices if i < len(ctx.findings)]
        else:
            eligible = [
                f
                for f in ctx.findings
                if getattr(f, "plausibility_score", 0) >= promote_threshold
                and not getattr(f, "exploit_success", False)
                and getattr(f, "gate_verdict", None) != "GATE_REFUTED"
            ]

        if not eligible:
            return ToolResult.success(
                f"No findings eligible for PoC generation (need plausibility >= {promote_threshold})."
            )

        max_concurrent = params.get("max_concurrent", 3)
        sem = asyncio.Semaphore(max_concurrent)
        proven = 0
        compiled = 0
        failed = 0

        async def _write_test(finding):
            nonlocal proven, compiled, failed
            async with sem:
                try:
                    worker = TestWriterWorker(
                        llm_client=test_llm,
                        graph=ctx.graph,
                    )
                    task = WorkerTask(
                        task_id=f"poc_{finding.id}",
                        task_type="test_writer",
                        context={
                            "finding": finding,
                            "repo_path": str(ctx.repo_path),
                        },
                    )
                    output = await asyncio.wait_for(worker.run(task), timeout=600)
                    if output and output.raw_output.get("exploit_success"):
                        finding.exploit_success = True
                        finding.test_code = output.raw_output.get("test_code", "")
                        finding.status = "PROVEN"
                        finding.contribute_score("poc_pass", 30, "PoC exploit succeeded")
                        proven += 1
                    elif output and output.raw_output.get("compiled"):
                        compiled += 1
                    else:
                        failed += 1
                except TimeoutError:
                    logger.warning(f"TestWriter timeout for: {finding.title}")
                    failed += 1
                except Exception as e:
                    logger.error(f"TestWriter error: {e}")
                    failed += 1

        await asyncio.gather(*[_write_test(f) for f in eligible])

        return ToolResult.success(
            f"TestWriter complete.\n"
            f"Attempted: {len(eligible)}\n"
            f"PROVEN (exploit passed): {proven}\n"
            f"Compiled but failed: {compiled}\n"
            f"Failed: {failed}",
            proven=proven,
            compiled=compiled,
            failed=failed,
        )
