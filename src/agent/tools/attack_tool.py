"""
AttackAnalysisTool — Run attack hypothesis + assumption + execution trace workers.

Wraps: AttackHypothesisWorker, AssumptionWorker, ExecutionTraceWorker
Reads: ctx.graph, ctx.recon_context
Writes: ctx.findings, ctx.worker_outputs
"""

import asyncio
import logging
import os

from src.agent.context import ToolContext
from src.agent.tool import PermissionLevel, Tool, ToolResult

logger = logging.getLogger(__name__)


class AttackAnalysisTool(Tool):
    def name(self) -> str:
        return "run_attack_analysis"

    def description(self) -> str:
        return (
            "Run attack hypothesis workers against hotspots. Includes three parallel "
            "worker types: (1) AttackHypothesisWorker — pattern-based vulnerability "
            "detection, (2) AssumptionWorker — first-principles zero-day discovery, "
            "(3) ExecutionTraceWorker — cross-function execution path analysis. "
            "EVM-only — requires a graph with hotspots. Produces Finding objects."
        )

    def permission_level(self) -> PermissionLevel:
        return PermissionLevel.EXECUTE

    def input_schema(self) -> dict:
        return {
            "type": "object",
            "properties": {
                "hotspot_ids": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Specific hotspot node_ids to analyze. Omit to analyze all.",
                },
                "include_assumption": {
                    "type": "boolean",
                    "description": "Run AssumptionWorker in parallel (default: true)",
                    "default": True,
                },
                "include_execution_trace": {
                    "type": "boolean",
                    "description": "Run ExecutionTraceWorker in parallel (default: true)",
                    "default": True,
                },
                "timeout": {
                    "type": "integer",
                    "description": "Per-worker timeout in seconds (default: 300)",
                    "default": 300,
                },
            },
        }

    def is_available(self, ctx: ToolContext) -> bool:
        return ctx.has_graph()

    async def execute(self, params: dict, ctx: ToolContext) -> ToolResult:
        from src.llm.providers import get_worker_llm
        from src.models.finding import Finding
        from src.pipeline.base_worker import WorkerTask
        from src.pipeline.workers.attack_hypothesis_worker import AttackHypothesisWorker
        from src.utils.graph_queries import get_graph_queries

        ctx.ensure_config()
        config = ctx.config
        timeout = params.get("timeout", 300)

        # Get hotspots
        queries = get_graph_queries(ctx.graph)
        all_hotspots = queries.get_high_risk_hotspots(min_score=40)

        requested_ids = params.get("hotspot_ids")
        if requested_ids:
            hotspots = [h for h in all_hotspots if h.node_id in requested_ids]
        else:
            hotspots = all_hotspots

        if not hotspots:
            return ToolResult.success("No hotspots to analyze.")

        # Initialize workers
        attack_model = os.getenv("ATTACK_MODEL_NAME", os.getenv("WORKER_MODEL_NAME", "grok-4-1-fast-reasoning"))
        attack_llm = get_worker_llm(model_name=attack_model)
        attack_worker = AttackHypothesisWorker(graph=ctx.graph, llm_client=attack_llm)

        assumption_worker = None
        include_assumption = params.get("include_assumption", True) and config.assumption_worker_enabled
        if include_assumption:
            from src.pipeline.workers.assumption_worker import AssumptionWorker

            assumption_model = os.getenv(
                "ASSUMPTION_MODEL_NAME", os.getenv("WORKER_MODEL_NAME", "grok-4-1-fast-reasoning")
            )
            assumption_llm = get_worker_llm(model_name=assumption_model)
            assumption_worker = AssumptionWorker(graph=ctx.graph, llm_client=assumption_llm)

        execution_trace_worker = None
        include_exec = params.get("include_execution_trace", True)
        exec_enabled = os.getenv("EXECUTION_TRACE_ENABLED", "true").lower() in ("true", "1", "yes")
        if include_exec and exec_enabled:
            try:
                from src.pipeline.workers.execution_trace_worker import ExecutionTraceWorker

                exec_model = os.getenv("EXECUTION_TRACE_MODEL_NAME", os.getenv("WORKER_MODEL_NAME", "gpt-5.4-mini"))
                exec_llm = get_worker_llm(model_name=exec_model)
                execution_trace_worker = ExecutionTraceWorker(graph=ctx.graph, llm_client=exec_llm)
            except Exception as e:
                logger.warning(f"ExecutionTraceWorker init failed: {e}")

        # Build tasks
        def _budget(priority: str) -> int:
            return {"CRITICAL": 8000, "HIGH": 5000, "MEDIUM": 3000}.get(priority, 3000)

        attack_tasks = [
            WorkerTask(
                task_id=f"attack_{h.node_id}",
                task_type="attack_analysis",
                hotspot=h,
                context={"recon_context": ctx.recon_context},
                budget_tokens=_budget(h.priority),
            )
            for h in hotspots
        ]

        assumption_tasks = (
            [
                WorkerTask(
                    task_id=f"assumption_{h.node_id}",
                    task_type="assumption_analysis",
                    hotspot=h,
                    context={},
                    budget_tokens=_budget(h.priority),
                )
                for h in hotspots
            ]
            if assumption_worker
            else []
        )

        exec_tasks = (
            [
                WorkerTask(
                    task_id=f"exec_trace_{h.node_id}",
                    task_type="execution_trace",
                    hotspot=h,
                    context={},
                    budget_tokens=_budget(h.priority),
                )
                for h in hotspots
            ]
            if execution_trace_worker
            else []
        )

        # Run all in parallel with semaphore
        concurrency = int(os.getenv("ATTACK_WORKER_CONCURRENCY", "15"))
        sem = asyncio.Semaphore(concurrency)

        async def _run(worker, task):
            async with sem:
                try:
                    return await asyncio.wait_for(worker.run(task), timeout=timeout)
                except TimeoutError:
                    logger.warning(f"TIMEOUT: {task.task_id}")
                    return None
                except Exception as e:
                    logger.error(f"EXCEPTION: {task.task_id}: {e}")
                    return None

        all_coros = (
            [_run(attack_worker, t) for t in attack_tasks]
            + [_run(assumption_worker, t) for t in assumption_tasks]
            + [_run(execution_trace_worker, t) for t in exec_tasks]
        )

        all_outputs = await asyncio.gather(*all_coros, return_exceptions=True)

        # Split results
        n_attack = len(attack_tasks)
        n_assumption = len(assumption_tasks)
        attack_outputs = all_outputs[:n_attack]
        assumption_outputs = all_outputs[n_attack : n_attack + n_assumption]
        exec_outputs = all_outputs[n_attack + n_assumption :]

        # Convert to Findings
        attack_conf_floor = int(os.getenv("ATTACK_CONFIDENCE_FLOOR", "50"))
        speculative_floor = int(os.getenv("ATTACK_SPECULATIVE_FLOOR", "30"))
        new_findings = 0

        def _process_outputs(outputs, hotspot_list, worker_type):
            nonlocal new_findings
            for output, hotspot in zip(outputs, hotspot_list):
                if output is None or isinstance(output, (Exception, BaseException)):
                    continue
                conf = getattr(output, "confidence", 0)
                floor = 25 if worker_type == "assumption" else attack_conf_floor
                spec_floor = 15 if worker_type == "assumption" else speculative_floor

                if conf >= floor:
                    finding = Finding.from_worker_output(output, hotspot)
                    finding.contribute_score(
                        f"{worker_type}_worker",
                        conf // 3,
                        f"{worker_type} confidence {conf}",
                    )
                    ctx.add_finding(finding)
                    new_findings += 1
                elif conf >= spec_floor:
                    finding = Finding.from_worker_output(output, hotspot)
                    finding.is_speculative = True
                    finding.contribute_score(
                        f"{worker_type}_worker",
                        conf // 5,
                        f"speculative {worker_type} confidence {conf}",
                    )
                    ctx.add_finding(finding)
                    new_findings += 1

                if not isinstance(output, (Exception, BaseException)):
                    dump = output.model_dump() if hasattr(output, "model_dump") else str(output)
                    ctx.worker_outputs.append(dump)

        _process_outputs(attack_outputs, hotspots, "attack")
        _process_outputs(assumption_outputs, hotspots, "assumption")
        _process_outputs(exec_outputs, hotspots, "execution_trace")

        # Summary
        succeeded = sum(1 for o in all_outputs if o is not None and not isinstance(o, (Exception, BaseException)))
        failed = len(all_outputs) - succeeded

        return ToolResult.success(
            f"Attack analysis complete.\n"
            f"Workers run: {len(all_outputs)} ({n_attack} attack, {n_assumption} assumption, {len(exec_tasks)} exec_trace)\n"
            f"Succeeded: {succeeded}, Failed/Timeout: {failed}\n"
            f"New findings generated: {new_findings}\n"
            f"Total findings so far: {len(ctx.findings)}",
            new_findings=new_findings,
            total_findings=len(ctx.findings),
        )
