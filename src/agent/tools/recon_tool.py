"""
ReconTool — Gather protocol-level intelligence before analysis.

Wraps: ReconWorker.run()
Sets: ctx.recon_context
"""

import os
from src.agent.tool import Tool, ToolResult, PermissionLevel
from src.agent.context import ToolContext


class ReconTool(Tool):

    def name(self) -> str:
        return "run_recon"

    def description(self) -> str:
        return (
            "Gather protocol-level intelligence: protocol type classification, "
            "on-chain data (Etherscan), documentation, NatSpec comments, compiler "
            "info, test intent analysis. Should be run early — its output enriches "
            "all downstream analysis."
        )

    def permission_level(self) -> PermissionLevel:
        return PermissionLevel.EXECUTE

    def input_schema(self) -> dict:
        return {
            "type": "object",
            "properties": {},
        }

    def is_available(self, ctx: ToolContext) -> bool:
        return ctx.repo_path is not None

    async def execute(self, params: dict, ctx: ToolContext) -> ToolResult:
        from src.llm.providers import get_worker_llm
        from src.agents.workers.recon_worker import ReconWorker
        from src.agents.base_worker import WorkerTask

        ctx.ensure_config()

        recon_model = os.getenv(
            "RECON_MODEL_NAME",
            os.getenv("WORKER_MODEL_NAME", "gemini-3-flash-preview"),
        )
        recon_llm = get_worker_llm(model_name=recon_model)

        etherscan = None
        if ctx.config.etherscan_enabled:
            from src.tools.etherscan_client import EtherscanClient
            etherscan = EtherscanClient()

        recon_worker = ReconWorker(
            graph=ctx.graph,
            llm_client=recon_llm,
            etherscan_client=etherscan,
        )

        repo_path = str(ctx.repo_path) if ctx.repo_path else None
        task = WorkerTask(
            task_id="recon_protocol",
            task_type="recon",
            context={
                "contract_names": ctx.contract_names,
                "contract_addresses": ctx.contract_addresses,
                "repo_url": ctx.repo_url,
                "repo_path": repo_path,
            },
        )

        try:
            output = await recon_worker.run(task)
        except Exception as e:
            return ToolResult.error(f"Recon failed: {e}")

        ctx.recon_context = output.raw_output

        # Build summary
        protocol_type = output.raw_output.get("protocol_classification", {}).get("type", "unknown")
        prior_exploits = output.raw_output.get("onchain_risk_signals", {}).get(
            "previous_exploits_detected", False
        )
        intel_sources = [k for k, v in output.raw_output.items() if v]

        summary = (
            f"Recon complete.\n"
            f"Protocol type: {protocol_type}\n"
            f"Prior exploits detected: {prior_exploits}\n"
            f"Intel sources gathered: {', '.join(intel_sources)}"
        )

        return ToolResult.success(summary, protocol_type=protocol_type)
