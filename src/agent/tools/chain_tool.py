"""
ChainAnalysisTool — Link findings into multi-step exploit chains.

Wraps: run_chain_analysis() from chain_analyzer.py
Reads: ctx.findings
Writes: updates finding chain metadata (chain_ids, chain_role, chain_severity_upgrade)
"""

from src.agent.context import ToolContext
from src.agent.tool import PermissionLevel, Tool, ToolResult


class ChainAnalysisTool(Tool):
    def name(self) -> str:
        return "run_chain_analysis"

    def description(self) -> str:
        return (
            "Deterministic postcondition-to-precondition matching across findings. "
            "Links findings into multi-step exploit chains (e.g., finding A enables "
            "finding B). No LLM calls — pure graph analysis. Upgrades severity for "
            "chained exploits."
        )

    def permission_level(self) -> PermissionLevel:
        return PermissionLevel.NONE

    def input_schema(self) -> dict:
        return {"type": "object", "properties": {}}

    def is_available(self, ctx: ToolContext) -> bool:
        return len(ctx.findings) >= 2

    async def execute(self, params: dict, ctx: ToolContext) -> ToolResult:
        ctx.ensure_config()
        if not ctx.config.chain_analysis_enabled:
            return ToolResult.success("Chain analysis is disabled in config.")

        if len(ctx.findings) < 2:
            return ToolResult.success("Need at least 2 findings for chain analysis.")

        from src.pipeline.chain_analyzer import run_chain_analysis

        try:
            chains = run_chain_analysis(ctx.findings)
        except Exception as e:
            return ToolResult.error(f"Chain analysis failed: {e}")

        chain_count = len(chains) if chains else 0
        upgraded = 0
        for chain in chains or []:
            if getattr(chain, "severity_upgraded", False):
                upgraded += 1

        return ToolResult.success(
            f"Chain analysis complete.\nChains discovered: {chain_count}\nSeverity upgrades: {upgraded}",
            chains=chain_count,
            upgrades=upgraded,
        )
