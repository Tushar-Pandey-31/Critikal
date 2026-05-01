"""
HotspotTool — Identify high-risk functions from the knowledge graph.

Wraps: GraphQueries.get_high_risk_hotspots() + risk aggregation
Reads: ctx.graph
"""

import os
from src.agent.tool import Tool, ToolResult, PermissionLevel
from src.agent.context import ToolContext


class HotspotTool(Tool):

    def name(self) -> str:
        return "find_hotspots"

    def description(self) -> str:
        return (
            "Identify high-risk functions in the codebase using the knowledge graph. "
            "Returns ranked hotspots with risk scores across multiple dimensions "
            "(structural, exploitability, impact). Also returns reentrancy risks, "
            "unprotected mutators, privilege escalation paths, and external calls. "
            "EVM-only — requires a Slither-derived graph."
        )

    def permission_level(self) -> PermissionLevel:
        return PermissionLevel.NONE

    def input_schema(self) -> dict:
        return {
            "type": "object",
            "properties": {
                "min_score": {
                    "type": "integer",
                    "description": "Minimum risk score threshold (default 70, lower for small codebases)",
                    "default": 70,
                },
            },
        }

    def is_available(self, ctx: ToolContext) -> bool:
        return ctx.has_graph()

    async def execute(self, params: dict, ctx: ToolContext) -> ToolResult:
        from src.utils.graph_queries import GraphQueries, get_graph_queries

        min_score = params.get("min_score", 70)

        try:
            queries = get_graph_queries(ctx.graph)

            hotspots = queries.get_high_risk_hotspots(min_score=min_score)

            # Adaptive threshold for small graphs
            if not hotspots and ctx.graph.number_of_nodes() < 50:
                lowered = max(25, min_score - 15)
                hotspots = queries.get_high_risk_hotspots(
                    min_score=lowered,
                    min_structural=10,
                    min_exploitability=5,
                    require_exploit_target=False,
                )

            reentrancy = queries.get_reentrancy_risks()
            unprotected = queries.get_unprotected_mutators()
            escalation = queries.get_privilege_escalation_risks()
            external_calls = queries.get_external_call_functions()
        except Exception as e:
            return ToolResult.error(f"Graph query failed: {e}")

        hotspot_list = [
            {
                "node_id": h.node_id,
                "contract": h.contract,
                "function": h.function,
                "risk_score": h.risk_score,
                "priority": h.priority,
                "risk_categories": h.risk_categories,
            }
            for h in hotspots
        ]

        summary_lines = [f"Found {len(hotspots)} hotspot(s):"]
        for h in hotspots[:10]:
            summary_lines.append(
                f"  [{h.priority}] {h.contract}.{h.function} "
                f"(score={h.risk_score}, categories={h.risk_categories})"
            )
        if len(hotspots) > 10:
            summary_lines.append(f"  ... and {len(hotspots) - 10} more")

        summary_lines.append(f"\nReentrancy risks: {len(reentrancy)}")
        summary_lines.append(f"Unprotected mutators: {len(unprotected)}")
        summary_lines.append(f"External calls: {len(external_calls)}")

        return ToolResult.success(
            "\n".join(summary_lines),
            hotspots=hotspot_list,
            reentrancy_count=len(reentrancy),
            unprotected_count=len(unprotected),
        )
