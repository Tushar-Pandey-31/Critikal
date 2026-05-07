"""
ThreatIntelTool — Threat profiling and attack vector matching.

Wraps: ThreatProfiler + AttackVectorDB
"""

from src.agent.context import ToolContext
from src.agent.tool import PermissionLevel, Tool, ToolResult


class ThreatIntelTool(Tool):

    def name(self) -> str:
        return "threat_intel"

    def description(self) -> str:
        return (
            "Classify the protocol type and match against known attack vectors. "
            "Returns threat profile (adversary types, invariants, composability risks) "
            "and precomputed attack vectors relevant to this protocol."
        )

    def permission_level(self) -> PermissionLevel:
        return PermissionLevel.READ_ONLY

    def input_schema(self) -> dict:
        return {"type": "object", "properties": {}}

    def is_available(self, ctx: ToolContext) -> bool:
        return ctx.has_graph()

    async def execute(self, params: dict, ctx: ToolContext) -> ToolResult:
        ctx.ensure_config()

        try:
            from src.intelligence.attack_vector_db import AttackVectorDB
            from src.intelligence.threat_profiler import ThreatProfiler
        except ImportError:
            return ToolResult.error("Threat intelligence module not available.")

        results = []

        if ctx.config.threat_profiler_enabled:
            try:
                profiler = ThreatProfiler()
                protocol_types = profiler.classify(ctx.graph)
                primary = protocol_types[0] if protocol_types else {"type": "unknown", "confidence": 0}
                profile = profiler.get_threat_profile(primary["type"])
                results.append(
                    f"Protocol: {primary['type']} (confidence: {primary['confidence']})\n"
                    f"Adversaries: {len(profile.adversaries)}\n"
                    f"Invariants: {len(profile.invariants)}\n"
                    f"Composability risks: {len(profile.composability_risks)}"
                )
            except Exception as e:
                results.append(f"Threat profiler failed: {e}")

        if ctx.config.attack_vector_db_enabled:
            try:
                vector_db = AttackVectorDB()
                proto_list = [p.get("type", "unknown") for p in protocol_types] if 'protocol_types' in locals() else []
                matched = vector_db.match_vectors(ctx.graph, proto_list)
                results.append(f"Matched {len(matched)} attack vectors.")
            except Exception as e:
                results.append(f"Attack vector DB failed: {e}")

        return ToolResult.success("\n".join(results) if results else "No threat intel available.")
