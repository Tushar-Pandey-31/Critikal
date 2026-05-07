"""
RAGSearchTool — Search historical exploit knowledge base.

Wraps: search_security_knowledge() + rag_mandatory_sweep()
Reads: ctx.findings (for sweep mode)
"""

from src.agent.context import ToolContext
from src.agent.tool import PermissionLevel, Tool, ToolResult


class RAGSearchTool(Tool):

    def name(self) -> str:
        return "search_exploits"

    def description(self) -> str:
        return (
            "Search the historical exploit knowledge base (ChromaDB + HuggingFace "
            "embeddings) for similar vulnerabilities. Use for: checking if a pattern "
            "has been exploited before, finding precedents, or running a mandatory "
            "RAG sweep across all current findings to compute confidence_rag_match."
        )

    def permission_level(self) -> PermissionLevel:
        return PermissionLevel.READ_ONLY

    def input_schema(self) -> dict:
        return {
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "Free-text search query (e.g., 'reentrancy ERC777 tokens')",
                },
                "sweep_findings": {
                    "type": "boolean",
                    "description": "Run RAG sweep across all current findings (updates confidence_rag_match)",
                    "default": False,
                },
            },
        }

    async def execute(self, params: dict, ctx: ToolContext) -> ToolResult:
        query = params.get("query", "")
        sweep = params.get("sweep_findings", False)

        # Direct query
        if query and not sweep:
            from src.pipeline.tools import search_security_knowledge
            try:
                result = search_security_knowledge.invoke(query)
                return ToolResult.success(result)
            except Exception as e:
                return ToolResult.error(f"RAG search failed: {e}")

        # Sweep mode
        if sweep and ctx.findings:
            ctx.ensure_config()
            if not ctx.config.rag_enabled:
                return ToolResult.success("RAG is disabled in config.")

            from src.pipeline.tools import search_security_knowledge
            matched = 0
            for finding in ctx.findings:
                search_query = f"{finding.title} {finding.hypothesis}"
                try:
                    result = search_security_knowledge.invoke(search_query)
                    if result and "No results" not in result and "Error" not in result:
                        finding.confidence_rag_match = min(
                            100, getattr(finding, "confidence_rag_match", 0) + 15
                        )
                        finding.contribute_score("rag_match", 10, "RAG precedent found")
                        matched += 1
                except Exception:
                    pass

            return ToolResult.success(
                f"RAG sweep complete. {matched}/{len(ctx.findings)} findings matched exploit precedents.",
                matched=matched,
            )

        return ToolResult.success("No query provided and sweep not requested.")
