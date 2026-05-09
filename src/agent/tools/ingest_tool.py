"""
IngestTool — Clone/copy repo, run Slither analysis, build knowledge graph.

Wraps: RepoManager + AnalysisEngine + GraphBuilder
Sets: ctx.repo_path, ctx.graph, ctx.contract_names
"""

from pathlib import Path

import networkx as nx

from src.agent.context import ToolContext
from src.agent.tool import PermissionLevel, Tool, ToolResult


class IngestTool(Tool):
    def name(self) -> str:
        return "ingest_repo"

    def description(self) -> str:
        return (
            "Clone/copy a repository, run Slither static analysis (EVM only), "
            "and build the knowledge graph. This MUST be called before any "
            "graph-based analysis tools (hotspots, attack workers, etc). "
            "For non-EVM targets, set skip_slither=true to just clone the repo."
        )

    def permission_level(self) -> PermissionLevel:
        return PermissionLevel.EXECUTE

    def input_schema(self) -> dict:
        return {
            "type": "object",
            "properties": {
                "repo": {
                    "type": "string",
                    "description": "Local path or GitHub URL of the target repo",
                },
                "skip_slither": {
                    "type": "boolean",
                    "description": "Skip Slither analysis (for non-EVM targets)",
                    "default": False,
                },
                "contract_addresses": {
                    "type": "object",
                    "description": "Optional mapping of contract names to on-chain addresses",
                    "default": {},
                },
            },
            "required": ["repo"],
        }

    async def execute(self, params: dict, ctx: ToolContext) -> ToolResult:
        if "input" in params and isinstance(params["input"], dict):
            params = params["input"]

        repo = params.get("repo") or params.get("repo_url") or params.get("url") or params.get("repository") or ""
        if not repo:
            return ToolResult.error(f"Missing 'repo'. Got keys: {list(params.keys())}")
        skip_slither = params.get("skip_slither", False)
        addresses = params.get("contract_addresses", {})

        # 1. Clone/copy repo
        from src.repo_manager import RepoManager

        repo_manager = RepoManager("./data/scratch")
        try:
            repo_path = repo_manager.clone_repo(repo)
            repo_manager.install_dependencies(repo_path)
        except Exception as e:
            return ToolResult.error(f"Repository ingestion failed: {e}")

        ctx.repo_path = Path(repo_path)
        ctx.repo_url = repo
        ctx.contract_addresses = addresses
        if ctx.shell_cwd is None:
            ctx.shell_cwd = Path(repo_path)

        # 2. Run Slither (EVM only)
        if not skip_slither:
            ctx.ensure_config()
            if ctx.config.slither_enabled:
                from src.analysis_engine import AnalysisEngine

                engine = AnalysisEngine()
                try:
                    slither_obj, ingestion_report = engine.run_analysis_v2(repo_path, targets=None)
                except Exception as e:
                    return ToolResult.success(
                        f"Repo cloned to {repo_path} but Slither failed: {e}. "
                        "You can still use semantic analysis tools on the raw source code.",
                        repo_path=str(repo_path),
                        slither_failed=True,
                    )

                if not slither_obj:
                    ctx.graph = nx.DiGraph()
                    diagnostics = ""
                    if ingestion_report and ingestion_report.warnings:
                        diagnostics = "; ".join(ingestion_report.warnings[:5])
                    return ToolResult.success(
                        f"Repo cloned to {repo_path}. Slither analysis failed "
                        f"({diagnostics}). Using empty graph — semantic analysis "
                        "tools will work on raw source files.",
                        repo_path=str(repo_path),
                        slither_failed=True,
                    )

                # 3. Build knowledge graph
                from src.graph import GraphBuilder

                builder = GraphBuilder()
                builder.build_graph(slither_obj)
                ctx.graph = builder.graph

                # Extract contract names
                contracts = set()
                functions = []
                for node_id, data in ctx.graph.nodes(data=True):
                    if data.get("type") == "contract":
                        contracts.add(data.get("name", node_id))
                    elif data.get("type") == "function":
                        functions.append(node_id)

                ctx.contract_names = list(contracts)

                summary = ingestion_report.summary() if ingestion_report else ""
                return ToolResult.success(
                    f"Repository ingested: {repo_path}\n"
                    f"Slither: {summary}\n"
                    f"Graph: {ctx.graph.number_of_nodes()} nodes, "
                    f"{ctx.graph.number_of_edges()} edges\n"
                    f"Contracts: {', '.join(contracts)}\n"
                    f"Functions: {len(functions)}",
                    repo_path=str(repo_path),
                    node_count=ctx.graph.number_of_nodes(),
                    edge_count=ctx.graph.number_of_edges(),
                    contract_names=list(contracts),
                )
            else:
                ctx.graph = nx.DiGraph()

        # No Slither — just repo clone
        ctx.graph = ctx.graph or nx.DiGraph()
        return ToolResult.success(
            f"Repository cloned to {repo_path}. "
            "Slither skipped — use semantic analysis tools for source-level analysis.",
            repo_path=str(repo_path),
        )
