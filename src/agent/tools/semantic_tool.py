"""
SemanticDiscoveryTool — LLM-native vulnerability analysis (no Slither required).

Wraps: run_semantic_discovery() — 4 agents: InvariantHunter, EconomicAttacker,
       TrustBoundaryAnalyzer, CrossContractStateChecker
Works on: ANY smart contract platform (not just EVM)
Writes: ctx.findings
"""

import os

from src.agent.context import ToolContext
from src.agent.tool import PermissionLevel, Tool, ToolResult


class SemanticDiscoveryTool(Tool):

    def name(self) -> str:
        return "run_semantic_analysis"

    def description(self) -> str:
        return (
            "Run LLM-native semantic analysis on raw source code. Does NOT require "
            "Slither or a compiled graph — works on any smart contract platform. "
            "Launches up to 4 parallel agents: InvariantHunter (conservation law "
            "violations), EconomicAttacker (flash loans, sandwich, price "
            "manipulation), TrustBoundaryAnalyzer (privilege escalation, "
            "delegatecall), CrossContractStateChecker (cross-contract reentrancy, "
            "stale state).\n\n"
            "IMPORTANT — curate your inputs. You've already run recon and "
            "find_hotspots; you know which contracts are in-scope vs which are "
            "deps/mocks/tests. Pass ONLY the 3–8 core contract files via `files`, "
            "or their names via `contracts`. Dumping the whole repo is wasteful "
            "(truncates important contracts) and often 504s on the LLM side. "
            "Omit both to fall back to whole-repo mode.\n\n"
            "Produces Finding objects."
        )

    def permission_level(self) -> PermissionLevel:
        return PermissionLevel.EXECUTE

    def input_schema(self) -> dict:
        return {
            "type": "object",
            "properties": {
                "files": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": (
                        "Explicit list of .sol file paths to analyze (absolute or "
                        "repo-relative). STRONGLY PREFERRED — pass the 3–8 core "
                        "in-scope contracts you identified via recon/hotspots. "
                        "The workers will read these files in full."
                    ),
                },
                "contracts": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": (
                        "Contract names to analyze (e.g. ['Vault', 'Strategy']). "
                        "Resolved to .sol files via the ingestion graph or "
                        "filename match. Use this when you don't have exact "
                        "paths but know the contract names."
                    ),
                },
                "agents": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": (
                        "Which agents to run. Options: invariant_hunter, "
                        "economic_attacker, trust_boundary, cross_contract. "
                        "Omit to run all. Narrow this down when you already "
                        "know the vulnerability class — e.g. for an access-"
                        "control hunt, use only ['trust_boundary']."
                    ),
                },
            },
        }

    def is_available(self, ctx: ToolContext) -> bool:
        return ctx.repo_path is not None

    async def execute(self, params: dict, ctx: ToolContext) -> ToolResult:
        from src.llm.providers import get_worker_llm
        from src.models.finding import Finding
        from src.pipeline.base_worker import WorkerOutput
        from src.pipeline.workers.semantic_discovery import run_semantic_discovery

        ctx.ensure_config()

        semantic_model = os.getenv(
            "SEMANTIC_MODEL_NAME",
            os.getenv("WORKER_MODEL_NAME", "gpt-5.4-mini"),
        )
        semantic_llm = get_worker_llm(model_name=semantic_model)

        files_param: list[str] = params.get("files") or []
        contracts_param: list[str] = params.get("contracts") or []
        agents_param: list[str] | None = params.get("agents") or None

        resolved_files = self._resolve_files(files_param, contracts_param, ctx)

        try:
            semantic_outputs = await run_semantic_discovery(
                repo_path=str(ctx.repo_path),
                llm_client=semantic_llm,
                model_name=semantic_model,
                recon_context=ctx.recon_context,
                sol_files=resolved_files or None,
                agents=agents_param,
            )
        except Exception as e:
            return ToolResult.error(f"Semantic discovery failed: {e}")

        new_findings = 0
        for so in semantic_outputs:
            finding = Finding.from_semantic_output(so)
            finding._seed_semantic_score()
            ctx.add_finding(finding)
            new_findings += 1

            # Multi-finding outputs
            all_raw = so.raw_output.get("all_findings", [])
            if len(all_raw) > 1:
                for extra in all_raw:
                    if extra == so.raw_output.get("best_finding"):
                        continue
                    extra_conf = int(extra.get("confidence", 0))
                    if extra_conf > 0:
                        extra_output = WorkerOutput(
                            worker_type=so.worker_type,
                            task_id=so.task_id,
                            hypothesis=extra.get("hypothesis", ""),
                            confidence=min(100, max(0, extra_conf)),
                            attack_path=extra.get("attack_path", []),
                            raw_output={
                                "vulnerability_class": extra.get("vulnerability_class", "semantic_discovery"),
                                "affected_contract": extra.get("affected_contract", ""),
                                "affected_function": extra.get("affected_function", ""),
                                "title": extra.get("title", ""),
                                "impact": extra.get("impact", ""),
                                "severity_estimate": extra.get("severity_estimate", "MEDIUM"),
                                "evidence": extra.get("evidence", ""),
                            },
                        )
                        ef = Finding.from_semantic_output(extra_output)
                        ef._seed_semantic_score()
                        ctx.add_finding(ef)
                        new_findings += 1

        return ToolResult.success(
            f"Semantic analysis complete.\n"
            f"Agent outputs: {len(semantic_outputs)}\n"
            f"New findings: {new_findings}\n"
            f"Total findings: {len(ctx.findings)}",
            new_findings=new_findings,
        )

    def _resolve_files(
        self,
        files: list[str],
        contracts: list[str],
        ctx: ToolContext,
    ) -> list[str]:
        """
        Resolve the brain's `files` + `contracts` inputs into absolute .sol paths.

        Order:
          1. `files` entries are taken as-is (abs path, or repo-relative). Missing
             paths are silently dropped — `run_semantic_discovery` will log them.
          2. `contracts` entries are resolved to file paths by scanning the graph
             for contract nodes whose `name` matches, then falling back to a
             filename match (`<Name>.sol`) under the repo.
        Deduped, preserving insertion order.
        """
        from pathlib import Path

        repo_path = Path(ctx.repo_path) if ctx.repo_path else None
        resolved: list[str] = []
        seen: set[str] = set()

        def _add(p: str) -> None:
            ap = os.path.abspath(p)
            if ap not in seen:
                seen.add(ap)
                resolved.append(ap)

        for f in files:
            if os.path.isabs(f):
                _add(f)
            elif repo_path:
                _add(str(repo_path / f))

        if contracts and repo_path:
            # Look up contract nodes in the graph first (fastest, most accurate)
            graph_file_map: dict[str, str] = {}
            if ctx.graph is not None:
                for node_id, data in ctx.graph.nodes(data=True):
                    if data.get("type") != "contract":
                        continue
                    name = data.get("name", "")
                    src_file = data.get("source_file") or data.get("file")
                    if name and src_file:
                        graph_file_map[name.lower()] = src_file

            for cname in contracts:
                key = cname.strip().lower()
                # Graph hit
                if key in graph_file_map:
                    p = graph_file_map[key]
                    if not os.path.isabs(p):
                        p = str(repo_path / p)
                    _add(p)
                    continue
                # Filename fallback — match `<Name>.sol`, skipping
                # test/mock/lib noise.
                exclude = {"test", "tests", "mock", "mocks", "lib",
                           "node_modules", "script", "scripts"}
                matches: list[str] = []
                for root, dirs, files_in_dir in os.walk(repo_path):
                    dirs[:] = [d for d in dirs if d.lower() not in exclude]
                    for fn in files_in_dir:
                        if fn.lower() == f"{cname.lower()}.sol":
                            matches.append(os.path.join(root, fn))
                # Prefer shortest path (most likely the canonical location)
                if matches:
                    matches.sort(key=len)
                    _add(matches[0])

        return resolved
