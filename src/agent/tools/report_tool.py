"""
ReportTool — Generate final audit report.

Wraps: ReportGenerator.generate()
Produces: HTML, Markdown, graph visualization, exploit artifacts
"""

from src.agent.tool import Tool, ToolResult, PermissionLevel
from src.agent.context import ToolContext


class ReportTool(Tool):

    def name(self) -> str:
        return "generate_report"

    def description(self) -> str:
        return (
            "Generate the final audit report from accumulated findings. "
            "Produces: interactive HTML report, Markdown (HackerOne/Immunefi ready), "
            "knowledge graph visualization, and exploit artifact directory."
        )

    def permission_level(self) -> PermissionLevel:
        return PermissionLevel.WRITE

    def input_schema(self) -> dict:
        return {
            "type": "object",
            "properties": {
                "output_dir": {
                    "type": "string",
                    "description": "Custom output directory. Default: data/reports/{repo}_{timestamp}/",
                },
            },
        }

    async def execute(self, params: dict, ctx: ToolContext) -> ToolResult:
        from src.reporting.report_generator import ReportGenerator

        repo_name = "unknown"
        if ctx.repo_url:
            repo_name = ctx.repo_url.rstrip("/").split("/")[-1]

        # Convert findings to lead dicts for backward compat with ReportGenerator
        leads = []
        for f in ctx.findings:
            if hasattr(f, "model_dump"):
                leads.append(f.model_dump())
            elif hasattr(f, "to_dict"):
                leads.append(f.to_dict())
            else:
                leads.append(str(f))

        jury_rejected = [
            f for f in ctx.findings
            if getattr(f, "jury_decision", None) == "REFUTED"
        ]

        try:
            generator = ReportGenerator(
                repo_url=ctx.repo_url or "",
                repo_name=repo_name,
                findings=ctx.findings,
                leads=leads,
                graph=ctx.graph,
                jury_rejected=jury_rejected,
            )
            paths = generator.generate()
        except Exception as e:
            return ToolResult.error(f"Report generation failed: {e}")

        report_html = paths.get("report_html", "")
        report_md = paths.get("report_md", "")

        return ToolResult.success(
            f"Report generated.\n"
            f"HTML: {report_html}\n"
            f"Markdown: {report_md}\n"
            f"Findings included: {len(ctx.findings)}\n"
            f"Proven exploits: {sum(1 for f in ctx.findings if getattr(f, 'exploit_success', False))}",
            report_html=report_html,
            report_md=report_md,
        )
