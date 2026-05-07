from datetime import datetime
from pathlib import Path

from src.models.finding import FindingStatus
from src.reporting.graph_visualizer import render_graph_html
from src.reporting.html_report import render_html_report
from src.reporting.markdown_report import render_markdown_report
from src.utils.node_ids import normalize_node_id


class ReportGenerator:
    def __init__(self, repo_url, repo_name, findings, leads, graph, token_usage=None, jury_rejected=None):
        self.repo_url = repo_url
        self.repo_name = repo_name or "unknown"
        self.findings = findings or []
        self.leads = leads or []
        self.graph = graph
        self.token_usage = token_usage
        self.jury_rejected = jury_rejected or []
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.output_dir = Path(f"data/reports/{self.repo_name}_{timestamp}")

    def generate(self) -> dict:
        self.output_dir.mkdir(parents=True, exist_ok=True)
        exploits_dir = self.output_dir / "exploits"
        exploits_dir.mkdir(exist_ok=True)

        poc_files = self._extract_exploits(exploits_dir)

        html_path = self.output_dir / "report.html"
        html_path.write_text(
            render_html_report(
                self.repo_url, self.repo_name,
                self.findings, self.leads, poc_files,
                token_usage=self.token_usage,
            ),
            encoding="utf-8",
        )

        md_path = self.output_dir / "report.md"
        md_path.write_text(
            render_markdown_report(
                self.repo_url, self.repo_name,
                self.findings, self.leads,
                token_usage=self.token_usage,
                jury_rejected=self.jury_rejected,
            ),
            encoding="utf-8",
        )

        graph_path = self.output_dir / "graph.html"
        graph_path.write_text(
            render_graph_html(self.graph, self.findings),
            encoding="utf-8",
        )

        print(f"[Reporter] Report saved to {self.output_dir}/")
        return {
            "report_html": str(html_path),
            "report_md": str(md_path),
            "graph_html": str(graph_path),
            "exploits_dir": str(exploits_dir),
        }

    def _extract_exploits(self, exploits_dir: Path) -> list[dict]:
        """Pull proven test code from findings/leads and write as .t.sol files."""
        poc_files = []
        for finding in self.findings:
            test_code = None
            exploit_success = False

            # Leads are the authoritative source for test_code (Finding dataclass
            # doesn't carry test_code). Match by normalized node id, mirroring the
            # pattern used in coordinator_node.
            for lead in self.leads:
                lead_node = normalize_node_id(lead.get("affected_function_node_id", ""))
                finding_node = normalize_node_id(finding.hotspot_node_id)
                if lead_node and lead_node == finding_node:
                    test_code = lead.get("test_code")
                    exploit_success = bool(lead.get("exploit_success"))
                    break

            # Fallback: broader match on contract+function name
            if not test_code:
                for lead in self.leads:
                    if (finding.affected_contract == lead.get("affected_contract")
                            and finding.affected_function == lead.get("affected_function")):
                        test_code = lead.get("test_code")
                        exploit_success = bool(lead.get("exploit_success"))
                        break

            if not test_code:
                continue

            # Also consider finding.status as proof signal
            if finding.status == FindingStatus.PROVEN:
                exploit_success = True

            safe_name = (
                f"ExploitTest_{finding.affected_contract}_{finding.affected_function}"
                .replace("::", "_")
                .replace("/", "_")
                .replace(" ", "_")
            )
            filename = f"{safe_name}.t.sol"
            filepath = exploits_dir / filename
            filepath.write_text(test_code, encoding="utf-8")
            poc_files.append({
                "filename": filename,
                "path": str(filepath),
                "proven": exploit_success,
                "contract": finding.affected_contract,
                "function": finding.affected_function,
                "test_code": test_code,
            })

        return poc_files
