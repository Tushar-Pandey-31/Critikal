from datetime import datetime

from src.models.finding import FindingStatus
from src.utils.node_ids import normalize_node_id


def render_markdown_report(
    repo_url: str,
    repo_name: str,
    findings: list,
    leads: list[dict],
    token_usage: dict | None = None,
) -> str:
    """Returns a Markdown report suitable for HackerOne / Immunefi submission."""
    date_str = datetime.now().strftime("%Y-%m-%d %H:%M UTC")

    severity_counts: dict[str, dict[str, int]] = {
        "CRITICAL": {"total": 0, "proven": 0},
        "HIGH": {"total": 0, "proven": 0},
        "MEDIUM": {"total": 0, "proven": 0},
        "LOW": {"total": 0, "proven": 0},
    }

    for f in findings:
        sev = f.severity_estimate if f.severity_estimate in severity_counts else "MEDIUM"
        severity_counts[sev]["total"] += 1
        if f.status == FindingStatus.PROVEN:
            severity_counts[sev]["proven"] += 1

    total_findings = sum(v["total"] for v in severity_counts.values())
    total_proven = sum(v["proven"] for v in severity_counts.values())

    lines = [
        f"# Critikal Security Report — {repo_name}",
        "",
        f"**Date:** {date_str}  ",
        f"**Repository:** {repo_url}  ",
        "**Tool:** Critikal v2.0 (AI-Powered Smart Contract Security)",
        "",
        "---",
        "",
        "## Executive Summary",
        "",
        f"{total_findings} vulnerability lead(s) identified. "
        f"{total_proven} proven with working Foundry PoC.",
        "",
        "| Severity | Count | Proven |",
        "|----------|-------|--------|",
    ]

    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        c = severity_counts[sev]
        lines.append(f"| {sev} | {c['total']} | {c['proven']} |")

    lines += ["", "---", ""]

    for idx, finding in enumerate(findings, start=1):
        is_proven = finding.status == FindingStatus.PROVEN
        proven_tag = "[PROVEN] " if is_proven else ""
        confidence_label = f"{finding.confidence}% (Proven)" if is_proven else f"{finding.confidence}%"

        lines += [
            f"## Finding {idx} — {proven_tag}{finding.title}",
            "",
            f"**Severity:** {finding.severity_estimate}  ",
            f"**Contract:** {finding.affected_contract}  ",
            f"**Function:** {finding.affected_function}  ",
            f"**Confidence:** {confidence_label}  ",
            "",
            "### Description",
            "",
            finding.hypothesis or "No hypothesis available.",
            "",
        ]

        if finding.attack_path:
            path_str = " → ".join(
                f"`{node}`" for node in finding.attack_path
            )
            lines += [
                "### Attack Path",
                "",
                path_str,
                "",
            ]

        if finding.impact:
            lines += [
                "### Impact",
                "",
                finding.impact,
                "",
            ]

        # Find matching test_code from leads
        test_code = _find_test_code(finding, leads)
        if test_code:
            lines += [
                "### Proof of Concept",
                "",
                "```solidity",
                test_code,
                "```",
                "",
                "### Reproduction",
                "",
                "```bash",
                f'forge test --match-path "test/ExploitTest_{finding.affected_contract}'
                f'_{finding.affected_function}.t.sol" \\',
                '           --match-test test_exploit -vvv',
                "```",
                "",
            ]

        lines += ["---", ""]

    # ── Token Usage & Cost Section ──
    if token_usage:
        lines += _render_token_usage_md(token_usage)

    return "\n".join(lines)


def _render_token_usage_md(token_usage: dict) -> list[str]:
    """Render the token usage section for the markdown report."""
    lines = [
        "## LLM Token Usage & Cost",
        "",
    ]

    agents = token_usage.get("agents", [])
    total = token_usage.get("total", {})
    elapsed = token_usage.get("elapsed_seconds", 0)

    if agents:
        lines += [
            "| Agent | Model | Calls | Input Tokens | Output Tokens | Input Chars | Output Chars | Est. Cost |",
            "|-------|-------|------:|-------------:|--------------:|------------:|-------------:|----------:|",
        ]
        for a in agents:
            lines.append(
                f"| {a['agent_name']} | {a['model']} | {a['call_count']} "
                f"| {a['input_tokens']:,} | {a['output_tokens']:,} "
                f"| {a['input_chars']:,} | {a['output_chars']:,} "
                f"| ${a['estimated_cost_usd']:.4f} |"
            )
        lines.append(
            f"| **TOTAL** | — | **{total.get('call_count', 0)}** "
            f"| **{total.get('input_tokens', 0):,}** | **{total.get('output_tokens', 0):,}** "
            f"| **{total.get('input_chars', 0):,}** | **{total.get('output_chars', 0):,}** "
            f"| **${total.get('estimated_cost_usd', 0):.4f}** |"
        )
    else:
        lines.append("No LLM calls were recorded.")

    lines += [
        "",
        f"**Pipeline Duration:** {elapsed:.0f}s  ",
        f"**Total Tokens:** {total.get('total_tokens', 0):,}  ",
        f"**Estimated Cost:** ${total.get('estimated_cost_usd', 0):.4f}",
        "",
        "---",
        "",
    ]

    return lines


def _find_test_code(finding, leads: list[dict]) -> str | None:
    """Locate test_code for a finding by matching against leads."""
    finding_node = normalize_node_id(finding.hotspot_node_id)
    for lead in leads:
        lead_node = normalize_node_id(lead.get("affected_function_node_id", ""))
        if lead_node and lead_node == finding_node and lead.get("test_code"):
            return lead["test_code"]
    for lead in leads:
        if (finding.affected_contract == lead.get("affected_contract")
                and finding.affected_function == lead.get("affected_function")
                and lead.get("test_code")):
            return lead["test_code"]
    return None
