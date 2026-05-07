import re
from collections import defaultdict
from datetime import datetime

from src.models.finding import FindingStatus
from src.utils.node_ids import normalize_node_id

# ═══════════════════════════════════════════════════════════
#  Finding ID helpers (Epic 7)
# ═══════════════════════════════════════════════════════════

_SEV_PREFIX = {"CRITICAL": "C", "HIGH": "H", "MEDIUM": "M", "LOW": "L"}


def _assign_finding_ids(findings: list) -> list:
    """Assign sequential IDs like C-01, H-02 per severity."""
    counters: dict[str, int] = defaultdict(int)
    for f in findings:
        sev = f.severity_estimate if f.severity_estimate in _SEV_PREFIX else "MEDIUM"
        counters[sev] += 1
        prefix = _SEV_PREFIX.get(sev, "F")
        f.report_id = f"{prefix}-{counters[sev]:02d}"
    return findings


def _normalize_vuln_class(vc: str) -> str:
    """Normalize vulnerability class strings for dedup comparison.

    Maps variant names to a canonical form so that e.g.
    'initializer_replay', 'Unprotected initializer ...', and
    'Uninitialized Implementation ...' all collapse to the same key.
    """
    vc = vc.lower().strip()
    # Strip common prefixes/suffixes
    vc = re.sub(r'[^a-z0-9_]', '_', vc)
    vc = re.sub(r'_+', '_', vc).strip('_')

    # Canonical mappings for common synonyms
    _CANONICAL = {
        'initializer_replay': 'initializer_frontrun',
        'unprotected_initializer': 'initializer_frontrun',
        'uninitialized_implementation': 'initializer_frontrun',
        'initializer_frontrun': 'initializer_frontrun',
        'access_control': 'access_control',
        'unprotected_function': 'access_control',
        'keeper_drain': 'admin_privilege',
        'admin_privilege': 'admin_privilege',
        'rug_pull': 'admin_privilege',
    }

    # Check exact match first
    if vc in _CANONICAL:
        return _CANONICAL[vc]

    # Check substring match for longer titles
    for pattern, canonical in _CANONICAL.items():
        if pattern in vc:
            return canonical

    return vc


def _deduplicate_findings(findings: list) -> list:
    """Merge findings that share the same (contract, function, vuln_class).

    Assigns root_cause_group to duplicates and keeps only the highest-confidence
    representative per group. This prevents reports with 4 variants of the same
    initializer bug submitted as separate findings.
    """
    # Build groups by (contract, function, normalized_vuln_class)
    groups: dict[str, list] = {}
    for f in findings:
        norm_vc = _normalize_vuln_class(f.vulnerability_class or "")
        key = f"{f.affected_contract}::{f.affected_function}::{norm_vc}"
        groups.setdefault(key, []).append(f)

    deduplicated: list = []
    for key, group in groups.items():
        if len(group) == 1:
            deduplicated.append(group[0])
            continue

        # Sort by confidence (desc), then severity weight
        sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        group.sort(key=lambda f: (-f.confidence, sev_order.get(f.severity_estimate, 4)))

        # Keep the best representative
        best = group[0]
        # Assign root_cause_group label
        rcg_label = f"{best.affected_contract}::{best.affected_function} ({_normalize_vuln_class(best.vulnerability_class or '')})"
        best.root_cause_group = rcg_label

        # Absorb info from duplicates into the best finding's description
        dup_titles = [f.title for f in group[1:] if f.title and f.title != best.title]
        if dup_titles:
            dedup_note = "Also reported as: " + "; ".join(dup_titles)
            if best.impact:
                best.impact = best.impact + "\n\n" + dedup_note
            else:
                best.impact = dedup_note

        # Use highest severity from the group
        for f in group:
            if sev_order.get(f.severity_estimate, 4) < sev_order.get(best.severity_estimate, 4):
                best.severity_estimate = f.severity_estimate

        deduplicated.append(best)

        merged_count = len(group) - 1
        print(f"  [Dedup] Merged {merged_count} duplicate(s) into {best.report_id or best.id[:8]}: {rcg_label}")

    return deduplicated


def _group_by_root_cause(findings: list) -> list[list]:
    """Group findings by root_cause_group. Ungrouped findings are singletons."""
    groups: dict[str, list] = {}
    singles = []
    for f in findings:
        rcg = getattr(f, "root_cause_group", "") or ""
        if rcg:
            groups.setdefault(rcg, []).append(f)
        else:
            singles.append([f])
    return list(groups.values()) + singles


# ═══════════════════════════════════════════════════════════
#  Main renderer
# ═══════════════════════════════════════════════════════════

def render_markdown_report(
    repo_url: str,
    repo_name: str,
    findings: list,
    leads: list[dict],
    token_usage: dict | None = None,
    jury_rejected: list | None = None,
    chain_hypotheses: list | None = None,
) -> str:
    """Returns a Markdown report suitable for HackerOne / Immunefi submission."""
    date_str = datetime.now().strftime("%Y-%m-%d %H:%M UTC")

    # Deduplicate findings sharing the same root cause before assigning IDs
    findings = _deduplicate_findings(findings)

    # Assign clean IDs
    findings = _assign_finding_ids(findings)

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
        f"{total_findings} vulnerability finding(s) identified. "
        f"{total_proven} proven with working Foundry PoC.",
        "",
        "| Severity | Count | Proven |",
        "|----------|-------|--------|",
    ]

    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        c = severity_counts[sev]
        lines.append(f"| {sev} | {c['total']} | {c['proven']} |")

    # Jury summary
    # FIX: ESCALATE means jurors disagreed — do NOT count as Confirmed.
    # ESCALATE is already counted in its own row below.
    jury_confirmed = sum(1 for f in findings if getattr(f, "jury_decision", "") in ("CONFIRMED", "CONFIRMED_UNPROVABLE"))
    jury_rejected_count = len(jury_rejected) if jury_rejected else 0
    jury_unprovable_count = sum(1 for f in findings if getattr(f, "jury_decision", "") == "CONFIRMED_UNPROVABLE")

    if jury_confirmed + jury_rejected_count > 0:
        lines.append("\n### Jury Validation Summary\n")
        lines.append("| Status | Count |")
        lines.append("|--------|-------|")
        lines.append(f"| Confirmed | {jury_confirmed - jury_unprovable_count} |")
        lines.append(f"| Confirmed (unprovable in isolation) | {jury_unprovable_count} |")
        lines.append(f"| Rejected (false positives) | {jury_rejected_count} |")
        lines.append(f"| Escalated (human review needed) | {sum(1 for f in findings if getattr(f, 'jury_decision', '') == 'ESCALATE')} |")

    lines += ["", "---", ""]

    # ── Findings (grouped by root cause) ──────────────────
    groups = _group_by_root_cause(findings)
    for group in groups:
        if len(group) > 1:
            # Root-cause group header
            rcg = group[0].root_cause_group
            ids = ", ".join(f.report_id for f in group)
            lines += [
                f"## Root Cause Group: {rcg}",
                f"*Findings {ids} share the same underlying root cause.*",
                "",
            ]

        for finding in group:
            lines += _render_finding(finding, leads)

    # ── Chain Hypotheses ──────────────────────────────────
    if chain_hypotheses:
        lines.append("\n---\n")
        lines.append("## 🔗 Multi-Step Exploit Chains\n")
        lines.append(
            "Chain analysis links findings where one vulnerability's postconditions "
            "create the preconditions needed by another, forming multi-step exploits.\n"
        )
        for chain in chain_hypotheses:
            enabler = chain.enabler_finding
            blocked = chain.blocked_finding
            e_id = getattr(enabler, 'report_id', enabler.id[:8])
            b_id = getattr(blocked, 'report_id', blocked.id[:8])
            lines.append(f"### {chain.chain_id}: {enabler.affected_function} → {blocked.affected_function}\n")
            lines.append(f"**Match:** {chain.match_strength} {chain.match_type}  ")
            lines.append(f"**Chain Severity:** `{chain.chain_severity}`\n")
            lines.append("| Role | Finding | Contract | Function |")
            lines.append("|------|---------|----------|----------|")
            lines.append(
                f"| Enabler | {e_id} | {enabler.affected_contract} | {enabler.affected_function} |"
            )
            lines.append(
                f"| Blocked | {b_id} | {blocked.affected_contract} | {blocked.affected_function} |"
            )
            lines.append(f"\n**Postcondition (B creates):** {chain.matched_postcondition}  ")
            lines.append(f"**Precondition (A needs):** {chain.matched_precondition}\n")
            if chain.combined_attack_steps:
                lines.append("**Combined Attack Sequence:**\n")
                for i, step in enumerate(chain.combined_attack_steps, 1):
                    lines.append(f"{i}. `{step}`")
                lines.append("")

    # ── Rejected findings ─────────────────────────────────
    if jury_rejected:
        lines.append("\n---\n")
        lines.append("## Jury-Rejected Findings\n")
        lines.append(
            "The following findings were identified by static analysis and hypothesis generation "
            "but rejected by the Jury as false positives or invalid:\n"
        )
        for finding in jury_rejected:
            lines.append(f"\n### ~~{finding.affected_function}~~ — REJECTED\n")
            lines.append(f"**Contract:** {finding.affected_contract}\n")
            lines.append(f"**Votes:** {getattr(finding, 'jury_vote_summary', '')}\n")
            lines.append(f"**Rejection reason:** {getattr(finding, 'jury_rejection_reason', '')}\n")

    # ── Vulnerability Leads ───────────────────────────────
    if leads:
        lines.append("\n---\n")
        lines.append("## Raw Vulnerability Leads\n")
        lines.append(
            "The following leads were identified during the initial analysis phase. "
            "Note: These are preliminary hypotheses and may not be fully validated findings.\n"
        )
        for lead in leads:
            sev = lead.get("severity", "UNKNOWN")
            title = lead.get("title", "Untitled")
            conf = lead.get("confidence_score", "N/A")
            contract = lead.get("affected_contract", "Unknown")
            func = lead.get("affected_function", "Unknown")
            lines.append(f"### {sev} | {title} (Confidence: {conf}%)\n")
            lines.append(f"**Contract:** {contract} | **Function:** {func}\n")
            hyp = lead.get("hypothesis", "No hypothesis provided.")
            lines.append(f"{hyp}\n")

    # ── Token Usage & Cost Section ──
    if token_usage:
        lines += _render_token_usage_md(token_usage)

    return "\n".join(lines)


def _render_finding(finding, leads: list[dict]) -> list[str]:
    """Render a single finding with all v2 fields."""
    is_proven = finding.status == FindingStatus.PROVEN
    proven_tag = "[PROVEN] " if is_proven else ""
    confidence_label = f"{finding.confidence}% (Proven)" if is_proven else f"{finding.confidence}%"
    fid = getattr(finding, "report_id", "") or ""
    evidence_tag = getattr(finding, "evidence_tag", "") or ""
    verdict = getattr(finding, "verdict", "") or ""

    lines = [
        f"## {fid} — {proven_tag}{finding.title}",
        "",
        f"**Severity:** {finding.severity_estimate}  ",
        f"**Contract:** {finding.affected_contract}  ",
        f"**Function:** {finding.affected_function}  ",
        f"**Confidence:** {confidence_label}  ",
    ]

    # v2: Evidence tag and verdict
    meta_parts = []
    if evidence_tag:
        meta_parts.append(f"**Evidence:** {evidence_tag}")
    if verdict and verdict != "UNASSESSED":
        meta_parts.append(f"**Verdict:** {verdict}")
    if meta_parts:
        lines.append("  ".join(meta_parts) + "  ")

    # v2: Chain link badges
    chain_ids = getattr(finding, "chain_ids", []) or []
    chain_role = getattr(finding, "chain_role", "") or ""
    chain_upgrade = getattr(finding, "chain_severity_upgrade", "") or ""
    if chain_ids:
        chain_str = ", ".join(chain_ids)
        lines.append(f"**Chains:** {chain_str} (role: {chain_role})  ")
        if chain_upgrade:
            lines.append(f"**Severity Upgrade:** {chain_upgrade}  ")

    # v2: Depth verdicts
    depth_verdicts = getattr(finding, "depth_verdicts", []) or []
    if depth_verdicts:
        lines.append(f"**Depth Passes:** {len(depth_verdicts)}  ")
        for dv in depth_verdicts:
            agent = dv.get("agent", "unknown")
            verdict_d = dv.get("verdict", "CONTESTED")
            lines.append(f"  - `{agent}` → **{verdict_d}** (confidence: {dv.get('confidence', '?')})  ")


    lines += [
        "",
        "### Description",
        "",
    ]

    # Story 6.1: Render assumption/violation/proof for first-principles findings
    if getattr(finding, "vulnerability_class", "") == "first_principles":
        raw = getattr(finding, "raw_output", {}) or {}
        lines += [
            "**Assumption violated:**",
            raw.get("assumption", "Unknown"),
            "",
            "**Violation mechanism:**",
            raw.get("violation", "Unknown"),
            "",
            "**Proof / Trace:**",
            raw.get("proof", "Unknown"),
            "",
        ]
    else:
        lines += [
            finding.hypothesis or "No hypothesis available.",
            "",
        ]

    # v2: Preconditions / postconditions
    preconditions = getattr(finding, "preconditions", []) or []
    preconditions_missing = getattr(finding, "preconditions_missing", []) or []
    postconditions = getattr(finding, "postconditions", []) or []

    if preconditions or preconditions_missing:
        lines.append("### Preconditions\n")
        for p in preconditions:
            lines.append(f"- ✅ {p}")
        for p in preconditions_missing:
            lines.append(f"- ❌ {p} *(not currently met)*")
        lines.append("")

    if postconditions:
        lines.append("### Postconditions (if exploited)\n")
        for p in postconditions:
            lines.append(f"- {p}")
        lines.append("")

    # Jury verdict
    jury_decision = getattr(finding, "jury_decision", "")
    if jury_decision:
        jury_emoji = {
            "CONFIRMED": "✅",
            "CONFIRMED_UNPROVABLE": "⚠️",
            "ESCALATE": "🔍",
            "REJECTED": "❌",
        }.get(jury_decision, "")
        lines.append(f"\n### Jury Verdict: {jury_emoji} {jury_decision}\n")
        vote_summary = getattr(finding, "jury_vote_summary", "")
        if vote_summary:
            lines.append(f"**Votes:** {vote_summary}\n")
        jury_reasoning = getattr(finding, "jury_reasoning", "")
        if jury_reasoning:
            lines.append(f"**Reasoning:** {jury_reasoning}\n")
        if jury_decision == "CONFIRMED_UNPROVABLE":
            unprovable_reason = getattr(finding, "jury_unprovable_reason", "")
            if unprovable_reason:
                lines.append(f"**Why unprovable in isolation:** {unprovable_reason}\n")
            lines.append("**Recommendation:** Test with mainnet fork or manual review\n")
        if jury_decision == "ESCALATE":
            lines.append("**Action required:** Human review recommended — jurors disagreed\n")

    if finding.attack_path:
        path_str = " → ".join(f"`{node}`" for node in finding.attack_path)
        lines += ["### Attack Path", "", path_str, ""]

    if finding.impact:
        lines += ["### Impact", "", finding.impact, ""]

    # v2: RAG references (deduplicated by source path)
    rag_matches = getattr(finding, "rag_matches", []) or []
    if rag_matches:
        seen_sources: set[str] = set()
        unique_matches: list[dict] = []
        for m in rag_matches:
            source = m.get("source", "Unknown")
            if source not in seen_sources:
                seen_sources.add(source)
                unique_matches.append(m)
        if unique_matches:
            lines.append("### Historical References (RAG)\n")
            for m in unique_matches[:3]:
                source = m.get("source", "Unknown")
                snippet = m.get("snippet", "")[:120]
                lines.append(f"- **{source}**: {snippet}...")
            lines.append("")

    # PoC code
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
            'forge test --match-test test_exploit -vvv',
            "```",
            "",
        ]

    lines += ["---", ""]
    return lines


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
