import html
from datetime import datetime

from src.models.finding import FindingStatus
from src.reporting.markdown_report import _assign_finding_ids
from src.utils.node_ids import normalize_node_id


def render_html_report(
    repo_url: str,
    repo_name: str,
    findings: list,
    leads: list[dict],
    poc_files: list[dict],
    token_usage: dict | None = None,
) -> str:
    """Returns a complete self-contained HTML string."""
    date_str = datetime.now().strftime("%Y-%m-%d %H:%M UTC")

    # Epic 7: Assign clean finding IDs (C-01, H-01, etc.)
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

    sidebar_items = _build_sidebar_items(findings)
    finding_panels = _build_finding_panels(findings, leads, poc_files)
    leads_panel = _build_leads_panel(leads) if leads else ""
    summary_html = _build_summary_table(severity_counts, total_findings, total_proven)
    token_usage_sidebar = _build_token_sidebar(token_usage) if token_usage else ""
    token_usage_panel = _build_token_panel(token_usage) if token_usage else ""

    e = html.escape
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Critikal Security Report — {e(repo_name)}</title>
<style>
{_CSS}
</style>
</head>
<body>
<header id="header">
  <div class="header-left">
    <span class="logo">CRITIKAL</span>
    <span class="header-title">Security Report</span>
  </div>
  <div class="header-right">
    <span class="header-meta">{e(repo_name)}</span>
    <span class="header-meta">{e(date_str)}</span>
  </div>
</header>
<div id="layout">
  <aside id="sidebar">
    <div class="sidebar-section">
      <h2>Findings</h2>
      {sidebar_items}
    </div>
    <div class="sidebar-section summary-section">
      <h2>Summary</h2>
      {summary_html}
    </div>
    {token_usage_sidebar}
    <div class="sidebar-section">
      <div class="meta-block">
        <span class="meta-label">Repository</span>
        <span class="meta-value">{e(repo_url)}</span>
      </div>
    </div>
  </aside>
  <main id="main">
    {finding_panels if findings else _NO_FINDINGS_HTML}
    {leads_panel}
    {token_usage_panel}
  </main>
</div>
<script>
{_JS}
</script>
</body>
</html>"""


# ═══════════════════════════════════════════════════════════
#  Helpers
# ═══════════════════════════════════════════════════════════

_SEV_COLORS = {
    "CRITICAL": "#f85149",
    "HIGH": "#f78166",
    "MEDIUM": "#d29922",
    "LOW": "#8b949e",
}

_SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def _badge(text: str, color: str, extra_class: str = "") -> str:
    cls = f"badge {extra_class}".strip()
    return f'<span class="{cls}" style="--badge-color:{color}">{html.escape(text)}</span>'


def _build_sidebar_items(findings: list) -> str:
    if not findings:
        return '<p class="empty">No findings</p>'
    parts = []
    for idx, f in enumerate(findings):
        is_proven = f.status == FindingStatus.PROVEN
        sev_color = _SEV_COLORS.get(f.severity_estimate, "#8b949e")
        icon = "●" if is_proven else "○"
        icon_color = "#3fb950" if is_proven else sev_color
        fid = getattr(f, 'report_id', '') or ''
        label = html.escape(f"{f.affected_contract}::{f.affected_function}")
        proven_tag = ' <span class="proven-tag">PROVEN</span>' if is_proven else ""
        evidence_tag = getattr(f, 'evidence_tag', '') or ''
        ev_html = f' <span class="evidence-tag">{html.escape(evidence_tag)}</span>' if evidence_tag else ''
        parts.append(
            f'<a class="sidebar-item" href="#finding-{idx}" data-idx="{idx}">'
            f'<span class="si-icon" style="color:{icon_color}">{icon}</span>'
            f'<span class="si-body">'
            f'<span class="si-sev" style="color:{sev_color}">{html.escape(fid)} {html.escape(f.severity_estimate)}</span>'
            f'{proven_tag}{ev_html}'
            f'<span class="si-name">{label}</span>'
            f'</span></a>'
        )
    return "\n".join(parts)


def _build_summary_table(severity_counts, total, proven) -> str:
    rows = ""
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        c = severity_counts[sev]
        color = _SEV_COLORS.get(sev, "#8b949e")
        rows += (
            f'<tr><td><span class="dot" style="background:{color}"></span>{sev}</td>'
            f'<td>{c["total"]}</td><td>{c["proven"]}</td></tr>'
        )
    return (
        f'<div class="summary-totals">'
        f'<span>{total} finding(s)</span>'
        f'<span class="proven-count">{proven} proven</span>'
        f'</div>'
        f'<table class="summary-table"><thead>'
        f'<tr><th>Severity</th><th>Count</th><th>Proven</th></tr>'
        f'</thead><tbody>{rows}</tbody></table>'
    )


def _find_test_code_for_finding(finding, leads: list[dict], poc_files: list[dict]) -> str | None:
    """Locate test_code: prefer poc_files (already written), fall back to leads."""
    for poc in poc_files:
        if poc["contract"] == finding.affected_contract and poc["function"] == finding.affected_function:
            return poc["test_code"]
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


def _build_finding_panels(findings: list, leads: list[dict], poc_files: list[dict]) -> str:
    panels = []
    for idx, f in enumerate(findings):
        is_proven = f.status == FindingStatus.PROVEN
        sev_color = _SEV_COLORS.get(f.severity_estimate, "#8b949e")

        # Status badges
        fid = getattr(f, 'report_id', '') or ''
        sev_badge = _badge(f"{fid} {f.severity_estimate}" if fid else f.severity_estimate, sev_color, "sev-badge")
        status_badge = (
            _badge("PROVEN EXPLOIT", "#3fb950", "status-badge")
            if is_proven
            else _badge("UNVERIFIED", "#d29922", "status-badge")
        )

        # v2: Evidence tag badge
        evidence_tag = getattr(f, 'evidence_tag', '') or ''
        ev_badge_html = ''
        if evidence_tag:
            ev_colors = {
                '[POC-PASS]': '#3fb950', '[POC-PASS-VARIANT]': '#56d364',
                '[POC-FAIL]': '#f85149', '[CODE-TRACE]': '#d29922',
                '[FUZZ-PASS]': '#79c0ff',
            }
            ev_color = ev_colors.get(evidence_tag, '#8b949e')
            ev_badge_html = _badge(evidence_tag, ev_color, 'evidence-badge')

        # v2: Verdict badge
        verdict = getattr(f, 'verdict', '') or ''
        verdict_badge_html = ''
        if verdict and verdict != 'UNASSESSED':
            v_colors = {
                'CONFIRMED': '#3fb950', 'PARTIAL': '#d29922',
                'CONTESTED': '#f78166', 'REFUTED': '#f85149',
            }
            v_color = v_colors.get(verdict, '#8b949e')
            verdict_badge_html = _badge(f'VERDICT: {verdict}', v_color, 'verdict-badge')

        # Attack path visualization
        attack_path_html = ""
        if f.attack_path:
            steps = []
            for node in f.attack_path:
                steps.append(f'<span class="path-node">{html.escape(node)}</span>')
            attack_path_html = (
                '<div class="attack-path">'
                + '<span class="path-arrow"></span>'.join(steps)
                + '</div>'
            )

        # Confidence bar
        conf = max(0, min(100, f.confidence))
        conf_color = "#3fb950" if conf >= 80 else ("#d29922" if conf >= 50 else "#f85149")

        # v2: Preconditions / postconditions
        preconditions_html = ''
        preconditions = getattr(f, 'preconditions', []) or []
        preconditions_missing = getattr(f, 'preconditions_missing', []) or []
        if preconditions or preconditions_missing:
            items = ''
            for p in preconditions:
                items += f'<li class="pre-met">✅ {html.escape(p)}</li>'
            for p in preconditions_missing:
                items += f'<li class="pre-unmet">❌ {html.escape(p)} <em>(not currently met)</em></li>'
            preconditions_html = f'<div class="section"><h3>Preconditions</h3><ul class="conditions-list">{items}</ul></div>'

        postconditions_html = ''
        postconditions = getattr(f, 'postconditions', []) or []
        if postconditions:
            items = ''.join(f'<li>{html.escape(p)}</li>' for p in postconditions)
            postconditions_html = f'<div class="section"><h3>Postconditions (if exploited)</h3><ul class="conditions-list">{items}</ul></div>'

        # v2: RAG references
        rag_html = ''
        rag_matches = getattr(f, 'rag_matches', []) or []
        if rag_matches:
            rag_items = ''
            for m in rag_matches[:3]:
                source = html.escape(m.get('source', 'Unknown'))
                snippet = html.escape(m.get('snippet', '')[:120])
                rag_items += f'<li><strong>{source}</strong>: {snippet}...</li>'
            rag_html = f'<div class="section"><h3>Historical References (RAG)</h3><ul class="rag-list">{rag_items}</ul></div>'

        # PoC code
        test_code = _find_test_code_for_finding(f, leads, poc_files)
        poc_html = ""
        if test_code:
            escaped_code = html.escape(test_code)
            repro_cmd = (
                f'forge test --match-path "test/ExploitTest_'
                f'{html.escape(f.affected_contract)}_{html.escape(f.affected_function)}'
                f'.t.sol" --match-test test_exploit -vvv'
            )
            poc_html = f"""
            <div class="section">
              <h3>Proof of Concept</h3>
              <div class="code-wrap">
                <button class="copy-btn" data-target="code-{idx}">Copy</button>
                <pre class="code-block" id="code-{idx}"><code>{escaped_code}</code></pre>
              </div>
            </div>
            <div class="section">
              <h3>Reproduction</h3>
              <div class="code-wrap">
                <button class="copy-btn" data-target="repro-{idx}">Copy</button>
                <pre class="code-block repro" id="repro-{idx}"><code>{html.escape(repro_cmd)}</code></pre>
              </div>
            </div>"""

        panels.append(f"""
    <article class="finding-panel" id="finding-{idx}">
      <div class="finding-header">
        <div class="badges">{sev_badge}{status_badge}{ev_badge_html}{verdict_badge_html}</div>
        <h2>{html.escape(f.affected_contract)}::{html.escape(f.affected_function)}</h2>
        <p class="finding-title">{html.escape(f.title)}</p>
      </div>
      <div class="section">
        <h3>Hypothesis</h3>
        <p>{html.escape(f.hypothesis or 'No hypothesis available.')}</p>
      </div>
      {f'<div class="section"><h3>Attack Path</h3>{attack_path_html}</div>' if attack_path_html else ''}
      {preconditions_html}
      {postconditions_html}
      <div class="section">
        <h3>Impact</h3>
        <p>{html.escape(f.impact or 'Not specified.')}</p>
      </div>
      <div class="section">
        <h3>Confidence</h3>
        <div class="confidence-bar-wrap">
          <div class="confidence-bar" style="width:{conf}%;background:{conf_color}"></div>
        </div>
        <span class="confidence-val" style="color:{conf_color}">{conf}%</span>
      </div>
      {rag_html}
      {poc_html}
    </article>""")
    return "\n".join(panels)


def _build_leads_panel(leads: list[dict]) -> str:
    if not leads:
        return ""
    
    rows = ""
    for idx, lead in enumerate(leads, 1):
        sev = html.escape(lead.get("severity", "UNKNOWN"))
        title = html.escape(lead.get("title", "Untitled"))
        conf = lead.get("confidence_score", "N/A")
        contract = html.escape(lead.get("affected_contract", "Unknown"))
        func = html.escape(lead.get("affected_function", "Unknown"))
        hyp = html.escape(lead.get("hypothesis", "No hypothesis provided."))
        
        rows += f'''
        <div class="section" style="border-bottom: 1px solid var(--border); padding-bottom: 16px; margin-bottom: 16px;">
          <h3 style="color: var(--text-bright); font-size: 14px; margin-bottom: 4px;">{idx}. {sev} | {title} (Confidence: {conf}%)</h3>
          <p style="font-family: monospace; font-size: 12px; margin-bottom: 8px;">{contract}::{func}</p>
          <p style="font-size: 13px;">{hyp}</p>
        </div>'''

    return f"""
    <article class="finding-panel" id="raw-leads">
      <div class="finding-header">
        <div class="badges">{{_badge('LEADS', '#8b949e', 'sev-badge')}}</div>
        <h2>Raw Vulnerability Leads</h2>
        <p class="finding-title">The following leads were identified during the initial analysis phase. Note: These are preliminary hypotheses and may not be fully validated findings.</p>
      </div>
      <div class="section">
        {{rows}}
      </div>
    </article>"""


def _build_token_sidebar(token_usage: dict) -> str:
    total = token_usage.get("total", {})
    return f"""
    <div class="sidebar-section">
      <h2>Token Usage</h2>
      <div class="summary-totals">
        <span>{total.get('call_count', 0)} LLM calls</span>
        <span class="proven-count">${total.get('estimated_cost_usd', 0):.4f}</span>
      </div>
      <table class="summary-table">
        <thead><tr><th>Metric</th><th>Value</th></tr></thead>
        <tbody>
          <tr><td>Input tokens</td><td>{total.get('input_tokens', 0):,}</td></tr>
          <tr><td>Output tokens</td><td>{total.get('output_tokens', 0):,}</td></tr>
          <tr><td>Total tokens</td><td>{total.get('total_tokens', 0):,}</td></tr>
          <tr><td>Duration</td><td>{token_usage.get('elapsed_seconds', 0):.0f}s</td></tr>
        </tbody>
      </table>
    </div>"""


def _build_token_panel(token_usage: dict) -> str:
    agents = token_usage.get("agents", [])
    total = token_usage.get("total", {})
    elapsed = token_usage.get("elapsed_seconds", 0)

    if not agents:
        return ""

    rows = ""
    for a in agents:
        rows += f"""<tr>
          <td>{html.escape(a['agent_name'])}</td>
          <td>{html.escape(a.get('model', ''))}</td>
          <td>{a['call_count']}</td>
          <td>{a['input_tokens']:,}</td>
          <td>{a['output_tokens']:,}</td>
          <td>{a['input_chars']:,}</td>
          <td>{a['output_chars']:,}</td>
          <td>${a['estimated_cost_usd']:.4f}</td>
        </tr>"""

    return f"""
    <article class="finding-panel" id="token-usage">
      <div class="finding-header">
        <div class="badges">{_badge('METRICS', '#58a6ff', 'sev-badge')}</div>
        <h2>LLM Token Usage & Cost</h2>
        <p class="finding-title">Per-agent breakdown of LLM API usage across the pipeline</p>
      </div>
      <div class="section">
        <table class="token-table">
          <thead>
            <tr>
              <th>Agent</th><th>Model</th><th>Calls</th>
              <th>Input Tokens</th><th>Output Tokens</th>
              <th>Input Chars</th><th>Output Chars</th>
              <th>Est. Cost</th>
            </tr>
          </thead>
          <tbody>
            {rows}
            <tr class="total-row">
              <td><strong>TOTAL</strong></td>
              <td>—</td>
              <td><strong>{total.get('call_count', 0)}</strong></td>
              <td><strong>{total.get('input_tokens', 0):,}</strong></td>
              <td><strong>{total.get('output_tokens', 0):,}</strong></td>
              <td><strong>{total.get('input_chars', 0):,}</strong></td>
              <td><strong>{total.get('output_chars', 0):,}</strong></td>
              <td><strong>${total.get('estimated_cost_usd', 0):.4f}</strong></td>
            </tr>
          </tbody>
        </table>
      </div>
      <div class="section">
        <p style="color:#8b949e;font-size:12px;">Pipeline duration: {elapsed:.0f}s &nbsp;|&nbsp; Total tokens: {total.get('total_tokens', 0):,} &nbsp;|&nbsp; Estimated cost: ${total.get('estimated_cost_usd', 0):.4f}</p>
      </div>
    </article>"""


_NO_FINDINGS_HTML = """
<div class="no-findings">
  <h2>No Findings</h2>
  <p>The analysis did not produce any vulnerability leads for this repository.</p>
</div>"""


# ═══════════════════════════════════════════════════════════
#  Inline CSS
# ═══════════════════════════════════════════════════════════

_CSS = """
:root {
  --bg: #0d1117;
  --surface: #161b22;
  --border: #30363d;
  --text: #c9d1d9;
  --text-bright: #f0f6fc;
  --accent: #58a6ff;
}
*, *::before, *::after { margin:0; padding:0; box-sizing:border-box; }
body { background:var(--bg); color:var(--text); font-family:system-ui,-apple-system,'Segoe UI',sans-serif; font-size:14px; line-height:1.55; }

/* ── Header ─────────────────── */
#header { position:fixed; top:0; left:0; right:0; height:52px; background:var(--surface); border-bottom:1px solid var(--border); display:flex; align-items:center; justify-content:space-between; padding:0 20px; z-index:100; }
.header-left { display:flex; align-items:center; gap:12px; }
.logo { font-weight:800; font-size:15px; color:#f78166; letter-spacing:1px; }
.header-title { font-size:14px; color:var(--text-bright); font-weight:600; }
.header-right { display:flex; gap:16px; }
.header-meta { font-size:12px; color:#8b949e; }

/* ── Layout ─────────────────── */
#layout { display:flex; margin-top:52px; min-height:calc(100vh - 52px); }
#sidebar { width:280px; min-width:280px; background:var(--surface); border-right:1px solid var(--border); overflow-y:auto; max-height:calc(100vh - 52px); position:sticky; top:52px; }
#main { flex:1; padding:24px 32px; overflow-y:auto; max-width:900px; }

/* ── Sidebar ────────────────── */
.sidebar-section { padding:16px; border-bottom:1px solid var(--border); }
.sidebar-section h2 { font-size:11px; text-transform:uppercase; letter-spacing:1px; color:#8b949e; margin-bottom:10px; }
.sidebar-item { display:flex; align-items:flex-start; gap:8px; padding:8px 10px; border-radius:6px; text-decoration:none; color:var(--text); cursor:pointer; transition:background .15s; }
.sidebar-item:hover { background:rgba(255,255,255,.04); }
.si-icon { font-size:14px; flex-shrink:0; margin-top:2px; }
.si-body { display:flex; flex-direction:column; gap:2px; min-width:0; }
.si-sev { font-size:11px; font-weight:700; text-transform:uppercase; }
.si-name { font-size:12px; color:#8b949e; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }
.proven-tag { font-size:10px; font-weight:700; color:#3fb950; background:rgba(63,185,80,.12); padding:1px 5px; border-radius:3px; margin-left:4px; }
.empty { font-size:12px; color:#484f58; }

/* Summary */
.summary-totals { display:flex; justify-content:space-between; margin-bottom:8px; font-size:13px; }
.proven-count { color:#3fb950; font-weight:600; }
.summary-table { width:100%; border-collapse:collapse; font-size:12px; }
.summary-table th { text-align:left; color:#8b949e; font-weight:500; border-bottom:1px solid var(--border); padding:4px 0; }
.summary-table td { padding:4px 0; }
.dot { display:inline-block; width:8px; height:8px; border-radius:50%; margin-right:6px; vertical-align:middle; }
.meta-block { display:flex; flex-direction:column; gap:4px; }
.meta-label { font-size:11px; color:#8b949e; text-transform:uppercase; letter-spacing:.5px; }
.meta-value { font-size:12px; color:var(--text); word-break:break-all; }

/* ── Finding Panels ─────────── */
.finding-panel { background:var(--surface); border:1px solid var(--border); border-radius:8px; padding:24px; margin-bottom:24px; }
.finding-header { margin-bottom:16px; }
.finding-header h2 { font-size:16px; color:var(--text-bright); font-family:'SFMono-Regular',Consolas,'Liberation Mono',Menlo,monospace; margin:8px 0 4px; }
.finding-title { font-size:13px; color:#8b949e; }
.badges { display:flex; gap:8px; flex-wrap:wrap; }
.badge { display:inline-block; font-size:11px; font-weight:700; padding:3px 8px; border-radius:4px; color:var(--badge-color); background:color-mix(in srgb, var(--badge-color) 14%, transparent); border:1px solid color-mix(in srgb, var(--badge-color) 30%, transparent); text-transform:uppercase; letter-spacing:.5px; }

/* Sections */
.section { margin-top:16px; }
.section h3 { font-size:12px; text-transform:uppercase; letter-spacing:.5px; color:#8b949e; margin-bottom:6px; }
.section p { color:var(--text); }

/* v2: Conditions lists */
.conditions-list { list-style:none; padding:0; }
.conditions-list li { padding:4px 0; font-size:13px; }
.pre-met { color:#3fb950; }
.pre-unmet { color:#f85149; }
.pre-unmet em { color:#8b949e; font-size:11px; }

/* v2: RAG references */
.rag-list { list-style:none; padding:0; }
.rag-list li { padding:4px 0; font-size:12px; color:#8b949e; border-left:2px solid #30363d; padding-left:10px; margin-bottom:4px; }
.rag-list strong { color:var(--accent); }

/* v2: Evidence & verdict badges */
.evidence-badge { font-size:10px; }
.verdict-badge { font-size:10px; }

/* Attack Path */
.attack-path { display:flex; flex-wrap:wrap; align-items:center; gap:4px; }
.path-node { background:#21262d; border:1px solid var(--border); border-radius:4px; padding:4px 8px; font-size:12px; font-family:monospace; color:var(--accent); }
.path-arrow::before { content:'\\2192'; color:#484f58; font-size:14px; margin:0 2px; }

/* Confidence */
.confidence-bar-wrap { height:6px; background:#21262d; border-radius:3px; overflow:hidden; margin-bottom:4px; }
.confidence-bar { height:100%; border-radius:3px; transition:width .3s; }
.confidence-val { font-size:13px; font-weight:700; }

/* Token Usage table */
.token-table { width:100%; border-collapse:collapse; font-size:12px; margin-top:8px; }
.token-table th { text-align:left; color:#8b949e; font-weight:500; border-bottom:1px solid var(--border); padding:6px 8px; font-size:11px; text-transform:uppercase; letter-spacing:.3px; }
.token-table td { padding:6px 8px; border-bottom:1px solid rgba(48,54,61,.5); }
.token-table .total-row td { border-top:2px solid var(--border); color:var(--text-bright); }

/* Code blocks */
.code-wrap { position:relative; }
.code-block { background:#0d1117; border:1px solid var(--border); border-radius:6px; padding:16px; overflow-x:auto; font-size:12px; line-height:1.5; font-family:'SFMono-Regular',Consolas,'Liberation Mono',Menlo,monospace; color:#c9d1d9; white-space:pre; }
.code-block code { color:inherit; }
.copy-btn { position:absolute; top:8px; right:8px; background:#21262d; color:#8b949e; border:1px solid var(--border); border-radius:4px; padding:3px 8px; font-size:11px; cursor:pointer; z-index:2; transition:color .15s; }
.copy-btn:hover { color:var(--text-bright); }

/* Syntax highlights (applied by JS) */
.sol-kw { color:#ff7b72; }
.sol-type { color:#79c0ff; }
.sol-fn { color:#d2a8ff; }
.sol-str { color:#a5d6ff; }
.sol-cmt { color:#8b949e; font-style:italic; }
.sol-num { color:#79c0ff; }

.no-findings { text-align:center; padding:80px 20px; color:#484f58; }
.no-findings h2 { font-size:20px; margin-bottom:8px; color:#8b949e; }

/* ── Print ──────────────────── */
@media print {
  body { background:#fff; color:#1c1e21; }
  #header { position:static; background:#fff; border-bottom:2px solid #000; }
  .logo { color:#d1242f; }
  .header-title, .header-meta { color:#1c1e21; }
  #layout { display:block; }
  #sidebar { display:none; }
  #main { max-width:100%; padding:0; }
  .finding-panel { background:#fff; border:1px solid #ccc; break-inside:avoid; page-break-inside:avoid; }
  .code-block { background:#f6f8fa; border:1px solid #d0d7de; color:#1c1e21; }
  .copy-btn { display:none; }
  .badge { print-color-adjust:exact; -webkit-print-color-adjust:exact; }
  .confidence-bar-wrap { print-color-adjust:exact; -webkit-print-color-adjust:exact; }
  .confidence-bar { print-color-adjust:exact; -webkit-print-color-adjust:exact; }
}
"""


# ═══════════════════════════════════════════════════════════
#  Inline JS — sidebar navigation, copy buttons, syntax highlight
# ═══════════════════════════════════════════════════════════

_JS = r"""
(function(){
  /* Sidebar click → smooth scroll to finding */
  document.querySelectorAll('.sidebar-item').forEach(function(a){
    a.addEventListener('click', function(e){
      e.preventDefault();
      var target = document.getElementById(a.getAttribute('href').slice(1));
      if(target) target.scrollIntoView({behavior:'smooth',block:'start'});
    });
  });

  /* Copy buttons */
  document.querySelectorAll('.copy-btn').forEach(function(btn){
    btn.addEventListener('click', function(){
      var el = document.getElementById(btn.dataset.target);
      if(!el) return;
      var text = el.textContent;
      navigator.clipboard.writeText(text).then(function(){
        btn.textContent = 'Copied!';
        setTimeout(function(){ btn.textContent = 'Copy'; }, 1500);
      });
    });
  });

  /* Minimal Solidity syntax highlighter */
  var KW = /\b(pragma|solidity|import|contract|interface|library|abstract|is|using|for|struct|enum|mapping|event|error|modifier|constructor|function|returns?|if|else|while|do|for|break|continue|emit|revert|require|assert|new|delete|try|catch|assembly|memory|storage|calldata|payable|external|public|internal|private|view|pure|virtual|override|indexed|anonymous|constant|immutable|unchecked)\b/g;
  var TYPES = /\b(address|bool|string|bytes\d*|int\d*|uint\d*)\b/g;
  var STRINGS = /(["'])(?:(?=(\\?))\2.)*?\1/g;
  var COMMENTS_LINE = /\/\/.*$/gm;
  var COMMENTS_BLOCK = /\/\*[\s\S]*?\*\//g;
  var NUMS = /\b(0x[0-9a-fA-F]+|\d+(\.\d+)?([eE][+-]?\d+)?)\b/g;

  function highlightSolidity(code){
    /* Protect comments & strings first by replacing with placeholders */
    var tokens = [];
    function save(cls){ return function(m){ tokens.push({cls:cls,text:m}); return '\x00'+String(tokens.length-1)+'\x00'; }; }
    code = code.replace(COMMENTS_BLOCK, save('sol-cmt'));
    code = code.replace(COMMENTS_LINE, save('sol-cmt'));
    code = code.replace(STRINGS, save('sol-str'));
    /* Escape HTML in remaining code */
    code = code.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
    /* Highlight keywords & types */
    code = code.replace(KW, '<span class="sol-kw">$1</span>');
    code = code.replace(TYPES, '<span class="sol-type">$1</span>');
    code = code.replace(NUMS, '<span class="sol-num">$1</span>');
    /* Restore protected tokens */
    code = code.replace(/\x00(\d+)\x00/g, function(_, i){
      var t=tokens[parseInt(i)];
      var escaped = t.text.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
      return '<span class="'+t.cls+'">'+escaped+'</span>';
    });
    return code;
  }

  /* Apply highlighting to all code blocks (skip reproduction blocks) */
  document.querySelectorAll('.code-block:not(.repro) code').forEach(function(el){
    el.innerHTML = highlightSolidity(el.textContent);
  });
})();
"""
