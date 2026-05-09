"""
FindingsWidget — live findings panel (right sidebar).

Monochrome. Severity differentiated by glyph weight, not hue — CRITICAL uses
a filled diamond, lower severities degrade to hollow shapes. The single cyan
accent is reserved for confidence and panel title.
"""

from rich.text import Text
from textual.containers import VerticalScroll
from textual.reactive import reactive
from textual.widgets import Static

FG = "#e8e8e8"
DIM = "#8a8a8a"
DIMMER = "#5a5a5a"
ACCENT = "#7dd3c0"
DANGER = "#e08a8a"
WARN = "#d9c47d"


# severity → (glyph, style)
SEVERITY_STYLES = {
    "CRITICAL": ("◆", f"bold {DANGER}"),
    "HIGH": ("◆", f"bold {WARN}"),
    "MEDIUM": ("◇", FG),
    "LOW": ("·", DIM),
}


class FindingCard(Static):
    """A single finding rendered as a card."""

    def __init__(self, finding_data: dict, index: int, **kwargs):
        super().__init__("", **kwargs)
        self.finding_data = finding_data
        self.index = index

    def on_mount(self):
        self._render_finding()

    def _render_finding(self):
        f = self.finding_data
        severity = str(f.get("severity_estimate", f.get("severity", "MEDIUM"))).upper()
        icon, style = SEVERITY_STYLES.get(severity, ("·", DIM))

        title = f.get("title", f.get("vulnerability_class", "Unknown"))
        contract = f.get("affected_contract", "?")
        function = f.get("affected_function", "?")
        confidence = f.get("confidence", 0)

        bar_filled = int(confidence / 10)
        bar_empty = 10 - bar_filled
        conf_bar = "█" * bar_filled + "░" * bar_empty

        text = Text()
        text.append(f"{icon}  ", style=style)
        text.append(f"F-{self.index + 1:03d}  ", style=DIM)
        text.append(f"{severity}\n", style=style)
        text.append(f"   {title[:40]}\n", style=FG)
        text.append(f"   {contract}::{function}\n", style=DIM)
        text.append(f"   {conf_bar} {confidence}%", style=ACCENT)

        self.update(text)


class FindingsWidget(VerticalScroll):
    """Live findings panel."""

    finding_count = reactive(0)

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._findings: list[dict] = []

    def compose(self):
        yield Static(
            Text("FINDINGS", style=f"bold {ACCENT}"),
            id="findings-title",
        )

    def add_finding(self, finding_data: dict):
        self._findings.append(finding_data)
        card = FindingCard(finding_data, len(self._findings) - 1)
        self.mount(card)
        self.finding_count = len(self._findings)
        self.scroll_end(animate=False)

    def update_from_context(self, findings: list):
        if len(findings) > len(self._findings):
            for i in range(len(self._findings), len(findings)):
                f = findings[i]
                if hasattr(f, "to_dict"):
                    data = f.to_dict()
                elif hasattr(f, "__dict__"):
                    data = vars(f)
                else:
                    data = f
                self.add_finding(data)

    def get_summary(self) -> str:
        if not self._findings:
            return "0"
        counts = {}
        for f in self._findings:
            sev = str(f.get("severity_estimate", f.get("severity", "?"))).upper()
            counts[sev] = counts.get(sev, 0) + 1
        parts = []
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            if sev in counts:
                parts.append(f"{counts[sev]}{sev[0]}")
        return f"{len(self._findings)} ({'/'.join(parts)})" if parts else str(len(self._findings))
