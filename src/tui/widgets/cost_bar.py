"""
CostBar — bottom status bar showing session cost, tokens, and progress.

Monochrome: single accent color (cyan) for emphasis, dim grays elsewhere.
Budget overflow uses a muted warning tint rather than bright red.
"""

from rich.text import Text
from textual.widgets import Static

# ── Palette (keep in sync with conversation_widget.py) ──
FG = "#e8e8e8"
DIM = "#8a8a8a"
DIMMER = "#5a5a5a"
FAINT = "#3a3a3a"
ACCENT = "#7dd3c0"
WARN = "#d9c47d"
DANGER = "#e08a8a"


class CostBar(Static):
    """
    Bottom status bar. Render:  $cost · ↑Kin ↓Kout · model · T<n> · ◆ findings
    """

    def __init__(self, **kwargs):
        super().__init__("", **kwargs)
        self._cost = 0.0
        self._budget = None
        self._input_tokens = 0
        self._output_tokens = 0
        self._model = "?"
        self._turn = 0
        self._max_turns = 200
        self._findings = 0
        self._memories = 0
        self._is_mounted = False

    def on_mount(self):
        self._is_mounted = True
        self._refresh_bar()

    def update_cost(self, cost: float, budget: float | None = None):
        self._cost = cost
        self._budget = budget
        self._refresh_bar()

    def update_tokens(self, input_tokens: int, output_tokens: int):
        self._input_tokens = input_tokens
        self._output_tokens = output_tokens
        self._refresh_bar()

    def update_turn(self, turn: int, max_turns: int = 200):
        self._turn = turn
        self._max_turns = max_turns
        self._refresh_bar()

    def update_model(self, model: str):
        self._model = model
        self._refresh_bar()

    def update_findings(self, count: int):
        self._findings = count
        self._refresh_bar()

    def update_memories(self, count: int):
        self._memories = count
        self._refresh_bar()

    def update_from_tracker(self, tracker, turn: int = 0, findings: int = 0, model: str = ""):
        if tracker:
            self._cost = tracker.session_cost
            self._budget = tracker.budget_usd
            self._input_tokens = tracker.total_input_tokens
            self._output_tokens = tracker.total_output_tokens
        self._turn = turn
        self._findings = findings
        if model:
            self._model = model
        self._refresh_bar()

    def _refresh_bar(self):
        if not self._is_mounted:
            return

        SEP = "  ·  "
        text = Text()

        # Cost — single accent, warn/danger only when budget overrun
        cost_str = f"${self._cost:.3f}"
        if self._budget:
            ratio = self._cost / self._budget if self._budget > 0 else 0
            budget_str = f" / ${self._budget:.2f}"
            if ratio >= 0.95:
                text.append(f"{cost_str}{budget_str}", style=f"bold {DANGER}")
            elif ratio >= 0.80:
                text.append(f"{cost_str}{budget_str}", style=f"bold {WARN}")
            else:
                text.append(f"{cost_str}{budget_str}", style=FG)
        else:
            text.append(cost_str, style=FG)

        text.append(SEP, style=FAINT)

        # Tokens — always dim
        in_k = self._input_tokens / 1000
        out_k = self._output_tokens / 1000
        text.append(f"↑{in_k:.0f}K ↓{out_k:.0f}K", style=DIM)

        text.append(SEP, style=FAINT)

        # Model — dim
        model_short = self._model.split("/")[-1] if "/" in self._model else self._model
        if len(model_short) > 24:
            model_short = model_short[:24]
        text.append(model_short, style=DIM)

        text.append(SEP, style=FAINT)

        # Turn — dim
        text.append(f"T{self._turn}", style=DIM)

        text.append(SEP, style=FAINT)

        # Findings — cyan when > 0, faint when 0
        if self._findings > 0:
            text.append(f"◆ {self._findings}", style=f"bold {ACCENT}")
        else:
            text.append("◆ 0", style=DIMMER)

        if self._memories > 0:
            text.append(SEP, style=FAINT)
            text.append(f"∎ {self._memories}", style=DIM)

        self.update(text)
