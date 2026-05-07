"""
ConversationWidget — main scrollable conversation stream.

Monochrome aesthetic to match critikalai.com: near-black background, off-white
text, one cyan accent, dim grays for secondary content.

Rendering model:
  ▸ user prompt               — bright, bold
  ∴ thinking stream           — dim italic, live-appended
  ⎿ assistant response        — off-white, markdown-rendered
    ⟳ tool_name args…         — dim + cyan tool name, while running
    ✓ tool_name (0.3s)        — dim, done
    ✗ tool_name (0.3s)        — soft red, error
    ◆ Finding #N added        — cyan accent
    ⊕ Sub-agent: desc         — dim
    ⊘ Context compacted       — dim italic
    ℹ system message          — dim italic
"""

from rich.markdown import Markdown
from rich.text import Text
from textual.widgets import RichLog

# ── Monochrome palette (keep in sync with styles.tcss) ──
FG        = "#e8e8e8"   # primary text
FG_BRIGHT = "#ffffff"   # emphasis
DIM       = "#8a8a8a"   # secondary
DIMMER    = "#5a5a5a"   # tertiary / done
FAINT     = "#3a3a3a"   # borders, separators
ACCENT    = "#7dd3c0"   # cyan — single accent, used sparingly
DANGER    = "#e08a8a"   # muted red, for errors/critical only


class ConversationWidget(RichLog):
    """
    Scrollable conversation log. Single-column, monochrome, minimal chrome.

    Streaming: call `begin_stream()` once, then `append_stream(chunk)` for each
    token, then `end_stream()` when the block is done.
    """

    def __init__(self, **kwargs):
        super().__init__(
            highlight=False,
            markup=True,
            wrap=True,
            auto_scroll=True,
            **kwargs,
        )
        self._streaming_kind: str | None = None
        self._stream_buffer: str = ""
        self._streamed_text_this_turn: bool = False

    # ── Streaming tokens ──

    def begin_stream(self, kind: str = "text"):
        """Open a streaming block. `kind` is 'text' or 'thinking'."""
        if self._streaming_kind and self._streaming_kind != kind:
            self.end_stream()

        if self._streaming_kind == kind:
            return

        self._streaming_kind = kind
        self._stream_buffer = ""

        if kind == "thinking":
            self.write(Text("  ∴ thinking", style=f"italic {DIM}"))
        else:
            self.write("")

    def append_stream(self, chunk: str, kind: str = "text"):
        """Append a token to the live streaming block."""
        if not chunk:
            return
        if self._streaming_kind != kind:
            self.begin_stream(kind)

        if kind == "text":
            self._streamed_text_this_turn = True

        self._stream_buffer += chunk
        while "\n" in self._stream_buffer:
            line, self._stream_buffer = self._stream_buffer.split("\n", 1)
            self._write_stream_line(line, kind)

    def end_stream(self):
        """Close any open streaming block; flush the tail."""
        if self._streaming_kind is None:
            return
        if self._stream_buffer:
            self._write_stream_line(self._stream_buffer, self._streaming_kind)
            self._stream_buffer = ""
        self._streaming_kind = None

    def finalize_message(self, fallback_text: str = ""):
        """Close the stream. If nothing streamed, render the fallback text
        (covers the astream→ainvoke fallback path where tokens never arrived)."""
        streamed = self._streamed_text_this_turn
        self.end_stream()
        self._streamed_text_this_turn = False
        if not streamed and fallback_text and fallback_text.strip():
            self.add_assistant_text(fallback_text)

    def _write_stream_line(self, line: str, kind: str):
        if kind == "thinking":
            self.write(Text(f"    {line}", style=f"italic {DIM}"))
        else:
            self.write(Text(line, style=FG))

    # ── User messages ──

    def add_user_message(self, text: str):
        self.end_stream()
        self.write("")
        for i, line in enumerate(text.split("\n")):
            prefix = "  ▸ " if i == 0 else "    "
            self.write(Text(f"{prefix}{line}", style=f"bold {FG_BRIGHT}"))

    # ── Assistant final text (non-streamed fallback) ──

    def add_assistant_text(self, text: str):
        self.end_stream()
        if not text or not text.strip():
            return
        self.write("")
        try:
            self.write(Markdown(text))
        except Exception:
            for line in text.split("\n"):
                self.write(Text(f"  {line}", style=FG))

    # ── Tool invocations ──

    def add_tool_start(self, tool_name: str, args_summary: str = ""):
        self.end_stream()
        display = tool_name
        if args_summary:
            trimmed = args_summary if len(args_summary) < 70 else args_summary[:67] + "..."
            display = f"{tool_name}  {trimmed}"
        line = Text()
        line.append("    ⟳ ", style=DIM)
        line.append(tool_name, style=ACCENT)
        if args_summary:
            rest = args_summary if len(args_summary) < 70 else args_summary[:67] + "..."
            line.append(f"  {rest}", style=DIMMER)
        self.write(line)

    def add_tool_complete(self, tool_name: str, elapsed_s: float, is_error: bool = False):
        self.end_stream()
        line = Text()
        if is_error:
            line.append("    ✗ ", style=DANGER)
            line.append(tool_name, style=DANGER)
        else:
            line.append("    ✓ ", style=DIMMER)
            line.append(tool_name, style=DIM)
        line.append(f"  {elapsed_s:.1f}s", style=DIMMER)
        self.write(line)

    # ── Findings ──

    def add_finding(self, index: int):
        self.end_stream()
        line = Text()
        line.append("    ◆ ", style=ACCENT)
        line.append(f"Finding #{index + 1}", style=f"bold {FG_BRIGHT}")
        line.append("  added", style=DIM)
        self.write(line)

    # ── Sub-agents ──

    def add_worker_spawned(self, description: str, model: str = ""):
        self.end_stream()
        line = Text()
        line.append("    ⊕ ", style=ACCENT)
        line.append(description, style=FG)
        if model:
            line.append(f"  {model}", style=DIMMER)
        self.write(line)

    def add_worker_complete(self, description: str):
        self.end_stream()
        line = Text()
        line.append("    ✓ ", style=DIMMER)
        line.append(description, style=DIM)
        self.write(line)

    # ── System ──

    def add_compact_notice(self, kind: str = ""):
        self.end_stream()
        label = f"context compacted ({kind})" if kind else "context compacted"
        self.write(Text(f"    ⊘ {label}", style=f"italic {DIM}"))

    def add_system_message(self, text: str):
        self.end_stream()
        for line in text.split("\n"):
            self.write(Text(f"    ℹ {line}", style=f"italic {DIM}"))

    def add_error(self, error: str):
        self.end_stream()
        self.write(Text(f"    ✗ {error}", style=f"bold {DANGER}"))
