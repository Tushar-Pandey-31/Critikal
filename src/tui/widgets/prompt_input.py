"""
PromptInput — multiline input widget with slash command support.

Handles:
- Enter to send (Ctrl+Enter for newline)
- Slash command detection (/ prefix)
- Input history navigation (Up/Down)
"""

from textual.message import Message
from textual.widgets import TextArea


class PromptInput(TextArea):
    """
    Multiline prompt input with slash command support.

    Emits PromptInput.Submitted when the user presses Enter.
    Ctrl+Enter inserts a newline.
    """

    DEFAULT_CSS = """
    PromptInput {
        height: auto;
        min-height: 1;
        max-height: 6;
        background: #0a0a0a;
        color: #e8e8e8;
        border: none;
    }
    PromptInput:focus {
        border: none;
    }
    """

    class Submitted(Message):
        """Emitted when the user submits input."""
        def __init__(self, value: str):
            super().__init__()
            self.value = value

    def __init__(self, **kwargs):
        # Textual's built-in monochrome theme — no syntax highlighting means
        # no stray color shows up in the prompt box.
        super().__init__(
            language=None,
            theme="vscode_dark",
            soft_wrap=True,
            show_line_numbers=False,
            **kwargs,
        )
        self._history: list[str] = []
        self._history_index = -1

    async def _on_key(self, event) -> None:
        """Handle key events for submit and history."""
        key = event.key

        # Enter = submit (plain enter, no modifiers)
        if key == "enter":
            event.prevent_default()
            event.stop()
            text = self.text.strip()
            if text:
                self._history.append(text)
                self._history_index = -1
                self.clear()
                self.post_message(self.Submitted(text))
            return

        # Shift+Enter or Ctrl+Enter = insert newline
        if key in ("shift+enter", "ctrl+enter"):
            # Insert a newline character
            self.insert("\n")
            event.prevent_default()
            event.stop()
            return

        # Up arrow when on first line = history back
        if key == "up" and self.cursor_location[0] == 0:
            if self._history and self._history_index < len(self._history) - 1:
                self._history_index += 1
                hist_text = self._history[-(self._history_index + 1)]
                self.clear()
                self.insert(hist_text)
                event.prevent_default()
                event.stop()
            return

        # Down arrow = history forward
        if key == "down" and self.cursor_location[0] == 0:
            if self._history_index > 0:
                self._history_index -= 1
                hist_text = self._history[-(self._history_index + 1)]
                self.clear()
                self.insert(hist_text)
            elif self._history_index == 0:
                self._history_index = -1
                self.clear()
            event.prevent_default()
            event.stop()
            return

    def is_slash_command(self) -> bool:
        """Check if the current input is a slash command."""
        return self.text.strip().startswith("/")

    def get_slash_command(self) -> tuple[str, str]:
        """Parse a slash command into (command, args)."""
        text = self.text.strip()
        if not text.startswith("/"):
            return ("", text)
        parts = text[1:].split(None, 1)
        cmd = parts[0] if parts else ""
        args = parts[1] if len(parts) > 1 else ""
        return (cmd, args)
