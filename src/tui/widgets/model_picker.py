"""
ModelPickerScreen — fullscreen modal for model configuration.

Overlay for the Critikal TUI. Lets the user:
  1. See which providers have API keys  (✅ / ❌)
  2. Browse all configurable agent roles and their current models
  3. Select a role → pick provider → pick model
  4. Changes are applied at runtime via os.environ

Colour palette matches the main TUI (monochrome + one cyan accent).

Usage from CritikalApp:
    self.push_screen(ModelPickerScreen(), callback=self._on_model_picker_dismiss)
"""

from __future__ import annotations

from rich.text import Text
from textual import on
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Vertical, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import Label, OptionList, Static
from textual.widgets.option_list import Option

from src.llm.model_registry import (
    PROVIDER_DISPLAY,
    apply_model_config,
    find_model_info,
    get_available_providers,
    get_current_config,
    get_models_for_provider,
)

# ── Palette (synced with styles.tcss) ────────────────────────────────
BG = "#0a0a0a"
SURFACE = "#111111"
BORDER = "#1f1f1f"
FG = "#e8e8e8"
FG_B = "#ffffff"
DIM = "#8a8a8a"
DIMMER = "#5a5a5a"
FAINT = "#3a3a3a"
ACCENT = "#7dd3c0"
DANGER = "#e08a8a"
WARN = "#d9c47d"
GREEN = "#7dd3a0"


class ModelPickerScreen(ModalScreen[dict[str, str] | None]):
    """
    Modal screen for model configuration.

    Returns a dict mapping changed role→model on dismiss, or None on cancel.
    """

    BINDINGS = [
        Binding("escape", "cancel", "Close", show=True),
    ]

    DEFAULT_CSS = """
    ModelPickerScreen {
        align: center middle;
    }

    #picker-container {
        width: 90;
        height: 40;
        max-width: 100%;
        max-height: 90%;
        background: #0a0a0a;
        border: round #1f1f1f;
        padding: 1 2;
    }

    #picker-title {
        width: 100%;
        text-align: center;
        color: #7dd3c0;
        text-style: bold;
        padding: 0 0 1 0;
    }

    #providers-bar {
        width: 100%;
        height: 3;
        padding: 0 1;
    }

    #provider-status {
        width: 100%;
        height: 1;
        padding: 0 0;
    }

    #separator-top {
        width: 100%;
        height: 1;
        color: #1f1f1f;
    }

    #roles-section {
        height: 1fr;
        width: 100%;
    }

    #roles-header {
        height: 1;
        padding: 0 1;
        color: #8a8a8a;
        text-style: italic;
    }

    #roles-list {
        height: 1fr;
        background: #0a0a0a;
        scrollbar-size: 1 1;
        scrollbar-color: #1f1f1f;
        scrollbar-color-hover: #3a3a3a;
        scrollbar-color-active: #7dd3c0;
        scrollbar-background: #0a0a0a;
    }

    #roles-list > .option-list--option {
        padding: 0 1;
    }

    #roles-list > .option-list--option-highlighted {
        background: #111111;
        color: #ffffff;
    }

    #separator-mid {
        width: 100%;
        height: 1;
        color: #1f1f1f;
    }

    #model-select-section {
        height: auto;
        max-height: 16;
        width: 100%;
        display: none;
    }

    #model-select-header {
        height: 1;
        padding: 0 1;
        color: #7dd3c0;
        text-style: bold;
    }

    #provider-select {
        height: auto;
        max-height: 6;
        background: #0a0a0a;
        scrollbar-size: 1 1;
        scrollbar-color: #1f1f1f;
        scrollbar-background: #0a0a0a;
    }

    #provider-select > .option-list--option-highlighted {
        background: #111111;
        color: #7dd3c0;
    }

    #model-select {
        height: auto;
        max-height: 8;
        background: #0a0a0a;
        scrollbar-size: 1 1;
        scrollbar-color: #1f1f1f;
        scrollbar-background: #0a0a0a;
        display: none;
    }

    #model-select > .option-list--option-highlighted {
        background: #111111;
        color: #7dd3c0;
    }

    #hint-bar {
        dock: bottom;
        height: 1;
        width: 100%;
        color: #5a5a5a;
        text-style: italic;
        padding: 0 1;
    }

    #custom-input-label {
        height: 1;
        padding: 0 1;
        color: #8a8a8a;
        display: none;
    }
    """

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._changes: dict[str, str] = {}
        self._selected_role: str | None = None
        self._phase: str = "roles"  # "roles" | "providers" | "models"
        self._available_providers: list[str] = []

    def compose(self) -> ComposeResult:
        with Vertical(id="picker-container"):
            yield Label("⚙  MODEL CONFIGURATION", id="picker-title")

            # Provider status bar
            yield Static("", id="provider-status")
            yield Static("", id="separator-top")

            # Roles list
            yield Static("  Current Agent Configuration", id="roles-header")
            with VerticalScroll(id="roles-section"):
                yield OptionList(id="roles-list")

            yield Static("", id="separator-mid")

            # Model selection area (hidden until a role is selected)
            with Vertical(id="model-select-section"):
                yield Static("  Select Provider", id="model-select-header")
                yield OptionList(id="provider-select")
                yield OptionList(id="model-select")

            yield Static(
                "  [↑↓] Navigate  [Enter] Select  [Esc] Back/Close",
                id="hint-bar",
            )

    def on_mount(self) -> None:
        self._available_providers = get_available_providers()
        self._render_provider_status()
        self._render_roles_list()
        self.query_one("#roles-list", OptionList).focus()

    # ── Renderers ────────────────────────────────────────────────────

    def _render_provider_status(self) -> None:
        """Show which providers have API keys."""
        parts = Text("  ")
        all_providers = ["openai", "anthropic", "xai", "gemini", "openrouter"]
        for i, p in enumerate(all_providers):
            has_key = p in self._available_providers
            icon = "✅" if has_key else "❌"
            name = PROVIDER_DISPLAY.get(p, p)
            parts.append(f"{icon} {name}", style=FG if has_key else DIMMER)
            if i < len(all_providers) - 1:
                parts.append("   ", style=FAINT)
        self.query_one("#provider-status", Static).update(parts)

    def _render_roles_list(self) -> None:
        """Populate the roles list with current config."""
        roles_list = self.query_one("#roles-list", OptionList)
        roles_list.clear_options()
        config = get_current_config()

        for role, model in config.items():
            # Build a rich display line
            line = Text()
            is_main = role == "Main Agent"

            # Role name (left-aligned, padded)
            role_display = f"{'▸ ' if is_main else '  '}{role}"
            line.append(f"{role_display:<24s}", style=f"bold {ACCENT}" if is_main else DIM)

            # Current model (right side)
            model_info = find_model_info(model)
            if model_info:
                line.append(f" {model_info.display_name}", style=FG_B if is_main else FG)
                line.append(f"  ({model_info.tier})", style=DIMMER)
            else:
                line.append(f" {model}", style=FG)

            # Mark changed roles
            if role in self._changes:
                line.append("  ●", style=GREEN)

            roles_list.add_option(Option(line, id=role))

        # Separator + info
        roles_list.add_option(None)
        info_line = Text()
        changes_count = len(self._changes)
        if changes_count:
            info_line.append(
                f"  {changes_count} change{'s' if changes_count != 1 else ''} pending",
                style=f"italic {GREEN}",
            )
        else:
            info_line.append("  Press Enter to change a model", style=f"italic {DIMMER}")
        roles_list.add_option(Option(info_line, id="_info", disabled=True))

    def _render_provider_select(self) -> None:
        """Show available providers for selection."""
        plist = self.query_one("#provider-select", OptionList)
        plist.clear_options()

        for p in self._available_providers:
            name = PROVIDER_DISPLAY.get(p, p)
            model_count = len(get_models_for_provider(p))
            line = Text()
            line.append(f"  {name}", style=ACCENT)
            line.append(f"  ({model_count} models)", style=DIMMER)
            plist.add_option(Option(line, id=p))

    def _render_model_select(self, provider: str) -> None:
        """Show models for the chosen provider."""
        mlist = self.query_one("#model-select", OptionList)
        mlist.clear_options()

        models = get_models_for_provider(provider)
        config = get_current_config()
        current_model = config.get(self._selected_role, "")

        # Group by tier
        tiers = {"flagship": [], "fast": [], "mini": [], "code": []}
        for m in models:
            tiers.setdefault(m.tier, []).append(m)

        tier_labels = {
            "flagship": "━━ Flagship",
            "fast": "━━ Fast",
            "mini": "━━ Mini / Efficient",
            "code": "━━ Code",
        }

        for tier, tier_models in tiers.items():
            if not tier_models:
                continue
            mlist.add_option(None)
            for m in tier_models:
                line = Text()
                is_current = m.id == current_model
                marker = "◆ " if is_current else "  "
                line.append(marker, style=ACCENT if is_current else "")
                line.append(m.display_name, style=FG_B if is_current else FG)
                ctx_k = m.context_window // 1000
                line.append(f"  {ctx_k}K ctx", style=DIMMER)
                if is_current:
                    line.append("  (current)", style=f"italic {ACCENT}")
                mlist.add_option(Option(line, id=m.id))

    # ── Event Handlers ───────────────────────────────────────────────

    @on(OptionList.OptionSelected, "#roles-list")
    def _on_role_selected(self, event: OptionList.OptionSelected) -> None:
        """User selected a role — show provider picker."""
        role = event.option_id
        if role is None or role == "_info":
            return

        self._selected_role = str(role)
        self._phase = "providers"

        # Show model selection area
        self.query_one("#model-select-section").display = True
        header = self.query_one("#model-select-header", Static)
        header.update(Text(f"  Select Provider for: {self._selected_role}", style=ACCENT))

        self._render_provider_select()
        self.query_one("#model-select", OptionList).display = False
        self.query_one("#provider-select", OptionList).display = True

        # Update hint
        self.query_one("#hint-bar", Static).update(
            Text("  [↑↓] Navigate  [Enter] Select Provider  [Esc] Back", style=f"italic {DIMMER}")
        )

        self.query_one("#provider-select", OptionList).focus()

    @on(OptionList.OptionSelected, "#provider-select")
    def _on_provider_selected(self, event: OptionList.OptionSelected) -> None:
        """User selected a provider — show model picker."""
        provider = str(event.option_id)
        self._phase = "models"

        header = self.query_one("#model-select-header", Static)
        provider_name = PROVIDER_DISPLAY.get(provider, provider)
        header.update(
            Text(
                f"  {provider_name} → {self._selected_role}",
                style=ACCENT,
            )
        )

        self.query_one("#provider-select", OptionList).display = False
        self.query_one("#model-select", OptionList).display = True
        self._render_model_select(provider)

        self.query_one("#hint-bar", Static).update(
            Text("  [↑↓] Navigate  [Enter] Apply  [Esc] Back", style=f"italic {DIMMER}")
        )

        self.query_one("#model-select", OptionList).focus()

    @on(OptionList.OptionSelected, "#model-select")
    def _on_model_selected(self, event: OptionList.OptionSelected) -> None:
        """User selected a model — apply it."""
        model_id = str(event.option_id)
        if not model_id or not self._selected_role:
            return

        # Apply the change
        apply_model_config(self._selected_role, model_id)
        self._changes[self._selected_role] = model_id

        # Return to roles view
        self._go_back_to_roles()

    # ── Navigation ───────────────────────────────────────────────────

    def action_cancel(self) -> None:
        """Esc key — context-sensitive: back or close."""
        if self._phase == "models":
            # Go back to provider select
            self._phase = "providers"
            self.query_one("#model-select", OptionList).display = False
            self.query_one("#provider-select", OptionList).display = True

            header = self.query_one("#model-select-header", Static)
            header.update(Text(f"  Select Provider for: {self._selected_role}", style=ACCENT))

            self.query_one("#hint-bar", Static).update(
                Text("  [↑↓] Navigate  [Enter] Select Provider  [Esc] Back", style=f"italic {DIMMER}")
            )
            self.query_one("#provider-select", OptionList).focus()

        elif self._phase == "providers":
            self._go_back_to_roles()

        else:
            # Close the screen — return changes (or None if no changes)
            self.dismiss(self._changes if self._changes else None)

    def _go_back_to_roles(self) -> None:
        """Return to the roles list view."""
        self._phase = "roles"
        self._selected_role = None
        self.query_one("#model-select-section").display = False

        self.query_one("#hint-bar", Static).update(
            Text("  [↑↓] Navigate  [Enter] Select  [Esc] Close", style=f"italic {DIMMER}")
        )

        # Refresh the roles list to show updated config
        self._render_roles_list()
        self.query_one("#roles-list", OptionList).focus()
