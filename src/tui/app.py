"""
CritikalApp — main Textual TUI application.

The fullscreen interactive terminal UI for the Critikal agent.

Layout:
┌────────────────────────────────────────────────────────────────┐
│  Header: CRITIKAL v2 │ Model │ $Cost │ Findings               │
├──────────────────────────────────┬─────────────────────────────┤
│  Conversation Stream             │  Findings Panel             │
│  (scrollable)                    │  (live updating)            │
│                                  ├─────────────────────────────┤
│                                  │  Worker Status              │
├──────────────────────────────────┴─────────────────────────────┤
│  Cost: $0.42 │ Tokens: 32K/8K │ Turn 7/200 │ 🔍3              │
├────────────────────────────────────────────────────────────────┤
│  > prompt input                                                │
└────────────────────────────────────────────────────────────────┘
"""

import asyncio
import logging
import os
import uuid
from pathlib import Path

from rich.text import Text
from textual import work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.widgets import Header, Static

from src.agent.context import ToolContext
from src.agent.cost import CostTracker
from src.agent.events import Event, EventBus, EventType
from src.agent.memory import AutoDream, SessionMemory
from src.agent.permissions import PermissionHandler
from src.agent.query_loop import QueryLoop
from src.agent.task_store import TaskStore
from src.agent.tools import get_all_tools
from src.tui.widgets.conversation_widget import ConversationWidget
from src.tui.widgets.cost_bar import CostBar
from src.tui.widgets.findings_widget import FindingsWidget
from src.tui.widgets.model_picker import ModelPickerScreen
from src.tui.widgets.prompt_input import PromptInput
from src.tui.widgets.worker_widget import WorkerWidget

logger = logging.getLogger(__name__)


# ── Slash Commands ──
SLASH_COMMANDS = {
    "compact": "Force context compaction",
    "cost": "Show detailed cost breakdown",
    "findings": "Toggle findings panel",
    "workers": "Toggle worker status panel",
    "status": "Show session status",
    "model": "Open model picker (or /model <name> for quick switch)",
    "export": "Export findings to file",
    "dream": "Run memory consolidation now",
    "quit": "Exit Critikal",
    "help": "Show available commands",
}


class CritikalApp(App):
    """
    Main Textual application for interactive Critikal sessions.

    Connects the EventBus to live-updating widgets.
    """

    TITLE = "CRITIKAL v2"
    SUB_TITLE = "autonomous security research"
    CSS_PATH = "styles.tcss"

    BINDINGS = [
        Binding("ctrl+c", "interrupt", "Interrupt", show=True),
        Binding("ctrl+q", "quit", "Quit", show=True),
        Binding("ctrl+f", "toggle_findings", "Findings", show=True),
        Binding("ctrl+w", "toggle_workers", "Workers", show=True),
        Binding("ctrl+m", "open_model_picker", "Models", show=True),
    ]

    def __init__(
        self,
        repo_url: str | None = None,
        model: str | None = None,
        budget_usd: float | None = None,
        permission_mode: str | None = None,
        resume_engagement: str | None = None,
        **kwargs,
    ):
        super().__init__(**kwargs)
        self.repo_url = repo_url
        self.model = model or os.getenv("AGENT_MODEL_NAME", "grok-4-1-fast-reasoning")
        self.budget_usd = budget_usd
        # The TUI does not yet ship a modal approval dialog, so "ask" cannot be
        # honoured here without silently auto-approving (which would be a
        # security misrepresentation). Coerce to "auto" and surface a warning
        # at on_mount; users who need true "ask" should run headless mode.
        requested_mode = permission_mode or "auto"
        if requested_mode == "ask":
            self._mode_coerced_from = "ask"
            self.permission_mode = "auto"
        else:
            self._mode_coerced_from = None
            self.permission_mode = requested_mode
        self.resume_engagement = resume_engagement

        # Generate or resume engagement ID
        self.engagement_id = resume_engagement or str(uuid.uuid4())[:8]

        # Agent subsystems (initialized on mount)
        self._ctx: ToolContext | None = None
        self._loop: QueryLoop | None = None
        self._event_consumer_task: asyncio.Task | None = None
        self._agent_running = False

    def compose(self) -> ComposeResult:
        """Build the TUI layout — single-column, conversation-first."""
        yield Header(show_clock=True)

        with Horizontal(id="main-container"):
            # Left: conversation takes full width
            with Vertical(id="left-panel"):
                yield ConversationWidget(id="conversation")

            # Right: findings+workers — hidden by default, toggled with Ctrl+F/Ctrl+W
            with Vertical(id="right-panel"):
                yield FindingsWidget(id="findings-panel")
                yield WorkerWidget(id="workers-panel")

        yield CostBar(id="cost-bar")

        with Vertical(id="prompt-area"):
            yield Static(
                Text("─" * 200, style="#1f1f1f"),
                id="prompt-separator",
            )
            yield Static(
                Text(
                    f"  {self.model} · {self.engagement_id}",
                    style="italic #5a5a5a",
                ),
                id="prompt-hint",
            )
            yield PromptInput(id="prompt-input")

    async def on_mount(self):
        """Initialize the agent subsystems when the app mounts."""
        conv = self.query_one("#conversation", ConversationWidget)
        conv.add_system_message(f"Critikal v2 — {self.model}")
        conv.add_system_message(f"Engagement: {self.engagement_id}")

        # Initialize context
        self._ctx = ToolContext(
            permission_mode=self.permission_mode,
            repo_url=self.repo_url,
            engagement_id=self.engagement_id,
        )
        self._ctx.event_bus = EventBus()
        self._ctx.task_store = TaskStore()
        self._ctx.cost_tracker = CostTracker(budget_usd=self.budget_usd)
        self._ctx.memory = SessionMemory(self.engagement_id)
        self._ctx.memory_dir = self._ctx.memory.memory_dir

        # Permission handler — for TUI, prompt via a dialog
        handler = PermissionHandler(prompt_callback=self._permission_prompt)

        # Build tools and query loop
        tools = get_all_tools()
        self._loop = QueryLoop(
            tools=tools,
            ctx=self._ctx,
            model=self.model,
            permission_handler=handler,
        )

        # Start event consumer
        self._event_consumer_task = asyncio.create_task(
            self._consume_events()
        )

        # Update cost bar
        cost_bar = self.query_one("#cost-bar", CostBar)
        cost_bar.update_model(self.model)

        conv.add_system_message(f"Engagement: {self.engagement_id} │ Memory: {self._ctx.memory_dir}")
        conv.add_system_message(f"{len(tools)} tools loaded │ Type a message or /help")
        if self._mode_coerced_from == "ask":
            conv.add_system_message(
                "Note: --permission-mode=ask is not supported in the TUI yet "
                "(no modal dialog). Coerced to 'auto'. Use headless mode for "
                "interactive approval."
            )

        # If repo_url provided, auto-start audit
        if self.repo_url:
            conv.add_system_message(f"Auto-starting audit: {self.repo_url}")
            self._submit_prompt(
                f"Target: {self.repo_url}\n\n"
                "Find real, exploitable vulnerabilities. Deliver a final "
                "report with confirmed findings, severities, attack "
                "scenarios, code locations, and a passing Foundry PoC for "
                "anything that moves money or breaks a safety invariant. "
                "Plan your own approach."
            )

        # Focus input
        self.query_one("#prompt-input", PromptInput).focus()

    async def on_prompt_input_submitted(self, event: PromptInput.Submitted):
        """Handle user input submission."""
        text = event.value.strip()
        if not text:
            return

        # Check for slash commands
        if text.startswith("/"):
            await self._handle_slash_command(text)
            return

        # Regular prompt — send to agent
        self._submit_prompt(text)

    @work(exclusive=True)
    async def _submit_prompt(self, prompt: str):
        """Run the agent with a user prompt (background worker)."""
        if self._agent_running:
            conv = self.query_one("#conversation", ConversationWidget)
            conv.add_system_message("Agent is already running. Wait or Ctrl+C to interrupt.")
            return

        self._agent_running = True
        conv = self.query_one("#conversation", ConversationWidget)
        conv.add_user_message(prompt)

        try:
            # The final text is already rendered via MESSAGE_CHUNK streaming +
            # MESSAGE_COMPLETE finalize — don't re-render or we get duplicate
            # content at the bottom of every turn.
            await self._loop.run(prompt)
        except asyncio.CancelledError:
            conv.add_system_message("Agent interrupted.")
        except Exception as e:
            conv.add_error(str(e))
            logger.error(f"Agent error: {e}", exc_info=True)
        finally:
            self._agent_running = False

        # Update cost bar
        self._update_cost_bar()

    async def _consume_events(self):
        """Background task that routes EventBus events to widgets."""
        if not self._ctx or not self._ctx.event_bus:
            return

        queue = self._ctx.event_bus.create_subscriber()
        try:
            while True:
                event = await queue.get()
                self._route_event(event)
        except asyncio.CancelledError:
            pass
        finally:
            if self._ctx and self._ctx.event_bus:
                self._ctx.event_bus.remove_subscriber(queue)

    def _route_event(self, event: Event):
        """Route an event to the appropriate widget(s)."""
        try:
            conv = self.query_one("#conversation", ConversationWidget)
            t = event.type
            d = event.data

            if t == EventType.MESSAGE_CHUNK:
                # Live token stream — the whole point of streaming is to show
                # the agent thinking in real time rather than a wall of text
                # at the end. `kind` distinguishes Anthropic thinking blocks
                # (dim/italic) from regular output.
                text = d.get("text", "")
                kind = d.get("kind", "text")
                if text:
                    conv.append_stream(text, kind=kind)

            elif t == EventType.MESSAGE_COMPLETE:
                # Close the stream. If streaming never delivered any tokens
                # (astream failed, fell back to ainvoke), render the full text
                # now so the user isn't left with an empty turn.
                conv.finalize_message(d.get("text", ""))

            elif t == EventType.TOOL_START:
                conv.add_tool_start(d.get("tool", "?"), d.get("args_summary", ""))

            elif t == EventType.TOOL_COMPLETE:
                conv.add_tool_complete(
                    d.get("tool", "?"),
                    d.get("elapsed_s", 0),
                    d.get("is_error", False),
                )

            elif t == EventType.FINDING_ADDED:
                idx = d.get("finding_index", 0)
                conv.add_finding(idx)
                findings_panel = self.query_one("#findings-panel", FindingsWidget)
                if self._ctx:
                    findings_panel.update_from_context(self._ctx.findings)

            elif t == EventType.WORKER_SPAWNED:
                desc = d.get("description", "?")
                model = d.get("model", "")
                conv.add_worker_spawned(desc, model)
                workers = self.query_one("#workers-panel", WorkerWidget)
                task_id = d.get("task_id", desc)
                workers.add_worker(task_id, desc, "running")

            elif t == EventType.WORKER_COMPLETE:
                desc = d.get("description", "?")
                conv.add_worker_complete(desc)
                workers = self.query_one("#workers-panel", WorkerWidget)
                task_id = d.get("task_id", desc)
                workers.complete_worker(task_id, True)

            elif t == EventType.COMPACT:
                conv.add_compact_notice(d.get("kind", ""))

            elif t == EventType.COST_UPDATE:
                self._update_cost_bar()

            elif t == EventType.STATUS:
                msg = d.get("message", "")
                if msg:
                    conv.add_system_message(msg)

            elif t == EventType.ERROR:
                err = d.get("error", "unknown")
                conv.add_error(err)

        except Exception as e:
            logger.debug(f"Event routing error (non-fatal): {e}")

    def _update_cost_bar(self):
        """Sync cost bar with current tracker state."""
        cost_bar = self.query_one("#cost-bar", CostBar)
        if self._ctx:
            findings_count = len(self._ctx.findings)
            memories_count = self._ctx.memory.get_memory_count() if self._ctx.memory else 0
            cost_bar.update_from_tracker(
                self._ctx.cost_tracker,
                turn=self._ctx.current_turn,
                findings=findings_count,
                model=self.model,
            )
            cost_bar.update_memories(memories_count)

    async def _handle_slash_command(self, text: str):
        """Handle slash commands."""
        parts = text[1:].split(None, 1)
        cmd = parts[0].lower() if parts else ""
        args = parts[1] if len(parts) > 1 else ""

        conv = self.query_one("#conversation", ConversationWidget)

        if cmd == "help":
            conv.add_system_message("Available commands:")
            for name, desc in SLASH_COMMANDS.items():
                conv.add_system_message(f"  /{name} — {desc}")

        elif cmd == "quit" or cmd == "exit":
            self.exit()

        elif cmd == "cost":
            if self._ctx and self._ctx.cost_tracker:
                summary = self._ctx.cost_tracker.summary()
                lines = [f"Session cost: ${summary['session_cost_usd']}"]
                if summary.get("budget_usd"):
                    lines.append(f"Budget: ${summary['budget_usd']}")
                lines.append(f"Input tokens: {summary['total_input_tokens']:,}")
                lines.append(f"Output tokens: {summary['total_output_tokens']:,}")
                for model, data in summary.get("per_model", {}).items():
                    lines.append(f"  {model}: ${data['cost']:.4f} ({data['calls']} calls)")
                conv.add_system_message("\n".join(lines))
            else:
                conv.add_system_message("No cost data yet.")

        elif cmd == "findings":
            panel = self.query_one("#right-panel")
            panel.display = not panel.display

        elif cmd == "workers":
            workers = self.query_one("#workers-panel", WorkerWidget)
            workers.display = not workers.display

        elif cmd == "status":
            if self._loop:
                stats = self._loop.get_conversation_stats()
                lines = [f"Model: {stats['model']}"]
                lines.append(f"Messages: {stats['messages']}")
                lines.append(f"Turns: {stats['turns']}")
                lines.append(f"Tools: {stats['tools_available']}")
                lines.append(f"Findings: {stats['findings']}")
                if self._ctx and self._ctx.memory:
                    lines.append(f"Memories: {self._ctx.memory.get_memory_count()}")
                conv.add_system_message("\n".join(lines))

        elif cmd == "model":
            if args:
                self.model = args.strip()
                if self._loop:
                    self._loop.model = self.model
                    self._loop._llm_cache.clear()  # Force re-init
                    self._loop._current_model = self.model
                conv.add_system_message(f"Model switched to: {self.model}")
                cost_bar = self.query_one("#cost-bar", CostBar)
                cost_bar.update_model(self.model)
                # Update prompt hint
                hint = self.query_one("#prompt-hint", Static)
                hint.update(Text(
                    f"  {self.model} · {self.engagement_id}",
                    style="italic #5a5a5a",
                ))
            else:
                self._open_model_picker()

        elif cmd == "compact":
            if self._loop:
                conv.add_system_message("Forcing compaction...")
                await self._loop.compactor.compact(self._loop.messages)
                conv.add_compact_notice()
            else:
                conv.add_system_message("No active loop.")

        elif cmd == "dream":
            if self._ctx and self._ctx.memory:
                conv.add_system_message("Running memory consolidation...")
                dreamer = AutoDream(self.engagement_id)
                try:
                    ok = await dreamer.consolidate(force=True)
                    if ok:
                        conv.add_system_message(f"Consolidated → {dreamer.consolidated_path}")
                    else:
                        conv.add_system_message("Nothing to consolidate.")
                except Exception as e:
                    conv.add_error(f"Dream failed: {e}")

        elif cmd == "export":
            if self._ctx and self._ctx.findings:
                export_path = Path(f"critikal_findings_{self.engagement_id}.json")
                import json
                with open(export_path, "w") as f:
                    findings_data = []
                    for finding in self._ctx.findings:
                        if hasattr(finding, "to_dict"):
                            findings_data.append(finding.to_dict())
                        elif hasattr(finding, "__dict__"):
                            findings_data.append(vars(finding))
                    json.dump(findings_data, f, indent=2, default=str)
                conv.add_system_message(f"Exported {len(findings_data)} findings → {export_path}")
            else:
                conv.add_system_message("No findings to export.")

        else:
            conv.add_system_message(f"Unknown command: /{cmd}. Type /help for available commands.")

    async def _permission_prompt(self, tool_name: str, params: dict, level: str) -> bool:
        """Permission decision for TUI mode.

        This callback only fires for tool calls the PermissionHandler did NOT
        already auto-approve based on the active mode. With no modal dialog
        implemented yet, the only honest options are: approve (yolo) or deny.
        DANGEROUS calls in 'auto' mode land here — denying them by default
        means destructive operations (e.g. raw shell, on-chain writes) cannot
        run in the TUI without explicitly opting in via --permission-mode yolo.
        """
        conv = self.query_one("#conversation", ConversationWidget)
        if self.permission_mode == "yolo":
            return True
        conv.add_system_message(
            f"[blocked] {tool_name} ({level}) requires approval — "
            f"relaunch with --permission-mode yolo to allow, or run headless."
        )
        return False

    def action_interrupt(self):
        """Handle Ctrl+C — interrupt the running agent."""
        if self._agent_running:
            conv = self.query_one("#conversation", ConversationWidget)
            conv.add_system_message("Interrupting agent...")
            # Cancel the worker
            workers = self.workers
            for worker in workers._running:
                worker.cancel()

    def action_toggle_findings(self):
        """Toggle the right panel (findings + workers)."""
        panel = self.query_one("#right-panel")
        panel.display = not panel.display
        conv = self.query_one("#conversation", ConversationWidget)
        if panel.display:
            conv.add_system_message("Findings panel shown (Ctrl+F to hide)")
        else:
            conv.add_system_message("Findings panel hidden (Ctrl+F to show)")

    def action_toggle_workers(self):
        """Toggle the right panel (findings + workers)."""
        panel = self.query_one("#right-panel")
        panel.display = not panel.display

    def action_open_model_picker(self):
        """Open the model configuration picker (Ctrl+M)."""
        self._open_model_picker()

    def _open_model_picker(self):
        """Push the ModelPickerScreen and handle dismiss."""
        self.push_screen(ModelPickerScreen(), callback=self._on_model_picker_dismiss)

    def _on_model_picker_dismiss(self, changes: dict[str, str] | None) -> None:
        """Handle model picker results — apply changes and update UI."""
        conv = self.query_one("#conversation", ConversationWidget)
        if not changes:
            conv.add_system_message("Model picker closed — no changes.")
            return

        # Apply changes and report
        for role, model_id in changes.items():
            conv.add_system_message(f"  ✓ {role} → {model_id}")

        # If main agent model changed, update the loop
        if "Main Agent" in changes:
            new_model = changes["Main Agent"]
            self.model = new_model
            if self._loop:
                self._loop.model = new_model
                self._loop._current_model = new_model
                self._loop._llm_cache.clear()  # Force re-init on next call

            # Update status bar and prompt hint
            cost_bar = self.query_one("#cost-bar", CostBar)
            cost_bar.update_model(new_model)
            hint = self.query_one("#prompt-hint", Static)
            hint.update(Text(
                f"  {new_model} · {self.engagement_id}",
                style="italic #5a5a5a",
            ))

        conv.add_system_message(
            f"Applied {len(changes)} model change{'s' if len(changes) != 1 else ''}."
        )

    async def on_unmount(self):
        """Cleanup on exit."""
        if self._event_consumer_task:
            self._event_consumer_task.cancel()
            try:
                await self._event_consumer_task
            except asyncio.CancelledError:
                pass

        # Post-session memory consolidation
        if self._ctx and self._ctx.memory and self._ctx.memory.get_memory_count() > 0:
            try:
                dreamer = AutoDream(self.engagement_id)
                await dreamer.consolidate()
            except Exception:
                pass
