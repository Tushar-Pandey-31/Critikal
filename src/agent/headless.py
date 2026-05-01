import asyncio
import logging
import os
import sys
import uuid

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

from src.agent.context import ToolContext
from src.agent.cost import CostTracker
from src.agent.events import EventBus, Event, EventType
from src.agent.hooks import HookRegistry
from src.agent.permissions import PermissionHandler
from src.agent.query_loop import QueryLoop
from src.agent.task_store import TaskStore
from src.agent.tools import get_all_tools
from src.agent.memory import SessionMemory, AutoDream, generate_away_summary

logger = logging.getLogger(__name__)


def _stdout_prompt_callback():
    """Create a prompt callback for headless mode that reads from stdin."""
    async def _prompt(tool_name: str, params: dict, level: str) -> bool:
        # In yolo mode this won't be called
        # In ask mode, print and wait for input
        print(f"\n[PERMISSION] Tool '{tool_name}' ({level}) wants to execute.")
        if params:
            for k, v in params.items():
                val = str(v)
                if len(val) > 100:
                    val = val[:100] + "..."
                print(f"  {k}: {val}")
        try:
            answer = input("Allow? [y/N]: ").strip().lower()
            return answer in ("y", "yes")
        except (EOFError, KeyboardInterrupt):
            return False
    return _prompt


class HeadlessRunner:
    """
    Runs the Critikal agent in headless mode (no TUI).

    Events are printed to stdout. Can run with a repo URL
    (full pipeline) or a custom prompt (free-form).
    """

    def __init__(
        self,
        model: str | None = None,
        permission_mode: str = "yolo",
        budget_usd: float | None = None,
        engagement_id: str | None = None,
    ):
        self.model = model or os.getenv("AGENT_MODEL_NAME", "claude-sonnet-4-6")
        self.permission_mode = permission_mode
        self.budget_usd = budget_usd
        self.engagement_id = engagement_id or str(uuid.uuid4())[:8]
        self._streaming_active = False

    async def run_audit(self, repo_url: str) -> str:
        """Run a full audit on a repo URL."""
        # The goal is stated; the path is not. The system prompt already
        # teaches methodology and the tool catalog is visible to the
        # model — enumerating steps here would just override the agent's
        # ability to reason about the target.
        prompt = (
            f"Target: {repo_url}\n\n"
            "You are engaged to find real, exploitable vulnerabilities in this "
            "codebase. Deliverable: a final audit report containing every "
            "confirmed finding, each with severity, a concrete attack scenario, "
            "affected code locations, and — for any finding that moves money or "
            "breaks a safety invariant — a working Foundry PoC that passes.\n\n"
            "Constraints:\n"
            "- Evidence, not speculation. A finding without a reproduction is a hypothesis.\n"
            "- Severity must match real impact (CRITICAL = funds can be drained or "
            "locked; don't inflate).\n"
            "- Fewer real findings beat many theoretical ones.\n\n"
            "You have the full tool catalog and a shell. Plan your own approach, "
            "pivot when evidence changes your hypothesis, and stop when you've "
            "exhausted the attack surface or the remaining risk is clearly low. "
            "Write the report when you're done."
        )
        return await self.run_prompt(prompt, repo_url=repo_url)

    async def run_prompt(self, prompt: str, repo_url: str | None = None) -> str:
        """Run the agent with a custom prompt."""
        # Preflight: check the chosen model has credentials before we
        # spin up subsystems. Otherwise the first LLM call fails, we
        # fall back to another provider, and *that* fails too — the
        # real cause ("no key set") is buried under retry noise.
        from src.llm.providers import check_provider_credentials
        ok, detail = check_provider_credentials(self.model)
        if not ok:
            msg = f"Preflight failed: {detail}"
            print(f"\n✗ {msg}\n")
            return msg

        # Build context
        ctx = ToolContext(
            permission_mode=self.permission_mode,
            repo_url=repo_url,
            engagement_id=self.engagement_id,
        )

        # Initialize subsystems
        ctx.event_bus = EventBus()
        ctx.task_store = TaskStore()
        ctx.cost_tracker = CostTracker(budget_usd=self.budget_usd)
        ctx.hooks = HookRegistry()

        # Initialize memory system
        ctx.memory = SessionMemory(self.engagement_id)
        ctx.memory_dir = ctx.memory.memory_dir
        print(f"  📝 Memory: {ctx.memory_dir}")

        # Set up permission handler
        if self.permission_mode == "yolo":
            handler = PermissionHandler()
            async def _auto_approve(*a):
                return True
            handler._prompt_callback = _auto_approve
        else:
            handler = PermissionHandler(prompt_callback=_stdout_prompt_callback())

        # Build tools
        tools = get_all_tools()

        # Create query loop
        loop = QueryLoop(
            tools=tools,
            ctx=ctx,
            model=self.model,
            permission_handler=handler,
        )

        # Start event consumer (stdout printer)
        consumer_task = asyncio.create_task(
            self._consume_events(ctx.event_bus)
        )

        # SessionStart hook (best-effort, pre-loop)
        if ctx.hooks is not None and ctx.hooks.has("SessionStart"):
            try:
                await ctx.hooks.fire(
                    "SessionStart",
                    payload={
                        "engagement_id": self.engagement_id,
                        "repo_url": repo_url,
                        "model": self.model,
                    },
                )
            except Exception as e:
                logger.warning(f"[hooks] SessionStart failed: {e}")

        # Run the agent
        try:
            result = await loop.run(prompt)
        except KeyboardInterrupt:
            result = "\n[Interrupted by user]"
        except Exception as e:
            logger.error(f"Agent failed: {e}", exc_info=True)
            result = f"Agent error: {e}"
        finally:
            # SessionEnd hook before we tear the bus down
            if ctx.hooks is not None and ctx.hooks.has("SessionEnd"):
                try:
                    await ctx.hooks.fire(
                        "SessionEnd",
                        payload={
                            "engagement_id": self.engagement_id,
                            "turns": loop.ctx.current_turn,
                        },
                    )
                except Exception as e:
                    logger.warning(f"[hooks] SessionEnd failed: {e}")

            consumer_task.cancel()
            try:
                await consumer_task
            except asyncio.CancelledError:
                pass

        # Print final stats
        stats = loop.get_conversation_stats()
        cost = ctx.cost_tracker.format_short() if ctx.cost_tracker else "$0.00"
        memories = ctx.memory.get_memory_count() if ctx.memory else 0
        print(f"\n{'='*60}")
        print(f"Session complete. Cost: {cost} | Turns: {stats['turns']} | "
              f"Findings: {stats['findings']} | Memories: {memories}")
        print(f"Engagement: {self.engagement_id}")
        print(f"{'='*60}")

        # Post-session: trigger memory consolidation (best-effort)
        if ctx.memory and ctx.memory.get_memory_count() > 0:
            try:
                dreamer = AutoDream(self.engagement_id)
                consolidated = await dreamer.consolidate()
                if consolidated:
                    print(f"  💭 Memory consolidated → {dreamer.consolidated_path}")
            except Exception as e:
                logger.warning(f"[dream] Post-session consolidation failed: {e}")

        return result

    async def _consume_events(self, bus: EventBus):
        """Print events to stdout."""
        queue = bus.create_subscriber()
        try:
            while True:
                event = await queue.get()
                self._print_event(event)
        except asyncio.CancelledError:
            pass
        finally:
            bus.remove_subscriber(queue)

    def _print_event(self, event: Event):
        """Format and print an event."""
        t = event.type
        d = event.data

        if t == EventType.MESSAGE_CHUNK:
            # Stream reasoning/thinking text in real-time.
            # Anthropic thinking blocks arrive with kind="thinking" — dim
            # them (ANSI 2) so they read as meta-commentary, not as the
            # assistant's committed output.
            text = d.get("text", "")
            if not text:
                return
            kind = d.get("kind", "text")
            if kind != self._streaming_active:
                # switching stream kind — new line + marker
                if self._streaming_active:
                    sys.stdout.write("\n")
                if kind == "thinking":
                    sys.stdout.write("\n\x1b[2m∴ thinking  ")
                else:
                    sys.stdout.write("\n\x1b[0m")
                self._streaming_active = kind
            if kind == "thinking":
                sys.stdout.write(f"\x1b[2m{text}\x1b[0m")
            else:
                sys.stdout.write(text)
            sys.stdout.flush()

        elif t == EventType.MESSAGE_COMPLETE:
            # Final assistant text — print with newline if not already streamed
            text = d.get("text", "")
            if text and not self._streaming_active:
                print(f"\n{text}")
            elif self._streaming_active:
                # End the streamed block with a newline
                print()
            self._streaming_active = False

        elif t == EventType.TOOL_START:
            tool = d.get("tool", "?")
            args = d.get("args_summary", "")
            print(f"\n  ⟳ {tool}({args})")
            self._streaming_active = False

        elif t == EventType.TOOL_COMPLETE:
            tool = d.get("tool", "?")
            elapsed = d.get("elapsed_s", 0)
            is_err = d.get("is_error", False)
            icon = "✗" if is_err else "✓"
            print(f"  {icon} {tool} ({elapsed}s)")

        elif t == EventType.FINDING_ADDED:
            idx = d.get("finding_index", "?")
            print(f"  🔍 Finding #{idx} added")

        elif t == EventType.WORKER_SPAWNED:
            desc = d.get("description", "?")
            model = d.get("model", "?")
            print(f"  ⊕ Sub-agent spawned: {desc} ({model})")

        elif t == EventType.WORKER_COMPLETE:
            desc = d.get("description", "?")
            print(f"  ✓ Sub-agent done: {desc}")

        elif t == EventType.COST_UPDATE:
            cost = d.get("cost", 0)
            if cost > 0:
                sys.stdout.write(f"\r  [${cost:.2f}]")
                sys.stdout.flush()

        elif t == EventType.COMPACT:
            print("  ⊘ Context compacted")

        elif t == EventType.STATUS:
            msg = d.get("message", "")
            if msg:
                print(f"  ℹ {msg}")

        elif t == EventType.TURN_COMPLETE:
            turn = d.get("turn", "?")
            logger.debug(f"Turn {turn} complete")

        elif t == EventType.ERROR:
            err = d.get("error", "unknown")
            print(f"  ✗ Error: {err}")
