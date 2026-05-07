"""
SpawnAgentTool — spawn sub-agents with their own query loops.

Sub-agents get their own QueryLoop instance, a restricted tool set,
and inherit the parent's ToolContext. They cannot spawn further sub-agents
(no recursive spawning).

Supports foreground (blocking) and background (async, returns task_id) modes.
"""

import asyncio
import logging
import os
import uuid

from src.agent.context import ToolContext
from src.agent.tool import PermissionLevel, Tool, ToolResult

logger = logging.getLogger(__name__)

DEFAULT_SUB_AGENT_MODEL = "gpt-5.4-mini"
DEFAULT_MAX_TURNS = 50
SUB_AGENT_TIMEOUT = 600  # 10 min

# Strong-ref set for fire-and-forget background tasks; prevents GC mid-flight.
_BG_TASKS: set[asyncio.Task] = set()


class SpawnAgentTool(Tool):

    def name(self) -> str:
        return "spawn_agent"

    def description(self) -> str:
        return (
            "Spawn a sub-agent with its own reasoning loop to handle a "
            "complex sub-task. The sub-agent gets its own conversation but "
            "shares the session's findings, graph, and context. Use for "
            "tasks that require autonomous multi-step reasoning. "
            "Returns the sub-agent's final text response."
        )

    def permission_level(self) -> PermissionLevel:
        return PermissionLevel.EXECUTE

    def input_schema(self) -> dict:
        return {
            "type": "object",
            "properties": {
                "prompt": {
                    "type": "string",
                    "description": (
                        "Full task prompt for the sub-agent. Be specific and "
                        "self-contained — the sub-agent has no conversation history."
                    ),
                },
                "description": {
                    "type": "string",
                    "description": "Short (3-5 word) description of the task.",
                },
                "model": {
                    "type": "string",
                    "description": f"Model to use (default: {DEFAULT_SUB_AGENT_MODEL}).",
                },
                "tools": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Allowlist of tool names. Omit for all available (except spawn_agent).",
                },
                "max_turns": {
                    "type": "integer",
                    "description": f"Max turns for the sub-agent (default: {DEFAULT_MAX_TURNS}).",
                },
                "background": {
                    "type": "boolean",
                    "description": "If true, runs in background and returns a task_id. Default: false.",
                    "default": False,
                },
            },
            "required": ["prompt", "description"],
        }

    async def execute(self, params: dict, ctx: ToolContext) -> ToolResult:
        from src.agent.events import Event, EventType
        from src.agent.permissions import PermissionHandler
        from src.agent.query_loop import QueryLoop
        from src.agent.tools import get_all_tools

        prompt = params["prompt"]
        description = params.get("description", "sub-agent task")
        model = params.get("model") or os.getenv(
            "SUB_AGENT_MODEL_NAME", DEFAULT_SUB_AGENT_MODEL
        )
        tool_allowlist = params.get("tools")
        max_turns = min(params.get("max_turns", DEFAULT_MAX_TURNS), 100)
        background = params.get("background", False)

        # Get available tools, EXCLUDING spawn_agent to prevent recursion
        all_tools = get_all_tools()
        sub_tools = [t for t in all_tools if t.name() != "spawn_agent"]

        # Apply allowlist if specified
        if tool_allowlist:
            sub_tools = [t for t in sub_tools if t.name() in tool_allowlist]

        # Sub-agents inherit the parent's permission handler so the parent's
        # mode (ask/auto/yolo), prompt callback, and session approvals all
        # apply. Previously we installed an auto-approve handler here, which
        # let a restricted-tool sub-agent request DANGEROUS operations that
        # the parent session would have prompted for — a privilege bypass.
        sub_permissions = getattr(ctx, "permission_handler", None) or PermissionHandler()

        # Create the sub-agent's query loop
        sub_loop = QueryLoop(
            tools=sub_tools,
            ctx=ctx,  # shared context
            model=model,
            max_turns=max_turns,
            permission_handler=sub_permissions,
        )

        task_id = f"agent_{uuid.uuid4().hex[:8]}"

        # Emit worker spawned event
        if ctx.event_bus:
            await ctx.event_bus.emit(Event(
                type=EventType.WORKER_SPAWNED,
                data={"task_id": task_id, "description": description, "model": model},
            ))

        if background:
            return await self._run_background(
                sub_loop, prompt, task_id, description, ctx
            )

        # Foreground: blocking
        try:
            result = await asyncio.wait_for(
                sub_loop.run(prompt),
                timeout=SUB_AGENT_TIMEOUT,
            )
        except TimeoutError:
            result = f"Sub-agent timed out after {SUB_AGENT_TIMEOUT}s."
            logger.warning(f"Sub-agent {task_id} timed out.")
        except Exception as e:
            result = f"Sub-agent error: {e}"
            logger.error(f"Sub-agent {task_id} failed: {e}", exc_info=True)

        # Emit worker complete
        if ctx.event_bus:
            await ctx.event_bus.emit(Event(
                type=EventType.WORKER_COMPLETE,
                data={
                    "task_id": task_id,
                    "description": description,
                    "result_preview": result[:200],
                },
            ))

        return ToolResult.success(result, task_id=task_id)

    async def _run_background(
        self,
        sub_loop,
        prompt: str,
        task_id: str,
        description: str,
        ctx: ToolContext,
    ) -> ToolResult:
        """Run the sub-agent as a background task."""
        from src.agent.events import Event, EventType

        # Register in task store if available
        if ctx.task_store:
            await ctx.task_store.create(
                subject=description,
                owner=ctx.session_id,
                task_id=task_id,
            )
            await ctx.task_store.update(task_id, status="running")

        async def _bg():
            try:
                result = await asyncio.wait_for(
                    sub_loop.run(prompt),
                    timeout=SUB_AGENT_TIMEOUT,
                )
                if ctx.task_store:
                    await ctx.task_store.update(
                        task_id, status="done", result=result[:5000]
                    )
            except TimeoutError:
                if ctx.task_store:
                    await ctx.task_store.update(
                        task_id, status="failed", error="Timed out"
                    )
            except Exception as e:
                if ctx.task_store:
                    await ctx.task_store.update(
                        task_id, status="failed", error=str(e)
                    )
            finally:
                if ctx.event_bus:
                    await ctx.event_bus.emit(Event(
                        type=EventType.WORKER_COMPLETE,
                        data={"task_id": task_id, "description": description},
                    ))

        _t = asyncio.create_task(_bg(), name=task_id)
        _BG_TASKS.add(_t)
        _t.add_done_callback(_BG_TASKS.discard)

        return ToolResult.success(
            f"Sub-agent '{description}' started in background.\n"
            f"Task ID: {task_id}\n"
            f"Model: {sub_loop.model}\n"
            f"Tools: {len(sub_loop.all_tools)}\n"
            f"Check status with task_store or wait for completion event.",
            task_id=task_id,
        )
