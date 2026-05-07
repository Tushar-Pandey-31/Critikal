"""
EventBus — decouples the query loop from the UI layer.

The query loop emits events (streaming text, tool invocations, findings).
The TUI or headless stdout consumer subscribes and renders them.
Same agent code, different consumers.
"""

import asyncio
import time
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class EventType(Enum):
    MESSAGE_CHUNK = "message_chunk"         # Streaming text delta from LLM
    MESSAGE_COMPLETE = "message_complete"   # Full assistant message done
    TOOL_START = "tool_start"               # Tool invocation begins
    TOOL_COMPLETE = "tool_complete"         # Tool invocation finished
    FINDING_ADDED = "finding_added"         # New finding discovered
    COST_UPDATE = "cost_update"             # Cost tracker updated
    WORKER_SPAWNED = "worker_spawned"       # Sub-agent started
    WORKER_COMPLETE = "worker_complete"     # Sub-agent finished
    TURN_COMPLETE = "turn_complete"         # Agent turn finished
    COMPACT = "compact"                     # Context was compacted
    STATUS = "status"                       # Generic status message
    ERROR = "error"                         # Error occurred

    # ── Lifecycle hooks (Claude Code-compatible names) ──
    PRE_TOOL_USE = "PreToolUse"             # Fires before every tool execution
    POST_TOOL_USE = "PostToolUse"           # Fires after every tool execution
    SESSION_START = "SessionStart"          # Fires when the agent starts
    SESSION_END = "SessionEnd"              # Fires when the agent exits


@dataclass
class Event:
    type: EventType
    data: dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)


class EventBus:
    """
    Async event bus using asyncio.Queue.

    Multiple subscribers can listen. Events are fanned out to all.
    """

    def __init__(self):
        self._subscribers: list[asyncio.Queue[Event]] = []
        self._lock = asyncio.Lock()

    async def emit(self, event: Event):
        """Emit an event to all subscribers."""
        async with self._lock:
            for queue in self._subscribers:
                try:
                    queue.put_nowait(event)
                except asyncio.QueueFull:
                    pass  # Drop if subscriber is lagging

    def emit_sync(self, event: Event):
        """Emit from sync context (best-effort, for use in ToolContext)."""
        for queue in self._subscribers:
            try:
                queue.put_nowait(event)
            except (asyncio.QueueFull, RuntimeError):
                pass

    async def subscribe(self) -> AsyncIterator[Event]:
        """Subscribe to events. Yields events as they arrive."""
        queue: asyncio.Queue[Event] = asyncio.Queue(maxsize=1000)
        async with self._lock:
            self._subscribers.append(queue)
        try:
            while True:
                event = await queue.get()
                yield event
        finally:
            async with self._lock:
                self._subscribers.remove(queue)

    def create_subscriber(self) -> asyncio.Queue[Event]:
        """Create a raw subscriber queue (for non-async-iterator consumers)."""
        queue: asyncio.Queue[Event] = asyncio.Queue(maxsize=1000)
        self._subscribers.append(queue)
        return queue

    def remove_subscriber(self, queue: asyncio.Queue[Event]):
        """Remove a subscriber queue."""
        if queue in self._subscribers:
            self._subscribers.remove(queue)
