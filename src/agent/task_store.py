"""
TaskStore — global concurrent task registry.

Tracks all sub-agent tasks, background tasks, and their status.
Thread-safe and exposed as tools for the agent to manage.
"""

import asyncio
import time
from dataclasses import dataclass, field
from typing import Any, Literal


@dataclass
class AgentTask:
    """A tracked task (sub-agent, background shell, etc.)."""
    id: str
    subject: str
    status: Literal["pending", "running", "done", "failed", "cancelled"] = "pending"
    owner: str = ""  # parent agent/session id
    result: str = ""
    error: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)

    def to_summary(self) -> str:
        elapsed = time.time() - self.created_at
        status_icon = {
            "pending": "○",
            "running": "⟳",
            "done": "✓",
            "failed": "✗",
            "cancelled": "⊘",
        }.get(self.status, "?")
        return f"{status_icon} [{self.id}] {self.subject} ({self.status}, {elapsed:.0f}s)"


class TaskStore:
    """
    Thread-safe in-memory task store.

    All modifications go through async methods protected by a lock.
    """

    def __init__(self):
        self._tasks: dict[str, AgentTask] = {}
        self._lock = asyncio.Lock()
        self._counter = 0

    async def create(
        self,
        subject: str,
        owner: str = "",
        task_id: str | None = None,
        **metadata,
    ) -> AgentTask:
        async with self._lock:
            if task_id is None:
                self._counter += 1
                task_id = f"task_{self._counter:03d}"
            task = AgentTask(
                id=task_id,
                subject=subject,
                owner=owner,
                metadata=metadata,
            )
            self._tasks[task_id] = task
            return task

    async def get(self, task_id: str) -> AgentTask | None:
        async with self._lock:
            return self._tasks.get(task_id)

    async def update(
        self,
        task_id: str,
        status: str | None = None,
        result: str | None = None,
        error: str | None = None,
    ) -> AgentTask | None:
        async with self._lock:
            task = self._tasks.get(task_id)
            if not task:
                return None
            if status:
                task.status = status
            if result is not None:
                task.result = result
            if error is not None:
                task.error = error
            task.updated_at = time.time()
            return task

    async def list_tasks(
        self,
        owner: str | None = None,
        status: str | None = None,
    ) -> list[AgentTask]:
        async with self._lock:
            tasks = list(self._tasks.values())
        if owner:
            tasks = [t for t in tasks if t.owner == owner]
        if status:
            tasks = [t for t in tasks if t.status == status]
        return sorted(tasks, key=lambda t: t.created_at, reverse=True)

    async def cancel(self, task_id: str) -> bool:
        async with self._lock:
            task = self._tasks.get(task_id)
            if not task:
                return False
            if task.status in ("done", "failed", "cancelled"):
                return False
            task.status = "cancelled"
            task.updated_at = time.time()
            return True
