"""
CronScheduler — background monitoring and recurring audit scheduling.

Uses APScheduler for cron-style scheduling of background agent runs.

Each scheduled task spawns a headless agent via HeadlessRunner in a
background asyncio task. Results are appended to the engagement's
session memory.

Config stored at: ~/.critikal/schedules.json
"""

import asyncio
import json
import logging
import os
import time
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)

SCHEDULES_PATH = Path(os.getenv(
    "CRITIKAL_SCHEDULES_FILE",
    os.path.expanduser("~/.critikal/schedules.json"),
))


@dataclass
class ScheduledTask:
    """A recurring scheduled audit task."""

    task_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    repo_url: str = ""
    cron_expr: str = "0 0 * * 1"  # Default: weekly on Monday midnight
    prompt: str = ""
    model: str = ""
    budget_usd: float | None = None
    engagement_id: str = ""
    enabled: bool = True
    created_at: float = field(default_factory=time.time)
    last_run_at: float = 0.0
    last_run_status: str = ""  # "success" | "error" | ""
    run_count: int = 0

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "ScheduledTask":
        return cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__})


class CronScheduler:
    """
    Manages recurring audit schedules using APScheduler.

    Usage:
        scheduler = CronScheduler()
        scheduler.add_task(ScheduledTask(
            repo_url="https://github.com/some/protocol",
            cron_expr="0 0 * * 1",
            prompt="Check for new commits and audit changes",
        ))
        await scheduler.start()  # Blocks, runs forever
    """

    def __init__(self):
        self._tasks: dict[str, ScheduledTask] = {}
        self._scheduler = None
        self._running_tasks: dict[str, asyncio.Task] = {}
        self._load_schedules()

    def _load_schedules(self):
        """Load schedules from disk."""
        if not SCHEDULES_PATH.exists():
            return
        try:
            with open(SCHEDULES_PATH) as f:
                data = json.load(f)
            for task_data in data.get("tasks", []):
                task = ScheduledTask.from_dict(task_data)
                self._tasks[task.task_id] = task
            logger.info(f"[scheduler] Loaded {len(self._tasks)} schedule(s)")
        except (json.JSONDecodeError, OSError) as e:
            logger.warning(f"[scheduler] Failed to load schedules: {e}")

    def _save_schedules(self):
        """Persist schedules to disk."""
        SCHEDULES_PATH.parent.mkdir(parents=True, exist_ok=True)
        data = {
            "tasks": [t.to_dict() for t in self._tasks.values()],
            "updated_at": time.time(),
        }
        try:
            with open(SCHEDULES_PATH, "w") as f:
                json.dump(data, f, indent=2)
        except OSError as e:
            logger.error(f"[scheduler] Failed to save schedules: {e}")

    def add_task(self, task: ScheduledTask) -> str:
        """Add a scheduled task. Returns the task ID."""
        if not task.engagement_id:
            task.engagement_id = task.task_id
        self._tasks[task.task_id] = task
        self._save_schedules()
        logger.info(f"[scheduler] Added task {task.task_id}: {task.repo_url} [{task.cron_expr}]")
        return task.task_id

    def remove_task(self, task_id: str) -> bool:
        """Remove a scheduled task."""
        if task_id in self._tasks:
            del self._tasks[task_id]
            self._save_schedules()
            logger.info(f"[scheduler] Removed task {task_id}")
            return True
        return False

    def list_tasks(self) -> list[ScheduledTask]:
        """List all scheduled tasks."""
        return list(self._tasks.values())

    def get_task(self, task_id: str) -> ScheduledTask | None:
        """Get a specific task."""
        return self._tasks.get(task_id)

    def toggle_task(self, task_id: str) -> bool:
        """Enable/disable a task. Returns new enabled state."""
        if task_id in self._tasks:
            self._tasks[task_id].enabled = not self._tasks[task_id].enabled
            self._save_schedules()
            return self._tasks[task_id].enabled
        return False

    async def start(self):
        """Start the scheduler. Blocks until cancelled."""
        try:
            from apscheduler.schedulers.asyncio import AsyncIOScheduler
            from apscheduler.triggers.cron import CronTrigger
        except ImportError:
            logger.error(
                "[scheduler] APScheduler not installed. "
                "Install with: poetry add apscheduler"
            )
            return

        self._scheduler = AsyncIOScheduler()

        for task in self._tasks.values():
            if not task.enabled:
                continue
            try:
                parts = task.cron_expr.split()
                if len(parts) == 5:
                    trigger = CronTrigger(
                        minute=parts[0],
                        hour=parts[1],
                        day=parts[2],
                        month=parts[3],
                        day_of_week=parts[4],
                    )
                else:
                    logger.warning(f"[scheduler] Invalid cron for {task.task_id}: {task.cron_expr}")
                    continue

                self._scheduler.add_job(
                    self._run_task,
                    trigger=trigger,
                    args=[task.task_id],
                    id=task.task_id,
                    name=f"audit-{task.task_id}",
                    replace_existing=True,
                )
                logger.info(f"[scheduler] Scheduled {task.task_id}: {task.cron_expr}")
            except Exception as e:
                logger.error(f"[scheduler] Failed to schedule {task.task_id}: {e}")

        self._scheduler.start()
        logger.info(f"[scheduler] Started with {len(self._tasks)} task(s)")

        # Run forever
        try:
            while True:
                await asyncio.sleep(60)
        except asyncio.CancelledError:
            self._scheduler.shutdown()

    async def run_once(self, task_id: str) -> str:
        """Run a single task immediately (for testing/manual trigger)."""
        return await self._run_task(task_id)

    async def _run_task(self, task_id: str) -> str:
        """Execute a scheduled task."""
        task = self._tasks.get(task_id)
        if not task:
            return f"Task {task_id} not found"

        logger.info(f"[scheduler] Running task {task_id}: {task.repo_url}")
        task.last_run_at = time.time()

        try:
            from src.agent.headless import HeadlessRunner

            runner = HeadlessRunner(
                model=task.model or None,
                permission_mode="yolo",
                budget_usd=task.budget_usd,
                engagement_id=task.engagement_id,
            )

            if task.repo_url:
                result = await runner.run_audit(task.repo_url)
            elif task.prompt:
                result = await runner.run_prompt(task.prompt)
            else:
                result = "No repo_url or prompt specified"

            task.last_run_status = "success"
            task.run_count += 1
            self._save_schedules()

            logger.info(f"[scheduler] Task {task_id} completed successfully")
            return result

        except Exception as e:
            task.last_run_status = f"error: {e}"
            self._save_schedules()
            logger.error(f"[scheduler] Task {task_id} failed: {e}", exc_info=True)
            return f"Error: {e}"

    def format_schedule_table(self) -> str:
        """Format all tasks as a readable table."""
        if not self._tasks:
            return "No scheduled tasks."

        lines = [
            f"{'ID':<10} {'Repo':<40} {'Cron':<15} {'Enabled':<8} {'Runs':<6} {'Last Status'}",
            "─" * 100,
        ]
        for t in self._tasks.values():
            repo = (t.repo_url or t.prompt)[:38]
            enabled = "✓" if t.enabled else "✗"
            lines.append(
                f"{t.task_id:<10} {repo:<40} {t.cron_expr:<15} {enabled:<8} {t.run_count:<6} {t.last_run_status}"
            )
        return "\n".join(lines)
