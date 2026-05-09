"""
WorkerWidget — sub-agent status tracker panel.

Monochrome: glyph-based status indicators, no bright colors.
"""

from rich.text import Text
from textual.containers import VerticalScroll
from textual.reactive import reactive
from textual.widgets import Static

FG = "#e8e8e8"
DIM = "#8a8a8a"
DIMMER = "#5a5a5a"
ACCENT = "#7dd3c0"
DANGER = "#e08a8a"


class WorkerEntry(Static):
    """A single worker status line."""

    def __init__(self, worker_id: str, description: str, status: str = "running", **kwargs):
        super().__init__("", **kwargs)
        self.worker_id = worker_id
        self.description = description
        self.status = status

    def on_mount(self):
        self._refresh_entry()

    def _refresh_entry(self):
        icons = {
            "running": ("◐", ACCENT),
            "done": ("✓", DIMMER),
            "error": ("✗", DANGER),
            "background": ("◓", DIM),
        }
        icon, color = icons.get(self.status, ("·", DIM))

        text = Text()
        text.append(f"{icon}  ", style=color)
        text.append(self.description[:28], style=FG if self.status == "running" else DIM)
        text.append(f"  {self.status}", style=DIMMER)
        self.update(text)

    def set_status(self, status: str):
        self.status = status
        self._refresh_entry()


class WorkerWidget(VerticalScroll):
    """Sub-agent status panel."""

    worker_count = reactive(0)

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._workers: dict[str, WorkerEntry] = {}

    def compose(self):
        yield Static(
            Text("WORKERS", style=f"bold {ACCENT}"),
            id="workers-title",
        )

    def add_worker(self, worker_id: str, description: str, status: str = "running"):
        if worker_id in self._workers:
            self._workers[worker_id].set_status(status)
            return
        entry = WorkerEntry(worker_id, description, status)
        self._workers[worker_id] = entry
        self.mount(entry)
        self.worker_count = len(self._workers)

    def complete_worker(self, worker_id: str, success: bool = True):
        if worker_id in self._workers:
            self._workers[worker_id].set_status("done" if success else "error")

    def update_from_task_store(self, task_store):
        if task_store is None:
            return
        for task_id, task in task_store.tasks.items():
            status = "done" if task.get("completed") else "running"
            if task.get("error"):
                status = "error"
            desc = task.get("description", task_id)
            self.add_worker(task_id, desc, status)

    def get_summary(self) -> str:
        running = sum(1 for w in self._workers.values() if w.status == "running")
        done = sum(1 for w in self._workers.values() if w.status == "done")
        if not self._workers:
            return ""
        return f"{running} active, {done} done"
