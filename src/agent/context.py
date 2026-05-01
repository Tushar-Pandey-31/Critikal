"""
ToolContext — shared execution environment for all tools.

Replaces LangGraph's AgentState TypedDict with a mutable object that
tools read from and write to during a session. Holds the graph, findings,
recon context, cost tracking, and all session state.

Inspired by Claude Code's ToolUseContext:
  - readFileState cache for read-before-write enforcement
  - abort mechanism
  - agent identity tracking
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, TYPE_CHECKING
import os
import uuid

if TYPE_CHECKING:
    import networkx as nx
    from src.models.finding import Finding
    from src.pipeline_config import PipelineConfig
    from src.agent.cost import CostTracker
    from src.agent.events import EventBus
    from src.agent.task_store import TaskStore


@dataclass
class FileReadState:
    """Tracks a file that was read, for read-before-write enforcement."""
    path: str
    mtime: float
    content_hash: str  # SHA256 of content at read time
    size: int


@dataclass
class ToolContext:
    """
    Shared mutable state passed to every tool execution.

    This is the single source of truth for the current session.
    Tools read prerequisites (graph, recon_context) and write
    results (findings, file_history) here.
    """

    # ── Identity ──
    session_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    engagement_id: str = ""

    # ── Filesystem ──
    working_dir: Path = field(default_factory=Path.cwd)
    repo_path: Path | None = None  # Set after ingestion

    # ── Analysis State ──
    graph: Any = None  # nx.DiGraph — set after Slither + GraphBuilder
    findings: list = field(default_factory=list)  # list[Finding]
    worker_outputs: list = field(default_factory=list)  # list[dict]
    recon_context: dict[str, Any] = field(default_factory=dict)
    contract_names: list[str] = field(default_factory=list)
    contract_addresses: dict[str, str] = field(default_factory=dict)
    repo_url: str | None = None

    # ── Configuration ──
    config: Any = None  # PipelineConfig — lazy init via get_config()

    # ── Tracking ──
    cost_tracker: Any = None  # CostTracker
    current_turn: int = 0
    file_history: list[tuple[str, str]] = field(default_factory=list)  # (path, action)

    # ── Read-before-write enforcement (inspired by Claude Code) ──
    read_file_state: dict[str, FileReadState] = field(default_factory=dict)

    # ── Shell State (persistent across bash calls) ──
    shell_cwd: Path | None = None
    shell_env: dict[str, str] = field(default_factory=dict)

    # ── Subsystems (set during initialization) ──
    event_bus: Any = None  # EventBus
    task_store: Any = None  # TaskStore
    memory: Any = None  # SessionMemory — per-engagement memory system
    memory_dir: Any = None  # Path — ~/.critikal/memory/<engagement_id>/
    permission_mode: str = "ask"  # "auto" | "ask" | "yolo"
    permission_handler: Any = None  # PermissionHandler — shared so sub-agents inherit parent policy
    hooks: Any = None  # HookRegistry — user-configured lifecycle hooks

    # ── Agent identity (for sub-agent tracking) ──
    agent_id: str | None = None
    is_subagent: bool = False

    def ensure_config(self):
        """Lazy-load PipelineConfig if not set."""
        if self.config is None:
            from src.pipeline_config import get_config
            self.config = get_config()

    def has_graph(self) -> bool:
        """Whether a Slither-derived graph is available."""
        return self.graph is not None and self.graph.number_of_nodes() > 0

    def add_finding(self, finding: Any):
        """Append a finding and emit event if event_bus is connected."""
        self.findings.append(finding)
        if self.event_bus:
            from src.agent.events import Event, EventType
            self.event_bus.emit_sync(Event(
                type=EventType.FINDING_ADDED,
                data={"finding_index": len(self.findings) - 1},
            ))

    def record_file_access(self, path: str, action: str = "read"):
        """Track file reads/writes for session history."""
        self.file_history.append((path, action))

    # ── Read-before-write system ──

    def register_file_read(self, path: str, content: str, mtime: float | None = None):
        """
        Register a file read — required before FileEdit/FileWrite can modify it.
        Inspired by Claude Code's readFileState cache.
        """
        import hashlib
        resolved = str(Path(path).resolve())
        if mtime is None:
            try:
                mtime = os.path.getmtime(resolved)
            except OSError:
                mtime = 0.0

        self.read_file_state[resolved] = FileReadState(
            path=resolved,
            mtime=mtime,
            content_hash=hashlib.sha256(content.encode("utf-8", errors="replace")).hexdigest(),
            size=len(content),
        )

    def check_file_write_allowed(self, path: str) -> tuple[bool, str]:
        """
        Check if writing to a file is allowed (read-before-write enforcement).

        Returns (allowed, reason).
        - New files are always allowed
        - Existing files must have been read first
        - If file mtime changed since read, writing is blocked (stale)
        """
        resolved = str(Path(path).resolve())

        # New files: always allowed
        if not os.path.exists(resolved):
            return True, "new file"

        # Check if file was read
        state = self.read_file_state.get(resolved)
        if state is None:
            return False, (
                f"File '{Path(resolved).name}' has not been read yet. "
                "Read the file first with file_read before editing/writing."
            )

        # Check mtime staleness
        try:
            current_mtime = os.path.getmtime(resolved)
        except OSError:
            return True, "cannot check mtime"

        if current_mtime > state.mtime:
            return False, (
                f"File '{Path(resolved).name}' was modified since last read "
                f"(read at {state.mtime:.0f}, now {current_mtime:.0f}). "
                "Re-read the file before modifying."
            )

        return True, "read verified"
