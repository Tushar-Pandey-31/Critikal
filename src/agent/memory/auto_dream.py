"""
AutoDream — post-session memory consolidation.

- Scans all session JSONL files for an engagement
- Uses a 4-phase consolidation prompt (Orient → Gather → Consolidate → Prune)
- Outputs a structured markdown file: ~/.critikal/memory/<engagement_id>/consolidated.md
- File-based locking to prevent concurrent consolidation
"""

import json
import logging
import os
import time
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# ── Constants ──
LOCK_FILE = ".consolidate-lock"
HOLDER_STALE_MS = 60 * 60  # 1 hour — stale lock threshold (seconds)
CONSOLIDATED_FILE = "consolidated.md"


class ConsolidationLock:
    """
    File-based mutex lock for the consolidation process.

    File-based mutex for the consolidation process.
    Lock file mtime = lastConsolidatedAt timestamp.
    PID-based ownership — stale locks (PID dead or >1h) are overwritten.
    """

    def __init__(self, memory_dir: Path):
        self._lock_path = memory_dir / LOCK_FILE

    def read_last_consolidated_at(self) -> float:
        """Read the last consolidation timestamp from the lock file."""
        if not self._lock_path.exists():
            return 0.0
        try:
            return self._lock_path.stat().st_mtime
        except OSError:
            return 0.0

    def try_acquire(self) -> float | None:
        """
        Try to acquire the consolidation lock.

        Returns prior mtime on success, None if already held by another process.
        """
        prior_mtime = self.read_last_consolidated_at()

        if self._lock_path.exists():
            try:
                content = self._lock_path.read_text().strip()
                holder_pid = int(content.split(":")[0]) if content else 0
                holder_time = float(content.split(":")[1]) if ":" in content else 0

                # Check if holder is still alive
                if holder_pid > 0:
                    try:
                        os.kill(holder_pid, 0)  # signal 0 = check existence
                        # Process exists — check staleness
                        if (time.time() - holder_time) < HOLDER_STALE_MS:
                            logger.info(f"[dream] Lock held by PID {holder_pid}, skipping")
                            return None
                        logger.warning(f"[dream] Stale lock from PID {holder_pid}, overwriting")
                    except OSError:
                        # PID dead, safe to take over
                        logger.info(f"[dream] Lock holder PID {holder_pid} is dead, taking over")
            except (ValueError, IndexError, OSError):
                pass  # Corrupt lock file, overwrite

        # Write our PID and timestamp
        try:
            self._lock_path.write_text(f"{os.getpid()}:{time.time()}")
            return prior_mtime
        except OSError as e:
            logger.error(f"[dream] Failed to acquire lock: {e}")
            return None

    def release(self):
        """Release the lock by updating mtime (keeps it for timestamp tracking)."""
        try:
            self._lock_path.write_text(f"0:{time.time()}")
        except OSError:
            pass

    def rollback(self, prior_mtime: float):
        """Restore mtime on consolidation failure."""
        try:
            os.utime(self._lock_path, (prior_mtime, prior_mtime))
        except OSError:
            pass


class AutoDream:
    """
    Memory consolidation agent.

    Reads all session memory entries for an engagement and uses an LLM
    to consolidate them into a structured knowledge document.

    Runs a 4-phase consolidation:
      1. Orient  — read existing consolidated.md
      2. Gather  — read new session entries since last consolidation
      3. Consolidate — merge new learnings into structured document
      4. Prune   — remove stale/redundant entries
    """

    def __init__(self, engagement_id: str, memory_dir: Path | None = None):
        from src.agent.memory.session_memory import MEMORY_BASE_DIR
        self.engagement_id = engagement_id
        self.memory_dir = (memory_dir or MEMORY_BASE_DIR) / engagement_id
        self.memory_dir.mkdir(parents=True, exist_ok=True)
        self._lock = ConsolidationLock(self.memory_dir)
        self._consolidated_path = self.memory_dir / CONSOLIDATED_FILE

    @property
    def consolidated_path(self) -> Path:
        return self._consolidated_path

    def has_consolidated(self) -> bool:
        """Whether a consolidated.md exists for this engagement."""
        return self._consolidated_path.exists()

    def read_consolidated(self) -> str:
        """Read the current consolidated document."""
        if not self._consolidated_path.exists():
            return ""
        return self._consolidated_path.read_text()

    async def consolidate(self, force: bool = False) -> bool:
        """
        Run the consolidation process.

        Returns True if consolidation was performed, False if skipped.
        """
        # Try to acquire lock
        prior_mtime = self._lock.try_acquire()
        if prior_mtime is None and not force:
            return False

        try:
            # Load session entries
            session_file = self.memory_dir / "session.jsonl"
            if not session_file.exists():
                logger.info("[dream] No session.jsonl found, nothing to consolidate")
                self._lock.release()
                return False

            entries = self._load_entries(session_file, since=prior_mtime or 0)
            if not entries and not force:
                logger.info("[dream] No new entries since last consolidation")
                self._lock.release()
                return False

            # Read existing consolidated doc
            existing = self.read_consolidated()

            # Build consolidation prompt
            prompt = self._build_consolidation_prompt(existing, entries)

            # Run LLM
            from src.llm.providers import get_worker_llm
            model = os.getenv("DREAM_MODEL_NAME", "gpt-5.4-mini")
            llm = get_worker_llm(model_name=model, temperature=0.0)

            from langchain_core.messages import HumanMessage
            response = await llm.ainvoke([HumanMessage(content=prompt)])
            result = response.content if isinstance(response.content, str) else str(response.content)

            # Write consolidated document
            self._consolidated_path.write_text(result)
            self._lock.release()

            logger.info(
                f"[dream] Consolidation complete for {self.engagement_id}: "
                f"{len(entries)} entries → {len(result)} chars"
            )
            return True

        except Exception as e:
            logger.error(f"[dream] Consolidation failed: {e}", exc_info=True)
            if prior_mtime is not None:
                self._lock.rollback(prior_mtime)
            return False

    def _load_entries(
        self, session_file: Path, since: float = 0
    ) -> list[dict[str, Any]]:
        """Load session entries newer than 'since' timestamp."""
        entries = []
        with open(session_file) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                    if entry.get("timestamp", 0) > since:
                        entries.append(entry)
                except json.JSONDecodeError:
                    continue
        return entries

    def _build_consolidation_prompt(
        self, existing: str, new_entries: list[dict]
    ) -> str:
        """
        Build the 4-phase consolidation prompt.
        """
        entries_text = "\n".join(
            f"- [{e.get('type', '?')}] {e.get('description', '?')}: {e.get('content', '')[:300]}"
            for e in new_entries
        )

        existing_section = ""
        if existing:
            existing_section = f"""\
## Phase 1: ORIENT — Current Knowledge

The following is the current consolidated knowledge document. Read it to understand
what is already known about this engagement.

```markdown
{existing[:5000]}
```
"""

        return f"""\
You are a memory consolidation agent for Critikal, a security research tool.

Your job: consolidate session learnings into a structured knowledge document
for future reference. Follow this 4-phase process:

{existing_section}

## Phase 2: GATHER — New Learnings

The following memory entries were extracted from recent sessions:

{entries_text}

## Phase 3: CONSOLIDATE — Merge

Take the new learnings and merge them into the existing knowledge document.
The output should be a single, well-organized Markdown document with these sections:

### Output Format:

```markdown
# Engagement: [protocol/project name]

## Protocol Overview
- What type of protocol is this?
- Key contracts and their roles
- Trust boundaries and privilege levels
- External dependencies (oracles, DEXs, bridges)

## Known Vulnerabilities
- Confirmed findings with severity, affected functions, and root causes
- Include confidence levels and whether PoC tests passed

## Attack Surface Notes
- Entry points, high-value targets, state mutators
- Access control patterns observed
- External call patterns

## Discovery Tactics
- What analysis approaches worked best
- Which tools were most effective
- What attack vectors were explored (including dead ends)

## Configuration Notes
- Model performance observations
- Worker settings that helped
- Pipeline configuration that was effective

## Open Questions
- Unresolved leads or theories
- Areas that need deeper investigation
```

## Phase 4: PRUNE

- Remove entries that are now redundant (subsumed by consolidated knowledge)
- Remove stale entries that contradict newer findings
- Keep the document concise — under 3000 words

OUTPUT the full consolidated Markdown document. No preamble, no explanation — just the document."""


async def run_dream(engagement_id: str, memory_dir: Path | None = None) -> bool:
    """Convenience function to run consolidation for an engagement."""
    dreamer = AutoDream(engagement_id, memory_dir)
    return await dreamer.consolidate()
