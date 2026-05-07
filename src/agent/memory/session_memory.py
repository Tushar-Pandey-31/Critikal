"""
SessionMemory — extracts and persists key learnings during an agent session.

Inspired by Claude Code's `services/SessionMemory/sessionMemory.ts`:
- Stores memories as append-only JSONL at ~/.critikal/memory/<engagement_id>/session.jsonl
- Extracts memories every N turns via a lightweight LLM sideQuery
- Retrieves relevant memories for context injection via keyword matching
"""

import json
import logging
import os
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# ── Constants ──
MEMORY_BASE_DIR = Path(os.getenv(
    "CRITIKAL_MEMORY_DIR",
    os.path.expanduser("~/.critikal/memory"),
))
EXTRACT_EVERY_N_TURNS = int(os.getenv("MEMORY_EXTRACT_INTERVAL", "10"))
MAX_MEMORIES_PER_QUERY = 5
MAX_MEMORY_FILES = 200
FRONTMATTER_MAX_CHARS = 2000  # Max chars to scan for keyword matching


@dataclass
class MemoryEntry:
    """A single memory unit persisted to session.jsonl."""

    type: str  # "finding", "recon", "tactic", "config", "feedback", "reference"
    description: str  # One-line summary (used for relevance matching)
    content: str  # Full detail
    source_turn: int
    timestamp: float = field(default_factory=time.time)
    engagement_id: str = ""

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "MemoryEntry":
        return cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__})


# ── Memory Type Constants (inspired by claurst's memoryTypes.ts) ──
MEMORY_TYPES = ("finding", "recon", "tactic", "config", "feedback", "reference")

WHAT_NOT_TO_SAVE = [
    "Raw source code (the agent can always re-read files)",
    "Exact line numbers (they shift between versions)",
    "Intermediate tool output (too verbose, summarize instead)",
    "Things already captured in the final report",
]


class SessionMemory:
    """
    Per-engagement session memory.

    Stores learnings as JSONL entries. Provides extraction (via LLM)
    and retrieval (via keyword matching) capabilities.
    """

    def __init__(self, engagement_id: str, memory_dir: Path | None = None):
        self.engagement_id = engagement_id
        self.memory_dir = (memory_dir or MEMORY_BASE_DIR) / engagement_id
        self.memory_dir.mkdir(parents=True, exist_ok=True)
        self._session_file = self.memory_dir / "session.jsonl"
        self._last_extract_turn = 0
        self._cache: list[MemoryEntry] | None = None

    @property
    def session_path(self) -> Path:
        return self._session_file

    def store(self, entry: MemoryEntry):
        """Append a memory entry to session.jsonl."""
        entry.engagement_id = self.engagement_id
        with open(self._session_file, "a") as f:
            f.write(json.dumps(entry.to_dict()) + "\n")
        # Invalidate cache
        self._cache = None
        logger.debug(f"[memory] Stored: {entry.type} — {entry.description[:60]}")

    def store_many(self, entries: list[MemoryEntry]):
        """Batch-store multiple entries."""
        for entry in entries:
            self.store(entry)

    def load_all(self) -> list[MemoryEntry]:
        """Load all memory entries from session.jsonl."""
        if self._cache is not None:
            return self._cache

        entries = []
        if not self._session_file.exists():
            return entries

        with open(self._session_file) as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    d = json.loads(line)
                    entries.append(MemoryEntry.from_dict(d))
                except (json.JSONDecodeError, TypeError) as e:
                    logger.warning(f"[memory] Corrupt entry at line {line_num}: {e}")

        self._cache = entries
        return entries

    def find_relevant(self, query: str, top_k: int = MAX_MEMORIES_PER_QUERY) -> list[MemoryEntry]:
        """
        Find memories relevant to a query via keyword matching.

        Simple but fast — no embedding infra needed. Scores based on
        word overlap between query and memory description+content.
        """
        entries = self.load_all()
        if not entries:
            return []

        query_words = set(query.lower().split())
        scored: list[tuple[float, MemoryEntry]] = []

        for entry in entries:
            # Build searchable text from description + first N chars of content
            searchable = (
                entry.description.lower() + " " +
                entry.content[:FRONTMATTER_MAX_CHARS].lower()
            )
            entry_words = set(searchable.split())

            # Jaccard-ish overlap score
            overlap = len(query_words & entry_words)
            if overlap == 0:
                continue
            score = overlap / max(len(query_words), 1)

            # Type boost: findings and tactics are more actionable
            if entry.type in ("finding", "tactic"):
                score *= 1.3
            elif entry.type == "recon":
                score *= 1.1

            scored.append((score, entry))

        # Sort by score descending, return top_k
        scored.sort(key=lambda x: x[0], reverse=True)
        return [entry for _, entry in scored[:top_k]]

    def should_extract(self, current_turn: int) -> bool:
        """Whether it's time to run a memory extraction pass."""
        return (current_turn - self._last_extract_turn) >= EXTRACT_EVERY_N_TURNS

    async def extract_and_store(
        self,
        messages: list[dict[str, Any]],
        current_turn: int,
    ):
        """
        Extract learnings from recent messages via LLM sideQuery.

        Runs a lightweight model to identify what the agent learned
        in the last N turns. Stores extracted memories to session.jsonl.
        """
        self._last_extract_turn = current_turn

        # Get recent messages (last EXTRACT_EVERY_N_TURNS * 2 messages)
        window = EXTRACT_EVERY_N_TURNS * 2
        recent = messages[-window:] if len(messages) > window else messages

        # Build extraction prompt
        conversation_text = self._format_messages_for_extraction(recent)
        if len(conversation_text) < 100:
            logger.debug("[memory] Too little content to extract from")
            return

        prompt = self._build_extraction_prompt(conversation_text)

        try:
            # Use a fast, cheap model for extraction
            from src.llm.providers import get_worker_llm
            extract_model = os.getenv("MEMORY_EXTRACT_MODEL", "gpt-5.4-mini")
            llm = get_worker_llm(model_name=extract_model, temperature=0.0)

            from langchain_core.messages import HumanMessage
            response = await llm.ainvoke([HumanMessage(content=prompt)])

            # Parse response as JSON array of memory entries
            text = response.content if isinstance(response.content, str) else str(response.content)
            entries = self._parse_extraction_response(text, current_turn)

            if entries:
                self.store_many(entries)
                logger.info(f"[memory] Extracted {len(entries)} memories from turns {current_turn - EXTRACT_EVERY_N_TURNS}–{current_turn}")

        except Exception as e:
            logger.warning(f"[memory] Extraction failed (non-fatal): {e}")

    def _format_messages_for_extraction(self, messages: list[dict]) -> str:
        """Format messages into a readable transcript for the extraction LLM."""
        parts = []
        for msg in messages:
            role = msg.get("role", "?")
            content = msg.get("content", "")
            if isinstance(content, list):
                # Tool results
                content = "\n".join(
                    r.get("content", "")[:500] for r in content
                    if isinstance(r, dict)
                )
            if isinstance(content, str) and len(content) > 1000:
                content = content[:500] + "\n...\n" + content[-500:]
            parts.append(f"[{role}] {content}")
        return "\n\n".join(parts)

    def _build_extraction_prompt(self, conversation_text: str) -> str:
        """Build the prompt for the memory extraction LLM."""
        return f"""\
You are a memory extraction agent for a security research tool called Critikal.

Your job: Read the following conversation excerpt and extract KEY LEARNINGS
that would be useful in future sessions analyzing the same or similar protocols.

Output a JSON array of memory objects. Each object has:
- "type": one of {list(MEMORY_TYPES)}
- "description": one-line summary (be specific — this is used for search matching)
- "content": full detail (2-5 sentences)

What to extract:
- Protocol architecture insights (type: "recon")
- Vulnerability patterns discovered (type: "finding")
- Attack tactics that worked or didn't (type: "tactic")
- Tool configuration that helped (type: "config")
- Corrections or refinements to approach (type: "feedback")
- External references found (type: "reference")

What NOT to save:
{chr(10).join(f"- {item}" for item in WHAT_NOT_TO_SAVE)}

If nothing worth remembering, return an empty array: []

CONVERSATION:
{conversation_text}

OUTPUT (valid JSON array only, no markdown fences):"""

    def _parse_extraction_response(
        self, text: str, current_turn: int
    ) -> list[MemoryEntry]:
        """Parse the LLM's extraction response into MemoryEntry objects."""
        # Strip markdown code fences if present
        text = text.strip()
        if text.startswith("```"):
            text = text.split("\n", 1)[1] if "\n" in text else text[3:]
        if text.endswith("```"):
            text = text[:-3]
        text = text.strip()

        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            # Try to find a JSON array within the text
            import re
            match = re.search(r'\[.*\]', text, re.DOTALL)
            if match:
                try:
                    data = json.loads(match.group())
                except json.JSONDecodeError:
                    logger.warning("[memory] Failed to parse extraction response as JSON")
                    return []
            else:
                return []

        if not isinstance(data, list):
            return []

        entries = []
        for item in data:
            if not isinstance(item, dict):
                continue
            mem_type = item.get("type", "feedback")
            if mem_type not in MEMORY_TYPES:
                mem_type = "feedback"
            entries.append(MemoryEntry(
                type=mem_type,
                description=item.get("description", "")[:200],
                content=item.get("content", "")[:2000],
                source_turn=current_turn,
                engagement_id=self.engagement_id,
            ))

        return entries

    def get_memory_count(self) -> int:
        """Return the number of stored memories."""
        return len(self.load_all())

    def memory_freshness_note(self, entry: MemoryEntry) -> str:
        """
        Generate a freshness caveat for a memory (inspired by claurst's memoryAge.ts).

        Memories older than 1 day get a staleness warning.
        """
        age_seconds = time.time() - entry.timestamp
        age_days = int(age_seconds / 86400)

        if age_days <= 0:
            return ""
        elif age_days == 1:
            return "[This memory is from yesterday — verify against current code]"
        else:
            return (
                f"[This memory is {age_days} days old. Memories are point-in-time "
                f"observations — claims about code behavior may be outdated. "
                f"Verify against current code before asserting as fact.]"
            )

    def format_for_prompt(self, entries: list[MemoryEntry]) -> str:
        """Format memory entries for injection into the system prompt."""
        if not entries:
            return ""

        lines = ["# Relevant Memories from Previous Sessions\n"]
        for entry in entries:
            freshness = self.memory_freshness_note(entry)
            lines.append(f"## [{entry.type.upper()}] {entry.description}")
            if freshness:
                lines.append(freshness)
            lines.append(entry.content)
            lines.append("")

        return "\n".join(lines)
