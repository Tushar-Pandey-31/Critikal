"""
Memory system for the Critikal agent.

Three layers (inspired by Claude Code's memdir + SessionMemory + autoDream):
  1. SessionMemory — per-turn extraction of learnings during a session
  2. AutoDream    — post-session consolidation of memories into structured docs
  3. AwaySummary  — catch-up summary when resuming a previous engagement
"""

from src.agent.memory.auto_dream import AutoDream
from src.agent.memory.away_summary import generate_away_summary
from src.agent.memory.session_memory import MemoryEntry, SessionMemory

__all__ = [
    "AutoDream",
    "MemoryEntry",
    "SessionMemory",
    "generate_away_summary",
]
