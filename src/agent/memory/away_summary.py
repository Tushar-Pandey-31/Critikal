"""
Away Summary — catch-up summary when resuming a previous engagement.

Inspired by Claude Code's `services/awaySummary.ts`:
- Generated when the user resumes a session via --resume <engagement_id>
- Reads session memory and consolidated docs to build a brief summary
- Injected into the system prompt as context
"""

import logging
import os
from pathlib import Path

logger = logging.getLogger(__name__)


async def generate_away_summary(engagement_id: str, memory_dir: Path | None = None) -> str:
    """
    Generate a catch-up summary for a resumed engagement.
    
    Returns a 1-5 sentence summary of what happened in previous sessions,
    or an empty string if no previous data exists.
    """
    from src.agent.memory.session_memory import SessionMemory, MEMORY_BASE_DIR
    from src.agent.memory.auto_dream import AutoDream

    base_dir = memory_dir or MEMORY_BASE_DIR
    sm = SessionMemory(engagement_id, base_dir)
    dreamer = AutoDream(engagement_id, base_dir)

    # If we have a consolidated doc, use that as the primary source
    consolidated = dreamer.read_consolidated()
    entries = sm.load_all()

    if not consolidated and not entries:
        return ""

    # Build resume context
    context_parts = []

    if consolidated:
        # Use first 2000 chars of consolidated doc
        context_parts.append(f"CONSOLIDATED KNOWLEDGE:\n{consolidated[:2000]}")

    if entries:
        # Last 10 entries as recent history
        recent = entries[-10:]
        recent_text = "\n".join(
            f"- [{e.type}] {e.description}" for e in recent
        )
        context_parts.append(f"RECENT MEMORIES ({len(entries)} total):\n{recent_text}")

    context = "\n\n".join(context_parts)

    # Generate summary via LLM
    try:
        from src.llm.providers import get_worker_llm
        model = os.getenv("MEMORY_EXTRACT_MODEL", "gemini-3-flash-preview")
        llm = get_worker_llm(model_name=model, temperature=0.0)

        from langchain_core.messages import HumanMessage
        prompt = f"""\
You are resuming a security research engagement. Based on the following
context from previous sessions, write a brief catch-up summary (2-5 sentences)
that tells the researcher what was accomplished and what's still open.

Be specific — mention protocol names, vulnerability classes found, 
confidence levels, and any open investigation threads.

{context}

SUMMARY:"""

        response = await llm.ainvoke([HumanMessage(content=prompt)])
        summary = response.content if isinstance(response.content, str) else str(response.content)
        summary = summary.strip()

        logger.info(f"[memory] Generated away summary for {engagement_id}: {len(summary)} chars")
        return summary

    except Exception as e:
        logger.warning(f"[memory] Away summary generation failed: {e}")
        # Fallback: simple stats-based summary
        if entries:
            types = {}
            for e in entries:
                types[e.type] = types.get(e.type, 0) + 1
            type_summary = ", ".join(f"{v} {k}(s)" for k, v in types.items())
            return (
                f"Resuming engagement {engagement_id}. "
                f"Previous sessions recorded {len(entries)} memories: {type_summary}."
            )
        return f"Resuming engagement {engagement_id}. Consolidated knowledge available."
