"""
AutoCompactor — context window management.

Two trigger points, matching Claude Code's compaction design:

  * micro-compact  at TRIGGER_FRACTION_PROACTIVE (75%) — runs in the
    background before the prompt is actually oversized, so normal turns
    never stall on a panicked reactive compact.
  * full compact   at TRIGGER_FRACTION_REACTIVE (90%) — last-ditch
    before the next LLM call overflows.

Compaction keeps the system message and the last KEEP_RECENT messages
verbatim, and summarizes everything in between using a fast LLM.

Message slicing respects API-round boundaries so we never emit an
assistant message with tool_calls that is missing its matching tool
results (Anthropic rejects that with a 400).

A circuit breaker disables compaction after MAX_FAILURES consecutive
errors.
"""

import logging
import os
from typing import Any

logger = logging.getLogger(__name__)

# Approximate context window sizes (in tokens) per model family
MODEL_CONTEXT_SIZES: dict[str, int] = {
    "claude-opus-4": 200_000,
    "claude-sonnet-4": 200_000,
    "claude-haiku-4": 200_000,
    "gemini-3-flash-preview": 1_000_000,
    "gemini-2.0-flash": 1_000_000,
    "gpt-4o": 128_000,
    "gpt-4o-mini": 128_000,
    "grok-3": 131_072,
}

TRIGGER_FRACTION_PROACTIVE = 0.75
TRIGGER_FRACTION_REACTIVE = 0.90
KEEP_RECENT = 10
MAX_FAILURES = 3

# Fallback char-to-token ratio when tiktoken is not installed.
# 3.5 is closer to reality for code-dense content than the old 4.0.
CHARS_PER_TOKEN_FALLBACK = 3.5


try:  # optional — avoids hard-requiring tiktoken
    import tiktoken
    _ENCODER = tiktoken.get_encoding("cl100k_base")
except Exception:  # pragma: no cover - optional dep
    _ENCODER = None


def _count_text_tokens(text: str) -> int:
    if not text:
        return 0
    if _ENCODER is not None:
        try:
            return len(_ENCODER.encode(text, disallowed_special=()))
        except Exception:
            pass
    return int(len(text) / CHARS_PER_TOKEN_FALLBACK)


def _estimate_tokens(messages: list[dict]) -> int:
    """Estimate tokens across a message list.

    Uses tiktoken's cl100k_base when available — it's not perfect for
    Anthropic/Gemini but it's dramatically closer than len/4, and the
    bias is consistent so trigger thresholds stay calibrated.
    """
    total = 0
    for msg in messages:
        content = msg.get("content", "")
        if isinstance(content, str):
            total += _count_text_tokens(content)
        elif isinstance(content, list):
            for block in content:
                if isinstance(block, dict):
                    text = block.get("text", "") or block.get("content", "")
                    total += _count_text_tokens(str(text))
                else:
                    total += _count_text_tokens(str(block))
        # tool_calls are small structured args; count name + args
        for tc in msg.get("tool_calls", []) or []:
            total += _count_text_tokens(str(tc.get("name", "")))
            total += _count_text_tokens(str(tc.get("args", "")))
    return total


def _get_context_size(model: str) -> int:
    """Get context window size for a model."""
    model_lower = model.lower()
    for key, size in MODEL_CONTEXT_SIZES.items():
        if key in model_lower:
            return size
    return 128_000  # safe default


def _find_round_boundary(messages: list[dict], desired_end: int) -> int:
    """Snap `desired_end` back to the nearest safe cut point.

    A cut point is safe when the message at that index is either the
    system message or a `user` message — i.e. never mid-round between
    an assistant's tool_calls and the matching tool results. The
    returned index is the first message to *keep* (so messages[:idx]
    are compactable).
    """
    if desired_end <= 0:
        return 0
    idx = min(desired_end, len(messages))
    while idx > 0:
        msg = messages[idx] if idx < len(messages) else None
        if msg is None:
            idx -= 1
            continue
        role = msg.get("role")
        # `user` is a clean boundary. `system` should never appear mid-list
        # but handle it defensively.
        if role in ("user", "system"):
            return idx
        idx -= 1
    return 0


class AutoCompactor:
    """
    Monitors message list size and compacts when approaching context limits.

    Compaction strategy:
    1. Keep the system message (messages[0]) always
    2. Keep the last KEEP_RECENT messages verbatim, extended backwards to
       the nearest round boundary so we never orphan tool_calls from
       their tool results.
    3. Summarize everything in between into a single condensed message
    """

    def __init__(self, model: str, compact_model: str | None = None):
        self.model = model
        self.compact_model = compact_model or os.getenv(
            "COMPACT_MODEL_NAME", "gemini-3-flash-preview"
        )
        self.context_size = _get_context_size(model)
        self.proactive_tokens = int(self.context_size * TRIGGER_FRACTION_PROACTIVE)
        self.reactive_tokens = int(self.context_size * TRIGGER_FRACTION_REACTIVE)
        self._failure_count = 0
        self._disabled = False
        self._compaction_count = 0
        self._last_estimate = 0

    # Back-compat alias for older callers.
    @property
    def trigger_tokens(self) -> int:
        return self.reactive_tokens

    def _token_count(self, messages: list[dict]) -> int:
        self._last_estimate = _estimate_tokens(messages)
        return self._last_estimate

    def should_compact(self, messages: list[dict]) -> bool:
        """Reactive trigger at 90% — compact before the next LLM call."""
        if self._disabled:
            return False
        if len(messages) <= KEEP_RECENT + 2:
            return False
        return self._token_count(messages) >= self.reactive_tokens

    def should_micro_compact(self, messages: list[dict]) -> bool:
        """Proactive trigger at 75% — compact early to avoid panic-compacting."""
        if self._disabled:
            return False
        if len(messages) <= KEEP_RECENT + 4:
            return False
        return self._token_count(messages) >= self.proactive_tokens

    async def compact(self, messages: list[dict]) -> bool:
        """
        Compact the message list in-place.

        Returns True if compaction succeeded, False otherwise.
        """
        if self._disabled:
            return False

        n = len(messages)
        if n <= KEEP_RECENT + 2:
            return False

        # Partition: system | compactable | recent
        system_msg = messages[0] if messages[0].get("role") == "system" else None
        start_idx = 1 if system_msg else 0

        # Snap the cut point back to a user-message boundary so we never
        # split an assistant+tool_calls from its matching tool results.
        desired_end = n - KEEP_RECENT
        end_idx = _find_round_boundary(messages, desired_end)
        if end_idx <= start_idx:
            return False

        compactable = messages[start_idx:end_idx]
        recent = messages[end_idx:]

        if not compactable:
            return False

        try:
            summary = await self._summarize(compactable)
        except Exception as e:
            logger.error(f"Compaction failed: {e}")
            self._failure_count += 1
            if self._failure_count >= MAX_FAILURES:
                logger.warning("Compaction circuit breaker triggered — disabling.")
                self._disabled = True
            return False

        # Rebuild message list in place. The synthetic user message
        # mirrors Claude Code's <compact-summary> marker so downstream
        # consumers can detect it.
        compact_msg = {
            "role": "user",
            "content": (
                "<compact-summary>\n"
                f"[Context compacted — summarizing {len(compactable)} earlier messages]\n\n"
                f"{summary}\n"
                "</compact-summary>"
            ),
        }

        messages.clear()
        if system_msg:
            messages.append(system_msg)
        messages.append(compact_msg)
        messages.extend(recent)

        self._compaction_count += 1
        self._failure_count = 0
        logger.info(
            f"Compacted {len(compactable)} messages into summary "
            f"(~{_estimate_tokens([compact_msg])} tokens). "
            f"Total compactions: {self._compaction_count}"
        )
        return True

    async def _summarize(self, messages: list[dict]) -> str:
        """Use a fast LLM to summarize a block of messages."""
        from src.llm.providers import get_worker_llm

        llm = get_worker_llm(model_name=self.compact_model, temperature=0.0)

        # Build a flat text representation of the messages
        parts = []
        for msg in messages:
            role = msg.get("role", "unknown")
            content = msg.get("content", "")
            if isinstance(content, list):
                # Extract text from content blocks
                texts = []
                for block in content:
                    if isinstance(block, dict):
                        if block.get("type") == "tool_use":
                            texts.append(f"[Tool: {block.get('name', '?')}]")
                        elif block.get("type") == "tool_result":
                            texts.append(f"[Tool result: {str(block.get('content', ''))[:200]}]")
                        else:
                            texts.append(block.get("text", str(block))[:500])
                    else:
                        texts.append(str(block)[:500])
                content = " | ".join(texts)
            elif isinstance(content, str) and len(content) > 1000:
                content = content[:1000] + "..."

            parts.append(f"[{role}] {content}")

        conversation_text = "\n".join(parts)

        # Truncate if too large for the compact model
        if len(conversation_text) > 50_000:
            conversation_text = conversation_text[:50_000] + "\n...[truncated]"

        prompt = (
            "Summarize this conversation segment concisely. Focus on:\n"
            "1. What the agent was trying to accomplish\n"
            "2. Key findings, decisions, and state changes\n"
            "3. Tool results that affect future actions\n"
            "4. Any errors or dead ends encountered\n\n"
            "Be factual. Preserve specific names, paths, and values.\n\n"
            f"Conversation:\n{conversation_text}"
        )

        from langchain_core.messages import HumanMessage
        response = await llm.ainvoke([HumanMessage(content=prompt)])
        return response.content if hasattr(response, "content") else str(response)

    @property
    def stats(self) -> dict:
        return {
            "compactions": self._compaction_count,
            "failures": self._failure_count,
            "disabled": self._disabled,
            "context_size": self.context_size,
            "proactive_tokens": self.proactive_tokens,
            "reactive_tokens": self.reactive_tokens,
            "last_estimate": self._last_estimate,
            "tokenizer": "tiktoken-cl100k" if _ENCODER is not None else "heuristic",
        }
