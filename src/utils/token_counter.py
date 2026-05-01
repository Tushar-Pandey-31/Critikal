"""
Centralized Token Counter — tracks LLM usage across all agents.

Thread-safe singleton that records per-agent:
  - Input/output tokens (from response metadata or char-based estimation)
  - Input/output character counts
  - Number of LLM calls
  - Estimated cost (Gemini Flash pricing)

Usage:
    from src.utils.token_counter import get_token_counter
    tc = get_token_counter()
    tc.record("AgentName", "gemini-3-flash-preview", input_text, output_text, response_metadata)
    summary = tc.get_summary()
"""

import threading
import time
import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)

# Model pricing (per 1M tokens) — updated April 2026
# Covers all models configured in .env. Keyed by bare model name
# (OpenRouter/provider prefixes are stripped before lookup).
_PRICING = {
    # ── Gemini ──────────────────────────────────────────────
    "gemini-3.1-pro-preview":       {"input": 1.25, "output": 10.00},
    "gemini-3.1-pro":               {"input": 1.25, "output": 10.00},
    "gemini-3.1-flash-lite-preview":{"input": 0.075, "output": 0.30},
    "gemini-3.1-flash-lite":        {"input": 0.075, "output": 0.30},
    "gemini-3-flash-preview":       {"input": 0.10, "output": 0.40},
    "gemini-3-flash":               {"input": 0.10, "output": 0.40},
    "gemini-3-flash-preview-lite":  {"input": 0.075, "output": 0.30},
    "gemini-2.0-flash":             {"input": 0.10, "output": 0.40},
    "gemini-1.5-pro":               {"input": 1.25, "output": 5.00},
    "gemini-1.5-flash":             {"input": 0.075, "output": 0.30},
    # ── Anthropic ───────────────────────────────────────────
    "claude-sonnet-4.6":            {"input": 3.00, "output": 15.00},
    "claude-sonnet-4":              {"input": 3.00, "output": 15.00},
    "claude-opus-4":                {"input": 15.00, "output": 75.00},
    "claude-3.5-sonnet":            {"input": 3.00, "output": 15.00},
    "claude-3-haiku":               {"input": 0.25, "output": 1.25},
    # ── OpenAI ──────────────────────────────────────────────
    "gpt-5.1":                      {"input": 2.00, "output": 8.00},
    "gpt-4o":                       {"input": 2.50, "output": 10.00},
    "gpt-4o-mini":                  {"input": 0.15, "output": 0.60},
    "o1":                           {"input": 15.00, "output": 60.00},
    "o1-mini":                      {"input": 3.00, "output": 12.00},
}
_DEFAULT_PRICING = {"input": 0.50, "output": 2.00}  # conservative default

# Rough chars-per-token ratio for estimation when metadata missing
_CHARS_PER_TOKEN = 4


def _normalize_model_name(model: str) -> str:
    """Strip OpenRouter/provider prefix to get bare model name.

    Examples:
        'openrouter/google/gemini-3.1-pro-preview' → 'gemini-3.1-pro-preview'
        'openrouter/anthropic/claude-sonnet-4.6'   → 'claude-sonnet-4.6'
        'gemini-3-flash-preview'                          → 'gemini-3-flash-preview'
    """
    name = model.lower().strip()
    if name.startswith("openrouter/"):
        parts = name.split("/")
        name = parts[-1] if len(parts) >= 3 else parts[-1]
    return name


def _get_pricing(model: str) -> dict:
    """Look up pricing for a model, with prefix-match fallback."""
    name = _normalize_model_name(model)

    # Exact match
    if name in _PRICING:
        return _PRICING[name]

    # Prefix match (e.g. "gemini-3.1-pro-preview-05" matches "gemini-3.1-pro-preview")
    for prefix, pricing in _PRICING.items():
        if name.startswith(prefix):
            return pricing

    logger.warning(f"[TokenCounter] Unknown model '{model}' (normalized: '{name}'), using default pricing")
    return _DEFAULT_PRICING


@dataclass
class AgentUsage:
    """Accumulated LLM usage for a single agent."""
    agent_name: str
    model: str = ""
    call_count: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    total_tokens: int = 0
    input_chars: int = 0
    output_chars: int = 0
    estimated_cost_usd: float = 0.0
    calls: list[dict[str, Any]] = field(default_factory=list)


class TokenCounter:
    """Thread-safe singleton that accumulates LLM token usage per agent."""

    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance._agents: dict[str, AgentUsage] = {}
                cls._instance._record_lock = threading.Lock()
                cls._instance._start_time = time.time()
            return cls._instance

    # ── Public API ──────────────────────────────────────────

    def record(
        self,
        agent_name: str,
        model: str,
        input_text: str,
        output_text: str,
        response_metadata: Any = None,
    ) -> None:
        """
        Record a single LLM call.

        Args:
            agent_name: Identifier for the agent (e.g. "AttackHypothesisWorker")
            model: Model name (e.g. "gemini-3-flash-preview")
            input_text: Full prompt text sent to the LLM
            output_text: Full response text from the LLM
            response_metadata: LangChain response_metadata dict (may contain usage_metadata)
        """
        input_chars = len(input_text) if input_text else 0
        output_chars = len(output_text) if output_text else 0

        # Try to extract real token counts from response metadata
        input_tokens, output_tokens = self._extract_tokens(
            response_metadata, input_chars, output_chars
        )
        total_tokens = input_tokens + output_tokens

        # Cost estimation — uses normalized model name + prefix-match fallback
        pricing = _get_pricing(model)
        cost = (
            (input_tokens / 1_000_000) * pricing["input"]
            + (output_tokens / 1_000_000) * pricing["output"]
        )

        call_record = {
            "timestamp": time.time(),
            "model": model,
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "input_chars": input_chars,
            "output_chars": output_chars,
            "estimated_cost_usd": round(cost, 6),
        }

        with self._record_lock:
            if agent_name not in self._agents:
                self._agents[agent_name] = AgentUsage(agent_name=agent_name, model=model)

            usage = self._agents[agent_name]
            usage.call_count += 1
            usage.input_tokens += input_tokens
            usage.output_tokens += output_tokens
            usage.total_tokens += total_tokens
            usage.input_chars += input_chars
            usage.output_chars += output_chars
            usage.estimated_cost_usd += cost
            usage.calls.append(call_record)

        logger.info(
            f"[TokenCounter] {agent_name}: +{input_tokens} in / +{output_tokens} out "
            f"(${cost:.4f}) — total calls: {usage.call_count}"
        )

    def get_summary(self) -> dict[str, Any]:
        """
        Returns a structured summary of all token usage.

        {
            "agents": [
                {
                    "agent_name": "AttackHypothesisWorker",
                    "model": "gemini-3-flash-preview",
                    "call_count": 5,
                    "input_tokens": 12000,
                    "output_tokens": 3000,
                    "total_tokens": 15000,
                    "input_chars": 48000,
                    "output_chars": 12000,
                    "estimated_cost_usd": 0.0036,
                },
                ...
            ],
            "total": {
                "call_count": 10,
                "input_tokens": 25000,
                "output_tokens": 8000,
                "total_tokens": 33000,
                "input_chars": 100000,
                "output_chars": 32000,
                "estimated_cost_usd": 0.0066,
            },
            "elapsed_seconds": 120.5,
        }
        """
        with self._record_lock:
            agents = []
            total = {
                "call_count": 0,
                "input_tokens": 0,
                "output_tokens": 0,
                "total_tokens": 0,
                "input_chars": 0,
                "output_chars": 0,
                "estimated_cost_usd": 0.0,
            }

            for usage in self._agents.values():
                agent_data = {
                    "agent_name": usage.agent_name,
                    "model": usage.model,
                    "call_count": usage.call_count,
                    "input_tokens": usage.input_tokens,
                    "output_tokens": usage.output_tokens,
                    "total_tokens": usage.total_tokens,
                    "input_chars": usage.input_chars,
                    "output_chars": usage.output_chars,
                    "estimated_cost_usd": round(usage.estimated_cost_usd, 6),
                }
                agents.append(agent_data)

                for key in total:
                    total[key] += agent_data.get(key, 0)

            total["estimated_cost_usd"] = round(total["estimated_cost_usd"], 6)

            return {
                "agents": sorted(agents, key=lambda a: a["estimated_cost_usd"], reverse=True),
                "total": total,
                "elapsed_seconds": round(time.time() - self._start_time, 1),
            }

    def reset(self) -> None:
        """Clear all recorded data."""
        with self._record_lock:
            self._agents.clear()
            self._start_time = time.time()

    # ── Private helpers ─────────────────────────────────────

    @staticmethod
    def _extract_tokens(
        response_metadata: Any,
        input_chars: int,
        output_chars: int,
    ) -> tuple[int, int]:
        """
        Extract token counts from LangChain response metadata.
        Falls back to character-based estimation if metadata unavailable.
        """
        if response_metadata and isinstance(response_metadata, dict):
            # LangChain Google GenAI format
            usage = response_metadata.get("usage_metadata") or response_metadata
            input_t = usage.get("input_tokens") or usage.get("prompt_token_count", 0)
            output_t = usage.get("output_tokens") or usage.get("candidates_token_count", 0)
            if input_t or output_t:
                return int(input_t), int(output_t)

        # Fallback: estimate from character counts
        return input_chars // _CHARS_PER_TOKEN, output_chars // _CHARS_PER_TOKEN


def get_token_counter() -> TokenCounter:
    """Get the global TokenCounter singleton."""
    return TokenCounter()
