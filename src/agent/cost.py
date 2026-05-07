"""
CostTracker — per-session API cost tracking with budget enforcement.

Tracks token usage and estimated cost across all LLM calls in a session,
including the main agent and all spawned workers/sub-agents.
"""

from dataclasses import dataclass, field
from threading import Lock
from typing import Any

# Approximate pricing per 1M tokens (input/output). These are tracked
# best-effort and drift over time; they are used for rough budget estimation,
# not billing. Treat any value older than ~6 months as stale and update
# against the provider's current published rates before trusting the numbers.
MODEL_PRICING: dict[str, tuple[float, float]] = {
    # (input_per_1M, output_per_1M)
    # ── OpenAI (current) ─────────────────────────────────────
    "gpt-5.5":            (5.0,  30.0),
    "gpt-5.5-pro":        (30.0, 180.0),
    "gpt-5.4":            (2.5,  20.0),
    "gpt-5.4-mini":       (0.4,  1.6),
    "gpt-5.4-nano":       (0.1,  0.4),
    "gpt-5.1":            (2.0,  8.0),
    "gpt-5":              (2.0,  8.0),
    "gpt-4o":             (2.5,  10.0),
    "gpt-4o-mini":        (0.15, 0.60),
    # ── xAI (current) ───────────────────────────────────────
    "grok-4-3":                   (3.0, 15.0),
    "grok-4-20-reasoning":        (3.0, 15.0),
    "grok-4-20-non-reasoning":    (3.0, 15.0),
    "grok-4-1-fast-reasoning":    (0.20, 0.50),
    "grok-4-1-fast-non-reasoning":(0.20, 0.50),
    "grok-code-fast-1":           (0.20, 1.50),
    "grok-4":                     (3.0, 15.0),
    "grok-3":                     (3.0, 15.0),
    # ── Legacy / opt-in via env ─────────────────────────────
    "claude-opus-4-7":      (15.0, 75.0),
    "claude-opus-4-6":      (15.0, 75.0),
    "claude-sonnet-4-6":    (3.0,  15.0),
    "claude-sonnet-4-5":    (3.0,  15.0),
    "claude-haiku-4-5":     (0.80, 4.0),
    "gemini-3-flash-preview": (0.15, 0.60),
    "gemini-3-pro-preview":   (1.25, 10.0),
    "gemini-2.0-flash":       (0.10, 0.40),
}


def _estimate_cost(model: str, input_tokens: int, output_tokens: int) -> float:
    """Estimate USD cost for a single API call."""
    # Find best matching model key
    pricing = None
    model_lower = model.lower()
    for key, rates in MODEL_PRICING.items():
        if key in model_lower:
            pricing = rates
            break
    if pricing is None:
        # Default: assume mid-tier pricing
        pricing = (2.0, 10.0)

    input_cost = (input_tokens / 1_000_000) * pricing[0]
    output_cost = (output_tokens / 1_000_000) * pricing[1]
    return input_cost + output_cost


@dataclass
class CostTracker:
    """Thread-safe cost tracker with optional budget enforcement."""

    budget_usd: float | None = None
    session_cost: float = 0.0
    total_input_tokens: int = 0
    total_output_tokens: int = 0
    per_model: dict[str, dict[str, Any]] = field(default_factory=dict)
    _lock: Lock = field(default_factory=Lock, repr=False)

    def record(self, model: str, input_tokens: int, output_tokens: int):
        """Record token usage from an API call."""
        cost = _estimate_cost(model, input_tokens, output_tokens)
        with self._lock:
            self.session_cost += cost
            self.total_input_tokens += input_tokens
            self.total_output_tokens += output_tokens
            if model not in self.per_model:
                self.per_model[model] = {
                    "input_tokens": 0, "output_tokens": 0, "cost": 0.0, "calls": 0,
                }
            entry = self.per_model[model]
            entry["input_tokens"] += input_tokens
            entry["output_tokens"] += output_tokens
            entry["cost"] += cost
            entry["calls"] += 1

    def is_over_budget(self) -> bool:
        """Check if session cost exceeds budget."""
        if self.budget_usd is None:
            return False
        with self._lock:
            return self.session_cost >= self.budget_usd

    def summary(self) -> dict[str, Any]:
        """Return a summary dict for display."""
        with self._lock:
            return {
                "session_cost_usd": round(self.session_cost, 4),
                "budget_usd": self.budget_usd,
                "total_input_tokens": self.total_input_tokens,
                "total_output_tokens": self.total_output_tokens,
                "per_model": dict(self.per_model),
            }

    def format_short(self) -> str:
        """Short display string for status bar."""
        with self._lock:
            return f"${self.session_cost:.2f}"
