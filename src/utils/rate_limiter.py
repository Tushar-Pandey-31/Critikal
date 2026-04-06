"""
GlobalRateLimiter & RateLimitedLLM — Centralized LLM throttling.

Sliding-window rate limiter that enforces per-model RPM/TPM limits.
RateLimitedLLM is a transparent wrapper that intercepts .invoke() and
.ainvoke() calls, acquires a rate-limit slot, and delegates to the real LLM.

Usage:
    from src.utils.rate_limiter import get_rate_limiter, RateLimitedLLM
    limiter = get_rate_limiter()
    wrapped = RateLimitedLLM(llm, limiter, key_pool, provider="gemini")
    response = await wrapped.ainvoke(messages)  # throttled automatically
"""

from __future__ import annotations
from pydantic import SecretStr


import asyncio
import collections
import logging
import os
import threading
import time
from typing import Any

logger = logging.getLogger(__name__)

# ── Default rate-limit tiers ────────────────────────────────────────
# Keyed by (model_prefix, tier).  "free" is the default.
# Limits sourced from official Gemini docs (Feb 2026) + OpenAI/Anthropic docs.

_TIER = os.getenv("RATE_LIMIT_TIER", "free").lower()

_MODEL_LIMITS: dict[str, dict[str, dict[str, int]]] = {
    # ── Gemini ──────────────────────────────────────────────
    "gemini-3.1-pro": {
        "free":    {"rpm": 5,   "tpm": 250_000,   "rpd": 100},
        "paid_t1": {"rpm": 150, "tpm": 1_000_000, "rpd": 1_500},
        "paid_t2": {"rpm": 500, "tpm": 2_000_000, "rpd": 10_000},
    },
    "gemini-3.1-flash-lite": {
        "free":    {"rpm": 15,  "tpm": 250_000,   "rpd": 1_000},
        "paid_t1": {"rpm": 300, "tpm": 1_000_000, "rpd": 1_500},
    },
    "gemini-3-flash": {
        "free":    {"rpm": 10,  "tpm": 250_000,   "rpd": 500},
        "paid_t1": {"rpm": 300, "tpm": 1_000_000, "rpd": 1_500},
    },
    "gemini-2.5-pro": {
        "free":    {"rpm": 5,   "tpm": 250_000,   "rpd": 100},
        "paid_t1": {"rpm": 150, "tpm": 1_000_000, "rpd": 1_500},
        "paid_t2": {"rpm": 500, "tpm": 2_000_000, "rpd": 10_000},
    },
    "gemini-2.5-flash": {
        "free":    {"rpm": 10,  "tpm": 250_000,   "rpd": 250},
        "paid_t1": {"rpm": 300, "tpm": 1_000_000, "rpd": 1_500},
        "paid_t2": {"rpm": 1500, "tpm": 2_000_000, "rpd": 10_000},
    },
    "gemini-2.5-flash-lite": {
        "free":    {"rpm": 15,  "tpm": 250_000,   "rpd": 1_000},
        "paid_t1": {"rpm": 300, "tpm": 1_000_000, "rpd": 1_500},
    },
    "gemini-2.0-flash": {
        "free":    {"rpm": 10,  "tpm": 250_000,   "rpd": 500},
        "paid_t1": {"rpm": 300, "tpm": 1_000_000, "rpd": 1_500},
    },
    "gemini-1.5-flash": {
        "free":    {"rpm": 15,  "tpm": 250_000,   "rpd": 500},
        "paid_t1": {"rpm": 300, "tpm": 1_000_000, "rpd": 1_500},
    },
    "gemini-1.5-pro": {
        "free":    {"rpm": 5,   "tpm": 250_000,   "rpd": 100},
        "paid_t1": {"rpm": 150, "tpm": 1_000_000, "rpd": 1_500},
    },
    # ── OpenAI ──────────────────────────────────────────────
    "gpt-5.1": {
        "free":    {"rpm": 500, "tpm": 30_000,  "rpd": 10_000},
        "paid_t1": {"rpm": 500, "tpm": 30_000,  "rpd": 10_000},
    },
    "gpt-4o": {
        "free":    {"rpm": 500, "tpm": 30_000,  "rpd": 10_000},
        "paid_t1": {"rpm": 500, "tpm": 30_000,  "rpd": 10_000},
    },
    "gpt-4o-mini": {
        "free":    {"rpm": 500, "tpm": 200_000, "rpd": 10_000},
        "paid_t1": {"rpm": 500, "tpm": 200_000, "rpd": 10_000},
    },
    # ── Anthropic ───────────────────────────────────────────
    "claude-sonnet-4": {
        "free":    {"rpm": 50, "tpm": 40_000, "rpd": 1_000},
        "paid_t1": {"rpm": 50, "tpm": 40_000, "rpd": 1_000},
    },
    "claude-sonnet": {
        "free":    {"rpm": 50, "tpm": 40_000, "rpd": 1_000},
        "paid_t1": {"rpm": 50, "tpm": 40_000, "rpd": 1_000},
    },
    "claude-haiku": {
        "free":    {"rpm": 50, "tpm": 50_000, "rpd": 1_000},
        "paid_t1": {"rpm": 50, "tpm": 50_000, "rpd": 1_000},
    },
}

# Absolute fallback if model is unknown
_FALLBACK_LIMITS = {"rpm": 10, "tpm": 250_000, "rpd": 500}


def _resolve_limits(model: str) -> dict[str, int]:
    """Resolve RPM/TPM/RPD limits for a model name and the active tier."""
    # Check env var override first: RATE_LIMIT_RPM_OVERRIDE
    rpm_override = os.getenv("RATE_LIMIT_RPM_OVERRIDE")
    if rpm_override:
        return {
            "rpm": int(rpm_override),
            "tpm": int(os.getenv("RATE_LIMIT_TPM_OVERRIDE", "250000")),
            "rpd": int(os.getenv("RATE_LIMIT_RPD_OVERRIDE", "10000")),
        }

    # Strip OpenRouter/provider prefix: "openrouter/google/gemini-3.1-pro" → "gemini-3.1-pro"
    model_lower = model.lower()
    if model_lower.startswith("openrouter/"):
        # Strip "openrouter/{provider}/" to get bare model name
        parts = model_lower.split("/")
        model_lower = parts[-1] if len(parts) >= 3 else parts[-1]

    # Try exact match, then prefix match
    for prefix, tiers in _MODEL_LIMITS.items():
        if model_lower.startswith(prefix):
            limits = tiers.get(_TIER, tiers.get("free", _FALLBACK_LIMITS))
            return dict(limits)

    logger.warning(f"[RateLimiter] Unknown model '{model}', using fallback limits")
    return dict(_FALLBACK_LIMITS)


class GlobalRateLimiter:
    """
    Async-safe singleton. Sliding-window RPM enforcement per (model, key_id).

    The window keeps timestamps of the last N requests. Before allowing
    a new request, it prunes expired entries and checks if the window
    is full.
    """

    _instance: GlobalRateLimiter | None = None
    _init_lock = threading.Lock()

    def __new__(cls) -> GlobalRateLimiter:
        with cls._init_lock:
            if cls._instance is None:
                inst = super().__new__(cls)
                # _windows[bucket_key] = deque of timestamps
                inst._windows: dict[str, collections.deque] = {}
                inst._limits_cache: dict[str, dict[str, int]] = {}
                inst._lock = threading.Lock()
                inst._async_locks: dict[str, asyncio.Lock] = {}
                inst._daily_counts: dict[str, int] = {}
                inst._daily_reset: float = 0.0
                cls._instance = inst
            return cls._instance

    # ── Public API ───────────────────────────────────────────

    async def acquire(
        self,
        model: str,
        key_id: str = "default",
        estimated_tokens: int = 0,
    ) -> None:
        """
        Async acquire — blocks until a request slot is available.

        Args:
            model: Model name (e.g. "gemini-2.5-flash")
            key_id: API key identifier (last 4 chars, for per-key tracking)
            estimated_tokens: Estimated input+output tokens (for TPM tracking)
        """
        bucket = f"{model}:{key_id}"
        limits = self._get_limits(model)
        rpm = limits["rpm"]

        # Get or create an async lock for this bucket
        if bucket not in self._async_locks:
            self._async_locks[bucket] = asyncio.Lock()

        async with self._async_locks[bucket]:
            window = self._get_window(bucket)
            now = time.time()

            # Prune entries older than 60 seconds
            cutoff = now - 60.0
            while window and window[0] < cutoff:
                window.popleft()

            if len(window) >= rpm:
                # Window full — wait until the oldest entry expires
                wait = window[0] - cutoff
                if wait > 0:
                    logger.info(
                        f"[RateLimiter] RPM limit ({rpm}) hit for {model}. "
                        f"Waiting {wait:.1f}s..."
                    )
                    await asyncio.sleep(wait + 0.05)
                    # Re-prune after sleeping
                    now = time.time()
                    cutoff = now - 60.0
                    while window and window[0] < cutoff:
                        window.popleft()

            window.append(time.time())

    def acquire_sync(
        self,
        model: str,
        key_id: str = "default",
        estimated_tokens: int = 0,
    ) -> None:
        """
        Blocking acquire — for sync .invoke() calls via asyncio.to_thread.
        """
        bucket = f"{model}:{key_id}"
        limits = self._get_limits(model)
        rpm = limits["rpm"]

        with self._lock:
            window = self._get_window(bucket)
            now = time.time()
            cutoff = now - 60.0
            while window and window[0] < cutoff:
                window.popleft()

            if len(window) >= rpm:
                wait = window[0] - cutoff
            else:
                wait = 0.0

        if wait > 0:
            logger.info(
                f"[RateLimiter] RPM limit ({rpm}) hit for {model}. "
                f"Waiting {wait:.1f}s..."
            )
            time.sleep(wait + 0.05)
            # Re-acquire after sleeping
            with self._lock:
                window = self._get_window(bucket)
                now = time.time()
                cutoff = now - 60.0
                while window and window[0] < cutoff:
                    window.popleft()

        with self._lock:
            window = self._get_window(bucket)
            window.append(time.time())

    def get_status(self, model: str, key_id: str = "default") -> dict:
        """Return diagnostic info about this bucket's rate window."""
        bucket = f"{model}:{key_id}"
        limits = self._get_limits(model)
        with self._lock:
            window = self._get_window(bucket)
            now = time.time()
            active = sum(1 for t in window if t > now - 60.0)
        return {
            "model": model,
            "key_suffix": key_id,
            "rpm_limit": limits["rpm"],
            "rpm_used": active,
            "rpm_remaining": max(0, limits["rpm"] - active),
            "tier": _TIER,
        }

    def reset(self) -> None:
        """Clear all windows (for testing)."""
        with self._lock:
            self._windows.clear()
            self._limits_cache.clear()
            self._daily_counts.clear()

    # ── Private ──────────────────────────────────────────────

    def _get_limits(self, model: str) -> dict[str, int]:
        if model not in self._limits_cache:
            self._limits_cache[model] = _resolve_limits(model)
        return self._limits_cache[model]

    def _get_window(self, bucket: str) -> collections.deque:
        if bucket not in self._windows:
            self._windows[bucket] = collections.deque()
        return self._windows[bucket]


# ── RateLimitedLLM Wrapper ──────────────────────────────────────────


class RateLimitedLLM:
    """
    Transparent wrapper around any LangChain BaseChatModel.

    Intercepts .invoke() and .ainvoke(), acquires a rate-limit slot
    from the GlobalRateLimiter, and handles 429 failover via the KeyPool.
    """

    def __init__(
        self,
        llm: Any,
        limiter: GlobalRateLimiter,
        key_pool: Any | None = None,
        provider: str = "gemini",
        model_name: str = "",
    ):
        self._llm = llm
        self._limiter = limiter
        self._key_pool = key_pool
        self._provider = provider
        self._model_name = model_name or getattr(llm, "model", "unknown")
        self._current_key: str = ""

        # Proxy common LLM attributes so workers can read them
        self.model = getattr(llm, "model", self._model_name)

    def __getattr__(self, name: str) -> Any:
        """Proxy any attribute access to the underlying LLM."""
        return getattr(self._llm, name)

    def invoke(self, *args: Any, **kwargs: Any) -> Any:
        """Sync invoke with rate limiting."""
        key_suffix = self._current_key[-4:] if self._current_key else "default"
        self._limiter.acquire_sync(self._model_name, key_suffix)
        try:
            return self._llm.invoke(*args, **kwargs)
        except Exception as e:
            if (self._is_rate_limit_error(e) or self._is_auth_error(e)) and self._key_pool:
                is_auth = self._is_auth_error(e)
                # Auth errors (401/402): bench permanently (1 hour)
                # Rate limits (429): bench temporarily (60s)
                cooldown = 3600.0 if is_auth else None
                self._key_pool.mark_cooldown(self._provider, self._current_key, cooldown)
                err_type = "401/402 auth" if is_auth else "429 rate-limit"
                logger.warning(
                    f"[RateLimitedLLM] {err_type} on key ...{key_suffix}, "
                    f"cooling down and retrying with next key..."
                )
                # Get a new key and retry once
                new_key = self._key_pool.get_key(self._provider)
                self._swap_key(new_key)
                self._limiter.acquire_sync(self._model_name, new_key[-4:])
                return self._llm.invoke(*args, **kwargs)
            raise

    async def ainvoke(self, *args: Any, **kwargs: Any) -> Any:
        """Async invoke with rate limiting."""
        key_suffix = self._current_key[-4:] if self._current_key else "default"
        await self._limiter.acquire(self._model_name, key_suffix)
        try:
            return await self._llm.ainvoke(*args, **kwargs)
        except Exception as e:
            if (self._is_rate_limit_error(e) or self._is_auth_error(e)) and self._key_pool:
                is_auth = self._is_auth_error(e)
                cooldown = 3600.0 if is_auth else None
                self._key_pool.mark_cooldown(self._provider, self._current_key, cooldown)
                err_type = "401/402 auth" if is_auth else "429 rate-limit"
                logger.warning(
                    f"[RateLimitedLLM] {err_type} on key ...{key_suffix}, "
                    f"cooling down and retrying with next key..."
                )
                new_key = await self._key_pool.get_key_async(self._provider)
                self._swap_key(new_key)
                await self._limiter.acquire(self._model_name, new_key[-4:])
                return await self._llm.ainvoke(*args, **kwargs)
            raise

    def set_key(self, key: str) -> None:
        """Set the current API key on this wrapper and the underlying LLM."""
        self._current_key = key
        self._swap_key(key)

    def _swap_key(self, new_key: str) -> None:
        """Swap the API key on the underlying LLM instance."""
        self._current_key = new_key
        # LangChain Google GenAI
        if hasattr(self._llm, "google_api_key"):
            self._llm.google_api_key = new_key
        # LangChain OpenAI
        elif hasattr(self._llm, "openai_api_key"):
            self._llm.openai_api_key = new_key
        # LangChain Anthropic
        elif hasattr(self._llm, "anthropic_api_key"):
            self._llm.anthropic_api_key = SecretStr(new_key)

    @staticmethod
    def _is_rate_limit_error(e: Exception) -> bool:
        """Check if an exception is a 429 rate-limit error."""
        err_str = str(e).lower()
        return any(
            kw in err_str
            for kw in ["429", "quota", "rate_limit", "rate limit", "resource_exhausted"]
        )

    @staticmethod
    def _is_auth_error(e: Exception) -> bool:
        """Check if an exception is a 401/402 auth or credit error."""
        err_str = str(e).lower()
        return any(
            kw in err_str
            for kw in ["401", "402", "user not found", "unauthorized", "requires more credits"]
        )


# ── Module-level accessor ──────────────────────────────────────────


def get_rate_limiter() -> GlobalRateLimiter:
    """Return the global rate limiter singleton."""
    return GlobalRateLimiter()
