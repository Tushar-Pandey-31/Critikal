"""
APIKeyPool — Manages rotating API keys for multiple LLM providers.

Thread-safe and async-compatible singleton. Reads comma-separated keys
from environment variables, rotates via round-robin, and automatically
benches keys that receive 429 responses.

Usage:
    from src.utils.key_pool import get_key_pool
    pool = get_key_pool()
    key = pool.get_key("gemini")              # round-robin, skips cooled-down
    pool.mark_cooldown("gemini", key, 60.0)   # bench for 60s after a 429
"""

from __future__ import annotations

import asyncio
import logging
import os
import threading
import time
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

# ── Environment variable names per provider ─────────────────────────
_POOL_ENV_VARS: dict[str, tuple[str, str]] = {
    # provider -> (pool_env_var, fallback_single_key_env_var)
    "gemini":      ("GOOGLE_API_KEYS",      "GOOGLE_API_KEY"),
    "openai":      ("OPENAI_API_KEYS",      "OPENAI_API_KEY"),
    "anthropic":   ("ANTHROPIC_API_KEYS",   "ANTHROPIC_API_KEY"),
    "openrouter":  ("OPENROUTER_API_KEYS",  "OPENROUTER_API_KEY"),
}

# Default cooldown when a key is rate-limited (seconds)
_DEFAULT_COOLDOWN = float(os.getenv("KEY_COOLDOWN_SECONDS", "60"))


@dataclass
class _KeyState:
    """Internal bookkeeping for a single API key."""
    key: str
    call_count: int = 0
    cooldown_until: float = 0.0  # epoch timestamp

    @property
    def is_available(self) -> bool:
        return time.time() >= self.cooldown_until


class APIKeyPool:
    """
    Singleton pool of API keys, one pool per provider.

    - get_key(provider): returns the next available key via round-robin.
    - mark_cooldown(provider, key): benches a key after a 429.
    - If ALL keys are on cooldown, blocks until the earliest one expires.
    """

    _instance: APIKeyPool | None = None
    _init_lock = threading.Lock()

    def __new__(cls) -> APIKeyPool:
        with cls._init_lock:
            if cls._instance is None:
                inst = super().__new__(cls)
                inst._pools: dict[str, list[_KeyState]] = {}
                inst._indices: dict[str, int] = {}
                inst._lock = threading.Lock()
                inst._async_lock = asyncio.Lock()
                inst._initialized_providers: set[str] = set()
                cls._instance = inst
            return cls._instance

    # ── Public API ───────────────────────────────────────────

    def get_key(self, provider: str) -> str:
        """
        Return the next available API key for *provider* (round-robin).

        If all keys are on cooldown, sleeps until one becomes available.
        Raises ValueError if no keys are configured for the provider.
        """
        self._ensure_loaded(provider)

        with self._lock:
            pool = self._pools[provider]
            if not pool:
                raise ValueError(
                    f"No API keys configured for provider '{provider}'. "
                    f"Set {_POOL_ENV_VARS.get(provider, ('???',))[0]} or "
                    f"{_POOL_ENV_VARS.get(provider, ('', '???'))[1]}"
                )

            start_idx = self._indices[provider]
            n = len(pool)

            # Scan for the next available key starting from the current index
            for offset in range(n):
                idx = (start_idx + offset) % n
                ks = pool[idx]
                if ks.is_available:
                    ks.call_count += 1
                    self._indices[provider] = (idx + 1) % n
                    return ks.key

            # All keys on cooldown — find the shortest wait
            earliest = min(ks.cooldown_until for ks in pool)
            wait = max(0.0, earliest - time.time())

        # Sleep outside the lock
        if wait > 0:
            logger.warning(
                f"[KeyPool] All {provider} keys on cooldown. "
                f"Sleeping {wait:.1f}s until next key is available..."
            )
            time.sleep(wait + 0.1)

        # Retry after cooldown
        return self.get_key(provider)

    async def get_key_async(self, provider: str) -> str:
        """Async version of get_key — uses asyncio.sleep instead of blocking."""
        self._ensure_loaded(provider)

        async with self._async_lock:
            pool = self._pools[provider]
            if not pool:
                raise ValueError(
                    f"No API keys configured for provider '{provider}'."
                )

            start_idx = self._indices[provider]
            n = len(pool)

            for offset in range(n):
                idx = (start_idx + offset) % n
                ks = pool[idx]
                if ks.is_available:
                    ks.call_count += 1
                    self._indices[provider] = (idx + 1) % n
                    return ks.key

            earliest = min(ks.cooldown_until for ks in pool)
            wait = max(0.0, earliest - time.time())

        if wait > 0:
            logger.warning(
                f"[KeyPool] All {provider} keys on cooldown. "
                f"Sleeping {wait:.1f}s..."
            )
            await asyncio.sleep(wait + 0.1)

        return await self.get_key_async(provider)

    def mark_cooldown(
        self,
        provider: str,
        key: str,
        duration_s: float | None = None,
    ) -> None:
        """
        Bench a key for *duration_s* seconds after a 429 response.
        Defaults to KEY_COOLDOWN_SECONDS env var (60s).
        """
        duration = duration_s if duration_s is not None else _DEFAULT_COOLDOWN
        with self._lock:
            pool = self._pools.get(provider, [])
            for ks in pool:
                if ks.key == key:
                    ks.cooldown_until = time.time() + duration
                    logger.warning(
                        f"[KeyPool] Benched {provider} key ...{key[-4:]} "
                        f"for {duration:.0f}s"
                    )
                    return
        logger.warning(f"[KeyPool] Attempted to cooldown unknown key for {provider}")

    def get_pool_status(self, provider: str) -> dict:
        """Return diagnostic info about the key pool."""
        self._ensure_loaded(provider)
        with self._lock:
            pool = self._pools.get(provider, [])
            return {
                "provider": provider,
                "total_keys": len(pool),
                "available_keys": sum(1 for ks in pool if ks.is_available),
                "keys": [
                    {
                        "suffix": f"...{ks.key[-4:]}",
                        "calls": ks.call_count,
                        "available": ks.is_available,
                        "cooldown_remaining": max(
                            0.0, ks.cooldown_until - time.time()
                        ),
                    }
                    for ks in pool
                ],
            }

    def reset(self) -> None:
        """Clear all pools (for testing)."""
        with self._lock:
            self._pools.clear()
            self._indices.clear()
            self._initialized_providers.clear()

    # ── Private ──────────────────────────────────────────────

    def _ensure_loaded(self, provider: str) -> None:
        """Lazy-load keys from environment on first access per provider."""
        if provider in self._initialized_providers:
            return

        with self._lock:
            if provider in self._initialized_providers:
                return

            pool_var, fallback_var = _POOL_ENV_VARS.get(
                provider, (f"{provider.upper()}_API_KEYS", f"{provider.upper()}_API_KEY")
            )

            raw = os.getenv(pool_var, "")
            keys = [k.strip() for k in raw.split(",") if k.strip()]

            # Always merge the fallback single key into the pool
            # (previously it was only used when the pool was empty,
            # causing 401s when pool keys were expired but the main key worked)
            single = os.getenv(fallback_var, "").strip()
            if single and single not in keys:
                keys.insert(0, single)  # primary key gets priority

            self._pools[provider] = [_KeyState(key=k) for k in keys]
            self._indices[provider] = 0
            self._initialized_providers.add(provider)

            logger.info(
                f"[KeyPool] Loaded {len(keys)} key(s) for provider '{provider}'"
            )
            if not keys:
                logger.warning(
                    f"[KeyPool] No keys found for '{provider}'. "
                    f"Set {pool_var} or {fallback_var}."
                )


def get_key_pool() -> APIKeyPool:
    """Return the global APIKeyPool singleton."""
    return APIKeyPool()
