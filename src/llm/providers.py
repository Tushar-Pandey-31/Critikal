"""
Provider detection and rate-limited LLM construction.

Moved out of src/pipeline/lead_agent.py so the agent path no longer depends on
the legacy coordinator. Only concern here is "given a model name, return a
rate-limited, key-pool-backed chat LLM".
"""

from __future__ import annotations

import logging
import os
from typing import Any

logger = logging.getLogger(__name__)

try:
    from langchain_google_genai import ChatGoogleGenerativeAI
except ImportError:
    ChatGoogleGenerativeAI = None

try:
    from langchain_anthropic import ChatAnthropic
except ImportError:
    ChatAnthropic = None

try:
    from langchain_openai import ChatOpenAI
except ImportError:
    ChatOpenAI = None


def detect_provider(model_name: str) -> str:
    """Detect provider id from a model name string.

    Raises ValueError on unknown prefixes. Falling back to a default provider
    silently routes a typo'd model (e.g. ``claude-sonnet-4-7``-with-extra-chars)
    to the wrong API and hides the misconfiguration behind a confusing 4xx.
    """
    m = model_name.lower()
    if m.startswith("gemini") or m.startswith("models/gemini"):
        return "gemini"
    if m.startswith("gpt") or m.startswith("o1") or m.startswith("o3") or m.startswith("o4"):
        return "openai"
    if m.startswith("claude"):
        return "anthropic"
    if m.startswith("grok"):
        return "xai"
    if m.startswith("openrouter/") or "/" in m:
        return "openrouter"
    raise ValueError(
        f"Unknown provider for model '{model_name}'. "
        "Supported prefixes: claude-, gemini-, gpt-/o1/o3/o4, grok-, openrouter/<model>."
    )


_PROVIDER_ENV_KEYS: dict[str, tuple[str, ...]] = {
    "anthropic": ("ANTHROPIC_API_KEY",),
    "gemini": ("GOOGLE_API_KEY", "GOOGLE_API_KEYS"),
    "openai": ("OPENAI_API_KEY",),
    "xai": ("XAI_API_KEY",),
    "openrouter": ("OPENROUTER_API_KEY",),
}


def check_provider_credentials(model_name: str) -> tuple[bool, str]:
    """Return (ok, message). `ok` is True if a credential is available
    for the model's provider, False with a human-readable reason otherwise.

    Covers both the shared key pool and the per-provider env vars. Used
    for preflight so we fail loudly *before* starting an agentic loop
    that would otherwise burn a retry cycle to discover the same thing.
    """
    try:
        provider = detect_provider(model_name)
    except ValueError as e:
        return False, str(e)

    try:
        from src.utils.key_pool import get_key_pool

        key_pool = get_key_pool()
        try:
            if key_pool.get_key(provider):
                return True, f"key-pool[{provider}]"
        except ValueError:
            pass
    except Exception:
        pass

    for env_var in _PROVIDER_ENV_KEYS.get(provider, ()):
        val = os.getenv(env_var)
        if val:
            return True, env_var

    expected = " / ".join(_PROVIDER_ENV_KEYS.get(provider, ("<unknown>",)))
    return False, (
        f"No API key found for model '{model_name}' (provider={provider}). "
        f"Set {expected} in your environment or .env file."
    )


def get_worker_llm(
    model_name: str | None = None,
    temperature: float = 0.0,
):
    """
    Return a rate-limited LLM with NO tools bound.

    Workers must use this. Never bind tools to a worker LLM — the tool
    registry is for the coordinator/agent loop.
    """
    from src.utils.key_pool import get_key_pool
    from src.utils.rate_limiter import RateLimitedLLM, get_rate_limiter

    if model_name is None:
        model_name = os.getenv("WORKER_MODEL_NAME", "gpt-5.4-mini")

    timeout = float(os.getenv("WORKER_LLM_TIMEOUT", "180"))
    max_retries = int(os.getenv("WORKER_LLM_MAX_RETRIES", "0"))
    provider = detect_provider(model_name)
    key_pool = get_key_pool()

    try:
        api_key = key_pool.get_key(provider)
    except ValueError:
        api_key = None

    if provider == "anthropic":
        if not ChatAnthropic:
            raise ImportError("langchain-anthropic is not installed. Run: pip install langchain-anthropic")
        llm = ChatAnthropic(
            model=model_name,
            temperature=temperature,
            timeout=timeout,
            api_key=api_key or os.getenv("ANTHROPIC_API_KEY"),
        )
    elif provider == "openrouter":
        if not ChatOpenAI:
            raise ImportError("langchain-openai is not installed.")
        clean_model = (
            model_name.removeprefix("openrouter/") if model_name.lower().startswith("openrouter/") else model_name
        )
        llm = ChatOpenAI(
            model=clean_model,
            temperature=temperature,
            timeout=timeout,
            openai_api_key=api_key or os.getenv("OPENROUTER_API_KEY"),
            openai_api_base="https://openrouter.ai/api/v1",
            default_headers={
                "HTTP-Referer": "https://github.com/critikal",
                "X-Title": "Critikal",
            },
            max_tokens=int(os.getenv("OPENROUTER_MAX_TOKENS", "16384")),
        )
    elif provider == "xai":
        if not ChatOpenAI:
            raise ImportError("langchain-openai is not installed.")
        llm = ChatOpenAI(
            model=model_name,
            temperature=temperature,
            timeout=timeout,
            openai_api_key=api_key or os.getenv("XAI_API_KEY"),
            openai_api_base="https://api.x.ai/v1",
        )
    elif provider == "openai":
        if not ChatOpenAI:
            raise ImportError("langchain-openai is not installed.")
        llm = ChatOpenAI(
            model=model_name,
            temperature=temperature,
            timeout=timeout,
            openai_api_key=api_key or os.getenv("OPENAI_API_KEY"),
        )
    else:
        transport = os.getenv("WORKER_LLM_TRANSPORT", "rest")
        kwargs: dict[str, Any] = {
            "model": model_name,
            "temperature": temperature,
            "timeout": timeout,
            "request_timeout": timeout,
            "max_retries": max_retries,
            "transport": transport,
        }
        # Prefer the key-pool key, then GOOGLE_API_KEY from env. We pass
        # it explicitly so ChatGoogleGenerativeAI never silently tries
        # Vertex AI / ADC when the user just wanted the public API.
        explicit_key = api_key or os.getenv("GOOGLE_API_KEY")
        if explicit_key:
            kwargs["google_api_key"] = explicit_key
        llm = ChatGoogleGenerativeAI(**kwargs)

    limiter = get_rate_limiter()
    wrapped = RateLimitedLLM(
        llm=llm,
        limiter=limiter,
        key_pool=key_pool,
        provider=provider,
        model_name=model_name,
    )
    if api_key:
        wrapped.set_key(api_key)

    logger.info(f"[get_worker_llm] {model_name} (provider={provider})")
    return wrapped
