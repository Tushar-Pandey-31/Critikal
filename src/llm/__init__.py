"""Provider-agnostic LLM construction for Critikal.

Everything here is independent of the legacy pipeline. Both the agent loop
and the legacy coordinator import from this module.
"""

from src.llm.providers import detect_provider, get_worker_llm

__all__ = ["detect_provider", "get_worker_llm"]
