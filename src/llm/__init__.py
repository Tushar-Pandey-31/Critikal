"""Provider-agnostic LLM construction for Critikal.

Everything here is independent of the legacy pipeline. Both the agent loop
and the legacy coordinator import from this module.
"""

from src.llm.providers import get_worker_llm, detect_provider

__all__ = ["get_worker_llm", "detect_provider"]
