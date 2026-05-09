"""Provider-agnostic LLM construction for Critikal.

Everything here is independent of the legacy pipeline. Both the agent loop
and the legacy coordinator import from this module.
"""

from src.llm.providers import detect_provider, get_worker_llm
from src.llm.model_registry import (
    AGENT_ROLES,
    PROVIDER_MODELS,
    ModelInfo,
    apply_model_config,
    get_available_providers,
    get_current_config,
    get_models_for_provider,
)

__all__ = [
    "detect_provider",
    "get_worker_llm",
    "AGENT_ROLES",
    "PROVIDER_MODELS",
    "ModelInfo",
    "apply_model_config",
    "get_available_providers",
    "get_current_config",
    "get_models_for_provider",
]
