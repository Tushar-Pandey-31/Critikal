"""
Model Registry — static catalog of LLM models and agent role mappings.

Provides:
  - PROVIDER_MODELS: curated catalog of models per provider (May 2026)
  - AGENT_ROLES: every configurable agent/worker → its env var
  - get_available_providers(): which providers have API keys set
  - get_models_for_provider(): list of ModelInfo for a provider
  - get_current_config(): snapshot of current model assignments
  - apply_model_config(): set a model for a role at runtime
"""

from __future__ import annotations

import os
from dataclasses import dataclass


# ── Model Info ───────────────────────────────────────────────────────

@dataclass(frozen=True)
class ModelInfo:
    """A single model entry in the catalog."""
    id: str                # API model string (e.g. "gpt-5.4-mini")
    display_name: str      # Human-friendly name
    provider: str          # openai | anthropic | xai | gemini | openrouter
    tier: str              # flagship | fast | mini | code
    context_window: int    # in tokens (approximate)


# ── Provider → API Key env vars ──────────────────────────────────────

PROVIDER_ENV_KEYS: dict[str, tuple[str, ...]] = {
    "openai":      ("OPENAI_API_KEY",),
    "anthropic":   ("ANTHROPIC_API_KEY",),
    "xai":         ("XAI_API_KEY",),
    "gemini":      ("GOOGLE_API_KEY", "GOOGLE_API_KEYS"),
    "openrouter":  ("OPENROUTER_API_KEY",),
}

PROVIDER_DISPLAY: dict[str, str] = {
    "openai":     "OpenAI",
    "anthropic":  "Anthropic",
    "xai":        "xAI (Grok)",
    "gemini":     "Google Gemini",
    "openrouter": "OpenRouter",
}


# ── Model Catalog (May 2026) ────────────────────────────────────────

PROVIDER_MODELS: dict[str, list[ModelInfo]] = {
    "openai": [
        ModelInfo("gpt-5.5",                    "GPT-5.5",               "openai", "flagship",  256_000),
        ModelInfo("gpt-5.4",                    "GPT-5.4",               "openai", "flagship",  128_000),
        ModelInfo("gpt-5.4-mini",               "GPT-5.4 Mini",          "openai", "mini",      128_000),
        ModelInfo("gpt-5.4-nano",               "GPT-5.4 Nano",          "openai", "mini",      128_000),
        ModelInfo("gpt-5.2",                    "GPT-5.2",               "openai", "fast",      128_000),
        ModelInfo("gpt-4.1-2025-04-14",         "GPT-4.1 (Apr 2025)",   "openai", "fast",      128_000),
        ModelInfo("gpt-4.1-mini-2025-04-14",    "GPT-4.1 Mini (Apr 2025)", "openai", "mini",   128_000),
    ],
    "anthropic": [
        ModelInfo("claude-opus-4-7",            "Claude Opus 4.7",       "anthropic", "flagship",  200_000),
        ModelInfo("claude-sonnet-4-6",          "Claude Sonnet 4.6",     "anthropic", "fast",      200_000),
        ModelInfo("claude-opus-4-6",            "Claude Opus 4.6",       "anthropic", "flagship",  200_000),
        ModelInfo("claude-haiku-4-5",           "Claude Haiku 4.5",      "anthropic", "mini",      200_000),
        ModelInfo("claude-sonnet-4-5",          "Claude Sonnet 4.5",     "anthropic", "fast",      200_000),
    ],
    "xai": [
        ModelInfo("grok-4.3",                   "Grok 4.3",              "xai", "flagship",  1_000_000),
        ModelInfo("grok-4-1-fast-reasoning",    "Grok 4.1 Fast (Reasoning)",    "xai", "fast",  131_072),
        ModelInfo("grok-4-1-fast-non-reasoning","Grok 4.1 Fast (Non-Reasoning)","xai", "fast",  131_072),
        ModelInfo("grok-code-fast-1",           "Grok Code Fast 1",      "xai", "code",     131_072),
    ],
    "gemini": [
        ModelInfo("gemini-3.1-pro",             "Gemini 3.1 Pro",        "gemini", "flagship",  2_000_000),
        ModelInfo("gemini-3-flash",             "Gemini 3 Flash",        "gemini", "fast",      1_000_000),
        ModelInfo("gemini-3.1-flash-lite",      "Gemini 3.1 Flash Lite", "gemini", "mini",      1_000_000),
        ModelInfo("gemini-2.5-pro",             "Gemini 2.5 Pro",        "gemini", "flagship",  1_000_000),
        ModelInfo("gemini-2.5-flash",           "Gemini 2.5 Flash",      "gemini", "fast",      1_000_000),
    ],
    "openrouter": [
        # OpenRouter is a meta-provider — users type custom model strings.
        # We list a few popular defaults for convenience.
        ModelInfo("anthropic/claude-sonnet-4-6", "Claude Sonnet 4.6 (OR)", "openrouter", "fast",  200_000),
        ModelInfo("openai/gpt-5.4",              "GPT-5.4 (OR)",           "openrouter", "flagship", 128_000),
        ModelInfo("google/gemini-3.1-pro",       "Gemini 3.1 Pro (OR)",    "openrouter", "flagship", 2_000_000),
    ],
}


# ── Agent Roles → Env Vars ───────────────────────────────────────────

AGENT_ROLES: dict[str, str] = {
    "Main Agent":          "AGENT_MODEL_NAME",
    "Recon Worker":        "RECON_MODEL_NAME",
    "Attack Hypothesis":   "ATTACK_MODEL_NAME",
    "Assumption Worker":   "ASSUMPTION_MODEL_NAME",
    "Semantic Discovery":  "SEMANTIC_MODEL_NAME",
    "Execution Trace":     "EXECUTION_TRACE_MODEL_NAME",
    "Test Writer":         "TEST_WRITER_MODEL_NAME",
    "Gate Filter":         "GATE_MODEL_NAME",
    "Depth Workers":       "DEPTH_MODEL_NAME",
    "Default Worker":      "WORKER_MODEL_NAME",
    "Jury — Skeptic":      "JURY_SKEPTIC_MODEL",
    "Jury — Attacker":     "JURY_ATTACKER_MODEL",
    "Jury — Auditor":      "JURY_AUDITOR_MODEL",
    "Jury — Judge":        "JURY_JUDGE_MODEL",
}

# Sensible defaults per role (used when env var is not set)
ROLE_DEFAULTS: dict[str, str] = {
    "Main Agent":          "grok-4-1-fast-reasoning",
    "Recon Worker":        "gpt-5.4-mini",
    "Attack Hypothesis":   "grok-4-1-fast-reasoning",
    "Assumption Worker":   "grok-4-1-fast-reasoning",
    "Semantic Discovery":  "gpt-5.4-mini",
    "Execution Trace":     "gpt-5.4-mini",
    "Test Writer":         "grok-code-fast-1",
    "Gate Filter":         "gpt-5.4-mini",
    "Depth Workers":       "gpt-5.4-mini",
    "Default Worker":      "gpt-5.4-mini",
    "Jury — Skeptic":      "gpt-4.1-mini-2025-04-14",
    "Jury — Attacker":     "grok-4-1-fast-non-reasoning",
    "Jury — Auditor":      "gpt-4.1-mini-2025-04-14",
    "Jury — Judge":        "grok-4-1-fast-non-reasoning",
}


# ── Public API ───────────────────────────────────────────────────────

def get_available_providers() -> list[str]:
    """Return list of provider IDs that have at least one API key set."""
    available = []
    for provider, keys in PROVIDER_ENV_KEYS.items():
        for key in keys:
            val = os.getenv(key, "").strip()
            if val:
                available.append(provider)
                break
    return available


def get_models_for_provider(provider: str) -> list[ModelInfo]:
    """Return known models for a provider."""
    return PROVIDER_MODELS.get(provider, [])


def get_all_known_model_ids() -> set[str]:
    """Return all model IDs across all providers."""
    ids = set()
    for models in PROVIDER_MODELS.values():
        for m in models:
            ids.add(m.id)
    return ids


def get_current_config() -> dict[str, str]:
    """
    Return current model assignment for every agent role.
    Reads from env vars (which may have been overridden at runtime).
    """
    config = {}
    for role, env_var in AGENT_ROLES.items():
        config[role] = os.getenv(env_var, ROLE_DEFAULTS.get(role, "—"))
    return config


def apply_model_config(role: str, model_id: str) -> None:
    """
    Set the model for a given role at runtime.

    Updates os.environ so that workers and the agent loop pick up the
    change on their next instantiation. Does NOT write to .env.
    """
    env_var = AGENT_ROLES.get(role)
    if not env_var:
        raise ValueError(f"Unknown role: {role}")
    os.environ[env_var] = model_id


def find_model_info(model_id: str) -> ModelInfo | None:
    """Look up a ModelInfo by its id string. Returns None if not in catalog."""
    for models in PROVIDER_MODELS.values():
        for m in models:
            if m.id == model_id:
                return m
    return None
