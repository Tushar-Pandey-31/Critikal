"""
Pipeline Configuration — single source of truth for all stage flags.

Every pipeline stage is flag-gated. AUDIT_MODE sets a preset; individual
flags always override the preset.

Environment variables:
    AUDIT_MODE            fast | standard | deep | semantic_only
    SLITHER_ENABLED       true/false
    SEMANTIC_DISCOVERY_ENABLED  true/false
    ASSUMPTION_WORKER_ENABLED   true/false
    DEPTH_WORKERS_ENABLED       true/false
    JURY_ENABLED                true/false
    GATE_ENABLED                true/false
    TESTWRITER_ENABLED          true/false
    FUZZ_GENERATOR_ENABLED      true/false
    RAG_ENABLED                 true/false
    CHAIN_ANALYSIS_ENABLED      true/false
    ETHERSCAN_ENABLED           true/false

    ─── Smart filtering (evidence accumulation architecture)
    PROMOTE_THRESHOLD           int  (default 50) — plausibility_score needed to reach TestWriter
    ATTACK_CONFIDENCE_FLOOR     int  (default 50) — attack worker min confidence for normal Finding
    ATTACK_SPECULATIVE_FLOOR    int  (default 30) — lower floor for SPECULATIVE Finding tier
    DEPTH_ON_REJECTED           true/false (default false) — run depth on jury-rejected findings
    SEMANTIC_FALLBACK_N         int  (default 3)  — max semantic findings to force-promote when attack workers find nothing
    SEMANTIC_FALLBACK_THRESHOLD int  (default 55) — min confidence for semantic synthetic fallback

    ─── LLM providers (OpenRouter — optional, not a hard dependency)
    OPENROUTER_API_KEY          str  — single key, used when WORKER_MODEL_NAME uses provider/model format
    OPENROUTER_API_KEYS         str  — comma-separated list for key rotation
    # Usage: set WORKER_MODEL_NAME=anthropic/claude-3.5-sonnet to route through OpenRouter
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field


def _env_bool(key: str, default: bool) -> bool:
    """Read a boolean from env. Accepts true/false/1/0/yes/no (case-insensitive)."""
    val = os.getenv(key)
    if val is None:
        return default
    return val.strip().lower() in ("true", "1", "yes")


# ── Mode Presets ─────────────────────────────────────────────────────

_MODE_PRESETS: dict[str, dict[str, bool]] = {
    "fast": {
        "slither_enabled": True,
        "semantic_discovery_enabled": False,
        "assumption_worker_enabled": False,
        "depth_workers_enabled": False,
        "jury_enabled": False,
        "gate_enabled": False,
        "testwriter_enabled": False,
        "fuzz_generator_enabled": False,
        "rag_enabled": False,
        "chain_analysis_enabled": False,
        "etherscan_enabled": False,
        "threat_profiler_enabled": False,
        "attack_vector_db_enabled": False,
    },
    "standard": {
        "slither_enabled": True,
        "semantic_discovery_enabled": False,
        "assumption_worker_enabled": True,
        "depth_workers_enabled": True,
        "jury_enabled": False,
        "gate_enabled": True,
        "testwriter_enabled": True,
        "fuzz_generator_enabled": False,
        "rag_enabled": True,
        "chain_analysis_enabled": True,
        "etherscan_enabled": True,
        "threat_profiler_enabled": True,
        "attack_vector_db_enabled": True,
    },
    "deep": {
        "slither_enabled": True,
        "semantic_discovery_enabled": True,
        "assumption_worker_enabled": True,
        "depth_workers_enabled": True,
        "jury_enabled": True,
        "gate_enabled": True,
        "testwriter_enabled": True,
        "fuzz_generator_enabled": True,
        "rag_enabled": True,
        "chain_analysis_enabled": True,
        "etherscan_enabled": True,
        "threat_profiler_enabled": True,
        "attack_vector_db_enabled": True,
    },
    "semantic_only": {
        "slither_enabled": False,
        "semantic_discovery_enabled": True,
        "assumption_worker_enabled": False,
        "depth_workers_enabled": True,
        "jury_enabled": True,
        "gate_enabled": True,
        "testwriter_enabled": True,
        "fuzz_generator_enabled": False,
        "rag_enabled": True,
        "chain_analysis_enabled": True,
        "etherscan_enabled": False,
        "threat_profiler_enabled": True,
        "attack_vector_db_enabled": True,
    },
}

# Mapping from dataclass field name → env var name
_FIELD_TO_ENV: dict[str, str] = {
    "slither_enabled": "SLITHER_ENABLED",
    "semantic_discovery_enabled": "SEMANTIC_DISCOVERY_ENABLED",
    "assumption_worker_enabled": "ASSUMPTION_WORKER_ENABLED",
    "depth_workers_enabled": "DEPTH_WORKERS_ENABLED",
    "jury_enabled": "JURY_ENABLED",
    "gate_enabled": "GATE_ENABLED",
    "testwriter_enabled": "TESTWRITER_ENABLED",
    "fuzz_generator_enabled": "FUZZ_GENERATOR_ENABLED",
    "rag_enabled": "RAG_ENABLED",
    "chain_analysis_enabled": "CHAIN_ANALYSIS_ENABLED",
    "etherscan_enabled": "ETHERSCAN_ENABLED",
    "threat_profiler_enabled": "THREAT_PROFILER_ENABLED",
    "attack_vector_db_enabled": "ATTACK_VECTOR_DB_ENABLED",
}


@dataclass
class PipelineConfig:
    """
    Immutable configuration for the Critikal pipeline.
    Created once at startup via `PipelineConfig.from_env()`.
    """

    slither_enabled: bool = True
    semantic_discovery_enabled: bool = False
    assumption_worker_enabled: bool = True
    depth_workers_enabled: bool = True
    jury_enabled: bool = False
    gate_enabled: bool = True
    testwriter_enabled: bool = True
    fuzz_generator_enabled: bool = False
    rag_enabled: bool = True
    chain_analysis_enabled: bool = True
    etherscan_enabled: bool = True
    threat_profiler_enabled: bool = True
    attack_vector_db_enabled: bool = True

    audit_mode: str = "standard"

    @classmethod
    def from_env(cls) -> PipelineConfig:
        """
        Build config from environment. Steps:
        1. Read AUDIT_MODE → apply preset defaults.
        2. Read individual flags → override preset where set.
        """
        mode = os.getenv("AUDIT_MODE", "standard").strip().lower()
        if mode not in _MODE_PRESETS:
            print(f"[Config] Unknown AUDIT_MODE '{mode}', falling back to 'standard'")
            mode = "standard"

        preset = _MODE_PRESETS[mode]
        overrides: dict[str, bool] = {}

        for field_name, env_key in _FIELD_TO_ENV.items():
            env_val = os.getenv(env_key)
            if env_val is not None:
                overrides[field_name] = env_val.strip().lower() in ("true", "1", "yes")

        # Merge: preset as base, overrides on top
        merged = {**preset, **overrides}
        config = cls(**merged, audit_mode=mode)
        config.print_summary()
        return config

    def print_summary(self) -> None:
        """Print a startup summary of enabled/disabled stages."""
        lines = [
            "",
            "╔══════════════════════════════════════════════════════╗",
            f"║  CRITIKAL Pipeline Config — mode: {self.audit_mode:<18s}║",
            "╠══════════════════════════════════════════════════════╣",
        ]
        for field_name, env_key in _FIELD_TO_ENV.items():
            enabled = getattr(self, field_name)
            icon = "✅" if enabled else "❌"
            label = field_name.replace("_", " ").replace("enabled", "").strip().title()
            lines.append(f"║  {icon}  {label:<44s}  ║")
        lines.append("╚══════════════════════════════════════════════════════╝")
        lines.append("")
        print("\n".join(lines))


# ── Module-level singleton ───────────────────────────────────────────

_config: PipelineConfig | None = None


def get_config() -> PipelineConfig:
    """Return the cached pipeline config (lazy-init from env on first call)."""
    global _config
    if _config is None:
        _config = PipelineConfig.from_env()
    return _config


def set_config(config: PipelineConfig) -> None:
    """Override the config (for testing)."""
    global _config
    _config = config
