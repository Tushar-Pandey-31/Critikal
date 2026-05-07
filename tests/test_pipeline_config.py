"""
Tests for PipelineConfig.
"""
import os
from unittest.mock import patch


class TestPipelineConfig:
    """Tests for PipelineConfig dataclass and from_env()."""

    def _fresh_config(self, env_overrides: dict):
        """Create a fresh config with specified env vars, clearing singleton cache."""
        import src.pipeline_config as pc
        pc._config = None  # reset singleton
        with patch.dict(os.environ, env_overrides, clear=False):
            # Remove any leftover env vars from previous tests
            for key in list(os.environ.keys()):
                if key.startswith(("SLITHER_ENABLED", "SEMANTIC_DISCOVERY_ENABLED",
                                   "ASSUMPTION_WORKER_ENABLED", "DEPTH_WORKERS_ENABLED",
                                   "JURY_ENABLED", "GATE_ENABLED", "TESTWRITER_ENABLED",
                                   "FUZZ_GENERATOR_ENABLED", "RAG_ENABLED",
                                   "CHAIN_ANALYSIS_ENABLED", "ETHERSCAN_ENABLED",
                                   "AUDIT_MODE")) and key not in env_overrides:
                    os.environ.pop(key, None)
            return pc.PipelineConfig.from_env()

    def test_default_is_standard(self):
        config = self._fresh_config({})
        assert config.audit_mode == "standard"
        assert config.slither_enabled is True
        assert config.semantic_discovery_enabled is False
        assert config.jury_enabled is False
        assert config.testwriter_enabled is True

    def test_fast_mode(self):
        config = self._fresh_config({"AUDIT_MODE": "fast"})
        assert config.audit_mode == "fast"
        assert config.slither_enabled is True
        assert config.jury_enabled is False
        assert config.testwriter_enabled is False
        assert config.depth_workers_enabled is False
        assert config.assumption_worker_enabled is False
        assert config.rag_enabled is False

    def test_deep_mode(self):
        config = self._fresh_config({"AUDIT_MODE": "deep"})
        assert config.audit_mode == "deep"
        assert config.slither_enabled is True
        assert config.semantic_discovery_enabled is True
        assert config.jury_enabled is True
        assert config.fuzz_generator_enabled is True
        assert config.depth_workers_enabled is True

    def test_semantic_only_mode(self):
        config = self._fresh_config({"AUDIT_MODE": "semantic_only"})
        assert config.audit_mode == "semantic_only"
        assert config.slither_enabled is False
        assert config.semantic_discovery_enabled is True
        assert config.jury_enabled is True
        assert config.testwriter_enabled is True

    def test_individual_override_beats_preset(self):
        """Individual env vars override the mode preset."""
        config = self._fresh_config({
            "AUDIT_MODE": "fast",
            "JURY_ENABLED": "true",
        })
        assert config.audit_mode == "fast"
        assert config.jury_enabled is True  # overridden from fast's default False
        assert config.testwriter_enabled is False  # fast default preserved

    def test_unknown_mode_falls_back_to_standard(self):
        config = self._fresh_config({"AUDIT_MODE": "nonexistent"})
        assert config.audit_mode == "standard"
        assert config.slither_enabled is True

    def test_env_bool_accepts_variants(self):
        """Bool parsing accepts true/1/yes/True/TRUE."""
        for val in ("true", "True", "TRUE", "1", "yes", "YES"):
            config = self._fresh_config({"JURY_ENABLED": val})
            assert config.jury_enabled is True, f"Failed for '{val}'"

        for val in ("false", "False", "0", "no", "NO", ""):
            config = self._fresh_config({"JURY_ENABLED": val})
            assert config.jury_enabled is False, f"Failed for '{val}'"
