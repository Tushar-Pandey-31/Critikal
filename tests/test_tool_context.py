"""
Tests for src/agent/context.py — ToolContext shared execution state.
"""

import os
import tempfile

from src.agent.context import ToolContext


class TestToolContextInit:

    def test_default_construction(self):
        ctx = ToolContext()
        assert ctx.session_id  # auto-generated
        assert ctx.findings == []
        assert ctx.worker_outputs == []
        assert ctx.graph is None
        assert ctx.repo_path is None
        assert ctx.permission_mode == "ask"

    def test_custom_construction(self):
        ctx = ToolContext(
            engagement_id="abc123",
            permission_mode="yolo",
        )
        assert ctx.engagement_id == "abc123"
        assert ctx.permission_mode == "yolo"

    def test_session_id_is_unique(self):
        ctx1 = ToolContext()
        ctx2 = ToolContext()
        assert ctx1.session_id != ctx2.session_id


class TestHasGraph:

    def test_no_graph_returns_false(self):
        ctx = ToolContext()
        assert ctx.has_graph() is False

    def test_empty_graph_returns_false(self):
        import networkx as nx
        ctx = ToolContext()
        ctx.graph = nx.DiGraph()
        assert ctx.has_graph() is False  # Empty graph = no nodes

    def test_populated_graph_returns_true(self):
        import networkx as nx
        ctx = ToolContext()
        ctx.graph = nx.DiGraph()
        ctx.graph.add_node("Contract::transfer")
        assert ctx.has_graph() is True


class TestAddFinding:

    def test_add_finding_appends(self):
        ctx = ToolContext()
        ctx.add_finding({"vuln": "reentrancy", "confidence": 80})
        assert len(ctx.findings) == 1
        assert ctx.findings[0]["vuln"] == "reentrancy"

    def test_add_multiple_findings(self):
        ctx = ToolContext()
        ctx.add_finding({"id": 1})
        ctx.add_finding({"id": 2})
        ctx.add_finding({"id": 3})
        assert len(ctx.findings) == 3

    def test_add_finding_with_event_bus(self):
        """add_finding should not raise even with an event bus attached."""
        from src.agent.events import EventBus
        ctx = ToolContext()
        ctx.event_bus = EventBus()
        ctx.add_finding({"vuln": "test"})
        assert len(ctx.findings) == 1


class TestFileReadWrite:

    def test_register_and_check_read(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".sol", delete=False) as f:
            f.write("// SPDX-License-Identifier: MIT\n")
            path = f.name

        try:
            ctx = ToolContext()
            ctx.register_file_read(path, "// SPDX-License-Identifier: MIT\n")
            allowed, reason = ctx.check_file_write_allowed(path)
            assert allowed, f"Expected allowed but got: {reason}"
        finally:
            os.unlink(path)

    def test_write_blocked_without_read(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".sol", delete=False) as f:
            f.write("// existing file\n")
            path = f.name

        try:
            ctx = ToolContext()
            allowed, reason = ctx.check_file_write_allowed(path)
            assert not allowed
            assert "not been read" in reason
        finally:
            os.unlink(path)

    def test_new_file_always_allowed(self):
        ctx = ToolContext()
        allowed, reason = ctx.check_file_write_allowed("/tmp/brand_new_file_xyz_123.sol")
        assert allowed
        assert "new file" in reason

    def test_stale_write_blocked_after_external_modification(self):
        """If file changes after read, write should be blocked."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".sol", delete=False) as f:
            f.write("original content\n")
            path = f.name

        try:
            ctx = ToolContext()
            # Register read with a very old mtime
            ctx.register_file_read(path, "original content\n", mtime=0.0)
            allowed, reason = ctx.check_file_write_allowed(path)
            assert not allowed
            assert "modified since last read" in reason
        finally:
            os.unlink(path)

    def test_record_file_access(self):
        ctx = ToolContext()
        ctx.record_file_access("/tmp/contract.sol", "read")
        ctx.record_file_access("/tmp/contract.sol", "write")
        assert len(ctx.file_history) == 2
        assert ctx.file_history[0] == ("/tmp/contract.sol", "read")
        assert ctx.file_history[1] == ("/tmp/contract.sol", "write")


class TestEnsureConfig:

    def test_lazy_config_load(self):
        ctx = ToolContext()
        assert ctx.config is None
        ctx.ensure_config()
        assert ctx.config is not None

    def test_config_not_reloaded(self):
        ctx = ToolContext()
        ctx.ensure_config()
        first_config = ctx.config
        ctx.ensure_config()
        assert ctx.config is first_config  # Same object, not reloaded
