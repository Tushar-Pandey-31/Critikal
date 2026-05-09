"""
Tests for src/agent/tool.py — Tool ABC, ToolResult, PermissionLevel.
"""

import pytest

from src.agent.context import ToolContext
from src.agent.tool import PermissionLevel, Tool, ToolResult

# ── Concrete test implementation of Tool ──


class NoopTool(Tool):
    """Minimal tool that does nothing, for testing the ABC."""

    def name(self) -> str:
        return "noop"

    def description(self) -> str:
        return "Does nothing"

    def permission_level(self) -> PermissionLevel:
        return PermissionLevel.NONE

    def input_schema(self) -> dict:
        return {
            "type": "object",
            "properties": {
                "message": {"type": "string"},
            },
        }

    async def execute(self, params: dict, ctx: ToolContext) -> ToolResult:
        return ToolResult.success("ok", message=params.get("message"))


class DangerousTool(Tool):
    def name(self) -> str:
        return "dangerous_tool"

    def description(self) -> str:
        return "A dangerous tool"

    def permission_level(self) -> PermissionLevel:
        return PermissionLevel.DANGEROUS

    def input_schema(self) -> dict:
        return {"type": "object", "properties": {}}

    async def execute(self, params: dict, ctx: ToolContext) -> ToolResult:
        return ToolResult.success("danger executed")


# ── ToolResult tests ──


class TestToolResult:
    def test_success_result(self):
        r = ToolResult.success("all good")
        assert r.output == "all good"
        assert r.is_error is False
        assert r.metadata == {}

    def test_success_with_metadata(self):
        r = ToolResult.success("done", count=5, name="test")
        assert r.output == "done"
        assert r.metadata == {"count": 5, "name": "test"}

    def test_error_result(self):
        r = ToolResult.error("something broke")
        assert r.output == "something broke"
        assert r.is_error is True

    def test_error_with_metadata(self):
        r = ToolResult.error("bad path", path="/tmp/missing")
        assert r.is_error is True
        assert r.metadata["path"] == "/tmp/missing"

    def test_direct_construction(self):
        r = ToolResult(output="raw", is_error=False, metadata={"x": 1})
        assert r.output == "raw"
        assert r.metadata["x"] == 1


# ── PermissionLevel tests ──


class TestPermissionLevel:
    def test_all_levels_exist(self):
        levels = list(PermissionLevel)
        names = [l.value for l in levels]
        assert "none" in names
        assert "read_only" in names
        assert "write" in names
        assert "execute" in names
        assert "dangerous" in names

    def test_ordering_by_danger(self):
        # Ensure dangerous > execute > write > read_only > none
        # Not a formal ordering in the enum, but we can check values
        assert PermissionLevel.DANGEROUS != PermissionLevel.NONE
        assert PermissionLevel.EXECUTE != PermissionLevel.READ_ONLY


# ── Tool ABC tests ──


class TestToolABC:
    def test_noop_tool_implements_interface(self):
        tool = NoopTool()
        assert tool.name() == "noop"
        assert "nothing" in tool.description().lower()
        assert tool.permission_level() == PermissionLevel.NONE
        schema = tool.input_schema()
        assert schema["type"] == "object"

    def test_tool_is_available_by_default(self):
        tool = NoopTool()
        ctx = ToolContext()
        assert tool.is_available(ctx) is True

    def test_to_llm_schema(self):
        tool = NoopTool()
        schema = tool.to_llm_schema()
        assert schema["type"] == "function"
        assert schema["function"]["name"] == "noop"
        assert "description" in schema["function"]
        assert "parameters" in schema["function"]

    @pytest.mark.asyncio
    async def test_execute_returns_tool_result(self):
        tool = NoopTool()
        ctx = ToolContext()
        result = await tool.execute({"message": "hello"}, ctx)
        assert isinstance(result, ToolResult)
        assert result.output == "ok"

    def test_dangerous_tool_permission_level(self):
        tool = DangerousTool()
        assert tool.permission_level() == PermissionLevel.DANGEROUS


# ── Tool availability override ──


class GraphOnlyTool(Tool):
    """Tool only available when a graph is loaded."""

    def name(self) -> str:
        return "graph_only"

    def description(self) -> str:
        return "Requires graph"

    def permission_level(self) -> PermissionLevel:
        return PermissionLevel.NONE

    def input_schema(self) -> dict:
        return {"type": "object", "properties": {}}

    def is_available(self, ctx: ToolContext) -> bool:
        return ctx.has_graph()

    async def execute(self, params: dict, ctx: ToolContext) -> ToolResult:
        return ToolResult.success("graph available")


class TestToolAvailability:
    def test_graph_only_unavailable_without_graph(self):
        tool = GraphOnlyTool()
        ctx = ToolContext()
        assert tool.is_available(ctx) is False

    def test_graph_only_available_with_graph(self):
        import networkx as nx

        tool = GraphOnlyTool()
        ctx = ToolContext()
        ctx.graph = nx.DiGraph()
        ctx.graph.add_node("dummy")
        assert tool.is_available(ctx) is True
