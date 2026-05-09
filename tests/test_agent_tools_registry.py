"""
Tests for src/agent/tools/__init__.py — tool registry.

Verifies all tools load without import errors, implement the Tool ABC
correctly, have unique names, valid JSON schemas, and proper permission
levels.
"""

from src.agent.tool import PermissionLevel, Tool
from src.agent.tools import get_agent_tools, get_all_tools, get_generic_tools, get_pipeline_tools


class TestToolRegistry:
    def test_get_all_tools_returns_list(self):
        tools = get_all_tools()
        assert isinstance(tools, list)
        assert len(tools) > 0

    def test_all_tools_are_tool_instances(self):
        tools = get_all_tools()
        for tool in tools:
            assert isinstance(tool, Tool), f"{tool} is not a Tool instance"

    def test_tool_names_are_unique(self):
        tools = get_all_tools()
        names = [t.name() for t in tools]
        assert len(names) == len(set(names)), f"Duplicate tool names: {[n for n in names if names.count(n) > 1]}"

    def test_tool_names_are_non_empty_strings(self):
        for tool in get_all_tools():
            name = tool.name()
            assert isinstance(name, str), f"Tool name must be str, got {type(name)}"
            assert len(name) > 0, "Tool name must not be empty"
            assert " " not in name, f"Tool name '{name}' must not contain spaces"

    def test_tool_descriptions_are_non_empty(self):
        for tool in get_all_tools():
            desc = tool.description()
            assert isinstance(desc, str), f"{tool.name()}: description must be str"
            assert len(desc) > 10, f"{tool.name()}: description too short: '{desc}'"

    def test_all_tools_have_valid_permission_levels(self):
        valid_levels = set(PermissionLevel)
        for tool in get_all_tools():
            level = tool.permission_level()
            assert level in valid_levels, f"{tool.name()}: invalid permission level {level}"

    def test_all_tools_have_valid_json_schema(self):
        for tool in get_all_tools():
            schema = tool.input_schema()
            assert isinstance(schema, dict), f"{tool.name()}: schema must be dict"
            assert "type" in schema, f"{tool.name()}: schema missing 'type'"
            assert schema["type"] == "object", f"{tool.name()}: schema type must be 'object', got '{schema['type']}'"

    def test_to_llm_schema_format(self):
        for tool in get_all_tools():
            llm_schema = tool.to_llm_schema()
            assert llm_schema["type"] == "function"
            assert "function" in llm_schema
            fn = llm_schema["function"]
            assert "name" in fn
            assert "description" in fn
            assert "parameters" in fn

    def test_pipeline_tools_loaded(self):
        tools = get_pipeline_tools()
        names = [t.name() for t in tools]
        assert "ingest_repo" in names
        assert "run_recon" in names
        assert "find_hotspots" in names
        assert "write_exploit_test" in names
        assert "generate_report" in names

    def test_generic_tools_loaded(self):
        tools = get_generic_tools()
        names = [t.name() for t in tools]
        assert "bash" in names
        assert "file_read" in names
        assert "grep" in names
        assert "glob" in names

    def test_agent_tools_loaded(self):
        tools = get_agent_tools()
        assert len(tools) > 0


class TestToolAvailability:
    def test_tools_available_by_default_in_empty_context(self):
        """Most tools should be available even before any analysis."""
        from src.agent.context import ToolContext

        ctx = ToolContext()
        all_tools = get_all_tools()

        # Generic tools and pipeline initiators should always be available
        always_available = {"bash", "file_read", "grep", "glob", "ingest_repo"}
        available_names = {t.name() for t in all_tools if t.is_available(ctx)}

        for name in always_available:
            assert name in available_names, f"'{name}' should be available in empty context"

    def test_graph_tools_unavailable_without_graph(self):
        """Graph query tools require a loaded graph."""
        from src.agent.context import ToolContext

        ctx = ToolContext()
        graph_tools = {"get_function_context", "find_state_mutators", "get_modifiers"}

        for tool in get_all_tools():
            if tool.name() in graph_tools:
                assert not tool.is_available(ctx), f"'{tool.name()}' should NOT be available without a graph"

    def test_graph_tools_available_with_graph(self):
        """Graph query tools become available once graph is loaded."""
        import networkx as nx

        from src.agent.context import ToolContext

        ctx = ToolContext()
        ctx.graph = nx.DiGraph()
        ctx.graph.add_node("Contract::func")
        graph_tools = {"get_function_context", "find_state_mutators", "get_modifiers"}

        for tool in get_all_tools():
            if tool.name() in graph_tools:
                assert tool.is_available(ctx), f"'{tool.name()}' should be available with a loaded graph"
