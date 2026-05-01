"""
Tests for src/agent/query_loop.py — the agentic reasoning loop.

These tests use mock LLMs and tools to avoid real API calls.
"""

import asyncio
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from src.agent.query_loop import QueryLoop, _summarize_args, TOOL_RESULT_BUDGET_CHARS
from src.agent.context import ToolContext
from src.agent.tool import Tool, ToolResult, PermissionLevel
from src.agent.events import EventBus, EventType


# ── Test doubles ──

class EchoTool(Tool):
    """Echoes input back — no LLM required."""

    def name(self) -> str:
        return "echo"

    def description(self) -> str:
        return "Echoes the input back"

    def permission_level(self) -> PermissionLevel:
        return PermissionLevel.NONE

    def input_schema(self) -> dict:
        return {
            "type": "object",
            "properties": {"text": {"type": "string"}},
        }

    async def execute(self, params: dict, ctx: ToolContext) -> ToolResult:
        return ToolResult.success(f"echo: {params.get('text', '')}")


class FailingTool(Tool):
    """Always raises an exception."""

    def name(self) -> str:
        return "fail"

    def description(self) -> str:
        return "Always fails"

    def permission_level(self) -> PermissionLevel:
        return PermissionLevel.NONE

    def input_schema(self) -> dict:
        return {"type": "object", "properties": {}}

    async def execute(self, params: dict, ctx: ToolContext) -> ToolResult:
        raise RuntimeError("Tool deliberately exploded")


def _make_ai_response(text: str = "done", tool_calls=None):
    """Create a fake LangChain AIMessage-like object."""
    msg = MagicMock()
    msg.content = text
    msg.tool_calls = tool_calls or []
    msg.usage_metadata = None
    return msg


def _make_tool_call_response(tool_name: str, args: dict, call_id: str = "call_1"):
    """Create a fake LangChain response that requests a tool call."""
    tc = {"id": call_id, "name": tool_name, "args": args}
    msg = MagicMock()
    msg.content = ""
    msg.tool_calls = [tc]
    msg.usage_metadata = None
    return msg


# ── _summarize_args tests ──

class TestSummarizeArgs:

    def test_empty_args(self):
        assert _summarize_args({}) == ""

    def test_short_args(self):
        result = _summarize_args({"repo": "https://github.com/x/y"})
        assert "repo" in result
        assert "https://github.com/x/y" in result

    def test_long_value_truncated(self):
        long_val = "a" * 200
        result = _summarize_args({"data": long_val})
        assert len(result) < 100
        assert "..." in result

    def test_multiple_args(self):
        result = _summarize_args({"a": "1", "b": "2"})
        assert "a=1" in result
        assert "b=2" in result


# ── Tool result budget tests ──

class TestToolResultBudget:

    def _make_loop(self) -> QueryLoop:
        ctx = ToolContext(permission_mode="yolo")
        return QueryLoop(tools=[], ctx=ctx, model="claude-sonnet-4-6")

    def test_short_result_unchanged(self):
        loop = self._make_loop()
        results = [{"tool_call_id": "c1", "content": "short output"}]
        budgeted = loop._apply_tool_result_budget(results)
        assert budgeted[0]["content"] == "short output"

    def test_oversized_result_truncated(self):
        loop = self._make_loop()
        big_content = "x" * (TOOL_RESULT_BUDGET_CHARS + 10_000)
        results = [{"tool_call_id": "c1", "content": big_content}]
        budgeted = loop._apply_tool_result_budget(results)
        content = budgeted[0]["content"]
        assert len(content) < len(big_content)
        assert "truncated" in content

    def test_multiple_results_each_budgeted(self):
        loop = self._make_loop()
        big = "y" * (TOOL_RESULT_BUDGET_CHARS + 1000)
        results = [
            {"tool_call_id": "c1", "content": big},
            {"tool_call_id": "c2", "content": "small"},
        ]
        budgeted = loop._apply_tool_result_budget(results)
        assert "truncated" in budgeted[0]["content"]
        assert budgeted[1]["content"] == "small"


# ── _parse_response tests ──

class TestParseResponse:

    def _make_loop(self) -> QueryLoop:
        ctx = ToolContext(permission_mode="yolo")
        return QueryLoop(tools=[], ctx=ctx)

    def test_parse_text_only_response(self):
        loop = self._make_loop()
        msg = _make_ai_response("Hello world")
        text, tool_calls = loop._parse_response(msg)
        assert text == "Hello world"
        assert tool_calls == []

    def test_parse_tool_call_response(self):
        loop = self._make_loop()
        msg = _make_tool_call_response("echo", {"text": "hi"}, call_id="call_abc")
        text, tool_calls = loop._parse_response(msg)
        assert len(tool_calls) == 1
        assert tool_calls[0]["name"] == "echo"
        assert tool_calls[0]["args"] == {"text": "hi"}
        assert tool_calls[0]["id"] == "call_abc"

    def test_parse_list_content(self):
        loop = self._make_loop()
        msg = MagicMock()
        msg.content = [{"type": "text", "text": "part 1"}, {"type": "text", "text": "part 2"}]
        msg.tool_calls = []
        text, _ = loop._parse_response(msg)
        assert "part 1" in text
        assert "part 2" in text

    def test_parse_empty_response(self):
        loop = self._make_loop()
        msg = MagicMock()
        msg.content = ""
        msg.tool_calls = []
        text, tool_calls = loop._parse_response(msg)
        assert text == ""
        assert tool_calls == []


# ── get_conversation_stats tests ──

class TestConversationStats:

    def test_initial_stats(self):
        ctx = ToolContext(permission_mode="yolo")
        loop = QueryLoop(tools=[], ctx=ctx, model="claude-sonnet-4-6")
        stats = loop.get_conversation_stats()
        assert stats["messages"] == 0
        assert stats["model"] == "claude-sonnet-4-6"
        assert stats["findings"] == 0
        assert stats["recovery"]["using_fallback"] is False

    def test_stats_reflect_findings(self):
        ctx = ToolContext(permission_mode="yolo")
        ctx.add_finding({"vuln": "reentrancy"})
        ctx.add_finding({"vuln": "overflow"})
        loop = QueryLoop(tools=[], ctx=ctx)
        stats = loop.get_conversation_stats()
        assert stats["findings"] == 2


# ── Tool execution tests ──

class TestToolExecution:

    @pytest.mark.asyncio
    async def test_execute_known_tool(self):
        ctx = ToolContext(permission_mode="yolo")
        loop = QueryLoop(tools=[EchoTool()], ctx=ctx)

        tool_calls = [{"id": "c1", "name": "echo", "args": {"text": "hello"}}]
        results = await loop._execute_tool_calls(tool_calls)

        assert len(results) == 1
        assert "echo: hello" in results[0]["content"]
        assert results[0]["tool_call_id"] == "c1"

    @pytest.mark.asyncio
    async def test_execute_unknown_tool(self):
        ctx = ToolContext(permission_mode="yolo")
        loop = QueryLoop(tools=[], ctx=ctx)

        tool_calls = [{"id": "c1", "name": "nonexistent", "args": {}}]
        results = await loop._execute_tool_calls(tool_calls)

        assert "unknown tool" in results[0]["content"].lower()

    @pytest.mark.asyncio
    async def test_execute_failing_tool_returns_error(self):
        ctx = ToolContext(permission_mode="yolo")
        loop = QueryLoop(tools=[FailingTool()], ctx=ctx)

        tool_calls = [{"id": "c1", "name": "fail", "args": {}}]
        results = await loop._execute_tool_calls(tool_calls)

        assert "[ERROR]" in results[0]["content"]

    @pytest.mark.asyncio
    async def test_permission_denied_in_ask_mode(self):
        """In 'ask' mode, a DANGEROUS tool with no callback should be denied."""
        from src.agent.tool import PermissionLevel

        class DangerousTool(Tool):
            def name(self): return "danger"
            def description(self): return "dangerous"
            def permission_level(self): return PermissionLevel.DANGEROUS
            def input_schema(self): return {"type": "object", "properties": {}}
            async def execute(self, p, c): return ToolResult.success("done")

        ctx = ToolContext(permission_mode="ask")
        loop = QueryLoop(tools=[DangerousTool()], ctx=ctx)

        tool_calls = [{"id": "c1", "name": "danger", "args": {}}]
        results = await loop._execute_tool_calls(tool_calls)
        # With no callback, permission should be denied
        assert "denied" in results[0]["content"].lower()


# ── Full agentic run with mocked LLM ──

class TestQueryLoopRun:

    @pytest.mark.asyncio
    async def test_run_returns_text_on_end_turn(self):
        """Agent returns immediately when LLM produces no tool calls."""
        ctx = ToolContext(permission_mode="yolo")
        loop = QueryLoop(tools=[], ctx=ctx, model="claude-sonnet-4-6")

        # Mock the LLM call to immediately return a text response
        with patch.object(loop, "_call_llm_with_recovery", new_callable=AsyncMock) as mock_llm:
            mock_llm.return_value = _make_ai_response("Analysis complete. No vulnerabilities found.")
            result = await loop.run("Audit this contract")

        assert "Analysis complete" in result

    @pytest.mark.asyncio
    async def test_run_executes_one_tool_then_ends(self):
        """Agent calls a tool, gets result, then ends."""
        ctx = ToolContext(permission_mode="yolo")
        loop = QueryLoop(tools=[EchoTool()], ctx=ctx)

        # Turn 1: call tool. Turn 2: return text.
        responses = [
            _make_tool_call_response("echo", {"text": "test_input"}),
            _make_ai_response("Tool returned. Done."),
        ]

        call_count = 0

        async def fake_llm():
            nonlocal call_count
            resp = responses[min(call_count, len(responses) - 1)]
            call_count += 1
            return resp

        with patch.object(loop, "_call_llm_with_recovery", side_effect=fake_llm):
            result = await loop.run("Use the echo tool")

        assert "Done" in result
        assert call_count == 2

    @pytest.mark.asyncio
    async def test_run_reaches_max_turns(self):
        """Agent stops at max_turns even if LLM keeps requesting tools."""
        ctx = ToolContext(permission_mode="yolo")
        loop = QueryLoop(tools=[EchoTool()], ctx=ctx, max_turns=3)

        # Always respond with a tool call so loop never ends naturally
        with patch.object(loop, "_call_llm_with_recovery", new_callable=AsyncMock) as mock_llm:
            mock_llm.return_value = _make_tool_call_response("echo", {"text": "loop"})
            result = await loop.run("Keep going forever")

        assert "Max turns" in result

    @pytest.mark.asyncio
    async def test_run_budget_exceeded(self):
        """Agent stops when budget is exceeded."""
        from src.agent.cost import CostTracker

        ctx = ToolContext(permission_mode="yolo")
        ctx.cost_tracker = CostTracker(budget_usd=0.0)  # Zero budget
        loop = QueryLoop(tools=[EchoTool()], ctx=ctx)

        responses = [
            _make_tool_call_response("echo", {"text": "x"}),
            _make_ai_response("Done"),
        ]
        idx = 0

        async def fake_llm():
            nonlocal idx
            r = responses[min(idx, len(responses) - 1)]
            idx += 1
            # Simulate spending money on first call
            ctx.cost_tracker.session_cost = 99.99
            return r

        with patch.object(loop, "_call_llm_with_recovery", side_effect=fake_llm):
            result = await loop.run("Do something")

        assert "Budget exceeded" in result
