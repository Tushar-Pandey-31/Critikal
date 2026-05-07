"""
Tests for src/agent/permissions.py — PermissionHandler.
"""

from unittest.mock import AsyncMock

import pytest

from src.agent.context import ToolContext
from src.agent.permissions import PermissionHandler
from src.agent.tool import PermissionLevel, Tool, ToolResult


def _make_tool(level: PermissionLevel) -> Tool:
    """Create a minimal tool with the given permission level."""
    class T(Tool):
        def name(self): return f"tool_{level.value}"
        def description(self): return f"Tool with {level.value} permission"
        def permission_level(self): return level
        def input_schema(self): return {"type": "object", "properties": {}}
        async def execute(self, p, c): return ToolResult.success("ok")
    return T()


class TestAutoApproveMatrix:

    @pytest.mark.asyncio
    async def test_yolo_approves_everything(self):
        handler = PermissionHandler()
        ctx = ToolContext(permission_mode="yolo")

        for level in PermissionLevel:
            tool = _make_tool(level)
            result = await handler.check(tool, {}, ctx)
            assert result is True, f"yolo mode should approve {level}"

    @pytest.mark.asyncio
    async def test_auto_approves_up_to_execute(self):
        handler = PermissionHandler()
        ctx = ToolContext(permission_mode="auto")

        approved_levels = [
            PermissionLevel.NONE,
            PermissionLevel.READ_ONLY,
            PermissionLevel.WRITE,
            PermissionLevel.EXECUTE,
        ]
        for level in approved_levels:
            tool = _make_tool(level)
            result = await handler.check(tool, {}, ctx)
            assert result is True, f"auto mode should approve {level}"

    @pytest.mark.asyncio
    async def test_auto_denies_dangerous_without_callback(self):
        handler = PermissionHandler()  # No callback
        ctx = ToolContext(permission_mode="auto")
        tool = _make_tool(PermissionLevel.DANGEROUS)
        result = await handler.check(tool, {}, ctx)
        assert result is False

    @pytest.mark.asyncio
    async def test_ask_approves_none_and_readonly(self):
        handler = PermissionHandler()
        ctx = ToolContext(permission_mode="ask")

        for level in [PermissionLevel.NONE, PermissionLevel.READ_ONLY]:
            tool = _make_tool(level)
            result = await handler.check(tool, {}, ctx)
            assert result is True, f"ask mode should approve {level}"

    @pytest.mark.asyncio
    async def test_ask_denies_write_without_callback(self):
        handler = PermissionHandler()
        ctx = ToolContext(permission_mode="ask")
        tool = _make_tool(PermissionLevel.WRITE)
        result = await handler.check(tool, {}, ctx)
        assert result is False


class TestPromptCallback:

    @pytest.mark.asyncio
    async def test_callback_called_when_approval_needed(self):
        callback = AsyncMock(return_value=True)
        handler = PermissionHandler(prompt_callback=callback)
        ctx = ToolContext(permission_mode="ask")
        tool = _make_tool(PermissionLevel.EXECUTE)

        result = await handler.check(tool, {"param": "value"}, ctx)

        assert result is True
        callback.assert_called_once()
        call_args = callback.call_args[0]
        assert call_args[0] == f"tool_{PermissionLevel.EXECUTE.value}"  # tool name

    @pytest.mark.asyncio
    async def test_callback_denial_propagated(self):
        callback = AsyncMock(return_value=False)
        handler = PermissionHandler(prompt_callback=callback)
        ctx = ToolContext(permission_mode="ask")
        tool = _make_tool(PermissionLevel.EXECUTE)

        result = await handler.check(tool, {}, ctx)
        assert result is False

    @pytest.mark.asyncio
    async def test_callback_exception_returns_false(self):
        async def crashing_callback(*_):
            raise RuntimeError("callback error")

        handler = PermissionHandler(prompt_callback=crashing_callback)
        ctx = ToolContext(permission_mode="ask")
        tool = _make_tool(PermissionLevel.WRITE)

        result = await handler.check(tool, {}, ctx)
        assert result is False


class TestSessionApprovals:

    @pytest.mark.asyncio
    async def test_session_approval_bypasses_mode(self):
        handler = PermissionHandler()  # No callback
        handler.approve_for_session("tool_dangerous")
        ctx = ToolContext(permission_mode="ask")
        tool = _make_tool(PermissionLevel.DANGEROUS)

        result = await handler.check(tool, {}, ctx)
        assert result is True

    @pytest.mark.asyncio
    async def test_revoke_session_approval(self):
        handler = PermissionHandler()
        handler.approve_for_session("tool_write")
        handler.revoke_session_approval("tool_write")
        ctx = ToolContext(permission_mode="ask")
        tool = _make_tool(PermissionLevel.WRITE)

        result = await handler.check(tool, {}, ctx)
        assert result is False
