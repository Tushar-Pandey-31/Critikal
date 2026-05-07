"""
Permission handler for tool execution.

Three modes:
  - ask:  prompt user for WRITE/EXECUTE/DANGEROUS; auto-approve NONE/READ_ONLY
  - auto: auto-approve NONE/READ_ONLY/WRITE/EXECUTE; prompt for DANGEROUS only
  - yolo: auto-approve everything (for headless/docker runs)
"""

import logging

from src.agent.context import ToolContext
from src.agent.tool import PermissionLevel, Tool

logger = logging.getLogger(__name__)

# Permission levels that each mode auto-approves
AUTO_APPROVE = {
    "ask": {PermissionLevel.NONE, PermissionLevel.READ_ONLY},
    "auto": {PermissionLevel.NONE, PermissionLevel.READ_ONLY,
             PermissionLevel.WRITE, PermissionLevel.EXECUTE},
    "yolo": {PermissionLevel.NONE, PermissionLevel.READ_ONLY,
             PermissionLevel.WRITE, PermissionLevel.EXECUTE,
             PermissionLevel.DANGEROUS},
}


class PermissionHandler:
    """
    Checks whether a tool invocation is allowed.

    In interactive mode (TUI), tools requiring approval will
    prompt the user via the event bus. In headless/yolo mode,
    everything is auto-approved.
    """

    def __init__(self, prompt_callback=None):
        """
        Args:
            prompt_callback: async callable(tool_name, params, level) -> bool
                Called when user approval is needed. If None, defaults to deny.
        """
        self._prompt_callback = prompt_callback
        self._session_approvals: set[str] = set()

    async def check(self, tool: Tool, params: dict, ctx: ToolContext) -> bool:
        """Returns True if the tool is allowed to execute."""
        level = tool.permission_level()
        mode = ctx.permission_mode

        approved = AUTO_APPROVE.get(mode, AUTO_APPROVE["ask"])
        if level in approved:
            return True

        # Check session-level approvals (user said "always allow X")
        if tool.name() in self._session_approvals:
            return True

        # Need user approval
        if self._prompt_callback:
            try:
                allowed = await self._prompt_callback(
                    tool.name(), params, level.value
                )
                return allowed
            except Exception as e:
                logger.error(f"Permission prompt failed: {e}")
                return False

        # No callback available — deny
        logger.warning(
            f"Tool '{tool.name()}' ({level.value}) denied — "
            f"no approval callback in mode '{mode}'."
        )
        return False

    def approve_for_session(self, tool_name: str):
        """Permanently approve a tool for the rest of this session."""
        self._session_approvals.add(tool_name)

    def revoke_session_approval(self, tool_name: str):
        """Revoke a session-level approval."""
        self._session_approvals.discard(tool_name)
