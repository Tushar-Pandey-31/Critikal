"""
FileWriteTool — Create or overwrite files.

For existing files, the agent should read first to confirm intent.
Creates parent directories automatically.
"""

from pathlib import Path

from src.agent.tool import Tool, ToolResult, PermissionLevel
from src.agent.context import ToolContext


class FileWriteTool(Tool):

    def name(self) -> str:
        return "file_write"

    def description(self) -> str:
        return (
            "Write content to a file, creating it if it doesn't exist or "
            "overwriting if it does. Creates parent directories automatically. "
            "For modifying existing files, prefer file_edit (search-and-replace) "
            "instead — it's safer and sends less data."
        )

    def permission_level(self) -> PermissionLevel:
        return PermissionLevel.WRITE

    def input_schema(self) -> dict:
        return {
            "type": "object",
            "properties": {
                "file_path": {
                    "type": "string",
                    "description": "Absolute or relative path to the file.",
                },
                "content": {
                    "type": "string",
                    "description": "The full content to write.",
                },
            },
            "required": ["file_path", "content"],
        }

    async def execute(self, params: dict, ctx: ToolContext) -> ToolResult:
        # Resilient param extraction
        if "input" in params and isinstance(params["input"], dict):
            params = params["input"]

        raw_path = params.get("file_path") or params.get("path") or params.get("filename") or ""
        content = params.get("content") or params.get("text") or params.get("data")

        if not raw_path:
            return ToolResult.error(
                f"Missing 'file_path'. Got keys: {list(params.keys())}. "
                f"Send {{'file_path': '<path>', 'content': '<text>'}}"
            )
        if content is None:
            return ToolResult.error(
                f"Missing 'content'. Got keys: {list(params.keys())}. "
                f"Send {{'file_path': '<path>', 'content': '<text>'}}"
            )

        p = Path(raw_path)
        if not p.is_absolute():
            p = (ctx.shell_cwd or ctx.working_dir) / p
        p = p.resolve()

        existed = p.exists()

        # Read-before-write enforcement (inspired by Claude Code)
        if existed:
            allowed, reason = ctx.check_file_write_allowed(str(p))
            if not allowed:
                return ToolResult.error(reason)

        try:
            p.parent.mkdir(parents=True, exist_ok=True)
            with open(p, "w", encoding="utf-8") as f:
                f.write(content)
        except Exception as e:
            return ToolResult.error(f"Failed to write {p}: {e}")

        lines = content.count("\n") + (1 if content and not content.endswith("\n") else 0)
        action = "overwritten" if existed else "created"
        ctx.record_file_access(str(p), "write")
        return ToolResult.success(f"File {action}: {p} ({lines} lines)")
