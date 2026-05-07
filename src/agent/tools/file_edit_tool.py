"""
FileEditTool — Search-and-replace editing within files.

Safer than file_write for modifications: only sends the diff.
Validates that old_string is unique before replacing.
"""

from pathlib import Path

from src.agent.context import ToolContext
from src.agent.tool import PermissionLevel, Tool, ToolResult


class FileEditTool(Tool):

    def name(self) -> str:
        return "file_edit"

    def description(self) -> str:
        return (
            "Edit a file by replacing an exact string with a new string. "
            "The old_string must appear exactly once in the file (unless "
            "replace_all is true). Safer and more efficient than rewriting "
            "the entire file."
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
                "old_string": {
                    "type": "string",
                    "description": "The exact text to find and replace.",
                },
                "new_string": {
                    "type": "string",
                    "description": "The replacement text.",
                },
                "replace_all": {
                    "type": "boolean",
                    "description": "Replace all occurrences (default: false).",
                    "default": False,
                },
            },
            "required": ["file_path", "old_string", "new_string"],
        }

    async def execute(self, params: dict, ctx: ToolContext) -> ToolResult:
        if "input" in params and isinstance(params["input"], dict):
            params = params["input"]

        raw_path = params.get("file_path") or params.get("path") or ""
        old_string = params.get("old_string") or params.get("old_str") or params.get("search")
        new_string = params.get("new_string") or params.get("new_str") or params.get("replace")
        replace_all = params.get("replace_all", False)

        if not raw_path:
            return ToolResult.error(f"Missing 'file_path'. Got keys: {list(params.keys())}")
        if old_string is None:
            return ToolResult.error(f"Missing 'old_string'. Got keys: {list(params.keys())}")
        if new_string is None:
            return ToolResult.error(f"Missing 'new_string'. Got keys: {list(params.keys())}")

        if old_string == new_string:
            return ToolResult.error("old_string and new_string are identical.")

        p = Path(raw_path)
        if not p.is_absolute():
            p = (ctx.shell_cwd or ctx.working_dir) / p
        p = p.resolve()

        if not p.exists():
            return ToolResult.error(f"File not found: {p}")
        if not p.is_file():
            return ToolResult.error(f"Not a file: {p}")

        # Read-before-write enforcement (inspired by Claude Code)
        allowed, reason = ctx.check_file_write_allowed(str(p))
        if not allowed:
            return ToolResult.error(reason)

        try:
            content = p.read_text(encoding="utf-8")
        except Exception as e:
            return ToolResult.error(f"Failed to read {p}: {e}")

        count = content.count(old_string)
        if count == 0:
            return ToolResult.error(
                f"old_string not found in {p}. "
                "Make sure you're using the exact text from the file."
            )
        if count > 1 and not replace_all:
            return ToolResult.error(
                f"old_string appears {count} times in {p}. "
                "Provide more context to make it unique, or set replace_all=true."
            )

        if replace_all:
            new_content = content.replace(old_string, new_string)
        else:
            new_content = content.replace(old_string, new_string, 1)

        try:
            p.write_text(new_content, encoding="utf-8")
        except Exception as e:
            return ToolResult.error(f"Failed to write {p}: {e}")

        replacements = count if replace_all else 1
        ctx.record_file_access(str(p), "edit")
        return ToolResult.success(
            f"Edited {p}: {replacements} replacement(s) made."
        )
