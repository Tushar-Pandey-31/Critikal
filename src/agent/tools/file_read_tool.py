"""
FileReadTool — Read file contents with offset/limit support.

Line-numbered output for precise referencing. Handles text and binary detection.
"""

import mimetypes
from pathlib import Path

from src.agent.context import ToolContext
from src.agent.tool import PermissionLevel, Tool, ToolResult

MAX_LINES = 2000


class FileReadTool(Tool):

    def name(self) -> str:
        return "file_read"

    def description(self) -> str:
        return (
            "Read a file's contents. Returns line-numbered text output. "
            "Use offset and limit for large files. Detects binary files."
        )

    def permission_level(self) -> PermissionLevel:
        return PermissionLevel.READ_ONLY

    def input_schema(self) -> dict:
        return {
            "type": "object",
            "properties": {
                "file_path": {
                    "type": "string",
                    "description": "Absolute or relative path to the file.",
                },
                "offset": {
                    "type": "integer",
                    "description": "Line number to start reading from (0-based). Default: 0.",
                    "default": 0,
                },
                "limit": {
                    "type": "integer",
                    "description": f"Maximum number of lines to read. Default: {MAX_LINES}.",
                    "default": MAX_LINES,
                },
            },
            "required": ["file_path"],
        }

    async def execute(self, params: dict, ctx: ToolContext) -> ToolResult:
        if "input" in params and isinstance(params["input"], dict):
            params = params["input"]

        raw_path = params.get("file_path") or params.get("path") or params.get("filename") or ""
        if not raw_path:
            return ToolResult.error(
                f"Missing 'file_path'. Got keys: {list(params.keys())}"
            )
        offset = max(params.get("offset", 0), 0)
        limit = min(params.get("limit", MAX_LINES), MAX_LINES)

        # Resolve path relative to working dir
        p = Path(raw_path)
        if not p.is_absolute():
            p = (ctx.shell_cwd or ctx.working_dir) / p
        p = p.resolve()

        if not p.exists():
            return ToolResult.error(f"File not found: {p}")
        if not p.is_file():
            return ToolResult.error(f"Not a file: {p}")

        # Binary detection
        mime, _ = mimetypes.guess_type(str(p))
        if mime and not mime.startswith("text/") and mime not in (
            "application/json", "application/xml", "application/javascript",
            "application/x-yaml", "application/toml",
        ):
            # Check first 8KB for null bytes
            try:
                with open(p, "rb") as f:
                    chunk = f.read(8192)
                if b"\x00" in chunk:
                    size = p.stat().st_size
                    return ToolResult.success(
                        f"Binary file: {p} ({size} bytes, type: {mime})"
                    )
            except Exception:
                pass

        try:
            with open(p, encoding="utf-8", errors="replace") as f:
                all_lines = f.readlines()
        except Exception as e:
            return ToolResult.error(f"Failed to read {p}: {e}")

        total = len(all_lines)
        selected = all_lines[offset:offset + limit]

        if not selected:
            if total == 0:
                return ToolResult.success(f"(empty file: {p})")
            return ToolResult.error(
                f"Offset {offset} is past end of file ({total} lines)."
            )

        # Format with line numbers
        numbered = []
        for i, line in enumerate(selected, start=offset + 1):
            numbered.append(f"{i}\t{line.rstrip()}")

        output = "\n".join(numbered)

        # Show truncation info
        if offset > 0 or offset + limit < total:
            output += f"\n\n[Showing lines {offset + 1}-{offset + len(selected)} of {total}]"

        ctx.record_file_access(str(p), "read")

        # Register in read-file-state cache for read-before-write enforcement
        full_content = "".join(all_lines)
        ctx.register_file_read(str(p), full_content)

        return ToolResult.success(output)
