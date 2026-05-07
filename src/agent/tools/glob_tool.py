"""
GlobTool — File pattern matching.

Fast file discovery using glob patterns. Returns matching paths
sorted by modification time (most recent first).
"""

import os
from pathlib import Path

from src.agent.context import ToolContext
from src.agent.tool import PermissionLevel, Tool, ToolResult

MAX_RESULTS = 500


class GlobTool(Tool):

    def name(self) -> str:
        return "glob"

    def description(self) -> str:
        return (
            "Find files matching a glob pattern (e.g., '**/*.sol', 'src/**/*.py'). "
            "Returns paths sorted by modification time (newest first). "
            "Use this to discover files before reading them."
        )

    def permission_level(self) -> PermissionLevel:
        return PermissionLevel.READ_ONLY

    def input_schema(self) -> dict:
        return {
            "type": "object",
            "properties": {
                "pattern": {
                    "type": "string",
                    "description": "Glob pattern (e.g., '**/*.sol', 'contracts/*.vy').",
                },
                "path": {
                    "type": "string",
                    "description": "Directory to search in. Defaults to working directory.",
                },
            },
            "required": ["pattern"],
        }

    async def execute(self, params: dict, ctx: ToolContext) -> ToolResult:
        if "input" in params and isinstance(params["input"], dict):
            params = params["input"]

        pattern = params.get("pattern") or params.get("glob") or ""
        if not pattern:
            return ToolResult.error(f"Missing 'pattern'. Got keys: {list(params.keys())}")
        search_path = params.get("path")

        root = Path(search_path) if search_path else (ctx.shell_cwd or ctx.working_dir)
        if not root.is_absolute():
            root = (ctx.shell_cwd or ctx.working_dir) / root
        root = root.resolve()

        if not root.exists():
            return ToolResult.error(f"Directory not found: {root}")
        if not root.is_dir():
            return ToolResult.error(f"Not a directory: {root}")

        try:
            matches = list(root.glob(pattern))
        except Exception as e:
            return ToolResult.error(f"Invalid glob pattern: {e}")

        # Filter to files only, skip .git internals
        files = [
            f for f in matches
            if f.is_file() and ".git" not in f.parts
        ]

        # Sort by mtime (newest first)
        files.sort(key=lambda f: os.path.getmtime(f), reverse=True)

        if not files:
            return ToolResult.success(f"No files matching '{pattern}' in {root}")

        truncated = len(files) > MAX_RESULTS
        files = files[:MAX_RESULTS]

        output = "\n".join(str(f) for f in files)
        if truncated:
            output += f"\n\n[Showing first {MAX_RESULTS} of {len(matches)} matches]"

        return ToolResult.success(output, count=len(files))
