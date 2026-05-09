"""
GrepTool — Regex content search across files.

Wraps Python's re module with glob-based file filtering.
Supports content mode (matching lines) and files_with_matches mode.
"""

import os
import re
from pathlib import Path

from src.agent.context import ToolContext
from src.agent.tool import PermissionLevel, Tool, ToolResult

MAX_RESULTS = 250
MAX_PATTERN_LEN = 1000
# Classic catastrophic-backtracking shapes: nested quantifiers on groups,
# alternation inside a quantifier, or repeated optional groups. These are
# a heuristic tripwire — not a full static analyzer, but they catch the
# textbook ReDoS patterns without blocking normal use.
_REDOS_SIGNATURES = (
    re.compile(r"\([^)]*[+*][^)]*\)[+*]"),  # (a+)+, (a*)+, (.+)*
    re.compile(r"\([^)]*\|[^)]*\)[+*]\+"),  # (a|b)++
    re.compile(r"\([^)]*\?[^)]*\)[+*]"),  # (a?)+ / (a?)*
    re.compile(r"\(\?:[^)]*[+*][^)]*\)[+*]"),  # non-capturing variants
)
# Per-file search timeout — prevents a pathological pattern on a huge
# line from hanging the whole tool.
PER_FILE_TIMEOUT_S = 5.0


def _looks_like_redos(pattern: str) -> str | None:
    """Return a human reason if the pattern looks dangerous, else None."""
    if len(pattern) > MAX_PATTERN_LEN:
        return f"pattern exceeds {MAX_PATTERN_LEN} chars"
    for sig in _REDOS_SIGNATURES:
        if sig.search(pattern):
            return "pattern contains nested quantifier shape prone to catastrophic backtracking"
    return None


class GrepTool(Tool):
    def name(self) -> str:
        return "grep"

    def description(self) -> str:
        return (
            "Search file contents using regex patterns. "
            "Returns matching lines with file paths and line numbers. "
            "Use glob parameter to filter which files to search."
        )

    def permission_level(self) -> PermissionLevel:
        return PermissionLevel.READ_ONLY

    def input_schema(self) -> dict:
        return {
            "type": "object",
            "properties": {
                "pattern": {
                    "type": "string",
                    "description": "Regex pattern to search for.",
                },
                "path": {
                    "type": "string",
                    "description": "File or directory to search in. Defaults to working directory.",
                },
                "glob": {
                    "type": "string",
                    "description": "Glob pattern to filter files (e.g., '*.sol', '**/*.py').",
                },
                "case_insensitive": {
                    "type": "boolean",
                    "description": "Case-insensitive search. Default: false.",
                    "default": False,
                },
                "output_mode": {
                    "type": "string",
                    "enum": ["content", "files_with_matches", "count"],
                    "description": "Output format. Default: files_with_matches.",
                    "default": "files_with_matches",
                },
                "context_lines": {
                    "type": "integer",
                    "description": "Lines of context around each match (content mode only).",
                    "default": 0,
                },
                "max_results": {
                    "type": "integer",
                    "description": f"Maximum results to return. Default: {MAX_RESULTS}.",
                    "default": MAX_RESULTS,
                },
            },
            "required": ["pattern"],
        }

    async def execute(self, params: dict, ctx: ToolContext) -> ToolResult:
        if "input" in params and isinstance(params["input"], dict):
            params = params["input"]

        pattern_str = params.get("pattern") or params.get("query") or params.get("regex") or params.get("search") or ""
        if not pattern_str:
            return ToolResult.error(f"Missing 'pattern'. Got keys: {list(params.keys())}")
        search_path = params.get("path")
        glob_pattern = params.get("glob")
        case_insensitive = params.get("case_insensitive", False)
        output_mode = params.get("output_mode", "files_with_matches")
        context_lines = params.get("context_lines", 0)
        max_results = min(params.get("max_results", MAX_RESULTS), MAX_RESULTS)

        # ReDoS tripwire — refuse known-dangerous shapes before compiling.
        danger = _looks_like_redos(pattern_str)
        if danger:
            return ToolResult.error(
                f"Refusing pattern: {danger}. Rewrite without nested quantifiers, or narrow the pattern."
            )

        flags = re.IGNORECASE if case_insensitive else 0
        try:
            regex = re.compile(pattern_str, flags)
        except re.error as e:
            return ToolResult.error(f"Invalid regex: {e}")

        # Determine search root
        root = Path(search_path) if search_path else (ctx.shell_cwd or ctx.working_dir)
        if not root.is_absolute():
            root = (ctx.shell_cwd or ctx.working_dir) / root
        root = root.resolve()

        if not root.exists():
            return ToolResult.error(f"Path not found: {root}")

        # Collect files
        if root.is_file():
            files = [root]
        else:
            files = self._collect_files(root, glob_pattern)

        # Search
        results = []
        files_matched = set()
        match_count = 0

        # Cap per-line length fed to regex.search. Catastrophic
        # backtracking is bounded by input length, so refusing to search
        # absurdly long lines (minified JS, generated blobs) is a cheap
        # second line of defense after the ReDoS tripwire.
        max_line_len = 20_000

        for fp in files:
            if len(results) >= max_results:
                break
            try:
                lines = fp.read_text(encoding="utf-8", errors="replace").splitlines()
            except Exception:
                continue

            for i, line in enumerate(lines):
                if len(line) > max_line_len:
                    continue
                if regex.search(line):
                    match_count += 1
                    files_matched.add(str(fp))

                    if output_mode == "content":
                        if len(results) >= max_results:
                            break
                        if context_lines > 0:
                            start = max(0, i - context_lines)
                            end = min(len(lines), i + context_lines + 1)
                            for j in range(start, end):
                                marker = ">" if j == i else " "
                                results.append(f"{fp}:{j + 1}{marker} {lines[j]}")
                            results.append("")  # separator
                        else:
                            results.append(f"{fp}:{i + 1}: {line}")
                    elif output_mode == "files_with_matches":
                        if str(fp) not in files_matched or len(files_matched) == match_count:
                            pass  # will be added via files_matched set
                        break  # one match per file is enough
                    # count mode: just keep counting

        if output_mode == "files_with_matches":
            output_lines = sorted(files_matched)[:max_results]
            output = "\n".join(output_lines) if output_lines else "No matches found."
            return ToolResult.success(output, match_count=len(output_lines))

        if output_mode == "count":
            return ToolResult.success(
                f"Matched {match_count} lines across {len(files_matched)} files.",
                match_count=match_count,
                files_count=len(files_matched),
            )

        # content mode
        if not results:
            return ToolResult.success("No matches found.")
        return ToolResult.success(
            "\n".join(results),
            match_count=match_count,
            files_count=len(files_matched),
        )

    def _collect_files(self, root: Path, glob_pattern: str | None) -> list[Path]:
        """Collect files to search, respecting glob filter and skipping binaries."""
        skip_dirs = {
            ".git",
            "node_modules",
            "__pycache__",
            ".venv",
            "venv",
            "target",
            "build",
            "dist",
            ".tox",
            "artifacts",
            "cache",
        }

        if glob_pattern:
            return sorted(root.glob(glob_pattern))

        files = []
        for dirpath, dirnames, filenames in os.walk(root):
            # Prune skip directories
            dirnames[:] = [d for d in dirnames if d not in skip_dirs]
            for fname in filenames:
                fp = Path(dirpath) / fname
                # Skip obvious binary extensions
                if fp.suffix.lower() in (
                    ".pyc",
                    ".pyo",
                    ".so",
                    ".o",
                    ".a",
                    ".exe",
                    ".dll",
                    ".bin",
                    ".png",
                    ".jpg",
                    ".gif",
                    ".zip",
                    ".tar",
                    ".gz",
                    ".pdf",
                    ".wasm",
                ):
                    continue
                files.append(fp)
                if len(files) > 50_000:
                    break  # safety limit
        return sorted(files)
