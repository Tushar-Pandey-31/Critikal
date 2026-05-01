"""
BashTool — Persistent shell with CWD/env state across calls.

Provides the agent with shell access. CWD and environment variables
persist across invocations via sentinel-based state capture.
Security classifier blocks dangerous commands.
"""

import asyncio
import logging
import os
import re
import shlex
import uuid
from pathlib import Path

from src.agent.tool import Tool, ToolResult, PermissionLevel
from src.agent.context import ToolContext

logger = logging.getLogger(__name__)

# Maximum output size before truncation (100KB)
MAX_OUTPUT_BYTES = 100_000
KEEP_HEAD = 50_000
KEEP_TAIL = 50_000

# Commands that are always blocked
BLOCKED_PATTERNS = [
    r"rm\s+-rf\s+/\s*$",           # rm -rf /
    r"rm\s+-rf\s+/\*",             # rm -rf /*
    r":\(\)\s*\{\s*:\|:\s*&\s*\}", # fork bomb
    r"dd\s+if=.*of=/dev/sd",       # dd to raw device
    r"mkfs\.",                      # format filesystem
    r">\s*/dev/sd",                 # redirect to raw device
    r"chmod\s+-R\s+777\s+/\s*$",   # chmod 777 /
]

DEFAULT_TIMEOUT = 120  # seconds
MAX_TIMEOUT = 600


def classify_command(command: str) -> str | None:
    """Return a reason string if the command should be blocked, else None."""
    for pattern in BLOCKED_PATTERNS:
        if re.search(pattern, command):
            return f"Blocked: matches dangerous pattern '{pattern}'"
    return None


class BashTool(Tool):

    def name(self) -> str:
        return "bash"

    def description(self) -> str:
        return (
            "Execute a shell command. CWD and environment variables persist "
            "across calls within the session. Use for system commands, "
            "running tools (slither, forge, nmap, etc.), and any operation "
            "that requires shell access."
        )

    def permission_level(self) -> PermissionLevel:
        return PermissionLevel.EXECUTE

    def input_schema(self) -> dict:
        return {
            "type": "object",
            "properties": {
                "command": {
                    "type": "string",
                    "description": "The shell command to execute.",
                },
                "description": {
                    "type": "string",
                    "description": "Human-readable description of what the command does (shown in UI).",
                },
                "timeout": {
                    "type": "integer",
                    "description": f"Timeout in seconds (default: {DEFAULT_TIMEOUT}, max: {MAX_TIMEOUT}).",
                },
                "run_in_background": {
                    "type": "boolean",
                    "description": "If true, returns a task_id immediately. Check results later.",
                    "default": False,
                },
                "dangerouslyDisableSandbox": {
                    "type": "boolean",
                    "description": (
                        "Disable OS-level sandbox for this call. Use when the command "
                        "requires write access outside the working directory, or when "
                        "bwrap causes issues with specific tools (e.g. Docker-in-Docker)."
                    ),
                    "default": False,
                },
            },
            "required": ["command"],
        }

    async def execute(self, params: dict, ctx: ToolContext) -> ToolResult:
        # Resilient param extraction — models sometimes use different key names
        # or nest params inside an "input" wrapper
        if "input" in params and isinstance(params["input"], dict):
            params = params["input"]  # Unwrap nested input

        command = (
            params.get("command")
            or params.get("cmd")
            or params.get("shell_command")
            or params.get("script")
            or ""
        )
        if isinstance(command, dict):
            command = command.get("command", command.get("cmd", ""))

        command = str(command).strip()
        if not command:
            available_keys = list(params.keys())
            return ToolResult.error(
                f"Missing 'command' parameter. Got keys: {available_keys}. "
                f"Send {{'command': '<shell command>'}}"
            )

        # Security check
        block_reason = classify_command(command)
        if block_reason:
            return ToolResult.error(block_reason)

        timeout = min(params.get("timeout", DEFAULT_TIMEOUT), MAX_TIMEOUT)
        run_bg = params.get("run_in_background", False)
        disable_sandbox = params.get("dangerouslyDisableSandbox", False)

        # Wrap with OS-level sandbox (bwrap on Linux, sandbox-exec on macOS)
        from src.agent.sandbox import SandboxManager, SandboxOptions
        cwd_str = str(ctx.shell_cwd or ctx.working_dir)
        sandbox_opts = SandboxOptions(
            allow_network=True,
            writable_paths=[cwd_str],
            working_dir=cwd_str,
            env_vars=dict(ctx.shell_env),
        )
        command = SandboxManager.wrapWithSandbox(
            command, "/bin/bash", sandbox_opts, dangerously_disable=disable_sandbox
        )

        # Determine working directory
        cwd = str(ctx.shell_cwd or ctx.working_dir)

        # Build sentinel-wrapped script to capture final cwd + env
        sentinel = f"__CRITIKAL_SENTINEL_{uuid.uuid4().hex[:8]}__"
        wrapped = (
            f"cd {shlex.quote(cwd)} 2>/dev/null\n"
        )
        # Restore persisted env vars
        for k, v in ctx.shell_env.items():
            wrapped += f"export {k}={shlex.quote(v)}\n"
        wrapped += (
            f"{command}\n"
            f"__exit_code=$?\n"
            f"echo '{sentinel}_CWD'\n"
            f"pwd\n"
            f"echo '{sentinel}_ENV'\n"
            f"env -0 2>/dev/null || env\n"
            f"echo '{sentinel}_EXIT'\n"
            f"echo $__exit_code\n"
        )

        if run_bg:
            return await self._run_background(wrapped, timeout, ctx)

        return await self._run_foreground(wrapped, timeout, sentinel, ctx)

    async def _run_foreground(
        self, script: str, timeout: int, sentinel: str, ctx: ToolContext
    ) -> ToolResult:
        try:
            proc = await asyncio.create_subprocess_exec(
                "bash", "-c", script,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
                env={**os.environ, **ctx.shell_env},
            )
            raw_out, _ = await asyncio.wait_for(
                proc.communicate(), timeout=timeout
            )
        except asyncio.TimeoutError:
            try:
                proc.kill()
            except ProcessLookupError:
                pass
            return ToolResult.error(f"Command timed out after {timeout}s.")
        except Exception as e:
            return ToolResult.error(f"Failed to execute: {e}")

        full_output = raw_out.decode("utf-8", errors="replace")

        # Parse sentinel blocks
        exit_code = proc.returncode or 0
        user_output = full_output

        cwd_marker = f"{sentinel}_CWD"
        env_marker = f"{sentinel}_ENV"
        exit_marker = f"{sentinel}_EXIT"

        if cwd_marker in full_output:
            parts = full_output.split(cwd_marker)
            user_output = parts[0].rstrip("\n")

            remainder = parts[1] if len(parts) > 1 else ""

            # Extract CWD
            if env_marker in remainder:
                cwd_section, remainder = remainder.split(env_marker, 1)
                new_cwd = cwd_section.strip()
                if new_cwd and Path(new_cwd).exists():
                    ctx.shell_cwd = Path(new_cwd)

            # Extract exit code
            if exit_marker in remainder:
                env_section, exit_section = remainder.split(exit_marker, 1)
                try:
                    exit_code = int(exit_section.strip())
                except ValueError:
                    pass

                # Parse env (null-separated if available)
                self._update_env(env_section, ctx)

        # Truncate if too large
        user_output = self._truncate(user_output)

        if exit_code != 0:
            return ToolResult.error(
                f"{user_output}\n\n[exit code: {exit_code}]",
                exit_code=exit_code,
            )

        return ToolResult.success(
            user_output if user_output else "(no output)",
            exit_code=exit_code,
        )

    async def _run_background(
        self, script: str, timeout: int, ctx: ToolContext
    ) -> ToolResult:
        task_id = f"bg_{uuid.uuid4().hex[:8]}"

        async def _bg_task():
            try:
                proc = await asyncio.create_subprocess_exec(
                    "bash", "-c", script,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.STDOUT,
                    env={**os.environ, **ctx.shell_env},
                )
                await asyncio.wait_for(proc.communicate(), timeout=timeout)
            except Exception as e:
                logger.error(f"Background task {task_id} failed: {e}")

        asyncio.create_task(_bg_task(), name=task_id)
        return ToolResult.success(
            f"Started background task: {task_id}",
            task_id=task_id,
        )

    def _update_env(self, env_section: str, ctx: ToolContext):
        """Parse environment variable output and update ctx.shell_env."""
        env_section = env_section.strip()
        if not env_section:
            return

        # Try null-separated first (from env -0)
        if "\0" in env_section:
            entries = env_section.split("\0")
        else:
            entries = env_section.split("\n")

        for entry in entries:
            entry = entry.strip()
            if "=" in entry:
                key, _, value = entry.partition("=")
                key = key.strip()
                # Only track user-set vars, skip system noise
                if key and not key.startswith("_") and key not in (
                    "SHLVL", "OLDPWD", "PWD", "HOSTNAME",
                ):
                    ctx.shell_env[key] = value

    @staticmethod
    def _truncate(output: str) -> str:
        """Truncate output if it exceeds MAX_OUTPUT_BYTES."""
        if len(output.encode("utf-8", errors="replace")) <= MAX_OUTPUT_BYTES:
            return output

        head = output[:KEEP_HEAD]
        tail = output[-KEEP_TAIL:]
        skipped = len(output) - KEEP_HEAD - KEEP_TAIL
        return f"{head}\n\n... [{skipped} characters truncated] ...\n\n{tail}"
