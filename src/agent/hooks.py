"""
HookRegistry — user-configured lifecycle hooks.

The harness (not the model) runs shell commands at specific lifecycle
points, so users can wire in automation without relying on prompt
instructions the model might ignore.

Supported events:
  * SessionStart  — fired once when a session begins
  * SessionEnd    — fired once when a session ends
  * PreToolUse    — fired before a tool executes (can block by exit != 0)
  * PostToolUse   — fired after a tool completes (output ignored)

Configuration (JSON), searched in this order:
  1. `$CRITIKAL_SETTINGS` environment variable
  2. `<cwd>/.critikal/settings.json`
  3. `~/.critikal/settings.json`

Shape:

    {
      "hooks": {
        "PreToolUse": [
          {
            "matcher": "bash",
            "hooks": [
              {"type": "command", "command": "echo bash-about-to-run"}
            ]
          }
        ],
        "SessionStart": [
          {"hooks": [{"type": "command", "command": "date"}]}
        ]
      }
    }

`matcher` is a regex matched against the tool name; omit or use "*" to
match everything. PreToolUse hooks that exit non-zero block the tool
call — the LLM receives the stderr output as a tool result.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import shlex
from dataclasses import dataclass
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

HOOK_TIMEOUT_S = 30
SETTINGS_FILES = (".critikal/settings.json",)


@dataclass
class HookResult:
    blocked: bool = False
    reason: str = ""
    stdout: str = ""
    stderr: str = ""


@dataclass
class _HookEntry:
    matcher: re.Pattern | None
    command: str


def _load_settings() -> dict[str, Any]:
    explicit = os.getenv("CRITIKAL_SETTINGS")
    candidates: list[Path] = []
    if explicit:
        candidates.append(Path(explicit))
    candidates.append(Path.cwd() / ".critikal" / "settings.json")
    candidates.append(Path.home() / ".critikal" / "settings.json")

    for path in candidates:
        try:
            if path.is_file():
                with path.open("r", encoding="utf-8") as fp:
                    return json.load(fp)
        except (OSError, json.JSONDecodeError) as e:
            logger.warning(f"[hooks] could not read {path}: {e}")
    return {}


class HookRegistry:
    """Dispatches lifecycle events to user-configured shell commands."""

    def __init__(self, settings: dict[str, Any] | None = None):
        cfg = settings if settings is not None else _load_settings()
        hooks_cfg = (cfg or {}).get("hooks", {}) or {}

        self._by_event: dict[str, list[_HookEntry]] = {}
        for event_name, entries in hooks_cfg.items():
            parsed: list[_HookEntry] = []
            for entry in entries or []:
                matcher_str = entry.get("matcher") or "*"
                pattern: re.Pattern | None
                if matcher_str in ("*", "", None):
                    pattern = None
                else:
                    try:
                        pattern = re.compile(matcher_str)
                    except re.error as e:
                        logger.warning(
                            f"[hooks] invalid matcher {matcher_str!r} for {event_name}: {e}"
                        )
                        continue
                for hook in entry.get("hooks", []) or []:
                    if hook.get("type") != "command":
                        continue
                    command = hook.get("command")
                    if not command:
                        continue
                    parsed.append(_HookEntry(matcher=pattern, command=command))
            if parsed:
                self._by_event[event_name] = parsed

    def has(self, event: str) -> bool:
        return bool(self._by_event.get(event))

    async def fire(
        self,
        event: str,
        *,
        tool_name: str | None = None,
        payload: dict[str, Any] | None = None,
    ) -> HookResult:
        """Run every configured hook for `event`.

        PreToolUse semantics: if any hook exits with a non-zero status,
        the result is marked `blocked=True` and `reason` carries the
        hook's stderr. The caller is expected to surface this to the
        LLM instead of running the tool.

        All other events treat exit codes as advisory.
        """
        entries = self._by_event.get(event, [])
        if not entries:
            return HookResult()

        payload_json = json.dumps(payload or {}, default=str)
        env = {
            **os.environ,
            "CRITIKAL_HOOK_EVENT": event,
            "CRITIKAL_HOOK_TOOL": tool_name or "",
            "CRITIKAL_HOOK_PAYLOAD": payload_json[:10_000],
        }

        aggregated_stdout: list[str] = []
        aggregated_stderr: list[str] = []

        for entry in entries:
            if tool_name is not None and entry.matcher is not None:
                if not entry.matcher.search(tool_name):
                    continue
            try:
                proc = await asyncio.create_subprocess_shell(
                    entry.command,
                    stdin=asyncio.subprocess.PIPE,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    env=env,
                )
                try:
                    stdout_b, stderr_b = await asyncio.wait_for(
                        proc.communicate(input=payload_json.encode("utf-8")),
                        timeout=HOOK_TIMEOUT_S,
                    )
                except TimeoutError:
                    proc.kill()
                    await proc.wait()
                    msg = f"hook timed out after {HOOK_TIMEOUT_S}s: {_short(entry.command)}"
                    logger.warning(f"[hooks] {msg}")
                    aggregated_stderr.append(msg)
                    continue
            except Exception as e:
                msg = f"hook failed to spawn ({_short(entry.command)}): {e}"
                logger.warning(f"[hooks] {msg}")
                aggregated_stderr.append(msg)
                continue

            stdout = stdout_b.decode("utf-8", errors="replace")
            stderr = stderr_b.decode("utf-8", errors="replace")
            if stdout:
                aggregated_stdout.append(stdout)
            if stderr:
                aggregated_stderr.append(stderr)

            if event == "PreToolUse" and proc.returncode not in (0, None):
                reason = stderr.strip() or stdout.strip() or (
                    f"PreToolUse hook exited {proc.returncode}"
                )
                return HookResult(
                    blocked=True,
                    reason=reason,
                    stdout="\n".join(aggregated_stdout),
                    stderr="\n".join(aggregated_stderr),
                )

        return HookResult(
            stdout="\n".join(aggregated_stdout),
            stderr="\n".join(aggregated_stderr),
        )


def _short(cmd: str, limit: int = 60) -> str:
    cmd = cmd.strip()
    if len(cmd) <= limit:
        return cmd
    return cmd[:limit] + "..."


# shlex re-export kept so callers can preview parsed commands if they
# ever want to show them back to users. Not strictly needed for runtime.
__all__ = ["HookRegistry", "HookResult", "shlex"]
