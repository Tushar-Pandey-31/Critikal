"""
SandboxRunTool — Write and execute arbitrary Solidity in an isolated Foundry project.

Lets the agent directly test exploit hypotheses without going through the full
finding pipeline. Creates a temp Foundry project, optionally forks a live chain,
writes the test contract, compiles, and runs it.

Isolation: forge is wrapped with bwrap (Linux) / sandbox-exec (macOS) via
SandboxManager. The temp directory is bind-mounted read-write; everything else
is read-only.

dangerouslyDisableSandbox bypasses OS-level isolation (per-call override).

Permission: EXECUTE
"""

import asyncio
import logging
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from shlex import quote as shlex_quote

from src.agent.context import ToolContext
from src.agent.sandbox import SandboxManager, SandboxOptions
from src.agent.tool import PermissionLevel, Tool, ToolResult

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 120


class SandboxRunTool(Tool):

    def name(self) -> str:
        return "sandbox_run"

    def description(self) -> str:
        return (
            "Write a Solidity test contract and execute it in an isolated Foundry project. "
            "Use this to prove or disprove exploit hypotheses: write a forge test, compile it, "
            "run it, and get the full output. Supports mainnet/testnet forking via fork_url. "
            "The test must be a complete Foundry test contract (inherits from Test, has setUp "
            "and test* functions). Execution is sandboxed via bwrap/sandbox-exec. "
            "Returns compiler output + test results."
        )

    def permission_level(self) -> PermissionLevel:
        return PermissionLevel.EXECUTE

    def input_schema(self) -> dict:
        return {
            "type": "object",
            "properties": {
                "test_code": {
                    "type": "string",
                    "description": (
                        "Complete Solidity test file content. Must be a valid Foundry test "
                        "contract (// SPDX-License-Identifier, pragma, import forge-std/Test.sol, "
                        "contract FooTest is Test { setUp, test* functions })."
                    ),
                },
                "fork_url": {
                    "type": "string",
                    "description": "Optional RPC URL to fork (e.g. mainnet, testnet). Enables vm.deal, real state.",
                },
                "fork_block": {
                    "type": "integer",
                    "description": "Block number to fork at. Only used when fork_url is set.",
                },
                "additional_contracts": {
                    "type": "object",
                    "description": "Optional map of filename -> Solidity source for helper contracts.",
                    "additionalProperties": {"type": "string"},
                },
                "verbosity": {
                    "type": "integer",
                    "description": "forge test verbosity: 1-5 (default: 3 = show logs + traces on fail).",
                    "default": 3,
                },
                "match_test": {
                    "type": "string",
                    "description": "Optional test function filter (forge --match-test).",
                },
                "timeout": {
                    "type": "integer",
                    "description": f"Timeout in seconds (default: {DEFAULT_TIMEOUT}).",
                },
                "dangerouslyDisableSandbox": {
                    "type": "boolean",
                    "description": (
                        "Disable OS-level sandbox for this test run. Use if bwrap causes "
                        "issues with forge (e.g. inside Docker, missing namespaces)."
                    ),
                    "default": False,
                },
            },
            "required": ["test_code"],
        }

    async def execute(self, params: dict, ctx: ToolContext) -> ToolResult:
        test_code = params.get("test_code", "").strip()
        if not test_code:
            return ToolResult.error("test_code is required")

        fork_url = params.get("fork_url") or os.getenv("FORK_URL") or os.getenv("ETH_RPC_URL")
        fork_block = params.get("fork_block")
        additional = params.get("additional_contracts", {})
        verbosity = params.get("verbosity", 3)
        match_test = params.get("match_test")
        timeout = min(params.get("timeout", DEFAULT_TIMEOUT), 600)
        disable_sandbox = params.get("dangerouslyDisableSandbox", False)

        tmp_dir = Path(tempfile.mkdtemp(prefix="critikal_sandbox_"))
        try:
            return await asyncio.get_event_loop().run_in_executor(
                None,
                self._run_sync,
                tmp_dir, test_code, fork_url, fork_block,
                additional, verbosity, match_test, timeout, disable_sandbox,
            )
        finally:
            shutil.rmtree(tmp_dir, ignore_errors=True)
            SandboxManager.cleanupAfterCommand()

    def _run_sync(
        self,
        tmp_dir: Path,
        test_code: str,
        fork_url: str | None,
        fork_block: int | None,
        additional: dict,
        verbosity: int,
        match_test: str | None,
        timeout: int,
        disable_sandbox: bool,
    ) -> ToolResult:
        sandbox_opts = SandboxOptions(
            # `forge init` needs network for the forge-std git fetch in some
            # templates; our `--no-git --empty` variant does not, so we keep
            # network tied to whether the caller actually requested a fork.
            allow_network=bool(fork_url),
            writable_paths=[str(tmp_dir)],
            working_dir=str(tmp_dir),
        )

        # 1. Initialise a bare Foundry project in the temp dir — sandboxed.
        init_shell_cmd = (
            f"forge init --no-git --force --empty {shlex_quote(str(tmp_dir))}"
        )
        init_shell_cmd = SandboxManager.wrapWithSandbox(
            init_shell_cmd, "/bin/bash", sandbox_opts, dangerously_disable=disable_sandbox
        )
        init_result = subprocess.run(
            ["bash", "-c", init_shell_cmd],
            capture_output=True, text=True, timeout=60,
        )
        if init_result.returncode != 0:
            return ToolResult.error(
                f"forge init failed:\n{init_result.stderr[:2000]}"
            )

        test_dir = tmp_dir / "test"
        test_dir.mkdir(parents=True, exist_ok=True)

        # 2. Write test file
        (test_dir / "Exploit.t.sol").write_text(test_code)

        # 3. Write any additional helper contracts
        for filename, source in (additional or {}).items():
            dest = test_dir / filename
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(source)

        # 4. Build forge test command
        forge_cmd_parts = [
            "forge", "test",
            f"-{'v' * min(max(verbosity, 1), 5)}",
        ]
        if fork_url:
            forge_cmd_parts += ["--fork-url", fork_url]
            if fork_block:
                forge_cmd_parts += ["--fork-block-number", str(fork_block)]
        if match_test:
            forge_cmd_parts += ["--match-test", match_test]

        # 5. Compile first to get clean error messages
        build_cmd = ["forge", "build"]
        build_shell_cmd = " ".join(build_cmd)
        build_shell_cmd = SandboxManager.wrapWithSandbox(
            build_shell_cmd, "/bin/bash", sandbox_opts, dangerously_disable=disable_sandbox
        )

        build_result = subprocess.run(
            ["bash", "-c", build_shell_cmd],
            cwd=str(tmp_dir),
            capture_output=True, text=True, timeout=60,
        )
        if build_result.returncode != 0:
            return ToolResult.error(
                f"Compilation failed:\n"
                f"{build_result.stdout[-3000:]}\n"
                f"{build_result.stderr[-3000:]}"
            )

        # 6. Run tests via sandbox
        forge_shell_cmd = " ".join(forge_cmd_parts)
        forge_shell_cmd = SandboxManager.wrapWithSandbox(
            forge_shell_cmd, "/bin/bash", sandbox_opts, dangerously_disable=disable_sandbox
        )

        try:
            test_result = subprocess.run(
                ["bash", "-c", forge_shell_cmd],
                cwd=str(tmp_dir),
                capture_output=True,
                text=True,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired:
            return ToolResult.error(f"forge test timed out after {timeout}s")

        stdout = test_result.stdout[-10000:]
        stderr = test_result.stderr[-3000:]
        passed = test_result.returncode == 0

        output = stdout
        if stderr and not passed:
            output += f"\n[stderr]\n{stderr}"
        output = output.strip() or "(no output)"

        return ToolResult(
            output=output,
            is_error=not passed,
            metadata={
                "passed": passed,
                "exit_code": test_result.returncode,
                "fork_url": fork_url,
                "fork_block": fork_block,
                "sandboxed": not disable_sandbox and SandboxManager.is_available(),
            },
        )
