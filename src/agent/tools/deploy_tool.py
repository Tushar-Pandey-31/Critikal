"""
DeployTool — Deploy contracts and interact with live chains.

Wraps forge create, forge script, and cast send/call.
Supports testnet and mainnet deployments.

Permission: DANGEROUS — this sends real on-chain transactions.
The agent must have explicit authorization before using this tool
against a mainnet or funded testnet account.

Sandbox: forge create and cast send are wrapped with SandboxManager
(bwrap on Linux / sandbox-exec on macOS). dangerouslyDisableSandbox
bypasses OS-level isolation per-call, matching the Claude Code BashTool
sandbox pattern.
"""

import asyncio
import logging
import os
import shlex
import subprocess
from pathlib import Path

from src.agent.tool import Tool, ToolResult, PermissionLevel
from src.agent.context import ToolContext
from src.agent.sandbox import SandboxManager, SandboxOptions

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 120


class DeployContractTool(Tool):

    def name(self) -> str:
        return "deploy_contract"

    def description(self) -> str:
        return (
            "Deploy a smart contract to a chain using forge create or forge script. "
            "Returns the deployed contract address and transaction hash. "
            "Private key is read from the env var named by private_key_env "
            "(default: DEPLOYER_PRIVATE_KEY). "
            "WARNING: This sends real on-chain transactions. Only use on testnets "
            "or chains you have authorization to interact with."
        )

    def permission_level(self) -> PermissionLevel:
        return PermissionLevel.DANGEROUS

    def input_schema(self) -> dict:
        return {
            "type": "object",
            "properties": {
                "contract_path": {
                    "type": "string",
                    "description": "Path to the Solidity file (e.g. 'src/Vault.sol') relative to repo root.",
                },
                "contract_name": {
                    "type": "string",
                    "description": "Contract name within the file (e.g. 'Vault').",
                },
                "rpc_url": {
                    "type": "string",
                    "description": "RPC endpoint. Falls back to ETH_RPC_URL env var.",
                },
                "constructor_args": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Constructor arguments as strings.",
                    "default": [],
                },
                "private_key_env": {
                    "type": "string",
                    "description": "Name of env var holding the deployer private key (default: DEPLOYER_PRIVATE_KEY).",
                    "default": "DEPLOYER_PRIVATE_KEY",
                },
                "value": {
                    "type": "string",
                    "description": "ETH to send with deployment (e.g. '1ether', '0.1 ether').",
                },
                "verify": {
                    "type": "boolean",
                    "description": "Verify contract on Etherscan after deployment.",
                    "default": False,
                },
                "etherscan_api_key_env": {
                    "type": "string",
                    "description": "Env var name for Etherscan API key (default: ETHERSCAN_API_KEY).",
                    "default": "ETHERSCAN_API_KEY",
                },
                "timeout": {
                    "type": "integer",
                    "description": "Timeout in seconds (default: 120).",
                },
                "dangerouslyDisableSandbox": {
                    "type": "boolean",
                    "description": (
                        "Disable OS-level sandbox for this deployment. Use when "
                        "bwrap causes issues (e.g. inside Docker, missing namespaces)."
                    ),
                    "default": False,
                },
            },
            "required": ["contract_path", "contract_name"],
        }

    async def execute(self, params: dict, ctx: ToolContext) -> ToolResult:
        contract_path = params.get("contract_path", "")
        contract_name = params.get("contract_name", "")
        rpc_url = params.get("rpc_url") or os.getenv("ETH_RPC_URL") or os.getenv("FORK_URL")
        constructor_args = params.get("constructor_args", [])
        pk_env = params.get("private_key_env", "DEPLOYER_PRIVATE_KEY")
        value = params.get("value")
        verify = params.get("verify", False)
        etherscan_env = params.get("etherscan_api_key_env", "ETHERSCAN_API_KEY")
        timeout = min(params.get("timeout", DEFAULT_TIMEOUT), 600)
        disable_sandbox = params.get("dangerouslyDisableSandbox", False)

        if not rpc_url:
            return ToolResult.error(
                "No RPC URL provided. Pass rpc_url or set ETH_RPC_URL env var."
            )

        private_key = os.getenv(pk_env)
        if not private_key:
            return ToolResult.error(
                f"No private key found in env var '{pk_env}'. "
                "Set the env var before deploying."
            )

        repo_path = ctx.repo_path or Path(".")

        cmd_parts = [
            "forge", "create",
            f"{contract_path}:{contract_name}",
            "--rpc-url", rpc_url,
            "--private-key", private_key,
            "--broadcast",
        ]

        if constructor_args:
            cmd_parts += ["--constructor-args"] + constructor_args

        if value:
            cmd_parts += ["--value", value]

        if verify:
            etherscan_key = os.getenv(etherscan_env)
            if etherscan_key:
                cmd_parts += ["--verify", "--etherscan-api-key", etherscan_key]
            else:
                logger.warning(f"verify=true but {etherscan_env} not set — skipping verification")

        logger.info(f"[deploy] Running: {' '.join(cmd_parts[:6])} ...")

        # Wrap with OS-level sandbox
        forge_shell_cmd = " ".join(shlex.quote(p) for p in cmd_parts)
        sandbox_opts = SandboxOptions(
            allow_network=True,
            writable_paths=[str(repo_path)],
            working_dir=str(repo_path),
        )
        forge_shell_cmd = SandboxManager.wrapWithSandbox(
            forge_shell_cmd, "/bin/bash", sandbox_opts, dangerously_disable=disable_sandbox
        )

        try:
            result = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: subprocess.run(
                    ["bash", "-c", forge_shell_cmd],
                    cwd=str(repo_path),
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                )
            )
        except subprocess.TimeoutExpired:
            return ToolResult.error(f"forge create timed out after {timeout}s")
        except Exception as e:
            return ToolResult.error(f"Deployment failed: {e}")

        stdout = result.stdout
        stderr = result.stderr
        passed = result.returncode == 0

        if not passed:
            return ToolResult.error(
                f"forge create failed (exit {result.returncode}):\n"
                f"{stdout[-2000:]}\n{stderr[-2000:]}"
            )

        # Parse deployed address from forge create output
        deployed_address = None
        tx_hash = None
        for line in stdout.splitlines():
            line_lower = line.lower()
            if "deployed to:" in line_lower:
                parts = line.split(":")
                if len(parts) > 1:
                    deployed_address = parts[-1].strip()
            elif "transaction hash:" in line_lower:
                parts = line.split(":")
                if len(parts) > 1:
                    tx_hash = parts[-1].strip()

        output = stdout.strip()
        if not output:
            output = "(no output)"

        return ToolResult.success(
            output,
            deployed_address=deployed_address,
            tx_hash=tx_hash,
            rpc_url=rpc_url,
            contract=f"{contract_path}:{contract_name}",
        )


class CastTool(Tool):
    """
    Cast tool — interact with any EVM chain via cast send / cast call / cast run.

    cast call:  read-only view calls
    cast send:  send transactions (mutating, requires private key)
    cast run:   simulate a tx from history
    cast code:  get contract bytecode
    cast storage: read storage slots
    """

    def name(self) -> str:
        return "cast"

    def description(self) -> str:
        return (
            "Interact with EVM chains using Foundry cast. "
            "Use cast call for read-only queries (no key needed). "
            "Use cast send for on-chain transactions (requires DEPLOYER_PRIVATE_KEY). "
            "Use cast run to simulate historical transactions. "
            "Use cast storage/code to inspect chain state. "
            "Supports any EVM-compatible RPC endpoint."
        )

    def permission_level(self) -> PermissionLevel:
        # cast call is read-only but cast send is dangerous.
        # We use DANGEROUS and let the permission system gate it.
        # In yolo mode (headless) everything is allowed.
        return PermissionLevel.DANGEROUS

    def input_schema(self) -> dict:
        return {
            "type": "object",
            "properties": {
                "subcommand": {
                    "type": "string",
                    "enum": ["call", "send", "run", "code", "storage", "balance", "abi-decode", "4byte"],
                    "description": "cast subcommand to run.",
                },
                "args": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Arguments passed directly to cast after the subcommand.",
                },
                "rpc_url": {
                    "type": "string",
                    "description": "RPC endpoint. Falls back to ETH_RPC_URL env var.",
                },
                "private_key_env": {
                    "type": "string",
                    "description": "Env var name for private key (used by cast send). Default: DEPLOYER_PRIVATE_KEY.",
                    "default": "DEPLOYER_PRIVATE_KEY",
                },
                "timeout": {
                    "type": "integer",
                    "description": "Timeout in seconds (default: 60).",
                },
                "dangerouslyDisableSandbox": {
                    "type": "boolean",
                    "description": "Disable OS-level sandbox for this call.",
                    "default": False,
                },
            },
            "required": ["subcommand", "args"],
        }

    async def execute(self, params: dict, ctx: ToolContext) -> ToolResult:
        subcommand = params.get("subcommand", "")
        args = params.get("args", [])
        rpc_url = params.get("rpc_url") or os.getenv("ETH_RPC_URL") or os.getenv("FORK_URL")
        pk_env = params.get("private_key_env", "DEPLOYER_PRIVATE_KEY")
        timeout = min(params.get("timeout", 60), 300)
        disable_sandbox = params.get("dangerouslyDisableSandbox", False)

        cmd_parts = ["cast", subcommand] + [str(a) for a in args]

        if rpc_url and "--rpc-url" not in args:
            cmd_parts += ["--rpc-url", rpc_url]

        # Inject private key for mutating operations
        if subcommand == "send":
            private_key = os.getenv(pk_env)
            if not private_key:
                return ToolResult.error(
                    f"cast send requires a private key. Set env var '{pk_env}'."
                )
            if "--private-key" not in args:
                cmd_parts += ["--private-key", private_key]

        logger.info(f"[cast] Running: {' '.join(cmd_parts[:5])} ...")

        # Wrap with OS-level sandbox
        cast_shell_cmd = " ".join(shlex.quote(p) for p in cmd_parts)
        cwd_str = str(ctx.repo_path or ".")
        sandbox_opts = SandboxOptions(
            allow_network=True,
            writable_paths=[cwd_str],
            working_dir=cwd_str,
        )
        cast_shell_cmd = SandboxManager.wrapWithSandbox(
            cast_shell_cmd, "/bin/bash", sandbox_opts, dangerously_disable=disable_sandbox
        )

        try:
            result = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: subprocess.run(
                    ["bash", "-c", cast_shell_cmd],
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                    cwd=cwd_str,
                )
            )
        except subprocess.TimeoutExpired:
            return ToolResult.error(f"cast {subcommand} timed out after {timeout}s")
        except Exception as e:
            return ToolResult.error(f"cast error: {e}")

        stdout = result.stdout.strip()
        stderr = result.stderr.strip()
        passed = result.returncode == 0

        if not passed:
            return ToolResult.error(
                f"cast {subcommand} failed (exit {result.returncode}):\n"
                f"{stdout}\n{stderr}"
            )

        return ToolResult.success(
            stdout or "(no output)",
            exit_code=result.returncode,
            subcommand=subcommand,
        )
