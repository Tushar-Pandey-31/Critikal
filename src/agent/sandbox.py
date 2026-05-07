"""
SandboxManager — OS-level process isolation for shell and forge execution.

Mirrors Claude Code's sandbox/sandbox-adapter.ts pattern:
  SandboxManager.wrapWithSandbox(command, shell, options?) -> wrapped_command

Linux:  bwrap (bubblewrap) — unshares PID/IPC/UTS namespaces, bind-mounts filesystem
macOS:  sandbox-exec — Apple's sandbox profile
Other:  no-op (returns command unchanged)

The BashTool and SandboxRunTool both use this. Per-call `dangerouslyDisableSandbox`
overrides the global sandbox policy, matching the Claude Code BashTool interface.
"""

import logging
import os
import platform
import shutil
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)

# Global sandbox policy — read from env
SANDBOX_ENABLED = os.getenv("CRITIKAL_SANDBOX", "1").lower() not in ("0", "false", "off")


@dataclass
class SandboxOptions:
    """Controls what the sandbox permits."""
    allow_network: bool = True          # Allow outbound network (needed for fork_url, API calls)
    writable_paths: list[str] = field(default_factory=list)  # Extra dirs to bind read-write
    readonly_paths: list[str] = field(default_factory=list)  # Extra dirs to bind read-only
    env_vars: dict[str, str] = field(default_factory=dict)   # Extra env vars to pass through
    working_dir: str | None = None       # Working directory inside sandbox


class SandboxManager:
    """
    Wraps shell commands with OS-level process isolation.

    Usage:
        wrapped = SandboxManager.wrapWithSandbox("forge test -vvv", "/bin/bash", options)
        subprocess.run(["bash", "-c", wrapped], ...)

    If bwrap/sandbox-exec is unavailable or sandboxing is globally disabled,
    returns the original command unchanged (no-op fallback).
    """

    _bwrap_checked: bool = False
    _bwrap_available: bool = False
    _sandbox_exec_checked: bool = False
    _sandbox_exec_available: bool = False

    @classmethod
    def is_available(cls) -> bool:
        """Whether sandbox wrapping is available on this platform."""
        system = platform.system()
        if system == "Linux":
            return cls._check_bwrap()
        elif system == "Darwin":
            return cls._check_sandbox_exec()
        return False

    @classmethod
    def _check_bwrap(cls) -> bool:
        if not cls._bwrap_checked:
            cls._bwrap_available = shutil.which("bwrap") is not None
            cls._bwrap_checked = True
            if cls._bwrap_available:
                logger.debug("[sandbox] bwrap available")
            else:
                logger.debug("[sandbox] bwrap not found — sandbox disabled on Linux")
        return cls._bwrap_available

    @classmethod
    def _check_sandbox_exec(cls) -> bool:
        if not cls._sandbox_exec_checked:
            cls._sandbox_exec_available = shutil.which("sandbox-exec") is not None
            cls._sandbox_exec_checked = True
        return cls._sandbox_exec_available

    @classmethod
    def wrapWithSandbox(
        cls,
        command: str,
        shell: str = "/bin/bash",
        options: SandboxOptions | None = None,
        dangerously_disable: bool = False,
    ) -> str:
        """
        Wrap a shell command with OS-level isolation.

        Args:
            command:            The shell command to execute.
            shell:              Shell binary (e.g. '/bin/bash').
            options:            Sandbox options (network, writable paths, etc.)
            dangerously_disable: Per-call override to bypass sandboxing.

        Returns:
            Wrapped command string, or original command if sandbox unavailable/disabled.
        """
        if dangerously_disable:
            logger.debug("[sandbox] dangerouslyDisableSandbox=true — running unsandboxed")
            return command

        if not SANDBOX_ENABLED:
            logger.debug("[sandbox] CRITIKAL_SANDBOX=0 — sandbox disabled globally")
            return command

        opts = options or SandboxOptions()
        system = platform.system()

        if system == "Linux" and cls._check_bwrap():
            return cls._wrap_bwrap(command, shell, opts)
        elif system == "Darwin" and cls._check_sandbox_exec():
            return cls._wrap_sandbox_exec(command, shell, opts)
        else:
            logger.debug(
                "[sandbox] No sandbox available on %s — running unsandboxed", system
            )
            return command

    @classmethod
    def _wrap_bwrap(cls, command: str, shell: str, opts: SandboxOptions) -> str:
        """Build a bwrap-wrapped command for Linux."""
        import shlex

        args = [
            "bwrap",
            # ── Filesystem ──
            # Bind the whole system read-only as base
            "--ro-bind", "/", "/",
            # Overlay /dev, /proc, /tmp fresh
            "--dev", "/dev",
            "--proc", "/proc",
            "--tmpfs", "/tmp",
            # ── Process isolation ──
            "--unshare-pid",
            "--unshare-ipc",
            "--unshare-uts",
            "--die-with-parent",
        ]

        # Network: share by default (needed for fork_url, API calls)
        if opts.allow_network:
            args += ["--share-net"]
        else:
            args += ["--unshare-net"]

        # Working directory: bind read-write
        if opts.working_dir and Path(opts.working_dir).exists():
            args += ["--bind", opts.working_dir, opts.working_dir]

        # User-supplied read-write paths
        for path in opts.writable_paths:
            if Path(path).exists():
                args += ["--bind", path, path]

        # User-supplied read-only paths (override the base ro-bind if needed)
        for path in opts.readonly_paths:
            if Path(path).exists():
                args += ["--ro-bind", path, path]

        # Foundry tooling: always read-only (forge, cast, anvil binaries + caches)
        foundry_home = Path(os.path.expanduser("~/.foundry"))
        if foundry_home.exists():
            args += ["--ro-bind", str(foundry_home), str(foundry_home)]

        # solc-select versions
        solc_home = Path(os.path.expanduser("~/.solc-select"))
        if solc_home.exists():
            args += ["--ro-bind", str(solc_home), str(solc_home)]

        # User home (read-only fallback — foundry/solc need this)
        home = Path.home()
        if home.exists() and str(home) != "/root":
            args += ["--ro-bind", str(home), str(home)]

        # ── Execute the shell ──
        args += ["--", shell, "-c", command]

        # Build env passthrough (bwrap clears env by default via --clearenv)
        # We use --setenv for critical vars
        env_args = []
        pass_through = [
            "PATH", "HOME", "USER", "LANG", "TERM",
            "ANTHROPIC_API_KEY", "GOOGLE_API_KEY", "OPENAI_API_KEY", "XAI_API_KEY",
            "ETHERSCAN_API_KEY", "ETH_RPC_URL", "FORK_URL", "DEPLOYER_PRIVATE_KEY",
        ]
        for var in pass_through:
            val = os.environ.get(var)
            if val:
                env_args += ["--setenv", var, val]

        for key, val in opts.env_vars.items():
            env_args += ["--setenv", key, val]

        # Insert env args right after "bwrap"
        full_args = [args[0]] + env_args + args[1:]
        return " ".join(shlex.quote(a) for a in full_args)

    @classmethod
    def _wrap_sandbox_exec(cls, command: str, shell: str, opts: SandboxOptions) -> str:
        """Build a sandbox-exec wrapped command for macOS."""
        import shlex
        import tempfile

        # Build a minimal sandbox profile
        network_rule = "(allow network*)" if opts.allow_network else "(deny network*)"

        profile_lines = [
            "(version 1)",
            "(allow default)",              # Start permissive
            "(deny process-fork)",          # No fork bombs
            "(deny file-write* (subpath \"/System\"))",
            "(deny file-write* (subpath \"/private/etc\"))",
            network_rule,
        ]

        # Add read-write permissions for writable paths
        for path in opts.writable_paths:
            profile_lines.append(f'(allow file-write* (subpath "{path}"))')

        profile = "\n".join(profile_lines)

        # Write profile to temp file (sandbox-exec takes a file path)
        profile_file = tempfile.NamedTemporaryFile(
            mode="w", suffix=".sb", delete=False, prefix="critikal_sb_"
        )
        profile_file.write(profile)
        profile_file.flush()
        profile_file.close()

        wrapped = (
            f"sandbox-exec -f {shlex.quote(profile_file.name)} "
            f"{shlex.quote(shell)} -c {shlex.quote(command)}; "
            f"__exit=$?; rm -f {shlex.quote(profile_file.name)}; exit $__exit"
        )
        return wrapped

    @classmethod
    def cleanupAfterCommand(cls) -> None:
        """Clean up any lingering sandbox state after a command completes."""
        # On Linux (bwrap), bwrap is a single process that exits with the command.
        # On macOS, we inline the profile cleanup in the command itself.
        pass

    @classmethod
    def refreshConfig(cls) -> None:
        """Re-read sandbox policy from environment."""
        global SANDBOX_ENABLED
        SANDBOX_ENABLED = os.getenv("CRITIKAL_SANDBOX", "1").lower() not in ("0", "false", "off")
        # Reset availability cache so next call re-checks
        cls._bwrap_checked = False
        cls._sandbox_exec_checked = False
