"""
Framework detection — nested-aware.

Detects Foundry, Hardhat, and Brownie projects at any nesting level
in the repository tree, not just the root directory.
"""

from __future__ import annotations

import logging
import os
import subprocess

from src.ingestion.models import FrameworkInstance

logger = logging.getLogger(__name__)

# Directories to skip during recursive scanning
_SKIP_DIRS = frozenset(
    {
        "node_modules",
        ".git",
        ".github",
        "__pycache__",
        "coverage",
        "dist",
        "build",
        "out",
        "cache",
        "artifacts",
        ".venv",
        "venv",
    }
)


class FrameworkDetector:
    """Detects build frameworks across a repository tree."""

    # ──────────────────────────────────────────────────────────
    #  Public API
    # ──────────────────────────────────────────────────────────

    @staticmethod
    def detect_at(directory: str) -> str | None:
        """
        Detect the primary framework at a specific directory.

        Returns "foundry" | "hardhat" | "brownie" | None.
        """
        if FrameworkDetector._is_foundry(directory):
            return "foundry"
        if FrameworkDetector._is_hardhat(directory):
            return "hardhat"
        if FrameworkDetector._is_brownie(directory):
            return "brownie"
        return None

    @staticmethod
    def detect_all(repo_path: str, max_depth: int = 4) -> list[FrameworkInstance]:
        """
        Recursively detect all framework instances in the repo tree.

        Scans up to *max_depth* levels deep to find nested projects
        (e.g. packages/contracts with its own foundry.toml).
        """
        instances: list[FrameworkInstance] = []
        repo_path = os.path.abspath(repo_path)

        for current_dir, subdirs, files in os.walk(repo_path):
            # Compute depth relative to repo root
            rel = os.path.relpath(current_dir, repo_path)
            depth = 0 if rel == "." else rel.count(os.sep) + 1
            if depth > max_depth:
                subdirs.clear()
                continue

            # Prune skip-dirs
            subdirs[:] = [d for d in subdirs if d not in _SKIP_DIRS]

            fw = FrameworkDetector.detect_at(current_dir)
            if fw:
                config_file = FrameworkDetector._config_file_for(current_dir, fw)
                instances.append(
                    FrameworkInstance(
                        framework=fw,
                        path=current_dir,
                        config_file=config_file,
                    )
                )
                # Don't recurse into subdirs of a detected framework root —
                # they belong to this framework's compilation unit.
                # Exception: we continue if this is the repo root to find nested ones.
                if current_dir != repo_path:
                    subdirs.clear()

        return instances

    # ──────────────────────────────────────────────────────────
    #  Framework Setup (migrated from AnalysisEngine)
    # ──────────────────────────────────────────────────────────

    @staticmethod
    def ensure_foundry_config(directory: str) -> bool:
        """
        Create foundry.toml when missing so CryticCompile detects Foundry.

        Some repos use forge without foundry.toml; forge infers config
        from lib/, but CryticCompile requires foundry.toml.
        """
        toml_path = os.path.join(directory, "foundry.toml")
        if os.path.exists(toml_path):
            return True

        lib_forge = os.path.isdir(os.path.join(directory, "lib", "forge-std")) or os.path.isdir(
            os.path.join(directory, "lib", "solmate")
        )
        if not lib_forge:
            return False

        try:
            result = subprocess.run(
                ["forge", "config", "--basic"],
                capture_output=True,
                text=True,
                timeout=10,
                cwd=directory,
            )
            if result.returncode == 0 and result.stdout.strip():
                content = result.stdout
                # Handle repos that keep tests in src/test
                if os.path.isdir(os.path.join(directory, "src", "test")) and "test =" not in content:
                    content = content.rstrip() + '\ntest = "src/test"\nscript = "scripts"\n'
                with open(toml_path, "w") as f:
                    f.write(content)
                print(f"  Created foundry.toml at {directory} (forge config --basic).")
                return True
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        return False

    @staticmethod
    def pre_build_foundry(directory: str) -> bool:
        """Run forge build before Slither so compilation artifacts are cached."""
        try:
            print(f"  Running forge build in {directory}...")
            result = subprocess.run(
                ["forge", "build"],
                capture_output=True,
                text=True,
                timeout=300,
                cwd=directory,
            )
            if result.returncode == 0:
                print("  forge build succeeded.")
                return True
            else:
                print(f"  forge build failed (exit {result.returncode}): {result.stderr[:300]}")
                return False
        except FileNotFoundError:
            print("  Warning: 'forge' not found, skipping pre-build.")
            return False
        except subprocess.TimeoutExpired:
            print("  Warning: forge build timed out after 300s.")
            return False

    @staticmethod
    def setup_hardhat_project(directory: str) -> tuple[str, list[str]]:
        """
        Prepare a Hardhat/npm project for Slither analysis.

        Returns (solc_args, solc_remaps) ready to pass to Slither.
        """
        print(f"  Hardhat project detected at {directory}.")

        # Step 1 — install node_modules
        node_modules = os.path.join(directory, "node_modules")
        if not os.path.isdir(node_modules):
            if FrameworkDetector._is_npm_available():
                print("  Running npm install...")
                try:
                    result = subprocess.run(
                        ["npm", "install"],
                        capture_output=True,
                        text=True,
                        timeout=300,
                        cwd=directory,
                    )
                    if result.returncode == 0:
                        print("  npm install succeeded.")
                    else:
                        print(f"  npm install failed (exit {result.returncode}): {result.stderr[:300]}")
                except subprocess.TimeoutExpired:
                    print("  npm install timed out after 300s.")
            else:
                print(
                    "  WARNING: npm/npx not found. Cannot install Hardhat dependencies.\n"
                    "  Install Node.js (https://nodejs.org) to enable full Hardhat support.\n"
                    "  Attempting per-file analysis with minimal remappings..."
                )

        # Step 2 — build remappings
        remaps: list[str] = []
        solc_args = ""

        if os.path.isdir(node_modules):
            try:
                for entry in os.scandir(node_modules):
                    if entry.name.startswith("@") and entry.is_dir():
                        remaps.append(f"{entry.name}=node_modules/{entry.name}")
            except Exception as e:
                logger.warning(f"Could not scan node_modules: {e}")

            common_scoped = ["@openzeppelin", "@uniswap", "@aave", "@chainlink", "@gnosis"]
            for pkg in common_scoped:
                pkg_path = os.path.join(node_modules, pkg.lstrip("@").split("/")[0] if "/" in pkg else pkg)
                # Handle scoped packages
                pkg_path_full = os.path.join(node_modules, pkg)
                if os.path.isdir(pkg_path_full):
                    mapping = f"{pkg}=node_modules/{pkg}"
                    if mapping not in remaps:
                        remaps.append(mapping)

            solc_args = "--base-path . --include-path node_modules"
        else:
            print("  node_modules not found. Remappings will be minimal.")

        if remaps:
            print(f"  Applied {len(remaps)} npm remapping(s): {', '.join(remaps[:5])}")

        return solc_args, remaps

    # ──────────────────────────────────────────────────────────
    #  Private Helpers
    # ──────────────────────────────────────────────────────────

    @staticmethod
    def _is_foundry(directory: str) -> bool:
        if os.path.exists(os.path.join(directory, "foundry.toml")):
            return True
        if os.path.isdir(os.path.join(directory, "lib", "forge-std")) or os.path.isdir(
            os.path.join(directory, "lib", "solmate")
        ):
            return True
        return False

    @staticmethod
    def _is_hardhat(directory: str) -> bool:
        return os.path.exists(os.path.join(directory, "hardhat.config.js")) or os.path.exists(
            os.path.join(directory, "hardhat.config.ts")
        )

    @staticmethod
    def _is_brownie(directory: str) -> bool:
        return os.path.exists(os.path.join(directory, "brownie-config.yaml"))

    @staticmethod
    def _is_npm_available() -> bool:
        try:
            subprocess.run(
                ["npm", "--version"],
                capture_output=True,
                timeout=5,
                check=True,
            )
            return True
        except Exception:
            return False

    @staticmethod
    def _config_file_for(directory: str, framework: str) -> str:
        if framework == "foundry":
            p = os.path.join(directory, "foundry.toml")
            return p if os.path.exists(p) else "lib/forge-std"
        if framework == "hardhat":
            for name in ("hardhat.config.js", "hardhat.config.ts"):
                p = os.path.join(directory, name)
                if os.path.exists(p):
                    return p
        if framework == "brownie":
            return os.path.join(directory, "brownie-config.yaml")
        return ""
