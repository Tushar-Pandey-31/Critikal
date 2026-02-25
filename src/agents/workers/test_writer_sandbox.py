import subprocess
import tempfile
import shutil
from dataclasses import dataclass
from pathlib import Path
import logging
import os
import stat

logger = logging.getLogger(__name__)

@dataclass
class Result:
    success: bool
    stdout: str
    stderr: str

class SandboxManager:
    """Manages an isolated temp environment for running Foundry tests."""
    
    def __init__(self, repo_path: str | None = None):
        self.tmp_dir: Path = Path(tempfile.mkdtemp())
        self.repo_path: Path | None = Path(repo_path) if repo_path else None
        
    def setup_foundry_project(self) -> None:
        if self.repo_path and self.repo_path.exists():
            self._setup_from_real_repo()
        else:
            self._setup_forge_init()

    def _resolve_foundry_root(self, base: Path) -> Path:
        """
        Find the directory that actually contains foundry.toml, starting from base.

        Handles repos where the Foundry project lives in a subdirectory, e.g.:
            ethernaut/             <- base (repo root)
            ethernaut/contracts/   <- actual Foundry root (has foundry.toml + lib/)

        Priority:
            1. base itself has foundry.toml -> return base
            2. A well-known subdirectory name has foundry.toml -> return that
            3. Any immediate child directory has foundry.toml -> return first match
            4. Fallback: return base and warn
        """
        if (base / "foundry.toml").exists():
            return base

        for name in ("contracts", "src", "protocol", "packages"):
            candidate = base / name
            if candidate.is_dir() and (candidate / "foundry.toml").exists():
                return candidate

        try:
            for child in sorted(base.iterdir()):
                if child.is_dir() and (child / "foundry.toml").exists():
                    return child
        except PermissionError:
            pass

        logger.warning(
            f"[Sandbox] Could not find foundry.toml under {base}. "
            f"Using base path as-is -- lib/ may not be found."
        )
        return base

    def _setup_from_real_repo(self) -> None:
        logger.info(f"[Sandbox] Setting up sandbox from {self.repo_path}")

        # Resolve the actual Foundry project root -- may differ from repo root.
        # e.g. ethernaut repo root -> ethernaut/contracts (where foundry.toml lives)
        foundry_root = self._resolve_foundry_root(self.repo_path)
        if foundry_root != self.repo_path:
            logger.info(
                f"[Sandbox] Foundry project root resolved to subdirectory: "
                f"{foundry_root}  (repo root was {self.repo_path})"
            )

        original_lib = foundry_root / "lib"
        sandbox_lib = self.tmp_dir / "lib"

        # Copy everything from the Foundry root except lib/
        for item in foundry_root.iterdir():
            if item.name == "lib":
                continue
            dest = self.tmp_dir / item.name
            if item.is_dir():
                shutil.copytree(str(item), str(dest), dirs_exist_ok=True, symlinks=False)
            else:
                shutil.copy2(str(item), str(dest))

        # Symlink lib/ -- fast and correct on Linux
        if original_lib.exists():
            resolved = original_lib.resolve()
            if not resolved.exists():
                logger.warning(
                    f"[Sandbox] lib/ symlink target does not exist after resolve: "
                    f"{resolved}. Falling back to copytree."
                )
                shutil.copytree(str(original_lib), str(sandbox_lib),
                                dirs_exist_ok=True, symlinks=False)
            else:
                try:
                    sandbox_lib.symlink_to(resolved)
                    logger.info(f"[Sandbox] Symlinked lib/ -> {resolved}")
                except OSError as e:
                    if os.name == "nt":
                        shutil.copytree(str(original_lib), str(sandbox_lib),
                                        dirs_exist_ok=True, symlinks=False)
                        logger.info(f"[Sandbox] Windows: copied lib/ instead of symlinking: {e}")
                    else:
                        logger.error(
                            f"[Sandbox] Unexpected symlink failure on Linux -- "
                            f"falling back to copytree. Error: {e}"
                        )
                        shutil.copytree(str(original_lib), str(sandbox_lib),
                                        dirs_exist_ok=True, symlinks=False)
        else:
            logger.error(
                f"[Sandbox] CRITICAL: lib/ not found at {original_lib}. "
                f"All dependency imports will fail. "
                f"Foundry root used: {foundry_root}  "
                f"(repo_path passed in: {self.repo_path})"
            )

        # Wipe any test/ that was copied from the repo — we only want our
        # generated ExploitTest.t.sol, not the repo's existing test suite.
        # Pre-existing repo tests import the full src/ tree and will break
        # the build if src/ has been pruned or is incomplete.
        sandbox_test_dir = self.tmp_dir / "test"
        if sandbox_test_dir.exists():
            shutil.rmtree(sandbox_test_dir)
        sandbox_test_dir.mkdir(parents=True, exist_ok=True)

        lib_exists = sandbox_lib.exists()
        print(f"[Sandbox] Ready at {self.tmp_dir}, lib exists: {lib_exists}")
        if not lib_exists:
            print(
                f"[Sandbox] WARNING: lib/ is missing -- all dependency imports will fail!\n"
                f"          Foundry root used: {foundry_root}\n"
                f"          repo_path received: {self.repo_path}"
            )

    def _setup_forge_init(self) -> None:
        """Fallback: initialize a blank Foundry project."""
        res = self.run("forge init --force")
        if not res.success:
            raise RuntimeError(
                f"Failed to initialize Foundry project in {self.tmp_dir}:\n{res.stderr}"
            )



    def write_test_file(self, filename: str, content: str) -> None:
        file_path = self.tmp_dir / filename
        file_path.parent.mkdir(parents=True, exist_ok=True)
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(content)

    def read_source_file(self, relative_path: str) -> str | None:
        file_path = self.tmp_dir / relative_path
        if file_path.exists():
            try:
                return file_path.read_text(encoding='utf-8')
            except Exception as e:
                logger.warning(f"[Sandbox] Could not read {relative_path}: {e}")
        return None

    def find_contract_file(self, contract_name: str) -> str | None:
        search_dirs = ["src", "contracts", "."]
        for search_dir in search_dirs:
            base = self.tmp_dir / search_dir
            if not base.exists():
                continue
            for sol_file in base.rglob("*.sol"):
                try:
                    content = sol_file.read_text(encoding='utf-8', errors='replace')
                    if f"contract {contract_name}" in content:
                        return str(sol_file.relative_to(self.tmp_dir))
                except Exception:
                    continue
        return None

    def get_src_path(self) -> str:
        """Return the source directory from foundry.toml (e.g. 'src' or 'contracts')."""
        toml_file = self.tmp_dir / "foundry.toml"
        if toml_file.exists():
            content = toml_file.read_text()
            for line in content.splitlines():
                line = line.strip()
                if line.startswith("src ="):
                    val = line.split("=", 1)[1].strip().strip('"')
                    if val and (self.tmp_dir / val).exists():
                        return val
        return "src" if (self.tmp_dir / "src").exists() else "."

    def get_test_path(self) -> str:
        """Return the test directory path from foundry.toml (e.g. 'test' or 'src/test')."""
        toml_file = self.tmp_dir / "foundry.toml"
        if toml_file.exists():
            content = toml_file.read_text()
            for line in content.splitlines():
                line = line.strip()
                if line.startswith("test ="):
                    val = line.split("=", 1)[1].strip().strip('"')
                    if val:
                        return val
        return "test"

    def get_remappings(self) -> dict[str, str]:
        remappings: dict[str, str] = {}

        remap_file = self.tmp_dir / "remappings.txt"
        if remap_file.exists():
            for line in remap_file.read_text().splitlines():
                line = line.strip()
                if "=" in line:
                    alias, target = line.split("=", 1)
                    remappings[alias.strip()] = target.strip()
            return remappings

        toml_file = self.tmp_dir / "foundry.toml"
        if toml_file.exists():
            from src.agents.workers.test_writer_worker import TestWriterWorker
            return TestWriterWorker._parse_toml_remappings(toml_file.read_text())

        return remappings

    def run(self, cmd: str) -> Result:
        try:
            proc = subprocess.run(
                cmd,
                cwd=str(self.tmp_dir),
                shell=True,
                capture_output=True,
                text=True,
                encoding='utf-8',
                errors='replace',
                timeout=120
            )
            return Result(
                success=(proc.returncode == 0),
                stdout=proc.stdout,
                stderr=proc.stderr
            )
        except subprocess.TimeoutExpired as e:
            return Result(
                success=False,
                stdout="",
                stderr=f"Command timed out after {e.timeout} seconds."
            )
        except Exception as e:
            return Result(
                success=False,
                stdout="",
                stderr=str(e)
            )

    def cleanup(self) -> None:
        try:
            if self.tmp_dir.exists():
                def handle_remove_readonly(func, path, exc):
                    os.chmod(path, stat.S_IWRITE)
                    func(path)
                shutil.rmtree(self.tmp_dir, onerror=handle_remove_readonly)
        except Exception as e:
            logger.warning(f"Failed to cleanup temp dir {self.tmp_dir}: {e}")