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

    def _setup_from_real_repo(self) -> None:
        logger.info(f"[Sandbox] Setting up sandbox from {self.repo_path}")

        for item in self.repo_path.iterdir():
            if item.name == "lib":
                continue  # handled separately below
            dest = self.tmp_dir / item.name
            if item.is_dir():
                shutil.copytree(str(item), str(dest), dirs_exist_ok=True, symlinks=False)
            else:
                shutil.copy2(str(item), str(dest))

        # Symlink lib/ — works because repo_path is now on /tmp/ (Linux fs)
        original_lib = self.repo_path / "lib"
        sandbox_lib = self.tmp_dir / "lib"
        if original_lib.exists():
            try:
                sandbox_lib.symlink_to(original_lib.resolve())
                logger.info(f"[Sandbox] Symlinked lib/ from {original_lib.resolve()}")
            except OSError as e:
                # Windows commonly blocks symlink creation without elevated privileges.
                if os.name == "nt":
                    shutil.copytree(str(original_lib), str(sandbox_lib), dirs_exist_ok=True, symlinks=False)
                    logger.info(f"[Sandbox] Symlink unavailable on Windows, copied lib/ instead: {e}")
                else:
                    raise
        
        test_dir = self.tmp_dir / "test"
        test_dir.mkdir(exist_ok=True)
        print(f"[Sandbox] Ready at {self.tmp_dir}, lib exists: {sandbox_lib.exists()}")

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