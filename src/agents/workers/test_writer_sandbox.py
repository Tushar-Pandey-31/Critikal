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
        """BUG-009 fix: delegates to shared utility."""
        from src.utils.foundry_root import resolve_foundry_root
        resolved = resolve_foundry_root(base)
        if resolved != base:
            logger.info(f"[Sandbox] Foundry root resolved: {base} -> {resolved}")
        return resolved

    def _setup_from_real_repo(self) -> None:
        foundry_root = self._resolve_foundry_root(self.repo_path)
        logger.info(f"[Sandbox] === SETUP START === tmp={self.tmp_dir} source={foundry_root}")

        # 1. Extract pristine remappings BEFORE the git submodules break in /tmp/
        remappings_content = ""
        if foundry_root and foundry_root.exists():
            try:
                proc = subprocess.run(
                    ["forge", "remappings"],
                    cwd=str(foundry_root),
                    capture_output=True,
                    text=True
                )
                if proc.returncode == 0:
                    remappings_content = proc.stdout
                    logger.info(f"[Sandbox] Captured {len(remappings_content.splitlines())} remappings from original repo.")
            except Exception as e:
                logger.warning(f"[Sandbox] Failed to extract remappings: {e}")

        # 2. Copy the repo (submodules will break, but we'll bypass that)
        logger.info(f"[Sandbox] Copying repo tree to {self.tmp_dir}...")
        shutil.copytree(
            str(foundry_root),
            str(self.tmp_dir),
            dirs_exist_ok=True,
            ignore=shutil.ignore_patterns("out", "cache", "broadcast", "__pycache__")
        )
        logger.info("[Sandbox] copytree complete.")

        self._ensure_foundry_deps()

        # 3. Write explicit remappings.txt to force Foundry to recognize lib/
        # BUG-003 fix: Always write live forge remappings when available.
        remap_file = self.tmp_dir / "remappings.txt"
        if remappings_content:
            remap_file.write_text(remappings_content)
        elif not remap_file.exists():
            # Bare minimum fallback
            remap_file.write_text("forge-std/=lib/forge-std/src/\nds-test/=lib/forge-std/lib/ds-test/src/\n")

        # Clean test/ dir (we only want our ExploitTest.t.sol)
        test_dir = self.tmp_dir / "test"
        if test_dir.exists():
            shutil.rmtree(test_dir, ignore_errors=True)
        test_dir.mkdir(parents=True, exist_ok=True)

        forge_std_ok = (self.tmp_dir / "lib" / "forge-std" / "src" / "Test.sol").exists()
        logger.info(f"[Sandbox] Ready at {self.tmp_dir}, forge-std/Test.sol exists: {forge_std_ok}")
        if not forge_std_ok:
            src_lib = self.repo_path / "lib" if self.repo_path else None
            if src_lib and src_lib.exists():
                try:
                    contents = [p.name for p in src_lib.iterdir()]
                    logger.warning(f"[Sandbox] CRITICAL: forge-std missing! Original lib/ contents: {contents}")
                except Exception:
                    logger.warning("[Sandbox] CRITICAL: forge-std missing! Could not list original lib/ contents.")
            else:
                logger.warning("[Sandbox] CRITICAL: forge-std missing and original lib/ does not exist!")

    def _ensure_foundry_deps(self) -> None:
        """
        Ensures forge-std is present in the sandbox.
        Step 1: Copy whatever lib/ exists from original repo (may have solmate, ds-test, etc.)
        Step 2: Always check forge-std; install if missing (handles repos that don't include it).
        """
        # Step 1: Copy lib/ from original repo (may be partial — e.g. solmate has ds-test only)
        src_lib = self.repo_path / "lib" if self.repo_path else None
        if src_lib and src_lib.exists():
            logger.info(f"[Sandbox] Copying lib/ from {src_lib} ...")
            shutil.copytree(
                str(src_lib),
                str(self.tmp_dir / "lib"),
                dirs_exist_ok=True,
                symlinks=False
            )
            try:
                lib_contents = [p.name for p in (self.tmp_dir / "lib").iterdir()]
                logger.info(f"[Sandbox] lib/ copied. Contents: {lib_contents}")
            except Exception:
                logger.info("[Sandbox] lib/ copied (could not list contents).")

        # Step 2: Always check forge-std and install if missing
        forge_std_test = self.tmp_dir / "lib" / "forge-std" / "src" / "Test.sol"
        if forge_std_test.exists():
            logger.info("[Sandbox] forge-std/Test.sol confirmed present.")
            return

        logger.info("[Sandbox] forge-std missing — installing via forge install...")
        if not (self.tmp_dir / ".git").exists():
            self.run("git init")
        result = self.run("forge install foundry-rs/forge-std --no-git --quiet")

        if forge_std_test.exists():
            logger.info("[Sandbox] forge-std/Test.sol confirmed after forge install.")
        else:
            logger.warning(
                f"[Sandbox] forge install finished but forge-std/Test.sol STILL missing! "
                f"stderr={result.stderr[:200] if result.stderr else 'none'}"
            )

    def _setup_forge_init(self) -> None:
        self.run("forge init --force --quiet")

    # ──────────────────────────────────────────────────────────────
    # ALL METHODS BELOW ARE UNCHANGED FROM YOUR ORIGINAL FILE
    # ──────────────────────────────────────────────────────────────

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
        import shlex
        try:
            proc = subprocess.run(
                shlex.split(cmd),
                cwd=str(self.tmp_dir),
                shell=False,
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
            return Result(success=False, stdout="", stderr=f"Command timed out after {e.timeout} seconds.")
        except Exception as e:
            return Result(success=False, stdout="", stderr=str(e))

    def cleanup(self) -> None:
        try:
            if self.tmp_dir.exists():
                def handle_remove_readonly(func, path, exc):
                    os.chmod(path, stat.S_IWRITE)
                    func(path)
                shutil.rmtree(self.tmp_dir, onerror=handle_remove_readonly)
        except Exception as e:
            logger.warning(f"Failed to cleanup temp dir {self.tmp_dir}: {e}")