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
    
    def __init__(self):
        self.tmp_dir: Path = Path(tempfile.mkdtemp())
        
    def setup_foundry_project(self) -> None:
        """Initializes a new Foundry project in the temp directory."""
        # Use forge init --force to init a directory that exists
        cmd = ["forge", "init", "--force"]
        res = self.run(" ".join(cmd))
        if not res.success:
            raise RuntimeError(f"Failed to initialize Foundry project in {self.tmp_dir}:\n{res.stderr}")

    def write_test_file(self, filename: str, content: str) -> None:
        """Writes a file to the sandbox."""
        file_path = self.tmp_dir / filename
        # Ensure parent directories exist
        file_path.parent.mkdir(parents=True, exist_ok=True)
        # Handle Windows paths correctly by using pathlib but write as UTF-8 text
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(content)

    def run(self, cmd: str) -> Result:
        """Executes a command inside the sandbox directory with a 60-second timeout."""
        try:
            # We use shell=True to easily parse arguments without shlex,
            # which might behave differently on Windows vs POSIX
            proc = subprocess.run(
                cmd,
                cwd=str(self.tmp_dir),
                shell=True,
                capture_output=True,
                text=True,
                timeout=60
            )
            return Result(
                success=(proc.returncode == 0),
                stdout=proc.stdout,
                stderr=proc.stderr
            )
        except subprocess.TimeoutExpired as e:
            return Result(
                success=False,
                stdout=(e.stdout.decode() if isinstance(e.stdout, bytes) else str(e.stdout)) if e.stdout else "",
                stderr=(f"Command timed out after {e.timeout} seconds.\n" + 
                       ((e.stderr.decode() if isinstance(e.stderr, bytes) else str(e.stderr)) if e.stderr else ""))
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
                import stat
                def handle_remove_readonly(func, path, exc):
                    os.chmod(path, stat.S_IWRITE)
                    func(path)
                shutil.rmtree(self.tmp_dir, onerror=handle_remove_readonly)
        except Exception as e:
            logger.warning(f"Failed to cleanup temp dir {self.tmp_dir}: {e}")
