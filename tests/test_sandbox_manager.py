import pytest
import os
import shutil
from unittest.mock import patch, MagicMock
from pathlib import Path
from src.agents.workers.test_writer_sandbox import SandboxManager, Result

def test_sandbox_creates_temp_dir():
    manager = SandboxManager()
    assert manager.tmp_dir.exists()
    assert manager.tmp_dir.is_dir()
    manager.cleanup()
    assert not manager.tmp_dir.exists()

@patch.object(SandboxManager, 'run')
def test_setup_foundry_project_success(mock_run):
    manager = SandboxManager()
    mock_run.return_value = Result(success=True, stdout="success", stderr="")
    
    manager.setup_foundry_project()
    mock_run.assert_called_once()
    assert "forge init" in mock_run.call_args[0][0]
    
    manager.cleanup()

@patch.object(SandboxManager, 'run')
def test_setup_foundry_project_failure(mock_run):
    manager = SandboxManager()
    mock_run.return_value = Result(success=False, stdout="", stderr="error")
    
    # _setup_forge_init doesn't raise — it just runs the command
    manager.setup_foundry_project()
    mock_run.assert_called_once()
        
    manager.cleanup()

def test_write_test_file():
    manager = SandboxManager()

    filename = "test_sub/MyTest.t.sol"
    content = "contract MyTest {}"

    manager.write_test_file(filename, content)

    file_path = manager.tmp_dir / filename
    assert file_path.exists()
    written = file_path.read_text(encoding='utf-8')
    # SPDX header is auto-prepended if missing
    assert "SPDX-License-Identifier" in written
    assert "contract MyTest {}" in written

    manager.cleanup()

@patch('subprocess.run')
def test_run_command_success(mock_run):
    manager = SandboxManager()
    mock_run.return_value = MagicMock(returncode=0, stdout="ok", stderr="")
    
    res = manager.run("echo hi")
    assert res.success is True
    assert res.stdout == "ok"
    
    manager.cleanup()

@patch('subprocess.run')
def test_run_command_timeout(mock_run):
    import subprocess
    manager = SandboxManager()
    
    mock_run.side_effect = subprocess.TimeoutExpired(cmd="sleep", timeout=60, output=b"stuck", stderr=b"")
    
    res = manager.run("sleep 60")
    assert res.success is False
    assert "timed out after 60" in res.stderr
    assert res.stdout == ""
    
    manager.cleanup()

def test_cleanup_even_on_crash():
    manager = SandboxManager()
    dir_path = manager.tmp_dir
    
    assert dir_path.exists()
    
    try:
        raise ValueError("Simulated crash")
    except ValueError:
        manager.cleanup()
        
    assert not dir_path.exists()

# Test the real run functionality locally if possible
# (Using something simple like python or echo)
def test_real_subprocess_run():
    manager = SandboxManager()
    # Cross platform way to echo something via python
    res = manager.run('python3 -c "print(\'hello from sandbox\')"')
    
    assert res.success is True
    assert "hello from sandbox" in res.stdout
    
    manager.cleanup()
