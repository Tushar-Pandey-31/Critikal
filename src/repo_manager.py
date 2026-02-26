import logging
import os
import subprocess
import shutil
from typing import Optional

import stat

logger = logging.getLogger(__name__)

class RepoManager:
    """
    Manages cloning of repositories and installation of dependencies.
    """
    def __init__(self, workspace_dir: str = "/app/data"):
        self.workspace_dir = workspace_dir
        if not os.path.exists(self.workspace_dir):
            os.makedirs(self.workspace_dir, exist_ok=True)

    def _handle_remove_readonly(self, func, path, exc):
        os.chmod(path, stat.S_IWRITE)
        func(path)

    def _normalize_repo_url(self, url: str) -> str:
        """Convert GitHub HTTPS URLs to SSH format if possible."""
        if url.startswith("https://github.com/"):
            repo_path = url.replace("https://github.com/", "")
            if not repo_path.endswith(".git"):
                repo_path += ".git"
                return f"git@github.com:{repo_path}"
        return url

    def clone_repo(self, url: str) -> str:
        """
        Clones a repository from a given URL into the workspace directory.
        If url is a local directory, it copies it to the workspace.
        Returns the path to the cloned/copied repository.
        """
        # Extract folder name from URL/Path
        url = self._normalize_repo_url(url)
        repo_name = os.path.basename(os.path.normpath(url))
        if repo_name.endswith(".git"):
            repo_name = repo_name[:-4]
        
        target_path = os.path.join(self.workspace_dir, repo_name)
        
        if os.path.exists(target_path):
            print(f"Directory {target_path} already exists. Removing it to clone fresh...")
            try:
                shutil.rmtree(target_path, onerror=self._handle_remove_readonly)
            except Exception as e:
                print(f"shutil.rmtree failed: {e}. Trying system command...")
                abs_target = os.path.abspath(target_path)
                if os.name == 'nt':
                    # Windows specific robust delete. Use powershell for better path handling.
                    subprocess.run(["powershell", "-Command", f"Remove-Item -Recurse -Force '{abs_target}'"], check=False)
                else:
                    subprocess.run(["rm", "-rf", abs_target], check=False)
            
            # Double check
            if os.path.exists(target_path):
                print(f"Warning: Failed to completely remove {target_path}. Clone may fail.")
            
        # Check if local directory
        if os.path.isdir(url):
            print(f"Copying local directory {url} to {target_path}...")
            shutil.copytree(url, target_path)
            print("Copy successful.")
            _init_submodules(target_path)
        else:
            try:
                # Clone with --depth 1 to avoid pulling full history
                # Use --recurse-submodules so lib/ dependencies (solmate, forge-std, etc.) are populated
                subprocess.run(
                    ["git", "clone", "--depth", "1", "--recurse-submodules", "--shallow-submodules", url, target_path],
                    check=True,
                    capture_output=True,
                    timeout=120,
                )
                print("Clone successful (with submodules).")
            except (subprocess.TimeoutExpired, subprocess.CalledProcessError) as e:
                if isinstance(e, subprocess.CalledProcessError):
                    print("Warning: Clone with submodules failed. Retrying without submodules...")
                else:
                    print("Warning: Clone timed out. Retrying without submodules...")
                subprocess.run(["git", "clone", "--depth", "1", url, target_path], check=True, capture_output=True)
                _init_submodules(target_path)
            # Ensure submodules are populated even if clone claimed success (some hosts skip them)
            _init_submodules(target_path)

        # Force forge install so lib/forge-std is populated before sandbox copies
        _force_forge_install(target_path)

        return target_path

    def install_dependencies(self, repo_path: str):
        """
        Detects project type (Foundry or Hardhat) and installs dependencies.
        """
        print(f"Checking for dependencies in {repo_path}...")
        
        # Check for Foundry
        if os.path.exists(os.path.join(repo_path, "foundry.toml")):
            print("Foundry project detected.")
            try:
                subprocess.run(["forge", "install", "--shallow"], cwd=repo_path, check=True, capture_output=True)
                print("Foundry dependencies installed.")
            except subprocess.CalledProcessError as e:
                print(f"Error installing Foundry dependencies: {e.stderr.decode()}")
            except FileNotFoundError:
                print("Warning: 'forge' executable not found. Skipping Foundry dependency installation.")
                
        # Check for Hardhat
        if os.path.exists(os.path.join(repo_path, "hardhat.config.js")) or \
           os.path.exists(os.path.join(repo_path, "hardhat.config.ts")):
            print("Hardhat project detected.")
            try:
                subprocess.run(["npm", "install"], cwd=repo_path, check=True, capture_output=True)
                print("Hardhat dependencies installed.")
            except subprocess.CalledProcessError as e:
                print(f"Error installing Hardhat dependencies: {e.stderr.decode()}")
            except FileNotFoundError:
                print("Warning: 'npm' executable not found. Skipping Hardhat dependency installation.")

        print("Dependency installation checking complete.")


def _init_submodules(repo_path: str) -> None:
    """Initialize git submodules when .gitmodules exists (e.g. lib/solmate, lib/forge-std)."""
    gitmodules = os.path.join(repo_path, ".gitmodules")
    if not os.path.exists(gitmodules):
        return
    try:
        subprocess.run(
            ["git", "submodule", "update", "--init", "--recursive"],
            cwd=repo_path,
            check=True,
            capture_output=True,
            timeout=180,
        )
        logger.info("[RepoManager] Git submodules initialized.")
    except Exception as e:
        logger.warning(f"[RepoManager] Could not initialize submodules: {e}")


def _force_forge_install(repo_path: str) -> None:
    """Run 'forge install --shallow' after clone to guarantee lib/forge-std is present."""
    toml = os.path.join(repo_path, "foundry.toml")
    if not os.path.exists(toml):
        logger.info("[RepoManager] No foundry.toml — skipping forge install.")
        return
    try:
        logger.info("[RepoManager] Running forge install --shallow to populate lib/...")
        res = subprocess.run(
            ["forge", "install", "--shallow"],
            cwd=repo_path,
            capture_output=True,
            text=True,
            timeout=180,
        )
        if res.returncode != 0:
            logger.warning(f"[RepoManager] forge install warning (non-zero): {res.stderr[:300]}")
        else:
            forge_std = os.path.join(repo_path, "lib", "forge-std", "src", "Test.sol")
            exists = os.path.exists(forge_std)
            logger.info(f"[RepoManager] forge install complete. forge-std/Test.sol exists: {exists}")
    except FileNotFoundError:
        logger.warning("[RepoManager] 'forge' not found — skipping forge install.")
    except subprocess.TimeoutExpired:
        logger.warning("[RepoManager] forge install timed out after 180s — continuing anyway.")
    except Exception as e:
        logger.warning(f"[RepoManager] forge install error: {e}")
