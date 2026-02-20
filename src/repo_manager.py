import os
import subprocess
import shutil
from typing import Optional

import stat

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

    def clone_repo(self, url: str) -> str:
        """
        Clones a repository from a given URL into the workspace directory.
        If url is a local directory, it copies it to the workspace.
        Returns the path to the cloned/copied repository.
        """
        # Extract folder name from URL/Path
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
        else:
            try:
                # Clone without --recursive initially to avoid submodule failures during clone
                # Foundry dependencies will be handled by 'forge install' or manual submodule update
                subprocess.run(["git", "clone", url, target_path], check=True, capture_output=True)
                print("Clone successful (non-recursive).")
            except subprocess.CalledProcessError as e:
                print(f"Error cloning repository: {e.stderr.decode()}")
                raise
            
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
                # Run forge install
                # Note: 'forge install' might require git submodules which are handled by forge but we need to ensure we're inside the repo
                subprocess.run(["forge", "install"], cwd=repo_path, check=True, capture_output=True)
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
