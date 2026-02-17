import os
import subprocess
import shutil
from typing import Optional

class RepoManager:
    """
    Manages cloning of repositories and installation of dependencies.
    """
    def __init__(self, workspace_dir: str = "/app/data"):
        self.workspace_dir = workspace_dir
        if not os.path.exists(self.workspace_dir):
            os.makedirs(self.workspace_dir, exist_ok=True)

    def clone_repo(self, url: str) -> str:
        """
        Clones a repository from a given URL into the workspace directory.
        Returns the path to the cloned repository.
        """
        # Extract folder name from URL
        repo_name = url.strip().split("/")[-1]
        if repo_name.endswith(".git"):
            repo_name = repo_name[:-4]
        
        target_path = os.path.join(self.workspace_dir, repo_name)
        
        if os.path.exists(target_path):
            print(f"Directory {target_path} already exists. Removing it to clone fresh...")
            shutil.rmtree(target_path)
            
        print(f"Cloning {url} to {target_path}...")
        try:
            subprocess.run(["git", "clone", "--recursive", url, target_path], check=True, capture_output=True)
            print("Clone successful.")
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
                
        # Check for Hardhat
        if os.path.exists(os.path.join(repo_path, "hardhat.config.js")) or \
           os.path.exists(os.path.join(repo_path, "hardhat.config.ts")):
            print("Hardhat project detected.")
            try:
                subprocess.run(["npm", "install"], cwd=repo_path, check=True, capture_output=True)
                print("Hardhat dependencies installed.")
            except subprocess.CalledProcessError as e:
                print(f"Error installing Hardhat dependencies: {e.stderr.decode()}")

        print("Dependency installation checking complete.")
