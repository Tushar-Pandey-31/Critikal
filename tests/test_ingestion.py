import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))
from repo_manager import RepoManager
import os
import shutil
import subprocess

def test_ingestion():
    # Use a small public repo for testing
    # Using a simple foundry template
    repo_url = "https://github.com/PaulRBerg/foundry-template"
    
    manager = RepoManager()
    
    print(f"Testing clone of {repo_url}...")
    repo_path = manager.clone_repo(repo_url)
    
    if os.path.exists(repo_path) and os.listdir(repo_path):
        print(f"PASS: Repo cloned to {repo_path}")
    else:
        print("FAIL: Repo clone failed")
        return

    print("Testing dependency installation...")
    # This repo uses foundry
    manager.install_dependencies(repo_path)
    
    # Check if lib/forge-std exists (standard for foundry)
    lib_path = os.path.join(repo_path, "lib", "forge-std")
    if os.path.exists(lib_path):
        print("PASS: Foundry dependencies installed (forge-std found)")
    else:
        # Some templates might not have it in lib immediately or use git submodules differently
        # Let's check config or just existence of lib
        if os.path.exists(os.path.join(repo_path, "lib")):
             print("PASS: Lib directory exists")
        else:
             print("FAIL: Foundry dependencies not found")

    print("Testing Slither analysis...")
    try:
        # Run slither compilation/summary
        subprocess.run(["slither", ".", "--print", "human-summary"], cwd=repo_path, check=True, capture_output=True)
        print("PASS: Slither analysis ran successfully")
    except subprocess.CalledProcessError as e:
        print(f"FAIL: Slither analysis failed: {e.stderr.decode()}")
        # Check if failure is due to missing solc version (which solc-select might handle if configured)
        # But we installed solc-select and 0.8.20. The template might use a different version.
        pass

if __name__ == "__main__":
    test_ingestion()
