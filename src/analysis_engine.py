import os
import subprocess
import re
from slither.slither import Slither
from typing import Optional

class AnalysisEngine:
    def __init__(self):
        pass

    def run_analysis(self, repo_path: str) -> Optional[Slither]:
        """
        Runs Slither analysis on the given repository path.
        Handles solc version mismatches by installing and switching versions.
        """
        if not os.path.exists(repo_path):
            print(f"Error: Path {repo_path} does not exist.")
            return None

        try:
            # Try initializing Slither directly
            slither = Slither(repo_path)
            return slither
        except Exception as e:
            error_msg = str(e)
            print(f"Slither initialization failed: {error_msg}")
            
            # Check for solc version error
            # Slither often throws error related to solc version if it doesn't match
            # e.g., "Solc version 0.8.0 is not installed" or similar
            # Or sometimes it just fails to compile.
            
            # Let's try to detect the required version from the files in the repo
            version = self._detect_solc_version(repo_path)
            if version:
                print(f"Detected required solc version: {version}")
                if self._switch_solc_version(version):
                    print("Retrying Slither analysis...")
                    try:
                        slither = Slither(repo_path)
                        return slither
                    except Exception as e2:
                        print(f"Retry failed: {e2}")
                        return None
                else:
                    print("Failed to switch solc version.")
                    return None
            else:
                print("Could not detect solc version from files.")
                return None

    def _detect_solc_version(self, repo_path: str) -> Optional[str]:
        """
        Scans .sol files in the repo to find the pragma solidity version.
        Returns the highest version found (or the first one).
        """
        # Regex to find version: pragma solidity ^0.8.0; or pragma solidity 0.8.0;
        version_pattern = re.compile(r'pragma\s+solidity\s+[\^><=]*\s*(\d+\.\d+\.\d+)')
        
        for root, _, files in os.walk(repo_path):
            for file in files:
                if file.endswith(".sol"):
                    try:
                        with open(os.path.join(root, file), 'r', encoding='utf-8') as f:
                            content = f.read()
                            match = version_pattern.search(content)
                            if match:
                                return match.group(1)
                    except Exception as e:
                        print(f"Error reading file {file}: {e}")
        return None

    def _switch_solc_version(self, version: str) -> bool:
        """
        Uses solc-select to install and set the required solc version.
        """
        try:
            # Check if version is already installed
            # We can just try 'solc-select use <version>' first, if it fails, try install
            
            # subprocess.run(["solc-select", "install", version], check=True) # Ensure it is installed
            # This might take time, so let's check output if needed, but blind install is safer if check is fast
            
            print(f"Installing solc version {version}...")
            subprocess.run(["solc-select", "install", version], check=True, capture_output=True)
            
            print(f"Switching to solc version {version}...")
            subprocess.run(["solc-select", "use", version], check=True, capture_output=True)
            
            return True
        except subprocess.CalledProcessError as e:
            print(f"Error switching solc version: {e}")
            return False
