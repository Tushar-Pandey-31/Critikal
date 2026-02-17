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
        import traceback
        if not os.path.exists(repo_path):
            print(f"Error: Path {repo_path} does not exist.")
            return None

        print(f"Starting Slither analysis on: {repo_path}")
        original_cwd = os.getcwd()
        try:
            os.chdir(repo_path)
            print(f"Changed CWD to {os.getcwd()}")
            
            # Check solc version
            try:
                res = subprocess.run(["solc", "--version"], capture_output=True, text=True)
                print(f"Current solc version: {res.stdout.strip()}")
            except Exception as e:
                print(f"Could not check solc version: {e}")

            # Try initializing Slither directly with '.'
            try:
                slither = Slither('.')
                print("Slither initialized successfully on first try.")
                return slither
            except Exception as e:
                error_msg = str(e)
                print(f"Slither initialization failed: {error_msg}")
                
                # Check for solc version error but also try fallback to per-file compilation
                # if it was a directory compilation error.
                
                # Fallback: try per-file if it's a directory
                # This works around CryticCompile/SoLC issues with raw directories
                if os.path.exists('Vulnerable.sol') or any(f.endswith('.sol') for f in os.listdir('.')):
                     print("Attempting per-file compilation fallback...")
                     sol_files = [f for f in os.listdir('.') if f.endswith('.sol')]
                     combined_slither = None
                     for f in sol_files:
                         try:
                             print(f"Compiling {f}...")
                             s = Slither(f)
                             if combined_slither is None:
                                 combined_slither = s
                             else:
                                 combined_slither.contracts.extend(s.contracts)
                         except Exception as ex:
                             print(f"Failed to compile {f}: {ex}")
                     
                     if combined_slither:
                         print("Per-file compilation successful.")
                         return combined_slither

                # Check for solc version error (original logic)
                version = self._detect_solc_version('.')
                if version:
                    print(f"Detected required solc version: {version}")
                    if self._switch_solc_version(version):
                        print("Retrying Slither analysis...")
                        
                        try:
                            slither = Slither('.')
                            print("Slither initialized successfully after version switch.")
                            return slither
                        except Exception as e2:
                             # Try per-file compilation AGAIN after version switch
                             print(f"Retry failed: {e2}. Trying per-file fallback with new version...")
                             sol_files = [f for f in os.listdir('.') if f.endswith('.sol')]
                             combined_slither = None
                             for f in sol_files:
                                 try:
                                     s = Slither(f)
                                     if combined_slither is None:
                                         combined_slither = s
                                     else:
                                         combined_slither.contracts.extend(s.contracts)
                                 except Exception as ex:
                                     print(f"Failed to compile {f}: {ex}")
                            
                             if combined_slither:
                                 return combined_slither
                                 
                             return None
                    else:
                        print("Failed to switch solc version.")
                        return None
                else:
                    print("Could not detect solc version from files.")
                    return None
        finally:
            os.chdir(original_cwd)
            print(f"Restored CWD to {original_cwd}")

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
