import os
import subprocess
import re
from slither.slither import Slither
from typing import Optional

class AnalysisEngine:
    def __init__(self):
        pass

    def run_analysis(self, repo_path: str, targets=None) -> Optional[Slither]:
        """
        Runs Slither analysis on the given repository path.
        Handles solc version mismatches by installing and switching versions.
        """
        import traceback
        if not os.path.exists(repo_path):
            print(f"Error: Path {repo_path} does not exist.")
            return None

        # Build list of targets (default to '.' if None)
        if targets is None:
            targets = ['.']
        elif isinstance(targets, str):
            targets = [targets]

        if os.path.isfile(repo_path):
            file_target = os.path.basename(repo_path)
            repo_path = os.path.dirname(repo_path)
            if targets == ['.']:
                targets = [file_target]

        original_cwd = os.getcwd()
        try:
            os.chdir(repo_path)
            print(f"Changed CWD to {os.getcwd()}")
            
            # Check for Brownie-style remappings if we're in a Brownie project
            solc_remaps = []
            solc_args = ""
            if os.path.exists("brownie-config.yaml"):
                print("Brownie config detected. Preparing manual remappings...")
                # If openzeppelin-contracts exists locally, use it
                if os.path.exists("openzeppelin-contracts"):
                    solc_remaps.append("@openzeppelin=openzeppelin-contracts")
                    solc_args = "--base-path . --include-path openzeppelin-contracts"
            
            # Try initializing Slither for each target
            combined_slither = None
            for target in targets:
                try:
                    print(f"Analyzing target: {target}")
                    # Slither library takes solc_args as a string.
                    # solc_remaps can be passed as a list of strings.
                    
                    s = Slither(target, solc_args=solc_args, solc_remaps=solc_remaps)
                    if combined_slither is None:
                        combined_slither = s
                    else:
                        combined_slither.contracts.extend(s.contracts)
                    print(f"Successfully analyzed {target}")
                except Exception as e:
                    error_msg = str(e)
                    print(f"Slither initialization failed for {target}: {error_msg}")
                    
                    # Version detection and retry logic
                    version = self._detect_solc_version('.')
                    if version:
                        print(f"Detected required solc version: {version}")
                        if self._switch_solc_version(version):
                            try:
                                print(f"Retrying analysis for {target} with version {version}...")
                                s = Slither(target, solc_args=solc_args, solc_remaps=solc_remaps)
                                if combined_slither is None:
                                    combined_slither = s
                                else:
                                    combined_slither.contracts.extend(s.contracts)
                            except Exception as e2:
                                print(f"Retry failed for {target}: {e2}")
            
            if combined_slither is None:
                # Fallback: try per-file if it's a directory and we failed
                # This works around CryticCompile/SoLC issues with raw directories
                if os.path.exists('Vulnerable.sol') or any(f.endswith('.sol') for f in os.listdir('.')):
                     print("Attempting per-file compilation fallback...")
                     sol_files = [f for f in os.listdir('.') if f.endswith('.sol')]
                     combined_slither = None
                     for f in sol_files:
                         try:
                             print(f"Compiling {f}...")
                             # Slither library takes solc_args as a string.
                             # solc_remaps can be passed as a list of strings.
                             s = Slither(f, solc_args=solc_args, solc_remaps=solc_remaps)
                             if combined_slither is None:
                                 combined_slither = s
                             else:
                                 combined_slither.contracts.extend(s.contracts)
                         except Exception as ex:
                             print(f"Failed to compile {f}: {ex}")
                     
                     if combined_slither:
                         print("Per-file compilation successful.")

            return combined_slither

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
