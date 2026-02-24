import os
import subprocess
import re
import logging
import traceback
from slither.slither import Slither
from typing import Optional

logger = logging.getLogger(__name__)


# ════════════════════════════════════════════════════════════
#  Slither Fault-Tolerance Patch
#
#  Slither's _convert_to_slithir() raises on per-contract SSA
#  conversion failures (e.g. OpenZeppelin Initializable proxy).
#  This kills the ENTIRE analysis even when 99% of contracts
#  parsed fine. We monkey-patch it to skip failing contracts.
# ════════════════════════════════════════════════════════════

_SLITHER_PATCHED = False


def _apply_slither_fault_tolerance_patch():
    global _SLITHER_PATCHED
    if _SLITHER_PATCHED:
        return
    _SLITHER_PATCHED = True

    from slither.solc_parsing.slither_compilation_unit_solc import SlitherCompilationUnitSolc

    def _fault_tolerant_convert_to_slithir(self) -> None:
        failed_contracts = set()

        for contract in self._compilation_unit.contracts:
            contract.add_constructor_variables()

            for func in contract.functions + contract.modifiers:
                try:
                    func.generate_slithir_and_analyze()
                except AttributeError as e:
                    self._underlying_contract_to_parser[contract].log_incorrect_parsing(
                        f"Impossible to generate IR for {contract.name}.{func.name} "
                        f"({func.source_mapping}):\n {e}"
                    )
                except Exception as e:
                    logger.warning(
                        f"Skipping IR generation for {contract.name}.{func.name}: {e}"
                    )
                    failed_contracts.add(contract.name)

            try:
                contract.convert_expression_to_slithir_ssa()
            except Exception as e:
                logger.warning(
                    f"Skipping SSA conversion for {contract.name}: {type(e).__name__}"
                )
                failed_contracts.add(contract.name)

        for func in self._compilation_unit.functions_top_level:
            try:
                func.generate_slithir_and_analyze()
            except Exception as e:
                logger.warning(f"Skipping IR for top-level {func.name}: {e}")

            try:
                func.generate_slithir_ssa({})
            except Exception as e:
                logger.warning(f"Skipping SSA for top-level {func.name}: {e}")

        try:
            self._compilation_unit.propagate_function_calls()
        except Exception as e:
            logger.warning(f"propagate_function_calls() failed: {e}")

        for contract in self._compilation_unit.contracts:
            try:
                contract.fix_phi()
                contract.update_read_write_using_ssa()
            except Exception as e:
                logger.warning(f"Skipping phi/SSA update for {contract.name}: {e}")
                failed_contracts.add(contract.name)

        if failed_contracts:
            print(
                f"  ⚠ Slither: Skipped SSA for {len(failed_contracts)} contract(s): "
                f"{', '.join(sorted(failed_contracts))}"
            )

    SlitherCompilationUnitSolc._convert_to_slithir = _fault_tolerant_convert_to_slithir
    print("  [AnalysisEngine] Slither fault-tolerance patch applied.")


class AnalysisEngine:
    def __init__(self):
        _apply_slither_fault_tolerance_patch()

    def _is_foundry_project(self) -> bool:
        return os.path.exists("foundry.toml")

    def _ensure_foundry_config(self) -> bool:
        """
        Create foundry.toml when missing so CryticCompile detects Foundry.
        Some repos (e.g. sentimentxyz/protocol) use forge without foundry.toml;
        forge infers config from lib/, but CryticCompile requires foundry.toml.
        """
        if os.path.exists("foundry.toml"):
            return True
        # Heuristic: Foundry-like if lib/forge-std or lib/solmate exists
        lib_forge = os.path.isdir("lib/forge-std") or os.path.isdir("lib/solmate")
        if not lib_forge:
            return False
        try:
            result = subprocess.run(
                ["forge", "config", "--basic"],
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode == 0 and result.stdout.strip():
                content = result.stdout
                # Fix test path when repo uses src/test (e.g. sentimentxyz/protocol)
                if os.path.isdir("src/test") and "test =" not in content:
                    content = content.rstrip() + '\ntest = "src/test"\nscript = "scripts"\n'
                with open("foundry.toml", "w") as f:
                    f.write(content)
                print("  Created foundry.toml for Foundry detection (forge config --basic).")
                return True
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        return False

    def _pre_build_foundry(self) -> bool:
        """Run forge build before Slither so compilation artifacts are cached."""
        try:
            print("  Running forge build (pre-compilation)...")
            result = subprocess.run(
                ["forge", "build"],
                capture_output=True, text=True, timeout=300,
            )
            if result.returncode == 0:
                print("  forge build succeeded.")
                return True
            else:
                print(f"  forge build failed (exit {result.returncode}): {result.stderr[:300]}")
                return False
        except FileNotFoundError:
            print("  Warning: 'forge' not found, skipping pre-build.")
            return False
        except subprocess.TimeoutExpired:
            print("  Warning: forge build timed out after 300s.")
            return False

    def run_analysis(self, repo_path: str, targets=None) -> Optional[Slither]:
        """
        Runs Slither analysis on the given repository path.
        Handles solc version mismatches by installing and switching versions.
        """
        if not os.path.exists(repo_path):
            print(f"Error: Path {repo_path} does not exist.")
            return None

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

            # Ensure foundry.toml exists for repos that use forge without it (e.g. sentimentxyz/protocol)
            self._ensure_foundry_config()

            solc_remaps = []
            solc_args = ""
            if os.path.exists("brownie-config.yaml"):
                print("Brownie config detected. Preparing manual remappings...")
                if os.path.exists("openzeppelin-contracts"):
                    solc_remaps.append("@openzeppelin=openzeppelin-contracts")
                    solc_args = "--base-path . --include-path openzeppelin-contracts"

            # For Foundry projects, ensure compilation cache exists
            if self._is_foundry_project():
                self._pre_build_foundry()

            combined_slither = None
            for target in targets:
                try:
                    print(f"Analyzing target: {target}")
                    s = Slither(target, solc_args=solc_args, solc_remaps=solc_remaps)
                    if combined_slither is None:
                        combined_slither = s
                    else:
                        combined_slither.contracts.extend(s.contracts)
                    print(f"Successfully analyzed {target}")
                except Exception as e:
                    print(f"Slither initialization failed for {target}: {type(e).__name__}: {e}")
                    traceback.print_exc()

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
                                print(f"Retry failed for {target}: {type(e2).__name__}: {e2}")
                                traceback.print_exc()

            if combined_slither is None:
                combined_slither = self._fallback_per_file(solc_args, solc_remaps)

            return combined_slither

        finally:
            os.chdir(original_cwd)
            print(f"Restored CWD to {original_cwd}")

    def _fallback_per_file(self, solc_args: str, solc_remaps: list) -> Optional[Slither]:
        """
        Fallback: try analyzing individual .sol files.
        For Foundry projects, search src/ and contracts/ rather than root.
        """
        search_dirs = []
        if self._is_foundry_project():
            for d in ["src", "contracts"]:
                if os.path.isdir(d):
                    search_dirs.append(d)
        if not search_dirs:
            search_dirs = ["."]

        sol_files = []
        for search_dir in search_dirs:
            for root, _, files in os.walk(search_dir):
                for f in files:
                    if f.endswith(".sol"):
                        sol_files.append(os.path.join(root, f))

        if not sol_files:
            return None

        print(f"Attempting per-file compilation fallback ({len(sol_files)} .sol files)...")
        combined_slither = None
        for f in sol_files:
            try:
                print(f"  Compiling {f}...")
                s = Slither(f, solc_args=solc_args, solc_remaps=solc_remaps)
                if combined_slither is None:
                    combined_slither = s
                else:
                    combined_slither.contracts.extend(s.contracts)
            except Exception as ex:
                print(f"  Failed to compile {f}: {ex}")

        if combined_slither:
            print("Per-file compilation successful.")
        return combined_slither

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
