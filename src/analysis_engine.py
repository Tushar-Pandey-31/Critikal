"""
Analysis Engine — Orchestrator for the cluster-based compilation pipeline.

This module is the public entry point for Penteam's ingestion layer.
All compilation logic has been delegated to submodules in src/ingestion/.

Public API:
    engine = AnalysisEngine()
    slither_obj = engine.run_analysis(repo_path)           # backward compat
    slither_obj, report = engine.run_analysis_v2(repo_path)  # new API
"""

import os
import logging
import traceback
from typing import Optional

from slither.slither import Slither

from src.ingestion.models import (
    IngestionReport,
    ClusterResult,
    CompilationCluster,
    RepoSizeClass,
)
from src.ingestion.strategy_resolver import CompilationStrategyResolver
from src.ingestion.cluster_builder import ClusterBuilder
from src.ingestion.import_resolver import ImportResolver
from src.ingestion.solc_manager import SolcManager
from src.ingestion.memory_guard import MemoryGuard
from src.ingestion.framework_detector import FrameworkDetector
from src.ingestion.fallback import FallbackCompiler, merge_slither_objects

logger = logging.getLogger(__name__)


def _deduplicate_contracts(slither_obj: Slither) -> Slither:
    """
    Remove duplicate contracts from a merged Slither object.

    When multiple clusters compile overlapping directories, the same
    contract can appear multiple times. Deduplicate by (name, source_file).

    Slither stores contracts in ``_contracts`` as a ``list[Contract]``.
    """
    seen = set()
    unique = []
    for contract in slither_obj.contracts:
        # Build a key from contract name + source file
        source_file = ""
        try:
            if contract.source_mapping and contract.source_mapping.filename:
                source_file = str(contract.source_mapping.filename.absolute)
        except Exception:
            pass
        key = (contract.name, source_file)
        if key not in seen:
            seen.add(key)
            unique.append(contract)
    # _contracts is a list, NOT a dict — Slither's .contracts property
    # returns self._contracts directly.
    slither_obj._contracts = unique
    return slither_obj


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
            logger.warning(
                f"  ⚠ Slither: Skipped SSA for {len(failed_contracts)} contract(s): "
                f"{', '.join(sorted(failed_contracts))}"
            )

    SlitherCompilationUnitSolc._convert_to_slithir = _fault_tolerant_convert_to_slithir
    logger.info("  [AnalysisEngine] Slither fault-tolerance patch applied.")


# ════════════════════════════════════════════════════════════
#  Analysis Engine
# ════════════════════════════════════════════════════════════

class AnalysisEngine:
    """
    Orchestrates cluster-based Solidity compilation via Slither.

    Delegates to:
      - CompilationStrategyResolver — directory scanning
      - MemoryGuard — size classification
      - FrameworkDetector — Foundry/Hardhat/Brownie detection
      - ClusterBuilder — pragma & import segmentation
      - SolcManager — deterministic solc switching
      - FallbackCompiler — 4-level fallback hierarchy
    """

    def __init__(self):
        _apply_slither_fault_tolerance_patch()
        self._solc_manager = SolcManager()
        self._strategy_resolver = CompilationStrategyResolver()

    # ──────────────────────────────────────────────────────────
    #  Legacy API (backward compatible)
    # ──────────────────────────────────────────────────────────

    def run_analysis(
        self,
        repo_path: str,
        targets=None,
    ) -> Optional[Slither]:
        """
        Backward-compatible entry point.

        Returns the combined Slither object, or None on total failure.
        Same signature as the original AnalysisEngine.
        """
        slither_obj, report = self.run_analysis_v2(repo_path, targets=targets)
        if report:
            logger.info(f"  {report.summary()}")
        return slither_obj

    # ──────────────────────────────────────────────────────────
    #  New API
    # ──────────────────────────────────────────────────────────

    def run_analysis_v2(
        self,
        repo_path: str,
        targets=None,
    ) -> tuple[Optional[Slither], IngestionReport]:
        """
        Full cluster-based compilation pipeline.

        Returns (combined_slither, ingestion_report).
        The report always contains structured diagnostics, even on failure.

        Pipeline steps:
          1. Detect frameworks across the repo
          2. Scan for contract roots
          3. Classify repo size & init memory guard
          4. Build clusters
          5. Compile each cluster (with fallback)
          6. Merge Slither objects
          7. Build report
        """
        report = IngestionReport()

        if not os.path.exists(repo_path):
            logger.info(f"Error: Path {repo_path} does not exist.")
            report.warnings.append(f"Path {repo_path} does not exist")
            return None, report

        repo_path = os.path.abspath(repo_path)

        # Handle single-file mode (backward compat)
        if os.path.isfile(repo_path):
            return self._compile_single_file(repo_path, report)

        original_cwd = os.getcwd()
        try:
            # ── Step 1: Detect all frameworks ─────────────────
            logger.info("Detecting frameworks...")
            frameworks = FrameworkDetector.detect_all(repo_path)
            report.frameworks_detected = list({fi.framework for fi in frameworks})
            if frameworks:
                logger.info(
                    f"  Found {len(frameworks)} framework instance(s): "
                    f"{', '.join(f'{fi.framework} @ {os.path.relpath(fi.path, repo_path)}' for fi in frameworks)}"
                )
            report.repo_type = (
                report.frameworks_detected[0] if report.frameworks_detected else "raw_solidity"
            )

            # ── Step 2: Classify repo size ─────────────────────
            total_sol = self._strategy_resolver.count_all_sol_files(repo_path)
            report.total_sol_files = total_sol
            guard = MemoryGuard(total_sol)
            report.size_class = guard.size_class.value
            logger.info(f"  Found {total_sol} .sol files [{report.size_class}]")

            # ── Step 3: Framework-first compilation ────────────
            #
            # Key insight: Foundry/Hardhat handle multi-pragma compilation
            # internally. Compile each framework directory as ONE unit.
            # Only cluster-split files NOT covered by any framework.
            #
            successful_slithers: list[Slither] = []
            framework_covered_dirs: list[str] = []

            if frameworks:
                logger.info("\nCompiling framework project(s) as whole units...")
                compiler = FallbackCompiler(self._solc_manager)

                for fi in frameworks:
                    fw_dir = fi.path
                    fw_name = fi.framework
                    rel = os.path.relpath(fw_dir, repo_path)
                    logger.info(f"\n─── Framework: {fw_name} @ {rel} ───")

                    # Create a single cluster for this framework directory
                    fw_cluster = CompilationCluster(
                        cluster_id=f"fw_{fw_name}_{rel.replace(os.sep, '_')}",
                        root_path=fw_dir,
                        sol_files=[],  # framework compiles everything
                        framework=fw_name,
                    )

                    try:
                        result = compiler.compile_cluster(fw_cluster, repo_path)
                        report.cluster_results.append(result)
                        report.clusters_detected += 1

                        if result.success and result.slither_obj:
                            successful_slithers.append(result.slither_obj)
                            report.clusters_compiled += 1
                            report.total_contracts_parsed += result.contracts_parsed
                            framework_covered_dirs.append(os.path.abspath(fw_dir))
                            logger.info(f"  ✅ {result.contracts_parsed} contracts parsed.")
                        else:
                            report.clusters_failed += 1
                            report.failed_clusters.append(fw_cluster.cluster_id)
                            logger.info(f"  ❌ Failed: {result.error}")
                    except Exception as e:
                        logger.error(f"Framework {fw_name} crashed: {e}")
                        traceback.print_exc()
                        report.clusters_failed += 1
                        report.clusters_detected += 1

            # ── Step 4: Cluster non-framework files ────────────
            #
            # Find contract roots NOT under any framework directory.
            # These are "orphan" .sol files that need cluster compilation.
            #
            roots = self._strategy_resolver.resolve(repo_path)
            orphan_roots = []
            for root in roots:
                root_abs = os.path.abspath(root.path)
                covered = any(
                    root_abs.startswith(fw_dir + os.sep) or root_abs == fw_dir
                    for fw_dir in framework_covered_dirs
                )
                if not covered:
                    orphan_roots.append(root)

            if orphan_roots:
                logger.info(f"\nBuilding clusters for {len(orphan_roots)} non-framework root(s)...")
                builder = ClusterBuilder(guard, self._solc_manager)
                clusters = builder.build_clusters(orphan_roots, repo_path)

                for c in clusters:
                    report.clusters_detected += 1
                    logger.info(
                        f"    - {c.cluster_id}: {len(c.sol_files)} files, "
                        f"solc={c.solc_version}"
                    )

                if not clusters and not successful_slithers:
                    return self._legacy_fallback(repo_path, targets, frameworks, report)

                compiler = FallbackCompiler(self._solc_manager)
                for cluster in clusters:
                    logger.info(f"\n─── Cluster: {cluster.cluster_id} ───")
                    try:
                        result = compiler.compile_cluster(cluster, repo_path)
                        report.cluster_results.append(result)

                        if result.success and result.slither_obj:
                            successful_slithers.append(result.slither_obj)
                            report.clusters_compiled += 1
                            report.total_contracts_parsed += result.contracts_parsed
                        else:
                            report.clusters_failed += 1
                            report.failed_clusters.append(cluster.cluster_id)
                    except Exception as e:
                        logger.error(f"Cluster {cluster.cluster_id} crashed: {e}")
                        traceback.print_exc()
                        report.clusters_failed += 1
                        report.cluster_results.append(ClusterResult(
                            cluster_id=cluster.cluster_id,
                            success=False,
                            error=str(e),
                        ))
            elif not successful_slithers:
                # No framework compilations succeeded, no orphan roots
                if not roots:
                    report.warnings.append("No Solidity files found")
                    return None, report
                return self._legacy_fallback(repo_path, targets, frameworks, report)

            report.memory_guard_triggered = guard.triggered
            report.solc_versions_used = self._solc_manager.versions_used

            # ── Step 5: Merge + deduplicate ────────────────────
            if not successful_slithers:
                logger.info("\n  All compilations failed. Attempting legacy fallback...")
                return self._legacy_fallback(repo_path, targets, frameworks, report)

            combined = merge_slither_objects(successful_slithers)
            if combined:
                before = len(combined.contracts)
                combined = _deduplicate_contracts(combined)
                after = len(combined.contracts)
                report.total_contracts_parsed = after
                if before != after:
                    logger.info(f"  Deduplicated: {before} → {after} unique contracts")

            logger.info(f"\n  ═══ {report.summary()} ═══")
            return combined, report

        except Exception as e:
            logger.error(f"Ingestion pipeline crashed: {e}")
            traceback.print_exc()
            report.warnings.append(f"Pipeline crash: {e}")
            # Try legacy fallback on crash
            try:
                return self._legacy_fallback(repo_path, targets, [], report)
            except Exception:
                return None, report
        finally:
            os.chdir(original_cwd)

    # ──────────────────────────────────────────────────────────
    #  Single File Mode
    # ──────────────────────────────────────────────────────────

    def _compile_single_file(
        self,
        file_path: str,
        report: IngestionReport,
    ) -> tuple[Optional[Slither], IngestionReport]:
        """Handle single .sol file compilation."""
        report.total_sol_files = 1
        report.clusters_detected = 1
        report.size_class = RepoSizeClass.SMALL.value

        original_cwd = os.getcwd()
        try:
            directory = os.path.dirname(file_path)
            filename = os.path.basename(file_path)
            os.chdir(directory)

            # Detect pragma and switch solc
            pragma = SolcManager.detect_pragma(file_path)
            if pragma:
                version = SolcManager.extract_version_from_pragma(pragma)
                if version:
                    self._solc_manager.ensure_version(version)

            s = Slither(filename)
            report.clusters_compiled = 1
            report.total_contracts_parsed = len(s.contracts)
            report.solc_versions_used = self._solc_manager.versions_used
            return s, report
        except Exception as e:
            logger.info(f"Single file compilation failed: {e}")
            report.clusters_failed = 1
            report.failed_clusters.append(file_path)
            report.warnings.append(str(e))
            return None, report
        finally:
            os.chdir(original_cwd)

    # ──────────────────────────────────────────────────────────
    #  Legacy Fallback (preserves old behavior)
    # ──────────────────────────────────────────────────────────

    def _legacy_fallback(
        self,
        repo_path: str,
        targets,
        frameworks: list,
        report: IngestionReport,
    ) -> tuple[Optional[Slither], IngestionReport]:
        """
        Fall back to the original AnalysisEngine behavior when the
        cluster-based pipeline cannot form clusters or all clusters fail.

        This preserves backward compatibility with the original engine.
        """
        logger.info("  [Legacy] Falling back to direct Slither invocation...")

        if targets is None:
            targets = ['.']
        elif isinstance(targets, str):
            targets = [targets]

        original_cwd = os.getcwd()
        try:
            os.chdir(repo_path)

            # Determine framework
            is_foundry = FrameworkDetector._is_foundry(".")
            is_hardhat = FrameworkDetector._is_hardhat(".")
            solc_args = ""
            solc_remaps: list[str] = []

            if is_hardhat and not is_foundry:
                solc_args, solc_remaps = FrameworkDetector.setup_hardhat_project(".")
            elif is_foundry or FrameworkDetector.ensure_foundry_config("."):
                FrameworkDetector.pre_build_foundry(".")
            elif FrameworkDetector._is_brownie("."):
                if os.path.exists("openzeppelin-contracts"):
                    solc_remaps.append("@openzeppelin=openzeppelin-contracts")
                    solc_args = "--base-path . --include-path openzeppelin-contracts"

            combined_slither = None
            for target in targets:
                try:
                    logger.info(f"  [Legacy] Analyzing target: {target}")
                    if is_foundry:
                        s = Slither(target, foundry=True)
                    elif is_hardhat:
                        s = Slither(target, hardhat=True)
                    else:
                        s = Slither(target, solc_args=solc_args, solc_remaps=solc_remaps)

                    if combined_slither is None:
                        combined_slither = s
                    else:
                        combined_slither.contracts.extend(s.contracts)
                    logger.info(f"  [Legacy] Successfully analyzed {target}")
                except Exception as e:
                    logger.info(f"  [Legacy] Failed for {target}: {e}")

                    # Try switching solc version
                    pragmas = SolcManager.detect_pragmas_in_directory(".")
                    if pragmas:
                        version = self._solc_manager.resolve_version_for_pragmas(pragmas)
                        if version and self._solc_manager.ensure_version(version):
                            try:
                                s = Slither(target, solc_args=solc_args, solc_remaps=solc_remaps)
                                if combined_slither is None:
                                    combined_slither = s
                                else:
                                    combined_slither.contracts.extend(s.contracts)
                                logger.info(f"  [Legacy] Retry succeeded for {target}")
                            except Exception as e2:
                                logger.info(f"  [Legacy] Retry failed: {e2}")

            if combined_slither is None:
                # Per-file fallback (respects file count limit)
                sol_files = self._strategy_resolver.collect_all_sol_files(repo_path)
                if len(sol_files) <= 50:
                    logger.info(f"  [Legacy] Attempting per-file fallback ({len(sol_files)} files)...")
                    for f in sol_files:
                        try:
                            rel = os.path.relpath(f, repo_path)
                            s = Slither(rel, solc_args=solc_args, solc_remaps=solc_remaps)
                            if combined_slither is None:
                                combined_slither = s
                            else:
                                combined_slither.contracts.extend(s.contracts)
                        except Exception:
                            pass
                else:
                    report.warnings.append(
                        f"Repo has {len(sol_files)} .sol files, "
                        "exceeds per-file fallback limit (50)."
                    )

            if combined_slither:
                report.clusters_compiled += 1
                report.total_contracts_parsed += len(combined_slither.contracts)
                report.solc_versions_used = self._solc_manager.versions_used

            return combined_slither, report

        finally:
            os.chdir(original_cwd)