"""
Fallback Compiler — 4-level compilation hierarchy.

Replaces the brute per-file fallback in the old AnalysisEngine with
a structured, layered approach that tries progressively finer-grained
compilation strategies before resorting to per-file mode.

Fallback levels:
  Level 0: Compile the cluster root directory directly
  Level 1: Compile subdirectories inside the cluster
  Level 2: Compile strongly connected import components
  Level 3: Per-file fallback (only if cluster has <50 files)
"""

from __future__ import annotations

import os
import logging
import traceback
from typing import Optional

from slither.slither import Slither

from src.ingestion.models import (
    CompilationCluster,
    ClusterResult,
)
from src.ingestion.solc_manager import SolcManager
from src.ingestion.framework_detector import FrameworkDetector
from src.ingestion.import_resolver import ImportResolver

logger = logging.getLogger(__name__)

# Maximum files for per-file fallback to be attempted
_PER_FILE_MAX = 50


class FallbackCompiler:
    """
    Compiles a single cluster using a layered fallback strategy.

    Usage::

        compiler = FallbackCompiler(solc_manager)
        result = compiler.compile_cluster(cluster, repo_path)
    """

    def __init__(self, solc_manager: SolcManager):
        self.solc_manager = solc_manager

    def compile_cluster(
        self,
        cluster: CompilationCluster,
        repo_path: str,
    ) -> ClusterResult:
        """
        Attempt to compile a cluster using layers 0–3.

        Returns a ClusterResult with the Slither object on success,
        or error details on failure.
        """
        # Ensure correct solc version for this cluster. If the install/switch
        # fails (e.g. slow GitHub download, unavailable version) we MUST stop
        # here — otherwise compilation silently runs against whatever solc is
        # globally active and produces misleading "requires different compiler
        # version" errors downstream.
        if cluster.solc_version:
            if not self.solc_manager.ensure_version(cluster.solc_version):
                return ClusterResult(
                    cluster_id=cluster.cluster_id,
                    success=False,
                    error=(
                        f"solc {cluster.solc_version} unavailable: solc-select "
                        f"install/switch failed (network issue or invalid version). "
                        f"Run `solc-select install {cluster.solc_version}` manually."
                    ),
                )

        # Determine framework-specific args
        framework = cluster.framework
        if not framework:
            framework = FrameworkDetector.detect_at(cluster.root_path)

        solc_args, solc_remaps = self._get_compilation_args(
            cluster.root_path, framework, repo_path,
        )

        # Prepare framework if needed
        if framework == "foundry":
            FrameworkDetector.ensure_foundry_config(cluster.root_path)
            FrameworkDetector.pre_build_foundry(cluster.root_path)
        elif framework == "hardhat":
            solc_args, solc_remaps = FrameworkDetector.setup_hardhat_project(
                cluster.root_path,
            )

        # ── Level 0: Direct cluster root compilation ──────────
        print(f"  [L0] Compiling cluster {cluster.cluster_id} at {cluster.root_path}...")
        result = self._try_compile(
            target=cluster.root_path,
            framework=framework,
            solc_args=solc_args,
            solc_remaps=solc_remaps,
        )
        if result:
            n_contracts = len(result.contracts)
            print(f"  [L0] Success: {n_contracts} contracts parsed.")
            return ClusterResult(
                cluster_id=cluster.cluster_id,
                success=True,
                slither_obj=result,
                contracts_parsed=n_contracts,
                fallback_level=0,
            )

        # ── Level 1: Subdirectory compilation ─────────────────
        print(f"  [L1] Trying subdirectory compilation for {cluster.cluster_id}...")
        subdir_result = self._compile_subdirs(
            cluster, framework, solc_args, solc_remaps,
        )
        if subdir_result and subdir_result.success:
            print(f"  [L1] Success: {subdir_result.contracts_parsed} contracts.")
            return subdir_result

        # ── Level 2: Import component compilation ─────────────
        print(f"  [L2] Trying import-component compilation for {cluster.cluster_id}...")
        scc_result = self._compile_import_components(
            cluster, solc_args, solc_remaps, repo_path,
        )
        if scc_result and scc_result.success:
            print(f"  [L2] Success: {scc_result.contracts_parsed} contracts.")
            return scc_result

        # ── Level 3: Per-file fallback ────────────────────────
        if len(cluster.sol_files) <= _PER_FILE_MAX:
            print(
                f"  [L3] Trying per-file fallback for {cluster.cluster_id} "
                f"({len(cluster.sol_files)} files)..."
            )
            per_file_result = self._compile_per_file(
                cluster, solc_args, solc_remaps,
            )
            if per_file_result and per_file_result.success:
                print(f"  [L3] Success: {per_file_result.contracts_parsed} contracts.")
                return per_file_result
        else:
            print(
                f"  [L3] Skipping per-file fallback: "
                f"{len(cluster.sol_files)} files exceeds limit ({_PER_FILE_MAX})."
            )

        # All levels failed
        return ClusterResult(
            cluster_id=cluster.cluster_id,
            success=False,
            error=f"All compilation levels (0–3) failed for {cluster.root_path}",
            fallback_level=3,
        )

    # ──────────────────────────────────────────────────────────
    #  Level 0: Direct Compilation
    # ──────────────────────────────────────────────────────────

    def _try_compile(
        self,
        target: str,
        framework: Optional[str],
        solc_args: str,
        solc_remaps: list[str],
    ) -> Optional[Slither]:
        """
        Try a single Slither invocation on the target.

        Uses framework-specific flags when applicable.
        """
        original_cwd = os.getcwd()
        try:
            # Slither expects CWD to be the project root for certain frameworks
            if os.path.isdir(target):
                os.chdir(target)
                slither_target = "."
            else:
                os.chdir(os.path.dirname(target))
                slither_target = os.path.basename(target)

            if framework == "foundry":
                return Slither(slither_target, foundry=True)
            elif framework == "hardhat":
                return Slither(slither_target, hardhat=True)
            else:
                return Slither(
                    slither_target,
                    solc_args=solc_args,
                    solc_remaps=solc_remaps,
                )
        except Exception as e:
            logger.debug(f"Compilation failed for {target}: {e}")
            return None
        finally:
            os.chdir(original_cwd)

    # ──────────────────────────────────────────────────────────
    #  Level 1: Subdirectory Compilation
    # ──────────────────────────────────────────────────────────

    def _compile_subdirs(
        self,
        cluster: CompilationCluster,
        framework: Optional[str],
        solc_args: str,
        solc_remaps: list[str],
    ) -> Optional[ClusterResult]:
        """
        Try compiling each subdirectory of the cluster root that
        contains .sol files.
        """
        root = cluster.root_path
        subdirs_with_sol: list[str] = []

        try:
            for entry in os.scandir(root):
                if not entry.is_dir():
                    continue
                if entry.name.lower() in ("lib", "node_modules", "test", "tests",
                                           ".git", "build", "out", "cache"):
                    continue
                # Check if this subdir has .sol files
                has_sol = any(
                    f.endswith(".sol")
                    for f in os.listdir(entry.path)
                    if os.path.isfile(os.path.join(entry.path, f))
                )
                if has_sol:
                    subdirs_with_sol.append(entry.path)
        except OSError:
            return None

        if not subdirs_with_sol:
            return None

        combined = None
        total_contracts = 0

        for subdir in subdirs_with_sol:
            s = self._try_compile(subdir, framework, solc_args, solc_remaps)
            if s:
                if combined is None:
                    combined = s
                else:
                    combined.contracts.extend(s.contracts)
                total_contracts += len(s.contracts)

        if combined:
            return ClusterResult(
                cluster_id=cluster.cluster_id,
                success=True,
                slither_obj=combined,
                contracts_parsed=total_contracts,
                fallback_level=1,
            )
        return None

    # ──────────────────────────────────────────────────────────
    #  Level 2: Import Component Compilation
    # ──────────────────────────────────────────────────────────

    def _compile_import_components(
        self,
        cluster: CompilationCluster,
        solc_args: str,
        solc_remaps: list[str],
        repo_path: str,
    ) -> Optional[ClusterResult]:
        """
        Build import graph for the cluster's files, find connected
        components, and compile each component separately.
        """
        if not cluster.sol_files:
            return None

        # Build import graph
        remappings = ImportResolver.collect_remappings(cluster.root_path)
        resolver = ImportResolver(remappings=remappings)
        import_graph = resolver.build_import_graph(
            cluster.sol_files, base_dir=cluster.root_path,
        )
        components = resolver.find_connected_components(import_graph)

        if not components:
            return None

        combined = None
        total_contracts = 0

        for component in components:
            # Find the common directory for this component
            comp_files = [f for f in component if os.path.isfile(f)]
            if not comp_files:
                continue

            # Try compiling the common root of this component
            comp_root = os.path.commonpath(comp_files)
            if os.path.isfile(comp_root):
                comp_root = os.path.dirname(comp_root)

            s = self._try_compile(comp_root, None, solc_args, solc_remaps)
            if s:
                if combined is None:
                    combined = s
                else:
                    combined.contracts.extend(s.contracts)
                total_contracts += len(s.contracts)
            else:
                # Fall through: try individual files in this component
                for f in comp_files:
                    s = self._try_compile(f, None, solc_args, solc_remaps)
                    if s:
                        if combined is None:
                            combined = s
                        else:
                            combined.contracts.extend(s.contracts)
                        total_contracts += len(s.contracts)

        if combined:
            return ClusterResult(
                cluster_id=cluster.cluster_id,
                success=True,
                slither_obj=combined,
                contracts_parsed=total_contracts,
                fallback_level=2,
            )
        return None

    # ──────────────────────────────────────────────────────────
    #  Level 3: Per-File Fallback
    # ──────────────────────────────────────────────────────────

    def _compile_per_file(
        self,
        cluster: CompilationCluster,
        solc_args: str,
        solc_remaps: list[str],
    ) -> Optional[ClusterResult]:
        """
        Last resort: compile each .sol file individually.
        """
        combined = None
        total = 0
        success_count = 0

        for sol_file in cluster.sol_files:
            s = self._try_compile(sol_file, None, solc_args, solc_remaps)
            total += 1
            if s:
                if combined is None:
                    combined = s
                else:
                    combined.contracts.extend(s.contracts)
                success_count += 1

        if combined:
            print(
                f"  Per-file compilation: {success_count}/{total} files succeeded."
            )
            return ClusterResult(
                cluster_id=cluster.cluster_id,
                success=True,
                slither_obj=combined,
                contracts_parsed=success_count,
                fallback_level=3,
            )
        return None

    # ──────────────────────────────────────────────────────────
    #  Helpers
    # ──────────────────────────────────────────────────────────

    @staticmethod
    def _get_compilation_args(
        cluster_path: str,
        framework: Optional[str],
        repo_path: str,
    ) -> tuple[str, list[str]]:
        """
        Build solc_args and solc_remaps for a non-framework cluster.
        """
        solc_args = ""
        solc_remaps: list[str] = []

        if framework == "brownie":
            oz_path = os.path.join(cluster_path, "openzeppelin-contracts")
            if os.path.isdir(oz_path):
                solc_remaps.append(f"@openzeppelin={oz_path}")
                solc_args = f"--base-path {cluster_path} --include-path {oz_path}"

        # Collect remappings from any available sources
        remappings = ImportResolver.collect_remappings(cluster_path)
        for alias, target in remappings.items():
            mapping = f"{alias}={target}"
            if mapping not in solc_remaps:
                solc_remaps.append(mapping)

        return solc_args, solc_remaps


def merge_slither_objects(objects: list[Slither]) -> Optional[Slither]:
    """
    Merge multiple Slither objects into a single combined object.

    The first object is used as the base, and contracts from subsequent
    objects are appended.
    """
    if not objects:
        return None
    combined = objects[0]
    for s in objects[1:]:
        combined.contracts.extend(s.contracts)
    return combined
