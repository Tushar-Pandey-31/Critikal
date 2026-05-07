"""
Cluster Builder — groups contract roots into compilation clusters.

Clusters are formed by:
  1. Shared imports (import-connected components)
  2. Shared base directories
  3. Compatible pragma versions

Each cluster is compiled independently with its own solc version.
"""

from __future__ import annotations

import logging
import os

from src.ingestion.import_resolver import ImportResolver
from src.ingestion.memory_guard import MemoryGuard
from src.ingestion.models import (
    CompilationCluster,
    ContractRoot,
)
from src.ingestion.solc_manager import SolcManager
from src.ingestion.strategy_resolver import CompilationStrategyResolver

logger = logging.getLogger(__name__)


class ClusterBuilder:
    """
    Segments contract roots into independently compilable clusters.

    Usage::

        builder = ClusterBuilder(memory_guard, solc_manager)
        clusters = builder.build_clusters(roots, repo_path)
    """

    def __init__(
        self,
        memory_guard: MemoryGuard,
        solc_manager: SolcManager,
    ):
        self.memory_guard = memory_guard
        self.solc_manager = solc_manager

    def build_clusters(
        self,
        roots: list[ContractRoot],
        repo_path: str,
    ) -> list[CompilationCluster]:
        """
        Build compilation clusters from the discovered contract roots.

        Algorithm:
          1. Collect all .sol files from each root.
          2. Build import graph across all files.
          3. Find connected components (import-linked groups).
          4. Split components with incompatible pragma versions.
          5. Enforce memory guard limits.
          6. Assign solc version per cluster.
        """
        repo_path = os.path.abspath(repo_path)
        resolver = CompilationStrategyResolver()

        # Step 1: Collect all .sol files with their root association
        all_sol_files: list[str] = []
        file_to_root: dict[str, ContractRoot] = {}

        for root in roots:
            for f_name in os.listdir(root.path):
                if f_name.endswith(".sol"):
                    full_path = os.path.join(root.path, f_name)
                    all_sol_files.append(full_path)
                    file_to_root[full_path] = root

        if not all_sol_files:
            logger.warning("ClusterBuilder: no .sol files found in any root.")
            return []

        # Step 2: Collect remappings and build import graph
        remappings = ImportResolver.collect_remappings(repo_path)
        import_resolver = ImportResolver(remappings=remappings)
        import_graph = import_resolver.build_import_graph(all_sol_files, base_dir=repo_path)

        # Step 3: Find connected components
        components = import_resolver.find_connected_components(import_graph)

        # Step 4: Build clusters from components
        clusters: list[CompilationCluster] = []
        cluster_idx = 0

        for component in components:
            # Only include files that are in our roots (not dependency files)
            root_files = [f for f in component if f in file_to_root]
            if not root_files:
                continue

            # Determine the cluster root directory (common parent)
            cluster_root = os.path.commonpath(root_files) if root_files else repo_path
            if os.path.isfile(cluster_root):
                cluster_root = os.path.dirname(cluster_root)

            # Collect pragma versions for this component
            pragmas: set[str] = set()
            for f in root_files:
                p = SolcManager.detect_pragma(f)
                if p:
                    pragmas.add(p)

            # Check if pragmas are compatible — if not, split
            sub_clusters = self._split_by_pragma(root_files, pragmas, cluster_root, cluster_idx)

            if sub_clusters:
                clusters.extend(sub_clusters)
                cluster_idx += len(sub_clusters)
            else:
                # All pragmas compatible — single cluster
                framework = self._determine_framework(root_files, file_to_root)
                solc_version = self.solc_manager.resolve_version_for_pragmas(pragmas)

                cluster = CompilationCluster(
                    cluster_id=f"cluster_{cluster_idx:03d}",
                    root_path=cluster_root,
                    sol_files=sorted(root_files),
                    pragma_versions=pragmas,
                    import_graph={
                        k: v for k, v in import_graph.items()
                        if k in component
                    },
                    framework=framework,
                    solc_version=solc_version,
                )
                clusters.append(cluster)
                cluster_idx += 1

        # Step 5: Enforce memory guard — split oversized clusters
        final_clusters: list[CompilationCluster] = []
        for cluster in clusters:
            if self.memory_guard.should_segment(len(cluster.sol_files)):
                sub = self._split_cluster_by_size(cluster)
                final_clusters.extend(sub)
            else:
                final_clusters.append(cluster)

        logger.info(
            f"ClusterBuilder: {len(final_clusters)} cluster(s) "
            f"from {len(roots)} root(s), {len(all_sol_files)} files"
        )
        return final_clusters

    # ──────────────────────────────────────────────────────────
    #  Pragma-based Splitting
    # ──────────────────────────────────────────────────────────

    def _split_by_pragma(
        self,
        files: list[str],
        pragmas: set[str],
        cluster_root: str,
        base_idx: int,
    ) -> list[CompilationCluster] | None:
        """
        Split files into sub-clusters if they have incompatible pragmas.

        Returns None if all pragmas are compatible (no split needed).
        """
        if len(pragmas) <= 1:
            return None

        # Group files by their major.minor version
        version_groups: dict[str, list[str]] = {}
        ungrouped: list[str] = []

        for f in files:
            pragma = SolcManager.detect_pragma(f)
            if pragma:
                ver = SolcManager.extract_version_from_pragma(pragma)
                if ver:
                    major_minor = ".".join(ver.split(".")[:2])
                    version_groups.setdefault(major_minor, []).append(f)
                    continue
            ungrouped.append(f)

        # If everything is same major.minor → no split needed
        if len(version_groups) <= 1:
            return None

        # Build sub-clusters for each version group
        clusters: list[CompilationCluster] = []
        idx = base_idx

        for major_minor, group_files in sorted(version_groups.items()):
            group_pragmas: set[str] = set()
            for f in group_files:
                p = SolcManager.detect_pragma(f)
                if p:
                    group_pragmas.add(p)

            solc_version = self.solc_manager.resolve_version_for_pragmas(group_pragmas)
            group_root = os.path.commonpath(group_files) if group_files else cluster_root
            if os.path.isfile(group_root):
                group_root = os.path.dirname(group_root)

            cluster = CompilationCluster(
                cluster_id=f"cluster_{idx:03d}_v{major_minor.replace('.', '')}",
                root_path=group_root,
                sol_files=sorted(group_files),
                pragma_versions=group_pragmas,
                import_graph={},
                framework=None,
                solc_version=solc_version,
            )
            clusters.append(cluster)
            idx += 1

        # Add ungrouped files to the largest cluster
        if ungrouped and clusters:
            largest = max(clusters, key=lambda c: len(c.sol_files))
            largest.sol_files.extend(ungrouped)
            largest.sol_files.sort()

        return clusters

    # ──────────────────────────────────────────────────────────
    #  Size-based Splitting
    # ──────────────────────────────────────────────────────────

    def _split_cluster_by_size(
        self,
        cluster: CompilationCluster,
    ) -> list[CompilationCluster]:
        """
        Split an oversized cluster into smaller chunks based on
        the memory guard's max cluster size.
        """
        max_size = self.memory_guard.get_max_cluster_size()
        files = cluster.sol_files
        chunks: list[CompilationCluster] = []

        for i in range(0, len(files), max_size):
            chunk_files = files[i:i + max_size]
            chunk_pragmas: set[str] = set()
            for f in chunk_files:
                p = SolcManager.detect_pragma(f)
                if p:
                    chunk_pragmas.add(p)

            chunk_root = os.path.commonpath(chunk_files) if chunk_files else cluster.root_path
            if os.path.isfile(chunk_root):
                chunk_root = os.path.dirname(chunk_root)

            solc_version = self.solc_manager.resolve_version_for_pragmas(chunk_pragmas)

            sub = CompilationCluster(
                cluster_id=f"{cluster.cluster_id}_chunk{i // max_size}",
                root_path=chunk_root,
                sol_files=chunk_files,
                pragma_versions=chunk_pragmas,
                import_graph={},
                framework=cluster.framework,
                solc_version=solc_version or cluster.solc_version,
            )
            chunks.append(sub)

        logger.info(
            f"MemoryGuard split cluster {cluster.cluster_id} into "
            f"{len(chunks)} chunk(s) (max {max_size} files each)"
        )
        return chunks

    # ──────────────────────────────────────────────────────────
    #  Helpers
    # ──────────────────────────────────────────────────────────

    @staticmethod
    def _determine_framework(
        files: list[str],
        file_to_root: dict[str, ContractRoot],
    ) -> str | None:
        """Determine framework for a set of files (majority vote)."""
        votes: dict[str, int] = {}
        for f in files:
            root = file_to_root.get(f)
            if root and root.framework_hint:
                votes[root.framework_hint] = votes.get(root.framework_hint, 0) + 1
        if not votes:
            return None
        return max(votes, key=votes.get)
