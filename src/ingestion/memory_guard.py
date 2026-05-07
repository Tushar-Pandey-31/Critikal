"""
Memory guard — repo size classification and memory-safe compilation.

Prevents uncontrolled RAM explosion by enforcing cluster size limits
based on the total number of Solidity files in the repository.
"""

from __future__ import annotations

import logging
import os

from src.ingestion.models import RepoSizeClass

logger = logging.getLogger(__name__)

# ════════════════════════════════════════════════════════════
#  Thresholds
# ════════════════════════════════════════════════════════════

_SIZE_THRESHOLDS = {
    RepoSizeClass.SMALL: 50,
    RepoSizeClass.MEDIUM: 300,
    RepoSizeClass.LARGE: 1000,
    # MASSIVE = everything above 1000
}

# Maximum number of .sol files allowed in a single compilation cluster
# before forced segmentation is applied.
_MAX_CLUSTER_SIZE = {
    RepoSizeClass.SMALL: 50,
    RepoSizeClass.MEDIUM: 100,
    RepoSizeClass.LARGE: 50,
    RepoSizeClass.MASSIVE: 30,
}

# Estimated memory cost factor (bytes per .sol file for AST + IR).
# Empirically: ~2–5 MB per non-trivial .sol file in Slither.
_AVG_AST_SIZE_FACTOR = 3 * 1024 * 1024  # 3 MB

# Absolute memory ceiling (in bytes) before forced segmentation.
_MEMORY_CEILING = 4 * 1024 * 1024 * 1024  # 4 GB


class MemoryGuard:
    """
    Classifies repository size and enforces memory-safe compilation.

    Usage::

        guard = MemoryGuard(total_sol_files=850)
        if guard.should_segment(cluster_size=200):
            # split the cluster
    """

    def __init__(self, total_sol_files: int = 0):
        self.total_sol_files = total_sol_files
        self.size_class = self.classify(total_sol_files)
        self._triggered = False

    # ──────────────────────────────────────────────────────────
    #  Classification
    # ──────────────────────────────────────────────────────────

    @staticmethod
    def classify(total_sol_files: int) -> RepoSizeClass:
        """Classify repo by .sol file count."""
        if total_sol_files < _SIZE_THRESHOLDS[RepoSizeClass.SMALL]:
            return RepoSizeClass.SMALL
        if total_sol_files < _SIZE_THRESHOLDS[RepoSizeClass.MEDIUM]:
            return RepoSizeClass.MEDIUM
        if total_sol_files < _SIZE_THRESHOLDS[RepoSizeClass.LARGE]:
            return RepoSizeClass.LARGE
        return RepoSizeClass.MASSIVE

    # ──────────────────────────────────────────────────────────
    #  Memory estimation
    # ──────────────────────────────────────────────────────────

    @staticmethod
    def estimate_memory_cost(sol_files: list[str]) -> int:
        """
        Estimate the memory cost of compiling a set of .sol files
        through Slither (AST + SlithIR + SSA).

        Returns estimated bytes.
        """
        total_size = 0
        for f in sol_files:
            try:
                total_size += os.path.getsize(f)
            except OSError:
                total_size += 5000  # conservative default for unreadable files
        # Slither typically expands source by ~50–100x during IR conversion
        return max(total_size * 60, len(sol_files) * _AVG_AST_SIZE_FACTOR)

    # ──────────────────────────────────────────────────────────
    #  Segmentation decisions
    # ──────────────────────────────────────────────────────────

    def get_max_cluster_size(self) -> int:
        """Maximum .sol files per cluster for the current size class."""
        return _MAX_CLUSTER_SIZE[self.size_class]

    def should_segment(self, cluster_size: int) -> bool:
        """
        Returns True if a cluster with *cluster_size* files should be
        split further based on the repo's size class.
        """
        max_size = self.get_max_cluster_size()
        if cluster_size > max_size:
            self._triggered = True
            logger.info(
                f"MemoryGuard: cluster_size={cluster_size} exceeds limit "
                f"({max_size}) for {self.size_class.value} repo. Segmenting."
            )
            return True
        return False

    def should_segment_by_memory(self, sol_files: list[str]) -> bool:
        """
        Returns True if estimated memory cost exceeds the ceiling.
        """
        cost = self.estimate_memory_cost(sol_files)
        if cost > _MEMORY_CEILING:
            self._triggered = True
            logger.warning(
                f"MemoryGuard: estimated memory {cost / (1024**3):.1f} GB "
                f"exceeds {_MEMORY_CEILING / (1024**3):.0f} GB ceiling. Forcing segmentation."
            )
            return True
        return False

    @property
    def triggered(self) -> bool:
        """True if the memory guard has enforced any segmentation."""
        return self._triggered
