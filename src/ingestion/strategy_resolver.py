"""
Compilation Strategy Resolver — intelligent directory scanning.

Replaces the naive ``Slither(".")`` invocation with a structured scan
that identifies all Solidity-containing directories, scores them,
and returns a prioritised list of ``ContractRoot`` objects.
"""

from __future__ import annotations

import os
import logging
from typing import Optional

from src.ingestion.models import ContractRoot
from src.ingestion.framework_detector import FrameworkDetector

logger = logging.getLogger(__name__)

# Directories excluded from scanning — these never contain
# user-authored contract source that should be compiled.
_EXCLUDED_DIRS = frozenset({
    "node_modules",
    "lib",
    "test",
    "tests",
    "scripts",
    "script",
    "build",
    "coverage",
    "dist",
    "artifacts",
    "out",
    "cache",
    ".git",
    ".github",
    "__pycache__",
    "mock",
    "mocks",
    "migrations",
    ".venv",
    "venv",
    "typechain",
    "typechain-types",
    "deployments",
})


class CompilationStrategyResolver:
    """
    Scans a repository to identify distinct compilation roots.

    A *compilation root* is a directory containing ``.sol`` files that
    should be independently compiled (possibly grouped with siblings
    into clusters later).
    """

    def __init__(self, max_depth: int = 6):
        self.max_depth = max_depth

    def resolve(self, repo_path: str) -> list[ContractRoot]:
        """
        Scan *repo_path* and return scored ``ContractRoot`` list.

        Scoring factors:
          - sol_count: more files → higher score (capped)
          - depth: shallower → higher score
          - Framework hint: having a framework → small bonus
        """
        repo_path = os.path.abspath(repo_path)
        roots: list[ContractRoot] = []

        for current_dir, subdirs, files in os.walk(repo_path):
            # Compute depth relative to repo root
            rel = os.path.relpath(current_dir, repo_path)
            depth = 0 if rel == "." else rel.count(os.sep) + 1

            if depth > self.max_depth:
                subdirs.clear()
                continue

            # Prune excluded directories
            subdirs[:] = sorted([d for d in subdirs if d.lower() not in _EXCLUDED_DIRS])

            # Count .sol files in this directory only (non-recursive)
            sol_count = sum(1 for f in files if f.endswith(".sol"))

            if sol_count == 0:
                continue

            # Detect framework at this directory
            framework_hint = FrameworkDetector.detect_at(current_dir)

            root = ContractRoot(
                path=current_dir,
                sol_count=sol_count,
                depth=depth,
                framework_hint=framework_hint,
            )
            root.score = self._score(root)
            roots.append(root)

        # Sort by score descending (highest priority first)
        roots.sort(key=lambda r: r.score, reverse=True)

        logger.info(
            f"StrategyResolver: found {len(roots)} contract root(s) "
            f"in {repo_path}"
        )
        return roots

    def count_all_sol_files(self, repo_path: str) -> int:
        """Count total .sol files in repo, excluding lib/node_modules."""
        repo_path = os.path.abspath(repo_path)
        total = 0
        for current_dir, subdirs, files in os.walk(repo_path):
            # Prune excluded directories
            base = os.path.basename(current_dir).lower()
            if base in _EXCLUDED_DIRS:
                subdirs.clear()
                continue
            subdirs[:] = [d for d in subdirs if d.lower() not in _EXCLUDED_DIRS]
            total += sum(1 for f in files if f.endswith(".sol"))
        return total

    def collect_all_sol_files(self, repo_path: str) -> list[str]:
        """Return absolute paths to all .sol files, excluding lib/node_modules."""
        repo_path = os.path.abspath(repo_path)
        result: list[str] = []
        for current_dir, subdirs, files in os.walk(repo_path):
            base = os.path.basename(current_dir).lower()
            if base in _EXCLUDED_DIRS:
                subdirs.clear()
                continue
            subdirs[:] = [d for d in subdirs if d.lower() not in _EXCLUDED_DIRS]
            for f in files:
                if f.endswith(".sol"):
                    result.append(os.path.join(current_dir, f))
        return result

    # ──────────────────────────────────────────────────────────
    #  Scoring
    # ──────────────────────────────────────────────────────────

    @staticmethod
    def _score(root: ContractRoot) -> float:
        """
        Score a ContractRoot for compilation priority.

        Higher score = should be compiled first / is more important.
        """
        # Base score from sol count (diminishing returns after 20)
        score = min(root.sol_count, 20) * 5.0

        # Depth penalty: deeper dirs are less likely to be primary source
        score -= root.depth * 3.0

        # Framework bonus: knowing the framework improves compilation success
        if root.framework_hint:
            score += 10.0

        return score
