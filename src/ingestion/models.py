"""
Data models for the ingestion pipeline.

All modules in src/ingestion/ share these dataclasses.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

# ════════════════════════════════════════════════════════════
#  Repo Size Classification
# ════════════════════════════════════════════════════════════


class RepoSizeClass(Enum):
    SMALL = "small"  # <50 .sol files
    MEDIUM = "medium"  # 50–300
    LARGE = "large"  # 300–1000
    MASSIVE = "massive"  # >1000


# ════════════════════════════════════════════════════════════
#  Strategy Resolver Models
# ════════════════════════════════════════════════════════════


@dataclass
class ContractRoot:
    """A directory containing Solidity source files suitable for compilation."""

    path: str  # Absolute path
    sol_count: int
    depth: int  # Relative to repo root
    framework_hint: str | None = None  # "foundry" | "hardhat" | "brownie" | None
    score: float = 0.0  # Computed priority score


# ════════════════════════════════════════════════════════════
#  Framework Detection Models
# ════════════════════════════════════════════════════════════


@dataclass
class FrameworkInstance:
    """A framework detected at a specific directory."""

    framework: str  # "foundry" | "hardhat" | "brownie"
    path: str  # Absolute path to the directory
    config_file: str  # The config file that triggered detection


# ════════════════════════════════════════════════════════════
#  Import Resolver Models
# ════════════════════════════════════════════════════════════


@dataclass
class ImportValidation:
    """Results of pre-Slither import graph validation."""

    valid: bool
    missing_files: list[str] = field(default_factory=list)
    circular_imports: list[list[str]] = field(default_factory=list)
    unresolvable_remappings: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


# ════════════════════════════════════════════════════════════
#  Compilation Cluster Models
# ════════════════════════════════════════════════════════════


@dataclass
class CompilationCluster:
    """
    A group of Solidity files that should be compiled together.

    Clusters are formed by:
      - Shared imports (import-connected components)
      - Shared base directories
      - Compatible pragma versions
    """

    cluster_id: str
    root_path: str  # Compilation root directory
    sol_files: list[str] = field(default_factory=list)
    pragma_versions: set[str] = field(default_factory=set)
    import_graph: dict[str, list[str]] = field(default_factory=dict)
    framework: str | None = None  # "foundry" | "hardhat" | "brownie" | None
    solc_version: str | None = None  # Resolved target version


# ════════════════════════════════════════════════════════════
#  Compilation Result Models
# ════════════════════════════════════════════════════════════


@dataclass
class ClusterResult:
    """Result of compiling a single cluster."""

    cluster_id: str
    success: bool
    slither_obj: object = None  # Slither | None (avoid import cycle)
    contracts_parsed: int = 0
    error: str | None = None
    fallback_level: int = 0  # 0=direct, 1=subdir, 2=SCC, 3=per-file


@dataclass
class IngestionReport:
    """
    Structured report of the full ingestion pipeline.

    Returned alongside the combined Slither object so callers
    always get diagnostics even on partial success.
    """

    repo_type: str = "unknown"
    frameworks_detected: list[str] = field(default_factory=list)
    total_sol_files: int = 0
    size_class: str = "unknown"
    clusters_detected: int = 0
    clusters_compiled: int = 0
    clusters_failed: int = 0
    memory_guard_triggered: bool = False
    failed_clusters: list[str] = field(default_factory=list)
    cluster_results: list[ClusterResult] = field(default_factory=list)
    solc_versions_used: list[str] = field(default_factory=list)
    total_contracts_parsed: int = 0
    warnings: list[str] = field(default_factory=list)

    def summary(self) -> str:
        """One-line human-readable summary."""
        status = "✅" if self.clusters_failed == 0 else "⚠️"
        return (
            f"{status} Ingestion: {self.clusters_compiled}/{self.clusters_detected} clusters compiled, "
            f"{self.total_contracts_parsed} contracts parsed, "
            f"{self.total_sol_files} .sol files ({self.size_class})"
        )
