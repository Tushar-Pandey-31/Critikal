"""
Critikal Ingestion Layer — Cluster-based compilation orchestration engine.

Public API:
    - IngestionReport, CompilationCluster, ContractRoot, RepoSizeClass
    - CompilationStrategyResolver
    - ClusterBuilder
    - ImportResolver
    - SolcManager
    - MemoryGuard
    - FrameworkDetector
    - FallbackCompiler
"""

from src.ingestion.models import (
    ClusterResult,
    CompilationCluster,
    ContractRoot,
    FrameworkInstance,
    ImportValidation,
    IngestionReport,
    RepoSizeClass,
)

__all__ = [
    "ClusterResult",
    "CompilationCluster",
    "ContractRoot",
    "FrameworkInstance",
    "ImportValidation",
    "IngestionReport",
    "RepoSizeClass",
]
