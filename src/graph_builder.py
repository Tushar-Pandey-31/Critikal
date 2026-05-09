"""
Backward-compatibility shim.

The GraphBuilder class has moved to src.graph.builder.
This module re-exports it so existing imports continue to work.

    # Old (still works):
    from src.graph_builder import GraphBuilder

    # New (preferred):
    from src.graph import GraphBuilder
"""

import warnings as _warnings

_warnings.warn(
    "Importing GraphBuilder from src.graph_builder is deprecated. Use 'from src.graph import GraphBuilder' instead.",
    DeprecationWarning,
    stacklevel=2,
)

from src.graph.builder import GraphBuilder
from src.graph.nodes_edges import ENABLE_CROSS_CONTRACT_EDGES

__all__ = ["ENABLE_CROSS_CONTRACT_EDGES", "GraphBuilder"]
