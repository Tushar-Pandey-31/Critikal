"""
Import Resolver — pre-Slither import graph validation.

Parses Solidity import statements, builds a dependency graph, and
validates it BEFORE invoking Slither, catching errors early:
  - Missing files
  - Circular imports
  - Unresolvable remappings
"""

from __future__ import annotations

import os
import re
import logging
from collections import defaultdict
from typing import Optional

from src.ingestion.models import ImportValidation

logger = logging.getLogger(__name__)

# ════════════════════════════════════════════════════════════
#  Import Statement Parsing
# ════════════════════════════════════════════════════════════

# Matches: import "path/to/File.sol";
# Matches: import {Foo} from "path/to/File.sol";
# Matches: import "path/to/File.sol" as Alias;
_IMPORT_RE = re.compile(
    r'''import\s+(?:'''
    r'''\{[^}]*\}\s+from\s+)?'''       # optional {Foo, Bar} from
    r'''["']([^"']+)["']'''             # "path/to/File.sol"
    r'''(?:\s+as\s+\w+)?'''             # optional as Alias
    r'''\s*;''',
    re.MULTILINE,
)


class ImportResolver:
    """
    Builds and validates the Solidity import graph.

    Usage::

        resolver = ImportResolver(remappings={"@oz/": "lib/openzeppelin/"})
        graph = resolver.build_import_graph(sol_files)
        validation = resolver.validate(graph)
        components = resolver.find_connected_components(graph)
    """

    def __init__(self, remappings: dict[str, str] | None = None):
        self.remappings = remappings or {}

    # ──────────────────────────────────────────────────────────
    #  Parsing
    # ──────────────────────────────────────────────────────────

    @staticmethod
    def parse_imports(sol_file: str) -> list[str]:
        """
        Extract all import paths from a Solidity file.

        Returns raw import strings exactly as they appear in source
        (before remapping resolution).
        """
        try:
            with open(sol_file, 'r', encoding='utf-8', errors='replace') as f:
                content = f.read()
        except Exception as e:
            logger.warning(f"Could not read {sol_file}: {e}")
            return []

        return _IMPORT_RE.findall(content)

    # ──────────────────────────────────────────────────────────
    #  Remapping Resolution
    # ──────────────────────────────────────────────────────────

    def resolve_import(
        self,
        import_path: str,
        from_file: str,
        base_dir: str,
    ) -> Optional[str]:
        """
        Resolve an import path to an absolute filesystem path.

        Resolution order:
          1. Apply remappings (e.g. @openzeppelin/=node_modules/@openzeppelin/)
          2. Relative to the importing file
          3. Relative to base_dir
        """
        # Step 1: Apply remappings
        resolved = import_path
        for prefix, target in self.remappings.items():
            if resolved.startswith(prefix):
                resolved = target + resolved[len(prefix):]
                break

        # Step 2: Try relative to importing file's directory
        from_dir = os.path.dirname(from_file)
        candidate = os.path.normpath(os.path.join(from_dir, resolved))
        if os.path.isfile(candidate):
            return os.path.abspath(candidate)

        # Step 3: Try relative to base directory
        candidate = os.path.normpath(os.path.join(base_dir, resolved))
        if os.path.isfile(candidate):
            return os.path.abspath(candidate)

        # Step 4: Try common lib/ and node_modules/ paths
        for search_dir in ("lib", "node_modules"):
            candidate = os.path.normpath(os.path.join(base_dir, search_dir, resolved))
            if os.path.isfile(candidate):
                return os.path.abspath(candidate)

        return None

    # ──────────────────────────────────────────────────────────
    #  Import Graph Construction
    # ──────────────────────────────────────────────────────────

    def build_import_graph(
        self,
        sol_files: list[str],
        base_dir: str | None = None,
    ) -> dict[str, list[str]]:
        """
        Build a dependency graph: file → [imported files].

        Keys and values are absolute paths. Unresolvable imports
        are recorded but excluded from the graph edges.
        """
        if base_dir is None and sol_files:
            base_dir = os.path.commonpath([os.path.dirname(f) for f in sol_files])
        base_dir = base_dir or "."

        graph: dict[str, list[str]] = defaultdict(list)
        self._unresolvable: list[tuple[str, str]] = []

        for sol_file in sol_files:
            abs_file = os.path.abspath(sol_file)
            graph.setdefault(abs_file, [])

            raw_imports = self.parse_imports(abs_file)
            for imp in raw_imports:
                resolved = self.resolve_import(imp, abs_file, base_dir)
                if resolved:
                    graph[abs_file].append(resolved)
                else:
                    self._unresolvable.append((abs_file, imp))

        return dict(graph)

    # ──────────────────────────────────────────────────────────
    #  Validation
    # ──────────────────────────────────────────────────────────

    def validate(self, import_graph: dict[str, list[str]]) -> ImportValidation:
        """
        Validate the import graph for common issues.

        Detects:
          - Missing files (imported but not in the graph)
          - Circular imports (strongly connected components with >1 node)
          - Unresolvable remappings (from build_import_graph)
        """
        all_files = set(import_graph.keys())
        missing: list[str] = []
        warnings: list[str] = []

        # Missing files: imported paths that don't exist
        for source, deps in import_graph.items():
            for dep in deps:
                if not os.path.isfile(dep):
                    missing.append(dep)

        # Circular imports: find cycles via DFS
        circular = self._find_cycles(import_graph)

        # Unresolvable remappings
        unresolvable = [
            f"{os.path.basename(f)}: {imp}"
            for f, imp in getattr(self, '_unresolvable', [])
        ]

        if unresolvable:
            warnings.append(
                f"{len(unresolvable)} import(s) could not be resolved "
                f"(may be library dependencies)."
            )

        valid = len(missing) == 0  # Circular imports are warnings, not blockers

        return ImportValidation(
            valid=valid,
            missing_files=missing,
            circular_imports=circular,
            unresolvable_remappings=unresolvable,
            warnings=warnings,
        )

    # ──────────────────────────────────────────────────────────
    #  Connected Components
    # ──────────────────────────────────────────────────────────

    @staticmethod
    def find_connected_components(
        import_graph: dict[str, list[str]],
    ) -> list[set[str]]:
        """
        Find weakly connected components in the import graph.

        Files that import each other (directly or transitively) belong
        to the same component and should be compiled together.
        """
        # Build undirected adjacency for weakly connected components
        adj: dict[str, set[str]] = defaultdict(set)
        all_nodes = set(import_graph.keys())
        for source, deps in import_graph.items():
            for dep in deps:
                adj[source].add(dep)
                adj[dep].add(source)
                all_nodes.add(dep)

        visited: set[str] = set()
        components: list[set[str]] = []

        for node in all_nodes:
            if node in visited:
                continue
            # BFS to find component
            component: set[str] = set()
            queue = [node]
            while queue:
                current = queue.pop()
                if current in visited:
                    continue
                visited.add(current)
                component.add(current)
                for neighbor in adj.get(current, set()):
                    if neighbor not in visited:
                        queue.append(neighbor)
            if component:
                components.append(component)

        return components

    # ──────────────────────────────────────────────────────────
    #  Private: Cycle Detection
    # ──────────────────────────────────────────────────────────

    @staticmethod
    def _find_cycles(graph: dict[str, list[str]]) -> list[list[str]]:
        """Find all cycles in the directed import graph (DFS-based)."""
        WHITE, GRAY, BLACK = 0, 1, 2
        color: dict[str, int] = {n: WHITE for n in graph}
        cycles: list[list[str]] = []
        path: list[str] = []

        def dfs(node: str) -> None:
            color[node] = GRAY
            path.append(node)
            for dep in graph.get(node, []):
                if dep not in color:
                    continue  # external dependency, skip
                if color[dep] == GRAY:
                    # Found a cycle: extract the cycle from path
                    idx = path.index(dep)
                    cycle = path[idx:] + [dep]
                    cycles.append(cycle)
                elif color[dep] == WHITE:
                    dfs(dep)
            path.pop()
            color[node] = BLACK

        for node in graph:
            if color[node] == WHITE:
                dfs(node)

        return cycles

    # ──────────────────────────────────────────────────────────
    #  Remapping Helpers
    # ──────────────────────────────────────────────────────────

    @staticmethod
    def parse_remappings_txt(remappings_path: str) -> dict[str, str]:
        """Parse a remappings.txt file into a dict."""
        remappings: dict[str, str] = {}
        try:
            with open(remappings_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if "=" in line and not line.startswith("#"):
                        alias, target = line.split("=", 1)
                        remappings[alias.strip()] = target.strip()
        except Exception as e:
            logger.warning(f"Could not parse {remappings_path}: {e}")
        return remappings

    @staticmethod
    def parse_foundry_toml_remappings(toml_path: str) -> dict[str, str]:
        """Extract remappings from foundry.toml."""
        remappings: dict[str, str] = {}
        try:
            with open(toml_path, 'r') as f:
                content = f.read()

            # Look for remappings = [...] section
            in_remappings = False
            for line in content.splitlines():
                stripped = line.strip()
                if stripped.startswith("remappings"):
                    in_remappings = True
                    # Handle inline: remappings = ["@oz/=lib/oz/"]
                    bracket_content = re.search(r'\[([^\]]+)\]', stripped)
                    if bracket_content:
                        for entry in bracket_content.group(1).split(","):
                            entry = entry.strip().strip('"').strip("'")
                            if "=" in entry:
                                alias, target = entry.split("=", 1)
                                remappings[alias.strip()] = target.strip()
                        in_remappings = False
                    continue
                if in_remappings:
                    if stripped == "]":
                        in_remappings = False
                        continue
                    entry = stripped.strip('"').strip("'").rstrip(",")
                    if "=" in entry:
                        alias, target = entry.split("=", 1)
                        remappings[alias.strip()] = target.strip()
        except Exception as e:
            logger.warning(f"Could not parse foundry.toml remappings: {e}")
        return remappings

    @staticmethod
    def collect_remappings(directory: str) -> dict[str, str]:
        """
        Collect all remappings for a directory from available sources.

        Priority: remappings.txt > foundry.toml > auto-detected
        """
        remappings: dict[str, str] = {}

        # 1. remappings.txt
        remap_file = os.path.join(directory, "remappings.txt")
        if os.path.exists(remap_file):
            remappings.update(ImportResolver.parse_remappings_txt(remap_file))

        # 2. foundry.toml
        toml_file = os.path.join(directory, "foundry.toml")
        if os.path.exists(toml_file):
            toml_remaps = ImportResolver.parse_foundry_toml_remappings(toml_file)
            for k, v in toml_remaps.items():
                if k not in remappings:
                    remappings[k] = v

        return remappings
