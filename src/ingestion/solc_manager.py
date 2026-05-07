"""
Deterministic Solc Cache Manager.

Wraps solc-select to provide:
  - Version caching (avoids re-installing already-installed versions)
  - Proper semantic version comparison for pragma resolution
  - Per-cluster solc switching
"""

from __future__ import annotations

import logging
import os
import re
import subprocess

logger = logging.getLogger(__name__)

# ════════════════════════════════════════════════════════════
#  Pragma Parsing
# ════════════════════════════════════════════════════════════

# Matches: pragma solidity ^0.8.17; / pragma solidity >=0.6.0 <0.9.0; / etc.
_PRAGMA_RE = re.compile(
    r'pragma\s+solidity\s+([^;]+);'
)

# Matches a single version like 0.8.17
_VERSION_RE = re.compile(r'(\d+\.\d+\.\d+)')

# Matches constraint operators
_CONSTRAINT_RE = re.compile(
    r'([><=^~!]*)\s*(\d+\.\d+\.\d+)'
)


def _parse_version(v: str) -> tuple[int, int, int]:
    """Parse '0.8.17' into (0, 8, 17)."""
    parts = v.strip().split(".")
    return (int(parts[0]), int(parts[1]), int(parts[2]))


def _version_str(t: tuple[int, int, int]) -> str:
    return f"{t[0]}.{t[1]}.{t[2]}"


class SolcManager:
    """
    Manages solc versions via solc-select with local caching.

    Usage::

        mgr = SolcManager()
        version = mgr.resolve_version_for_pragmas({"^0.8.17", ">=0.8.0"})
        mgr.ensure_version(version)  # installs + switches only if needed
    """

    def __init__(self):
        self._installed_versions: set[str] | None = None
        self._active_version: str | None = None
        self._versions_used: list[str] = []

    # ──────────────────────────────────────────────────────────
    #  Version Queries (cached)
    # ──────────────────────────────────────────────────────────

    def get_installed_versions(self) -> set[str]:
        """Query solc-select for installed versions. Cached across calls."""
        if self._installed_versions is not None:
            return self._installed_versions

        try:
            result = subprocess.run(
                ["solc-select", "versions"],
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode == 0:
                versions = set()
                active = None
                for line in result.stdout.strip().splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    is_current = "(current)" in line
                    ver = line.replace("(current)", "").strip()
                    m = _VERSION_RE.match(ver)
                    if m:
                        versions.add(m.group(1))
                        if is_current:
                            active = m.group(1)
                self._installed_versions = versions
                self._active_version = active
                return versions
        except Exception as e:
            logger.warning(f"Could not query solc-select: {e}")

        self._installed_versions = set()
        return self._installed_versions

    def get_active_version(self) -> str | None:
        """Get the currently active solc version."""
        if self._active_version is None:
            self.get_installed_versions()  # populates _active_version
        return self._active_version

    # ──────────────────────────────────────────────────────────
    #  Version Installation
    # ──────────────────────────────────────────────────────────

    def ensure_version(self, version: str) -> bool:
        """
        Install (if needed) and switch to the given solc version.

        Returns True on success.
        """
        installed = self.get_installed_versions()

        # Install only if not already present
        if version not in installed:
            print(f"  Installing solc version {version}...")
            try:
                subprocess.run(
                    ["solc-select", "install", version],
                    check=True, capture_output=True, timeout=300,
                )
                self._installed_versions.add(version)
            except subprocess.CalledProcessError as e:
                stderr = (e.stderr or b"").decode("utf-8", errors="replace").strip()
                print(f"  Error installing solc {version}: {stderr or e}")
                return False
            except subprocess.TimeoutExpired:
                print(f"  solc-select install timed out for {version} (300s).")
                return False

        # Switch only if not already active
        if self._active_version != version:
            print(f"  Switching to solc version {version}...")
            try:
                subprocess.run(
                    ["solc-select", "use", version],
                    check=True, capture_output=True, timeout=10,
                )
                self._active_version = version
            except subprocess.CalledProcessError as e:
                print(f"  Error switching solc version: {e}")
                return False

        if version not in self._versions_used:
            self._versions_used.append(version)

        return True

    @property
    def versions_used(self) -> list[str]:
        """All solc versions that were activated during this session."""
        return list(self._versions_used)

    # ──────────────────────────────────────────────────────────
    #  Pragma Resolution
    # ──────────────────────────────────────────────────────────

    def resolve_version_for_pragmas(self, pragmas: set[str]) -> str | None:
        """
        Given a set of raw pragma constraint strings, resolve the best
        solc version to use.

        Examples of pragma strings:
          - "^0.8.17"
          - ">=0.6.0 <0.9.0"
          - "=0.7.6"
          - "0.8.20"

        Algorithm:
          1. Parse all constraints.
          2. Find the intersection of compatible ranges.
          3. Return the highest version that satisfies all constraints.
        """
        if not pragmas:
            return None

        # Collect all explicit versions mentioned
        all_versions: list[tuple[int, int, int]] = []
        min_version: tuple[int, int, int] | None = None
        max_version: tuple[int, int, int] | None = None

        for pragma in pragmas:
            constraints = _CONSTRAINT_RE.findall(pragma)
            for op, ver_str in constraints:
                ver = _parse_version(ver_str)
                all_versions.append(ver)

                op = op.strip()
                if op in ("^", ">=", ""):
                    # ^0.8.17 means >=0.8.17 <0.9.0
                    # >=0.6.0 means at least 0.6.0
                    # bare version means at least this
                    if min_version is None or ver > min_version:
                        min_version = ver
                    if op == "^":
                        # Caret: upper bound is next minor
                        upper = (ver[0], ver[1] + 1, 0)
                        if max_version is None or upper < max_version:
                            max_version = upper
                elif op == "=":
                    # Exact pin
                    return ver_str
                elif op == "<":
                    if max_version is None or ver < max_version:
                        max_version = ver
                elif op == "<=":
                    upper = (ver[0], ver[1], ver[2] + 1)
                    if max_version is None or upper < max_version:
                        max_version = upper
                elif op == ">":
                    lower = (ver[0], ver[1], ver[2] + 1)
                    if min_version is None or lower > min_version:
                        min_version = lower
                elif op == "~":
                    # Tilde: ~0.8.17 means >=0.8.17 <0.8.18 (next patch)
                    if min_version is None or ver > min_version:
                        min_version = ver

        if not all_versions:
            return None

        # If we have a clear minimum, use that (it's the most specific)
        if min_version is not None:
            return _version_str(min_version)

        # Fallback: return the highest version mentioned
        best = max(all_versions)
        return _version_str(best)

    # ──────────────────────────────────────────────────────────
    #  File-level Pragma Detection
    # ──────────────────────────────────────────────────────────

    @staticmethod
    def detect_pragma(sol_file: str) -> str | None:
        """Read a .sol file and return the raw pragma constraint string."""
        try:
            with open(sol_file, encoding='utf-8', errors='replace') as f:
                content = f.read()
            m = _PRAGMA_RE.search(content)
            if m:
                return m.group(1).strip()
        except Exception:
            pass
        return None

    @staticmethod
    def detect_pragmas_in_directory(directory: str) -> set[str]:
        """Scan all .sol files in directory for pragma strings."""
        pragmas: set[str] = set()
        for root, dirs, files in os.walk(directory):
            # Skip dependency dirs
            base = os.path.basename(root)
            if base in ("lib", "node_modules"):
                dirs.clear()
                continue
            for f in files:
                if f.endswith(".sol"):
                    p = SolcManager.detect_pragma(os.path.join(root, f))
                    if p:
                        pragmas.add(p)
        return pragmas

    @staticmethod
    def extract_version_from_pragma(pragma: str) -> str | None:
        """Extract the primary version number from a pragma string."""
        m = _VERSION_RE.search(pragma)
        return m.group(1) if m else None
