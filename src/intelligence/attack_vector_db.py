"""
Attack Vector Database (P0.2)

160+ curated attack vectors in machine-readable YAML with:
- Detection patterns (what to look for in code)
- False-positive guards (when it's NOT a bug)
- Protocol-type filtering
- Prompt-injectable bundle generation

Usage:
    db = AttackVectorDB()
    matched = db.match_vectors(graph, ["vault", "lending"])
    bundle = db.build_agent_bundle(matched, hotspot_source)
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml
import networkx as nx

logger = logging.getLogger(__name__)

_DATA_DIR = Path(__file__).parent / "data"
_VECTORS_PATH = _DATA_DIR / "vectors.yaml"


# ════════════════════════════════════════════════════════════
#  Data Model
# ════════════════════════════════════════════════════════════

@dataclass
class AttackVector:
    """A single curated attack vector with detection and FP guard."""
    id: str                              # "V001"
    title: str                           # "ERC4626 Share Inflation"
    root_cause: str                      # Why this bug exists
    detection_pattern: str               # What to look for in code
    false_positive_guard: str            # When this is NOT a bug
    applicable_protocols: list[str]      # ["vault", "lending"]
    severity_range: str                  # "HIGH-CRITICAL"
    category: str = ""                   # "arithmetic", "access_control", etc.
    references: list[str] = field(default_factory=list)

    def format_compact(self) -> str:
        """Format as a compact block for prompt injection."""
        return (
            f"[{self.id}] {self.title} ({self.severity_range})\n"
            f"  Root cause: {self.root_cause}\n"
            f"  Look for: {self.detection_pattern}\n"
            f"  NOT a bug if: {self.false_positive_guard}\n"
        )


# ════════════════════════════════════════════════════════════
#  Attack Vector Database
# ════════════════════════════════════════════════════════════

class AttackVectorDB:
    """
    Curated attack vector database loaded from YAML.
    Provides matching, filtering, and prompt-injectable bundles.
    """

    def __init__(self, vectors_path: str | Path | None = None):
        self._vectors_path = Path(vectors_path) if vectors_path else _VECTORS_PATH
        self._vectors: list[AttackVector] = []
        self._by_id: dict[str, AttackVector] = {}
        self._by_protocol: dict[str, list[AttackVector]] = {}
        self._by_category: dict[str, list[AttackVector]] = {}
        self._load_vectors()

    def _load_vectors(self) -> None:
        """Load and index vectors from YAML."""
        if not self._vectors_path.exists():
            logger.warning(f"Attack vectors not found at {self._vectors_path}")
            return

        try:
            with open(self._vectors_path, "r") as f:
                raw = yaml.safe_load(f) or {}
        except Exception as e:
            logger.error(f"Failed to load attack vectors: {e}")
            return

        for entry in raw.get("vectors", []):
            vec = AttackVector(
                id=entry.get("id", "V???"),
                title=entry.get("title", "Unnamed"),
                root_cause=entry.get("root_cause", ""),
                detection_pattern=entry.get("detection_pattern", ""),
                false_positive_guard=entry.get("false_positive_guard", ""),
                applicable_protocols=entry.get("applicable_protocols", []),
                severity_range=entry.get("severity_range", "UNKNOWN"),
                category=entry.get("category", ""),
                references=entry.get("references", []),
            )
            self._vectors.append(vec)
            self._by_id[vec.id] = vec

            # Index by protocol
            for proto in vec.applicable_protocols:
                self._by_protocol.setdefault(proto, []).append(vec)

            # Index by category
            if vec.category:
                self._by_category.setdefault(vec.category, []).append(vec)

        logger.info(f"Loaded {len(self._vectors)} attack vectors across {len(self._by_protocol)} protocol types")

    @property
    def total_vectors(self) -> int:
        return len(self._vectors)

    def get_vector(self, vector_id: str) -> AttackVector | None:
        """Get a single vector by ID."""
        return self._by_id.get(vector_id)

    def get_all_vectors(self) -> list[AttackVector]:
        """Get all loaded vectors."""
        return list(self._vectors)

    def match_vectors(
        self,
        graph: nx.DiGraph,
        protocol_types: list[str],
        *,
        include_universal: bool = True,
    ) -> list[AttackVector]:
        """
        Return vectors applicable to this codebase based on protocol types.

        Args:
            graph: The knowledge graph (used for additional signal matching)
            protocol_types: Detected protocol types (e.g., ["vault", "lending"])
            include_universal: If True, include vectors with ["all"] protocol type

        Returns:
            Deduplicated list of matching vectors, sorted by severity.
        """
        matched_ids: set[str] = set()
        matched: list[AttackVector] = []

        for proto in protocol_types:
            for vec in self._by_protocol.get(proto, []):
                if vec.id not in matched_ids:
                    matched_ids.add(vec.id)
                    matched.append(vec)

        # Include universal vectors (applicable to all protocol types)
        if include_universal:
            for vec in self._by_protocol.get("all", []):
                if vec.id not in matched_ids:
                    matched_ids.add(vec.id)
                    matched.append(vec)

        # Sort by severity: CRITICAL > HIGH > MEDIUM > LOW
        severity_order = {
            "CRITICAL": 0,
            "HIGH-CRITICAL": 1,
            "HIGH": 2,
            "MEDIUM-HIGH": 3,
            "MEDIUM": 4,
            "LOW-MEDIUM": 5,
            "LOW": 6,
        }
        matched.sort(key=lambda v: severity_order.get(v.severity_range, 99))

        logger.info(
            f"Matched {len(matched)} vectors for protocol types {protocol_types}"
        )
        return matched

    def match_vectors_for_hotspot(
        self,
        matched_vectors: list[AttackVector],
        hotspot_source: str,
    ) -> list[AttackVector]:
        """
        Further filter matched vectors against a specific hotspot's source code.
        Uses lightweight keyword matching — NOT full analysis (that's the agent's job).

        Returns vectors where at least one detection keyword appears in the source.
        """
        if not hotspot_source:
            return matched_vectors  # can't filter without source, return all

        source_lower = hotspot_source.lower()
        relevant: list[AttackVector] = []

        for vec in matched_vectors:
            # Extract key terms from detection pattern
            detection_lower = vec.detection_pattern.lower()
            # Look for function names, variable names, or patterns
            keywords = _extract_detection_keywords(detection_lower)

            if any(kw in source_lower for kw in keywords):
                relevant.append(vec)

        return relevant

    def build_agent_bundle(
        self,
        vectors: list[AttackVector],
        hotspot_source: str = "",
        *,
        max_vectors: int = 20,
        max_tokens: int = 2000,
    ) -> str:
        """
        Build a prompt-injectable bundle of relevant vectors.

        The bundle is formatted as a compact block that fits within the agent's
        context window. Each vector includes its ID, title, detection pattern,
        and false-positive guard.

        Args:
            vectors: List of matched vectors to include
            hotspot_source: Source code of the hotspot (for relevance filtering)
            max_vectors: Maximum number of vectors in the bundle
            max_tokens: Approximate token budget (4 chars ≈ 1 token)

        Returns:
            Formatted string ready for prompt injection.
        """
        if not vectors:
            return ""

        # Further filter by hotspot relevance if source is available
        if hotspot_source:
            relevant = self.match_vectors_for_hotspot(vectors, hotspot_source)
            # Fall back to all matched if no relevant found
            if not relevant:
                relevant = vectors
        else:
            relevant = vectors

        # Cap at max_vectors
        relevant = relevant[:max_vectors]

        # Build the bundle
        lines = [
            "═══ ATTACK VECTOR DATABASE ═══",
            f"({len(relevant)} vectors matched for this hotspot)",
            "",
            "For EACH vector below, classify as:",
            "  SKIP: Both construct AND concept are absent from the code",
            "  DROP: Guard unambiguously blocks (cite exact guard code)",
            "  INVESTIGATE: No guard, partial guard, or guard with gaps",
            "",
        ]

        char_count = sum(len(line) for line in lines)
        included = 0

        for vec in relevant:
            entry = vec.format_compact()
            entry_chars = len(entry)

            if char_count + entry_chars > max_tokens * 4:
                lines.append(f"... ({len(relevant) - included} more vectors truncated)")
                break

            lines.append(entry)
            char_count += entry_chars
            included += 1

        lines.append(f"═══ END VECTORS ({included} included) ═══")
        return "\n".join(lines)

    def get_vectors_by_category(self, category: str) -> list[AttackVector]:
        """Get all vectors in a specific category."""
        return list(self._by_category.get(category, []))

    def get_categories(self) -> list[str]:
        """Get all available vector categories."""
        return sorted(self._by_category.keys())

    def get_protocol_types(self) -> list[str]:
        """Get all protocol types that have vectors."""
        return sorted(self._by_protocol.keys())


# ════════════════════════════════════════════════════════════
#  Helpers
# ════════════════════════════════════════════════════════════

def _extract_detection_keywords(detection_pattern: str) -> list[str]:
    """
    Extract searchable keywords from a detection pattern string.
    Looks for function names, variable names, and Solidity patterns.
    """
    import re

    keywords: list[str] = []

    # Extract function-like names: word followed by ()
    func_matches = re.findall(r'\b(\w+)\(\)', detection_pattern)
    keywords.extend(func_matches)

    # Extract camelCase/PascalCase identifiers (likely contract/function names)
    ident_matches = re.findall(r'\b([a-zA-Z_]\w{3,})\b', detection_pattern)
    # Filter out common English words
    stopwords = {
        "look", "find", "check", "that", "this", "with", "from", "without",
        "used", "uses", "using", "where", "when", "what", "function",
        "contract", "variable", "state", "internal", "external", "public",
        "private", "modifier", "require", "assert", "return", "call",
        "transfer", "should", "must", "does", "have", "been", "will",
        "before", "after", "during", "between", "within",
    }
    for ident in ident_matches:
        if ident.lower() not in stopwords and len(ident) >= 4:
            keywords.append(ident.lower())

    return list(set(keywords))
