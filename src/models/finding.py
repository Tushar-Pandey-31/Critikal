from enum import Enum
from dataclasses import dataclass, field
from datetime import datetime, timezone
import uuid


class FindingStatus(Enum):
    DRAFT = "draft"
    SANITY_PASSED = "sanity_passed"
    SANITY_FAILED = "sanity_failed"
    LOGIC_PASSED = "logic_passed"
    LOGIC_FAILED = "logic_failed"
    PROMOTED = "promoted"
    PROVEN = "proven"
    REJECTED = "rejected"


@dataclass
class EvidenceNode:
    node_id: str         # Canonical graph node ID — must exist in graph
    node_type: str       # "function" | "variable" | "modifier"
    contract: str
    name: str
    relevance: str       # Why this node supports the finding


@dataclass
class Finding:
    id: str
    hotspot_node_id: str
    vulnerability_class: str
    title: str
    hypothesis: str
    evidence_nodes: list[EvidenceNode]
    attack_path: list[str]         # Ordered node IDs — entry → ... → vuln
    status: FindingStatus
    confidence: int                # 0–100
    impact: str
    preconditions: list[str]
    affected_contract: str
    affected_function: str
    severity_estimate: str         # "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"
    severity: str                  # DEPRECATED: use severity_estimate instead
    sanity_verdict: dict | None = None
    logic_verdict: dict | None = None
    test_result: dict | None = None
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    @classmethod
    def from_worker_output(cls, output, hotspot) -> "Finding":
        """
        Converts a WorkerOutput into a Finding.
        Called by the Coordinator after receiving Attack Worker results.
        """
        from src.utils.node_ids import normalize_node_id

        raw = output.raw_output or {}
        return cls(
            id=str(uuid.uuid4()),
            hotspot_node_id=hotspot.node_id,
            vulnerability_class=raw.get("vulnerability_class", "unknown"),
            title=raw.get("title", "Unnamed Lead"),
            hypothesis=output.hypothesis or "",
            evidence_nodes=[
                EvidenceNode(
                    node_id=normalize_node_id(nid),
                    node_type="function",   # Refined by Sanity Jury later
                    contract=hotspot.contract,
                    name=nid.split(".")[-1] if "." in nid else nid,
                    relevance="Cited by Attack Worker"
                )
                for nid in output.evidence_node_ids
            ],
            attack_path=[normalize_node_id(p) for p in output.attack_path],
            status=FindingStatus.DRAFT,
            confidence=output.confidence,
            impact=raw.get("impact", "Unknown"),
            preconditions=raw.get("preconditions", []),
            affected_contract=hotspot.contract,
            affected_function=hotspot.function,
            severity_estimate=hotspot.priority,
            severity=hotspot.priority,
        )

