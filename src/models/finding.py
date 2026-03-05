from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, List

from src.agents.base_worker import WorkerOutput
from src.hotspot_engine import Hotspot


class FindingStatus(str, Enum):
    UNCONFIRMED = "UNCONFIRMED"
    PROVEN = "PROVEN"
    DISPROVEN = "DISPROVEN"
    REJECTED = "REJECTED"


@dataclass
class EvidenceNode:
    node_id: str


@dataclass
class Finding:
    id: str
    hotspot_node_id: str
    affected_contract: str
    affected_function: str
    vulnerability_class: str
    hypothesis: str | None
    attack_path: List[str]
    evidence_nodes: List[EvidenceNode]
    confidence: int
    severity_estimate: str
    impact: str | None
    title: str | None
    risk_score: int = 0
    status: FindingStatus = FindingStatus.UNCONFIRMED

    @classmethod
    def from_worker_output(cls, output: WorkerOutput, hotspot: Hotspot) -> Finding:
        raw = output.raw_output or {}
        vuln_class = raw.get("vulnerability_class", "unknown")
        title = raw.get("title") or f"{vuln_class} in {hotspot.contract}.{hotspot.function}"
        return cls(
            id=str(uuid.uuid4()),
            hotspot_node_id=hotspot.node_id,
            affected_contract=raw.get("affected_contract", hotspot.contract),
            affected_function=raw.get("affected_function", hotspot.function),
            vulnerability_class=vuln_class,
            hypothesis=output.hypothesis,
            attack_path=output.attack_path or [],
            evidence_nodes=[EvidenceNode(node_id=nid) for nid in (output.evidence_node_ids or [])],
            confidence=output.confidence,
            severity_estimate=raw.get("severity_estimate", hotspot.priority),
            impact=raw.get("impact"),
            title=title,
            risk_score=hotspot.risk_score,
        )
