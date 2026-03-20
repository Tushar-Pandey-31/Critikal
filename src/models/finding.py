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


class FindingVerdict(str, Enum):
    """Verdict taxonomy — richer than binary PROVEN/REJECTED.
    CONFIRMED:  Strong evidence, exploitable with high confidence.
    PARTIAL:    Exploitable only under specific preconditions not yet met.
    CONTESTED:  Evidence is mixed or incomplete — needs depth pass or human review.
    REFUTED:    Proven non-exploitable with production-quality evidence.
    """
    CONFIRMED = "CONFIRMED"
    PARTIAL = "PARTIAL"
    CONTESTED = "CONTESTED"
    REFUTED = "REFUTED"
    UNASSESSED = "UNASSESSED"


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

    # ── v2: Verdict taxonomy ──────────────────────────────────────
    verdict: str = FindingVerdict.UNASSESSED
    evidence_tag: str = ""  # [POC-PASS] / [POC-FAIL] / [CODE-TRACE] / [POC-PASS-VARIANT] / [FUZZ-PASS]

    # ── v2: Chain analysis fields ─────────────────────────────────
    # preconditions: what must be true for this exploit to work
    preconditions: List[str] = field(default_factory=list)
    # preconditions_missing: conditions NOT currently met (enables chain matching)
    preconditions_missing: List[str] = field(default_factory=list)
    # postconditions: state changes if this exploit succeeds (enables chain matching)
    postconditions: List[str] = field(default_factory=list)

    # ── v2: Depth pass tracking ───────────────────────────────────
    depth_pass_count: int = 0
    depth_verdicts: List[dict] = field(default_factory=list)  # [{agent, verdict, reasoning}]

    # ── v2: Confidence decomposition ──────────────────────────────
    confidence_evidence: int = 0     # 0-100: strength of code/PoC evidence
    confidence_consensus: int = 0    # 0-100: how many agents agree
    confidence_rag_match: int = 0    # 0-100: historical precedent match

    # ── v2: Report fields ─────────────────────────────────────────
    report_id: str = ""           # C-01, H-01, etc. (assigned at report time)
    root_cause_group: str = ""    # for consolidation: same root_cause_group → merged
    rag_matches: List[dict] = field(default_factory=list)  # [{source, snippet}]

    # ── Jury system fields (existing) ─────────────────────────────
    jury_decision: str = ""
    jury_vote_summary: str = ""
    jury_unprovable: bool = False
    jury_unprovable_reason: str = ""
    jury_escalate: bool = False
    jury_brief: dict = field(default_factory=dict)
    jury_reasoning: str = ""
    jury_rejection_reason: str = ""

    @classmethod
    def from_worker_output(cls, output: WorkerOutput, hotspot: Hotspot) -> Finding:
        raw = output.raw_output or {}
        vuln_class = raw.get("vulnerability_class", "unknown")
        title = raw.get("title") or f"{vuln_class} in {hotspot.contract}.{hotspot.function}"

        # v2: Extract preconditions/postconditions/verdict from attack worker output
        preconditions = raw.get("preconditions", [])
        if isinstance(preconditions, str):
            preconditions = [preconditions]
        preconditions_missing = raw.get("preconditions_missing", [])
        if isinstance(preconditions_missing, str):
            preconditions_missing = [preconditions_missing]
        postconditions = raw.get("postconditions", [])
        if isinstance(postconditions, str):
            postconditions = [postconditions]

        # Map attack worker verdict to FindingVerdict
        raw_verdict = raw.get("verdict", "").upper()
        verdict = FindingVerdict.UNASSESSED
        if raw_verdict in ("CONFIRMED", "PARTIAL", "CONTESTED", "REFUTED"):
            verdict = raw_verdict

        # Initial confidence decomposition: evidence axis = worker confidence
        conf = output.confidence

        return cls(
            id=str(uuid.uuid4()),
            hotspot_node_id=hotspot.node_id,
            affected_contract=raw.get("affected_contract", hotspot.contract),
            affected_function=raw.get("affected_function", hotspot.function),
            vulnerability_class=vuln_class,
            hypothesis=output.hypothesis,
            attack_path=output.attack_path or [],
            evidence_nodes=[EvidenceNode(node_id=nid) for nid in (output.evidence_node_ids or [])],
            confidence=conf,
            severity_estimate=raw.get("severity_estimate", hotspot.priority),
            impact=raw.get("impact"),
            title=title,
            risk_score=hotspot.risk_score,
            # v2 fields
            verdict=verdict,
            evidence_tag="[CODE-TRACE]",  # default before PoC runs
            preconditions=preconditions,
            preconditions_missing=preconditions_missing,
            postconditions=postconditions,
            confidence_evidence=conf,
        )
