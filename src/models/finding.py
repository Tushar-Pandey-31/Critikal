from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, List

from src.agents.base_worker import WorkerOutput
from src.hotspot_engine import Hotspot

EVIDENCE_TAG_WEIGHTS = {
    "[POC-PASS]": 1.0,          # forge test exits 0
    "[POC-FAIL]": 0.4,          # PoC compiled but didn't pass
    "[PROD-ONCHAIN]": 1.0,      # verified on mainnet
    "[GRAPH-SIGNAL]": 0.7,      # deterministic Slither-derived
    "[CODE]": 0.8,              # specific code line reference
    "[RAG-MATCH]": 0.6,         # RAG/Solodit precedent found
    "[INFERRED]": 0.3,          # LLM reasoning without code ref
    "[LLM-ONLY]": 0.2,          # no code reference or assumption-worker
}


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
    evidence_tags: List[str] = field(default_factory=list)

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

    # ── v2: Chain analysis fields ─────────────────────────────────
    chain_ids: List[str] = field(default_factory=list)      # CH-01, CH-02 if part of a chain
    chain_role: str = ""                                     # "enabler" or "blocked" or ""
    chain_severity_upgrade: str = ""                         # "MEDIUM → HIGH" etc.


    jury_decision: str = ""
    jury_vote_summary: str = ""
    jury_unprovable: bool = False
    jury_unprovable_reason: str = ""
    jury_escalate: bool = False
    jury_brief: dict = field(default_factory=dict)
    jury_reasoning: str = ""
    jury_rejection_reason: str = ""

    # ── Story 6.2: Gate evaluation fields ─────────────────────────
    # Applied BEFORE the full jury debate. Cheap model, 4 sequential gates.
    # gate_verdict: PASS (all 4 gates cleared) | GATE_REFUTED | GATE_DEMOTED
    gate_verdict: str = ""           # "" = not yet gate-evaluated
    gate_failed: int = 0             # 1-4: which gate killed/demoted this finding
    gate_quote: str = ""             # exact code line that triggered the gate verdict


    def compute_mechanical_confidence(self) -> int:
        """
        Composite = Evidence×0.35 + Consensus×0.25 + RAG×0.2 + LLM_raw×0.2
        Evidence = max weight of any tag present
        """
        tag_weights = [EVIDENCE_TAG_WEIGHTS.get(t, 0.0) for t in self.evidence_tags]
        evidence_score = max(tag_weights) if tag_weights else 0.2
        rag_score = self.confidence_rag_match / 100
        consensus_score = self.confidence_consensus / 100
        llm_score = self.confidence_evidence / 100
        composite = (evidence_score * 0.35 + consensus_score * 0.25 +
                     rag_score * 0.2 + llm_score * 0.2)
        return min(100, round(composite * 100))

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
            evidence_tags=raw.get("evidence_tags", ["[LLM-ONLY]"]),
            preconditions=preconditions,
            preconditions_missing=preconditions_missing,
            postconditions=postconditions,
            confidence_evidence=conf,
        )

    @classmethod
    def from_semantic_output(cls, output: WorkerOutput) -> Finding:
        """Create a Finding from a semantic discovery WorkerOutput (no Hotspot required).

        Semantic agents (InvariantHunter, EconomicAttacker, TrustBoundaryAnalyzer,
        CrossContractStateChecker) produce WorkerOutput objects without any
        Slither-derived Hotspot. This factory synthesises the necessary metadata
        from the WorkerOutput.raw_output dict so findings flow through the same
        jury → depth → chain → report pipeline as graph-based findings.
        """
        raw = output.raw_output or {}
        contract = raw.get("affected_contract", "Unknown")
        function = raw.get("affected_function", "Unknown")
        vuln_class = raw.get("vulnerability_class", "semantic_discovery")
        title = raw.get("title") or f"{vuln_class} in {contract}.{function}"

        preconditions = raw.get("preconditions", [])
        if isinstance(preconditions, str):
            preconditions = [preconditions]
        preconditions_missing = raw.get("preconditions_missing", [])
        if isinstance(preconditions_missing, str):
            preconditions_missing = [preconditions_missing]
        postconditions = raw.get("postconditions", [])
        if isinstance(postconditions, str):
            postconditions = [postconditions]

        raw_verdict = raw.get("verdict", "").upper()
        verdict = FindingVerdict.UNASSESSED
        if raw_verdict in ("CONFIRMED", "PARTIAL", "CONTESTED", "REFUTED"):
            verdict = raw_verdict

        conf = output.confidence
        node_id = f"{contract}::{function}"

        return cls(
            id=str(uuid.uuid4()),
            hotspot_node_id=node_id,
            affected_contract=contract,
            affected_function=function,
            vulnerability_class=vuln_class,
            hypothesis=output.hypothesis,
            attack_path=output.attack_path or [],
            evidence_nodes=[EvidenceNode(node_id=nid) for nid in (output.evidence_node_ids or [])],
            confidence=conf,
            severity_estimate=raw.get("severity_estimate", "MEDIUM"),
            impact=raw.get("impact"),
            title=title,
            risk_score=0,
            # v2 fields
            verdict=verdict,
            evidence_tags=raw.get("evidence_tags", ["[INFERRED]"]),
            preconditions=preconditions,
            preconditions_missing=preconditions_missing,
            postconditions=postconditions,
            confidence_evidence=conf,
        )
