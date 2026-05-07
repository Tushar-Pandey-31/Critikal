"""
JuryContextPackage — builds the evidence package sent to all jurors.

Built once per finding, sent identically to all 3 jurors.
Contains only verified, deterministic information — no LLM speculation.
"""

from __future__ import annotations

from typing import Any


def build_jury_context_package(
    finding: Any,
    hotspot: Any,
    graph: Any,
    raw_source_code: str,
) -> dict:
    """
    Build the jury context package for a single finding.

    This package is built once and sent identically to all 3 jurors.
    It contains only deterministic, verifiable information.
    Never contains LLM speculation beyond the hypothesis itself.
    """
    node_data = graph.nodes.get(hotspot.node_id, {})

    return {
        # Deterministic anchor
        "node_id": hotspot.node_id,
        "contract": hotspot.contract,
        "function": hotspot.function,

        # Raw source — just the vulnerable contract file, not whole repo
        "source_code": raw_source_code,

        # Graph scores
        "scores": {
            "structural": node_data.get("structural_score", 0),
            "exploitability": node_data.get("exploitability_score", 0),
            "impact": node_data.get("impact_score", 0),
            "final": node_data.get("final_score", 0),
        },

        # Deterministic graph signals — these are facts, not opinions
        "signals": {
            "reentrancy_risk": node_data.get("reentrancy_risk", False),
            "is_unprotected_mutator": node_data.get("is_unprotected_mutator", False),
            "can_escalate_privileges": node_data.get("can_escalate_privileges", False),
            "state_write_after_external_call": node_data.get("state_write_after_external_call", False),
            "makes_external_call": node_data.get("makes_external_call", False),
            "is_protected": node_data.get("is_protected", False),
            "access_control_type": node_data.get("access_control_type", "none"),
            "taint_sources": node_data.get("taint_sources", []),
            "tainted_state_writes": node_data.get("tainted_state_writes", []),
            "has_reentrancy_guard": node_data.get("has_reentrancy_guard", False),
            "flash_loan_risk": node_data.get("flash_loan_risk", False),
            "flash_loan_risk_factors": node_data.get("flash_loan_risk_factors", {}),
            "flash_loan_score": node_data.get("flash_loan_score", 0),
            "invariant_violations": node_data.get("invariant_violations", []),
            "invariant_violation_count": node_data.get("invariant_violation_count", 0),
            "external_protocols": node_data.get("external_protocols", []),
            "cross_protocol_risks": node_data.get("cross_protocol_risks", []),
        },

        # Titan pattern hits — deterministic regex evidence
        "pattern_hits": node_data.get("pattern_hit_details", []),

        # The hypothesis to validate — this IS LLM output, jurors should treat skeptically
        "hypothesis": {
            "vulnerability_class": getattr(finding, "vulnerability_class", "unknown"),
            "narrative": getattr(finding, "hypothesis", ""),
            "attack_path": getattr(finding, "attack_path", []),
            "confidence": getattr(finding, "confidence", 0),
            "impact": getattr(finding, "impact", ""),
            "preconditions": getattr(finding, "preconditions", []),
        },
    }
