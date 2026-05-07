
from src.hotspot_engine import Hotspot
from src.models.finding import Finding
from src.pipeline.base_worker import WorkerOutput


def test_finding_normalizes_attack_and_evidence_ids():
    hotspot = Hotspot(
        node_id="Vault::withdraw",
        contract="Vault",
        function="withdraw",
        risk_score=90,
        risk_categories=["reentrancy"],
        signals={},
        priority="HIGH",
    )
    output = WorkerOutput(
        worker_type="attack_hypothesis",
        confidence=80,
        attack_path=["Vault.withdraw", "Vault::withdraw"],
        evidence_node_ids=["Vault.balances", "Vault::balances"],
        raw_output={},
    )
    finding = Finding.from_worker_output(output, hotspot)
    assert finding.attack_path == ["Vault.withdraw", "Vault::withdraw"]
    assert [e.node_id for e in finding.evidence_nodes] == ["Vault.balances", "Vault::balances"]


def test_finding_default_status_is_unconfirmed():
    hotspot = Hotspot(
        node_id="C::f",
        contract="C",
        function="f",
        risk_score=80,
        risk_categories=[],
        signals={},
        priority="MEDIUM",
    )
    output = WorkerOutput(worker_type="attack_hypothesis", confidence=50, raw_output={})
    finding = Finding.from_worker_output(output, hotspot)
    from src.models.finding import FindingStatus
    assert finding.status == FindingStatus.UNCONFIRMED
