import asyncio
from unittest.mock import MagicMock
from src.agents.workers.test_writer_worker import TestWriterWorker
from src.models.finding import Finding, FindingStatus

dummy_finding = Finding(
    id="f1",
    hotspot_node_id="Contract::vuln",
    vulnerability_class="reentrancy",
    title="Test Finding",
    hypothesis="Hypothesis text",
    evidence_nodes=[],
    attack_path=["Contract::entry", "Contract::vuln"],
    status=FindingStatus.UNCONFIRMED,
    confidence=50,
    impact="High",
    severity_estimate="HIGH",
    affected_contract="Contract",
    affected_function="vuln"
)

worker = TestWriterWorker(llm_client=MagicMock())
scaffold = worker._generate_test_scaffold(dummy_finding, "deploy_path:Contract", is_legacy=True, target_pragma="^0.4.24")

print("---SCAFFOLD OUTPUT---")
print(scaffold)
print("---------------------")
if "BridgeInterfaces.sol" in scaffold:
    print("FAIL: BridgeInterfaces.sol should not be in scaffold for bridge mode.")
else:
    print("PASS: BridgeInterfaces.sol is removed.")
