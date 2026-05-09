from unittest.mock import MagicMock

import pytest

from src.models.finding import Finding, FindingStatus
from src.pipeline.base_worker import WorkerTask
from src.pipeline.workers.fuzz_generator import FuzzGeneratorWorker


@pytest.fixture
def mock_llm():
    llm = MagicMock()
    return llm


@pytest.fixture
def dummy_finding():
    return Finding(
        id="f1",
        hotspot_node_id="Contract::vuln",
        vulnerability_class="reentrancy",
        title="Test Finding",
        hypothesis="Hypothesis text",
        evidence_nodes=[],
        attack_path=["Contract::entry", "Contract::vuln"],
        status=FindingStatus.PROVEN,
        confidence=80,
        impact="High",
        severity_estimate="CRITICAL",
        affected_contract="Contract",
        affected_function="vuln",
    )


@pytest.mark.asyncio
async def test_extends_worker_agent(mock_llm):
    worker = FuzzGeneratorWorker(llm_client=mock_llm)
    assert worker.get_worker_type() == "fuzz-generator"
    assert worker.MAX_ATTEMPTS == 3


@pytest.mark.asyncio
async def test_missing_finding_in_context(mock_llm):
    worker = FuzzGeneratorWorker(llm_client=mock_llm)
    task = WorkerTask(task_id="t1", task_type="fuzz_generator", context={})
    output = await worker.run(task)

    assert output.confidence == 0
    assert "error" in output.raw_output
    assert "Missing finding" in output.raw_output["error"]


@pytest.mark.asyncio
async def test_successful_fuzz_violation(mock_llm, dummy_finding, monkeypatch, tmp_path):
    mock_llm.invoke.return_value = MagicMock(
        content="```solidity\ncontract FuzzTest { function invariant_test() public {} }\n```"
    )

    mock_sandbox = MagicMock()
    mock_sandbox.tmp_dir = tmp_path
    mock_sandbox.get_test_path.return_value = tmp_path / "test"
    # Build succeeds, Test fails (meaning an invariant was broken -> fuzzing success)
    mock_sandbox.run_forge_build.return_value = MagicMock(success=True)
    mock_sandbox.run.return_value = MagicMock(success=False, logs="Invariant broken!")

    worker = FuzzGeneratorWorker(llm_client=mock_llm)

    task = WorkerTask(
        task_id="t1", task_type="fuzz_generator", context={"finding": dummy_finding, "sandbox": mock_sandbox}
    )

    output = await worker.run(task)

    assert output.raw_output["compiled"] is True
    assert output.raw_output["violation_found"] is True
    assert output.confidence == 100  # Boosted from 80
    assert "contract FuzzTest" in output.raw_output["fuzz_code"]


@pytest.mark.asyncio
async def test_unsuccessful_fuzz_violation(mock_llm, dummy_finding, monkeypatch, tmp_path):
    mock_llm.invoke.return_value = MagicMock(
        content="```solidity\ncontract FuzzTest { function invariant_test() public {} }\n```"
    )

    mock_sandbox = MagicMock()
    mock_sandbox.tmp_dir = tmp_path
    mock_sandbox.get_test_path.return_value = tmp_path / "test"
    # Build succeeds, Test succeeds (meaning invariant NOT broken -> fuzzing failed to find bug)
    mock_sandbox.run_forge_build.return_value = MagicMock(success=True)
    mock_sandbox.run.return_value = MagicMock(success=True, logs="Passed!")

    worker = FuzzGeneratorWorker(llm_client=mock_llm)

    task = WorkerTask(
        task_id="t1", task_type="fuzz_generator", context={"finding": dummy_finding, "sandbox": mock_sandbox}
    )

    output = await worker.run(task)

    assert output.raw_output["compiled"] is True
    assert output.raw_output["violation_found"] is False
    assert output.confidence == 80  # Unchanged
