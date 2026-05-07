import asyncio
from unittest.mock import AsyncMock, Mock

import pytest

from src.pipeline.workers.jury_worker import gate_evaluate


@pytest.fixture
def mock_finding():
    finding = Mock()
    finding.hypothesis = "attacker can reenter withdraw"
    finding.affected_contract = "Vault"
    finding.affected_function = "withdraw"
    finding.vulnerability_class = "reentrancy"
    finding.confidence = 80
    finding.attack_path = ["Vault::withdraw"]
    return finding

@pytest.fixture
def source_code():
    return "function withdraw() public { require(msg.sender == owner); ... }"

@pytest.mark.asyncio
async def test_gate_eval_pass(mock_finding, source_code):
    llm = Mock()
    llm.ainvoke = AsyncMock(return_value=Mock(
        content='{"verdict": "PASS", "gate": 0, "quote": ""}'
    ))

    result = await gate_evaluate(mock_finding, source_code, llm)
    assert result.verdict == "PASS"
    assert result.gate == 0
    assert result.quote == ""

@pytest.mark.asyncio
async def test_gate1_concrete_refutation_returns_refuted(mock_finding, source_code):
    llm = Mock()
    llm.ainvoke = AsyncMock(return_value=Mock(
        content='{"verdict": "GATE_REFUTED", "gate": 1, "quote": "require(msg.sender == owner);"}'
    ))

    result = await gate_evaluate(mock_finding, source_code, llm)
    assert result.verdict == "GATE_REFUTED"
    assert result.gate == 1
    assert result.quote == "require(msg.sender == owner);"

@pytest.mark.asyncio
async def test_gate3_privileged_only_demotes(mock_finding, source_code):
    llm = Mock()
    llm.ainvoke = AsyncMock(return_value=Mock(
        content='{"verdict": "GATE_DEMOTED", "gate": 3, "quote": "onlyOwner"}'
    ))

    result = await gate_evaluate(mock_finding, source_code, llm)
    assert result.verdict == "GATE_DEMOTED"
    assert result.gate == 3
    assert result.quote == "onlyOwner"

@pytest.mark.asyncio
async def test_gate_eval_timeout_fails_open(mock_finding, source_code, monkeypatch):
    llm = Mock()
    async def delayed_invoke(*args, **kwargs):
        await asyncio.sleep(2)
        return Mock(content="")
    llm.ainvoke = delayed_invoke

    # _GATE_TIMEOUT is read once at module import; patch the resolved constant.
    from src.pipeline.workers import jury_worker
    monkeypatch.setattr(jury_worker, "_GATE_TIMEOUT", 1)

    result = await gate_evaluate(mock_finding, source_code, llm)
    assert result.verdict == "PASS"  # Fails open
    assert result.quote == "timeout"
