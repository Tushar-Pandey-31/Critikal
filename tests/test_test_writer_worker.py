import pytest
import json
from unittest.mock import MagicMock, AsyncMock

from src.agents.workers.test_writer_worker import TestWriterWorker
from src.agents.base_worker import WorkerTask
from src.models.finding import Finding, FindingStatus

@pytest.fixture
def mock_llm():
    llm = MagicMock()
    llm.ainvoke = AsyncMock()
    return llm

@pytest.fixture
def dummy_finding():
    return Finding(
        finding_id="f1",
        hotspot_node_id="Contract.vuln",
        vulnerability_class="reentrancy",
        title="Test Finding",
        hypothesis="Hypothesis text",
        evidence_nodes=[],
        attack_path=["Contract.entry", "Contract.vuln"],
        status=FindingStatus.DRAFT,
        confidence=50,
        impact="High",
        preconditions=[]
    )

def test_extends_worker_agent(mock_llm):
    worker = TestWriterWorker(llm_client=mock_llm)
    assert worker.get_worker_type() == "test-writer"
    assert worker.MAX_ATTEMPTS == 6

@pytest.mark.asyncio
async def test_missing_finding_in_context(mock_llm):
    worker = TestWriterWorker(llm_client=mock_llm)
    task = WorkerTask(task_id="t1", task_type="test_write", context={})
    output = await worker.run(task)
    
    assert output.confidence == 0
    assert "error" in output.raw_output
    assert "Missing or invalid 'finding'" in output.raw_output["error"]

@pytest.mark.asyncio
async def test_happy_path(mock_llm, dummy_finding):
    mock_llm.ainvoke.return_value = MagicMock(content="```solidity\ncontract Exploit { }\n```")
    
    worker = TestWriterWorker(llm_client=mock_llm)
    worker._compile_and_test = AsyncMock(return_value=(True, True, None))
    
    task = WorkerTask(
        task_id="t1", 
        task_type="test_write", 
        context={"finding": dummy_finding, "relevant_code": {}}
    )
    
    output = await worker.run(task)
    
    assert output.confidence == 100  # exploit success -> 100
    assert output.raw_output["compiled"] is True
    assert output.raw_output["exploit_success"] is True
    assert output.raw_output["test_code"] == "contract Exploit { }"
    assert output.raw_output["attempts"] == 1
    assert output.raw_output["last_error"] is None

@pytest.mark.asyncio
async def test_compile_fail_then_succeed(mock_llm, dummy_finding):
    # LLM will be called twice. Mock its responses.
    responses = [
        MagicMock(content="```solidity\nbad code\n```"),
        MagicMock(content="```solidity\ngood code\n```")
    ]
    mock_llm.ainvoke.side_effect = responses
    
    worker = TestWriterWorker(llm_client=mock_llm)
    # Stub compilation to fail first time, succeed second time
    worker._compile_and_test = AsyncMock(side_effect=[
        (False, False, "Syntax error"),
        (True, True, None)
    ])
    
    task = WorkerTask(task_id="t1", task_type="test", context={"finding": dummy_finding})
    output = await worker.run(task)
    
    assert output.raw_output["attempts"] == 2
    assert output.raw_output["test_code"] == "good code"
    assert output.raw_output["compiled"] is True
    assert output.raw_output["exploit_success"] is True
    assert output.confidence == 100 # Exploit success -> 100

@pytest.mark.asyncio
async def test_max_attempts_exceeded(mock_llm, dummy_finding):
    mock_llm.ainvoke.return_value = MagicMock(content="```sol\nbad code\n```")
    
    worker = TestWriterWorker(llm_client=mock_llm)
    worker._compile_and_test = AsyncMock(return_value=(False, False, "Compiler Error"))
    
    task = WorkerTask(task_id="t1", task_type="test", context={"finding": dummy_finding})
    output = await worker.run(task)
    
    assert output.raw_output["attempts"] == 6
    assert output.raw_output["compiled"] is False
    assert output.raw_output["last_error"] == "Compiler Error"
    assert output.confidence == 50  # Original confidence because we failed

@pytest.mark.asyncio
async def test_extract_code_fallback(mock_llm, dummy_finding):
    # LLM returns some random chat first, valid code second
    responses = [
        MagicMock(content="Wait what? I am not JSON"),
        MagicMock(content="```\nvalid code snippet\n```")
    ]
    mock_llm.ainvoke.side_effect = responses
    
    worker = TestWriterWorker(llm_client=mock_llm)
    worker._compile_and_test = AsyncMock(side_effect=[
        (False, False, "Syntax error"),
        (True, True, None)
    ])
    
    task = WorkerTask(task_id="t1", task_type="test", context={"finding": dummy_finding})
    output = await worker.run(task)
    
    assert output.raw_output["attempts"] == 2
    assert output.raw_output["compiled"] is True
    assert output.raw_output["test_code"] == "valid code snippet"
    assert output.confidence == 100

@pytest.mark.asyncio
async def test_exploit_fails_but_compiles(mock_llm, dummy_finding):
    mock_llm.ainvoke.return_value = MagicMock(content="```solidity\nvalid code\n```")
    
    worker = TestWriterWorker(llm_client=mock_llm)
    # Compiles fine, but assertion fails in test
    worker._compile_and_test = AsyncMock(return_value=(True, False, "Test failed: Assertion Error"))
    
    task = WorkerTask(task_id="t1", task_type="test", context={"finding": dummy_finding})
    output = await worker.run(task)
    
    assert output.raw_output["attempts"] == 6  # It will retry to fix it until max attempts
    assert output.raw_output["compiled"] is True
    assert output.raw_output["exploit_success"] is False
    assert output.raw_output["last_error"] == "Test failed: Assertion Error"
    assert output.confidence == 50  # Original confidence preserved

@pytest.mark.asyncio
async def test_missing_test_code_key(mock_llm, dummy_finding):
    # LLM completely fails to provide it as markdown or anything
    mock_llm.ainvoke.return_value = MagicMock(content="")
    worker = TestWriterWorker(llm_client=mock_llm)
    task = WorkerTask(task_id="t1", task_type="test", context={"finding": dummy_finding})
    output = await worker.run(task)
    
    assert output.raw_output["attempts"] == 6
    assert "did not return any code" in output.raw_output["last_error"]

def test_extract_test_code_direct():
    worker = TestWriterWorker(llm_client=None)
    
    # 1. solidity case
    res1 = worker._extract_test_code("Here is the code:\n```solidity\ncontract A {}\n```")
    assert res1 == "contract A {}"
    
    # 2. sol case
    res2 = worker._extract_test_code("```sol\ncontract B {}\n```")
    assert res2 == "contract B {}"
    
    # 3. unmarked case
    res3 = worker._extract_test_code("```\ncontract C {}\n```")
    assert res3 == "contract C {}"
    
    # 4. full fallback
    res4 = worker._extract_test_code("contract D {}")
    assert res4 == "contract D {}"
