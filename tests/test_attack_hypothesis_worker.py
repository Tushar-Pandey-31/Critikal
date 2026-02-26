import pytest
import uuid
import json
import networkx as nx
from unittest.mock import MagicMock, AsyncMock, patch
from src.agents.workers.attack_hypothesis_worker import AttackHypothesisWorker, CATEGORY_TO_CLASS
from src.agents.base_worker import WorkerTask, WorkerOutput, WorkerAgent
from src.hotspot_engine import Hotspot
from src.models.finding import Finding, FindingStatus

# =================================================================
#  Fixtures
# =================================================================

@pytest.fixture
def mock_graph():
    G = nx.DiGraph()
    # Add a hotspot node
    G.add_node("Vault.withdraw", type="function", contract="Vault", name="withdraw", risk_score=95)
    # Add a target state var
    G.add_node("Vault.balances", type="state_variable", contract="Vault", name="balances")
    # Add a call edge
    G.add_edge("Vault.withdraw", "Vault.balances", type="WRITES")
    return G

@pytest.fixture
def reentrancy_hotspot():
    return Hotspot(
        node_id="Vault.withdraw",
        contract="Vault",
        function="withdraw",
        risk_score=95,
        risk_categories=["reentrancy"],
        signals={
            "reentrancy_risk": True,
            "state_write_after_external_call": True, 
            "makes_external_call": True, 
            "entry_points": ["Vault.withdraw"],
            "reachable_from_external_entry": True
        },
        priority="CRITICAL"
    )

@pytest.fixture
def mock_llm():
    llm = MagicMock()
    llm.ainvoke = AsyncMock()
    return llm

# =================================================================
#  Group 1: Base Class Contract (4 tests)
# =================================================================

def test_extends_worker_agent(mock_graph, mock_llm):
    worker = AttackHypothesisWorker(graph=mock_graph, llm_client=mock_llm)
    assert isinstance(worker, WorkerAgent)

def test_get_worker_type(mock_graph, mock_llm):
    worker = AttackHypothesisWorker(graph=mock_graph, llm_client=mock_llm)
    assert worker.get_worker_type() == "attack_hypothesis"

@pytest.mark.asyncio
async def test_returns_worker_output(mock_graph, mock_llm, reentrancy_hotspot):
    mock_llm.ainvoke.return_value = MagicMock(content='{"vulnerability_class": "reentrancy", "confidence": 90, "attack_path": ["Vault.withdraw"], "evidence_node_ids": ["Vault.withdraw"]}')
    worker = AttackHypothesisWorker(graph=mock_graph, llm_client=mock_llm)
    task = WorkerTask(task_id="t1", task_type="attack", hotspot=reentrancy_hotspot)
    output = await worker.run(task)
    assert isinstance(output, WorkerOutput)

@pytest.mark.asyncio
async def test_no_hotspot_returns_zero_confidence(mock_graph, mock_llm):
    worker = AttackHypothesisWorker(graph=mock_graph, llm_client=mock_llm)
    task = WorkerTask(task_id="t2", task_type="attack", hotspot=None)
    output = await worker.run(task)
    assert output.confidence == 0
    assert output.worker_type == "attack_hypothesis"

# =================================================================
#  Group 2: Reentrancy Detection (5 tests)
# =================================================================

@pytest.mark.asyncio
async def test_reentrancy_hotspot_produces_finding(mock_graph, mock_llm, reentrancy_hotspot):
    mock_llm.ainvoke.return_value = MagicMock(content='{"vulnerability_class": "reentrancy", "confidence": 90, "attack_path": ["Vault.withdraw"], "evidence_node_ids": ["Vault.withdraw"], "title": "T", "hypothesis": "H", "impact": "I", "preconditions": [], "reasoning": "R"}')
    worker = AttackHypothesisWorker(graph=mock_graph, llm_client=mock_llm)
    task = WorkerTask(task_id="t3", task_type="attack", hotspot=reentrancy_hotspot)
    output = await worker.run(task)
    assert output.confidence == 90
    assert output.raw_output["vulnerability_class"] == "reentrancy"

@pytest.mark.asyncio
async def test_attack_path_is_ordered_list_of_strings(mock_graph, mock_llm, reentrancy_hotspot):
    path = ["Entry::func", "Proxy::call", "Vault::withdraw"]
    mock_llm.ainvoke.return_value = MagicMock(content=json.dumps({
        "vulnerability_class": "reentrancy", "confidence": 90, "attack_path": ["Entry.func", "Proxy.call", "Vault.withdraw"], "evidence_node_ids": ["Vault.withdraw"]
    }))
    worker = AttackHypothesisWorker(graph=mock_graph, llm_client=mock_llm)
    task = WorkerTask(task_id="t4", task_type="attack", hotspot=reentrancy_hotspot)
    output = await worker.run(task)
    assert output.attack_path == path
    assert all(isinstance(x, str) for x in output.attack_path)

@pytest.mark.asyncio
async def test_attack_path_starts_from_entry_point(mock_graph, mock_llm, reentrancy_hotspot):
    # Walkthrough Gate: Confirm prompt instructions for entry point start
    worker = AttackHypothesisWorker(graph=mock_graph, llm_client=mock_llm)
    graph_context = {"signals_summary": reentrancy_hotspot.signals}
    prompt = worker._build_prompt(reentrancy_hotspot, graph_context, {})
    assert "Start with the external entry point, end with the vulnerable function" in prompt[0]["content"]

@pytest.mark.asyncio
async def test_evidence_node_ids_is_list_of_strings(mock_graph, mock_llm, reentrancy_hotspot):
    evidence = ["Vault::withdraw", "Vault::balances"]
    mock_llm.ainvoke.return_value = MagicMock(content=json.dumps({
        "vulnerability_class": "reentrancy", "confidence": 90, "attack_path": ["Vault.withdraw"], "evidence_node_ids": ["Vault.withdraw", "Vault.balances"]
    }))
    worker = AttackHypothesisWorker(graph=mock_graph, llm_client=mock_llm)
    task = WorkerTask(task_id="t6", task_type="attack", hotspot=reentrancy_hotspot)
    output = await worker.run(task)
    assert output.evidence_node_ids == evidence

@pytest.mark.asyncio
async def test_hypothesis_is_non_empty_string(mock_graph, mock_llm, reentrancy_hotspot):
    hypo = "This is a serious vulnerability."
    mock_llm.ainvoke.return_value = MagicMock(content=json.dumps({
        "vulnerability_class": "reentrancy", "confidence": 90, "attack_path": ["Vault.withdraw"], "evidence_node_ids": ["Vault.withdraw"], "hypothesis": hypo
    }))
    worker = AttackHypothesisWorker(graph=mock_graph, llm_client=mock_llm)
    task = WorkerTask(task_id="t7", task_type="attack", hotspot=reentrancy_hotspot)
    output = await worker.run(task)
    assert output.hypothesis == hypo

# =================================================================
#  Group 3: LLM Integration & Thresholds (3 tests)
# =================================================================

@pytest.mark.asyncio
async def test_attack_worker_reentrancy_detection_happy_path(mock_graph, mock_llm, reentrancy_hotspot):
    mock_llm.ainvoke.return_value = MagicMock(content=json.dumps({
        "vulnerability_class": "reentrancy", "title": "T", "hypothesis": "H", "attack_path": ["Vault.withdraw"], "evidence_node_ids": ["Vault.withdraw"], "confidence": 90
    }))
    worker = AttackHypothesisWorker(graph=mock_graph, llm_client=mock_llm)
    task = WorkerTask(task_id="t8", task_type="attack", hotspot=reentrancy_hotspot)
    output = await worker.run(task)
    assert output.confidence == 90
    assert output.hypothesis == "H"

@pytest.mark.asyncio
async def test_attack_worker_low_confidence_suppression(mock_graph, mock_llm, reentrancy_hotspot):
    reentrancy_hotspot.signals = {} # Remove strong signals to prevent confidence boosting
    mock_llm.ainvoke.return_value = MagicMock(content=json.dumps({
        "vulnerability_class": "unknown", "confidence": 30, "attack_path": ["Vault.withdraw"], "evidence_node_ids": ["Vault.withdraw"]
    }))
    worker = AttackHypothesisWorker(graph=mock_graph, llm_client=mock_llm)
    task = WorkerTask(task_id="t9", task_type="attack", hotspot=reentrancy_hotspot)
    output = await worker.run(task)
    assert output.confidence == 0
    assert output.hypothesis is None

@pytest.mark.asyncio
async def test_attack_worker_unparseable_response_graceful_fail(mock_graph, mock_llm, reentrancy_hotspot):
    mock_llm.ainvoke.return_value = MagicMock(content="Wait, I am an AI and I am confused...")
    worker = AttackHypothesisWorker(graph=mock_graph, llm_client=mock_llm)
    task = WorkerTask(task_id="t10", task_type="attack", hotspot=reentrancy_hotspot)
    output = await worker.run(task)
    assert output.confidence == 35
    assert "error" in output.raw_output

# =================================================================
#  Group 4: Recon Context Integration (3 tests)
# =================================================================

@pytest.mark.asyncio
async def test_recon_context_included_in_prompt(mock_graph, mock_llm, reentrancy_hotspot):
    # Walkthrough Gate: recon_context["protocol_type"] visibly present in the LLM prompt
    recon = {"protocol_type": "vault", "known_attack_patterns": ["Pattern A"]}
    worker = AttackHypothesisWorker(graph=mock_graph, llm_client=mock_llm)
    prompt = worker._build_prompt(reentrancy_hotspot, {}, recon)
    user_msg = prompt[1]["content"]
    assert "Protocol Type: vault" in user_msg
    assert "Pattern A" in user_msg

@pytest.mark.asyncio
async def test_worker_does_not_crash_with_empty_recon_context(mock_graph, mock_llm, reentrancy_hotspot):
    mock_llm.ainvoke.return_value = MagicMock(content='{"vulnerability_class": "reentrancy", "confidence": 90, "attack_path": ["V"], "evidence_node_ids": ["E"]}')
    worker = AttackHypothesisWorker(graph=mock_graph, llm_client=mock_llm)
    task = WorkerTask(task_id="t11", task_type="attack", hotspot=reentrancy_hotspot, context={}) 
    output = await worker.run(task)
    assert output.confidence == 90

@pytest.mark.asyncio
async def test_recon_context_read_not_requeried(mock_graph, mock_llm, reentrancy_hotspot):
    # Robust behavior test: Ensure it uses the value from the task context
    recon = {"protocol_type": "custom_protocol"}
    task = WorkerTask(task_id="t12", task_type="attack", hotspot=reentrancy_hotspot, context={"recon_context": recon})
    
    worker = AttackHypothesisWorker(graph=mock_graph, llm_client=mock_llm)
    with patch.object(worker, '_build_prompt', wraps=worker._build_prompt) as mock_build:
        mock_llm.ainvoke.return_value = MagicMock(content='{"vulnerability_class": "reentrancy", "confidence": 90, "attack_path": ["V"], "evidence_node_ids": ["E"]}')
        await worker.run(task)
        mock_build.assert_called()
        # Verify the third argument to _build_prompt (recon_context) matches
        assert mock_build.call_args[0][2] == recon

# =================================================================
#  Group 5: Finding Schema Integration (5 tests)
# =================================================================

def test_finding_from_worker_output_reentrancy(reentrancy_hotspot):
    output = WorkerOutput(
        worker_type="attack_hypothesis",
        confidence=90,
        hypothesis="H",
        attack_path=["A", "B"],
        evidence_node_ids=["E1", "E2"],
        raw_output={"vulnerability_class": "reentrancy", "title": "T"}
    )
    finding = Finding.from_worker_output(output, reentrancy_hotspot)
    assert finding.vulnerability_class == "reentrancy"
    assert finding.confidence == 90
    assert finding.status == FindingStatus.DRAFT

def test_finding_attack_path_matches_worker_output(reentrancy_hotspot):
    path = ["Vault.withdraw", "Vault.balances"]
    output = WorkerOutput(
        worker_type="attack_hypothesis",
        confidence=90,
        attack_path=path,
        raw_output={}
    )
    finding = Finding.from_worker_output(output, reentrancy_hotspot)
    # from_worker_output normalizes dot → double-colon
    assert finding.attack_path == ["Vault::withdraw", "Vault::balances"] 

def test_finding_evidence_nodes_match_evidence_node_ids(reentrancy_hotspot):
    ids = ["Vault.withdraw", "Vault.balances"]
    output = WorkerOutput(
        worker_type="attack_hypothesis",
        confidence=90,
        evidence_node_ids=ids,
        raw_output={}
    )
    finding = Finding.from_worker_output(output, reentrancy_hotspot)
    assert len(finding.evidence_nodes) == 2
    # from_worker_output normalizes dot → double-colon
    assert [n.node_id for n in finding.evidence_nodes] == ["Vault::withdraw", "Vault::balances"]

@pytest.mark.asyncio
async def test_coordinator_suppresses_zero_confidence(mock_graph, reentrancy_hotspot):
    # Walkthrough Gate: At least one hotspot where confidence was 0 and Coordinator skipped it
    from src.agents.lead_agent import coordinator_node
    
    state = {
        "graph": mock_graph,
        "messages": [],
        "findings": [],
        "worker_outputs": [],
        "recon_context": {"protocol_type": "vault"},
        "contract_names": ["Vault"],
        "contract_addresses": {},
    }
    
    # Mocking dependencies in lead_agent.py
    with patch("src.agents.lead_agent.get_high_risk_hotspots", return_value=[reentrancy_hotspot]), \
         patch("src.agents.lead_agent.ReconWorker") as mock_recon_cls, \
         patch("src.agents.lead_agent.AttackHypothesisWorker") as mock_attack_cls, \
         patch("src.agents.lead_agent.get_llm") as mock_get_llm:
        
        # Mock LLM for coordinator
        mock_llm = MagicMock()
        mock_get_llm.return_value = mock_llm
        # Mock LLM response to avoid parsing error
        mock_msg = MagicMock()
        mock_msg.content = '{"vulnerability_leads": [], "target_nodes": [], "analysis_summary": {"strategy": "test"}, "escalation_needed": false}'
        mock_llm.invoke.return_value = mock_msg
        
        # Mock ReconWorker returns context
        mock_recon = mock_recon_cls.return_value
        mock_recon.run = AsyncMock(return_value=WorkerOutput(
            worker_type="recon", confidence=0, raw_output={"protocol_type": "vault"}
        ))
        
        # Mock AttackWorker returns zero confidence
        mock_attack = mock_attack_cls.return_value
        mock_attack.run = AsyncMock(return_value=WorkerOutput(
            worker_type="attack_hypothesis", confidence=0, raw_output={}
        ))
        
        result = await coordinator_node(state)
        assert len(result.get("findings", [])) == 0

def test_vulnerability_class_mapping():
    assert CATEGORY_TO_CLASS["reentrancy"] == "reentrancy"
    assert CATEGORY_TO_CLASS["can_escalate_privileges"] == "privilege_escalation"

# One more test to reach 20 total
@pytest.mark.asyncio
async def test_confidence_threshold_rejection_logs_detailed_parsed_output(mock_graph, mock_llm, reentrancy_hotspot):
    # If confidence is below threshold, verify raw_output contains the parsed data for debugging
    reentrancy_hotspot.signals = {} # Prevent strong signal confidence boosting
    mock_llm.ainvoke.return_value = MagicMock(content='{"vulnerability_class": "unknown", "confidence": 10, "attack_path": ["V"], "evidence_node_ids": ["E"]}')
    worker = AttackHypothesisWorker(graph=mock_graph, llm_client=mock_llm)
    task = WorkerTask(task_id="t_threshold", task_type="attack", hotspot=reentrancy_hotspot)
    output = await worker.run(task)
    assert output.confidence == 0
    assert "parsed" in output.raw_output
    assert output.raw_output["parsed"]["confidence"] == 10


@pytest.mark.asyncio
async def test_unparseable_response_fallback_uses_canonical_node_id(mock_graph, mock_llm, reentrancy_hotspot):
    mock_llm.ainvoke.return_value = MagicMock(content="nonsense")
    worker = AttackHypothesisWorker(graph=mock_graph, llm_client=mock_llm)
    output = await worker.run(WorkerTask(task_id="t_fallback", task_type="attack", hotspot=reentrancy_hotspot))
    assert output.attack_path == ["Vault::withdraw"]
