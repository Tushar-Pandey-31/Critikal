import pytest
import json
import asyncio
from unittest.mock import MagicMock, patch
from pydantic import ValidationError
from langchain_core.messages import AIMessage, HumanMessage, SystemMessage

from src.agents.base_worker import WorkerOutput, WorkerAgent
from src.agents.lead_agent import (
    coordinator_node, 
    lead_researcher_node, 
    synthesize_worker_outputs, 
    should_escalate_to_human
)
from src.agents.state import AgentState

# ────────────────────────────────────────────────────────────
#  Group 1: Base Class Contract (4 tests)
# ────────────────────────────────────────────────────────────

def test_worker_output_model():
    """Validate WorkerOutput fields, defaults, and serialization."""
    wo = WorkerOutput(
        worker_type="test_worker",
        hypothesis="Found reentrancy",
        evidence_node_ids=["Contract::func"],
        confidence=85,
        raw_output={"details": "some data"}
    )
    assert wo.worker_type == "test_worker"
    assert wo.confidence == 85
    assert "Contract::func" in wo.evidence_node_ids
    
    # Test JSON serialization
    data = wo.model_dump()
    assert data["worker_type"] == "test_worker"
    assert data["confidence"] == 85

def test_worker_output_validation():
    """Test confidence clamping and type validation via Pydantic."""
    # Invalid confidence (high)
    with pytest.raises(ValidationError):
        WorkerOutput(worker_type="t", confidence=101)
    
    # Invalid confidence (low)
    with pytest.raises(ValidationError):
        WorkerOutput(worker_type="t", confidence=-1)
    
    # Missing worker_type
    with pytest.raises(ValidationError):
        WorkerOutput(confidence=50)

def test_abstract_interface():
    """Ensure WorkerAgent cannot be instantiated directly."""
    with pytest.raises(TypeError):
        WorkerAgent()

def test_concrete_worker_runs():
    """Ensure a concrete subclass can run and return WorkerOutput."""
    class TestWorker(WorkerAgent):
        def get_worker_type(self) -> str:
            return "test"
            
        async def run(self, input_data: dict) -> WorkerOutput:
            return WorkerOutput(
                worker_type="test",
                hypothesis="Success",
                confidence=100
            )
    
    worker = TestWorker()
    output = asyncio.run(worker.run({}))
    assert isinstance(output, WorkerOutput)
    assert output.confidence == 100


# ────────────────────────────────────────────────────────────
#  Group 2: Lead Routing / Coordination (4 tests)
# ────────────────────────────────────────────────────────────

@patch("src.agents.lead_agent.get_llm")
@pytest.mark.asyncio
async def test_coordinator_node_calls_hotspots(mock_get_llm):
    """Coordinator invokes get_high_risk_hotspots tool."""
    mock_llm = MagicMock()
    # Mock a tool call response
    mock_llm.invoke.return_value = AIMessage(
        content="",
        tool_calls=[{
            "name": "get_high_risk_hotspots",
            "args": {},
            "id": "call_1"
        }]
    )
    mock_get_llm.return_value = mock_llm
    
    state = AgentState(
        messages=[],
        vulnerability_leads=[],
        target_nodes=[],
        human_feedback=None,
        worker_outputs=[],
        strategy=None,
        pending_workers=[],
        graph=MagicMock()
    )
    
    result = await coordinator_node(state)
    assert len(result["messages"]) == 1
    assert result["messages"][0].tool_calls[0]["name"] == "get_high_risk_hotspots"

@patch("src.agents.lead_agent.get_llm")
@pytest.mark.asyncio
async def test_coordinator_generates_strategy(mock_get_llm):
    """Coordinator output includes strategy from JSON."""
    mock_llm = MagicMock()
    mock_response = {
        "analysis_summary": {
            "contracts_analyzed": ["Test"],
            "total_risks_identified": 1,
            "strategy": "Analyze reentrancy in withdraw"
        },
        "vulnerability_leads": [],
        "escalation_needed": False
    }
    mock_llm.invoke.return_value = AIMessage(content=f"```json\n{json.dumps(mock_response)}\n```")
    # Ensure tool_calls is empty
    mock_llm.invoke.return_value.tool_calls = []
    
    mock_get_llm.return_value = mock_llm
    
    state = AgentState(
        messages=[HumanMessage(content="Start")],
        vulnerability_leads=[],
        target_nodes=[],
        human_feedback=None,
        worker_outputs=[],
        strategy=None,
        pending_workers=[],
        graph=MagicMock()
    )
    
    result = await coordinator_node(state)
    assert result["strategy"] == "Analyze reentrancy in withdraw"

@patch("src.agents.lead_agent.get_llm")
@pytest.mark.asyncio
async def test_coordinator_with_no_risks(mock_get_llm):
    """Graceful handling of zero-risk graphs."""
    mock_llm = MagicMock()
    mock_response = {
        "analysis_summary": {"strategy": "Done", "total_risks_identified": 0},
        "vulnerability_leads": []
    }
    mock_llm.invoke.return_value = AIMessage(content=json.dumps(mock_response))
    mock_llm.invoke.return_value.tool_calls = []
    mock_get_llm.return_value = mock_llm
    
    state = AgentState(
        messages=[],
        vulnerability_leads=[],
        target_nodes=[],
        human_feedback=None,
        worker_outputs=[],
        strategy=None,
        pending_workers=[],
        graph=MagicMock()
    )
    
    result = await coordinator_node(state)
    assert len(result["vulnerability_leads"]) == 0

# DELETED: test_backward_compat_lead_researcher
# Reason: Redundant with test_lead_researcher_node_alias_warning in test_lead_agent.py.
# Identity check fails because the alias is now a wrapper emitting DeprecationWarning.


# ────────────────────────────────────────────────────────────
#  Group 3: Synthesis (4 tests)
# ────────────────────────────────────────────────────────────

def test_synthesize_empty_outputs():
    """Empty worker list -> empty leads."""
    assert synthesize_worker_outputs([]) == []

def test_synthesize_single_output():
    """Single worker output converted to lead."""
    outputs = [{
        "worker_type": "reentrancy",
        "hypothesis": "Possible reentrancy",
        "evidence_node_ids": ["A::b"],
        "confidence": 90
    }]
    leads = synthesize_worker_outputs(outputs)
    assert len(leads) == 1
    assert leads[0]["confidence"] == 90
    assert leads[0]["id"] == "LEAD-001"

def test_synthesize_multiple_outputs():
    """Multiple outputs merged and deduplicated by evidence."""
    outputs = [
        {
            "worker_type": "reentrancy",
            "hypothesis": "Low conf reentrancy",
            "evidence_node_ids": ["Vault::withdraw"],
            "confidence": 40
        },
        {
            "worker_type": "access_control",
            "hypothesis": "High conf access control",
            "evidence_node_ids": ["Vault::withdraw"],
            "confidence": 80
        }
    ]
    leads = synthesize_worker_outputs(outputs)
    # Should pick the higher confidence one for the same target
    assert len(leads) == 1
    assert leads[0]["confidence"] == 80
    assert leads[0]["worker_type"] == "access_control"

def test_should_escalate_to_human():
    """Escalation logic for ambiguous confidence and disagreement."""
    # 1. Ambiguous confidence (between 30 and 70)
    ambiguous = [{"confidence": 50}]
    should, reason = should_escalate_to_human(ambiguous)
    assert should is True
    assert "ambiguous" in reason.lower()
    
    # 2. High disagreement (0 and 100)
    disagree = [{"confidence": 10}, {"confidence": 90}]
    should, reason = should_escalate_to_human(disagree)
    assert should is True
    assert "high disagreement" in reason.lower()
    
    # 3. Solid confidence (none in 30-70 range, no high variance)
    solid = [{"confidence": 90}, {"confidence": 85}]
    should, reason = should_escalate_to_human(solid)
    assert should is False

# ────────────────────────────────────────────────────────────
#  Group 4: Fix-specific Tests (Fix 2, 3, 4)
# ────────────────────────────────────────────────────────────

def test_worker_output_attack_path_defaults_empty():
    """Verify attack_path field exists and defaults to empty list (Fix 2)."""
    output = WorkerOutput(worker_type="test")
    assert output.attack_path == []

def test_worker_output_attack_path_preserves_order():
    """Verify attack_path preserves order (Fix 2)."""
    path = ["Vault.deposit", "Vault._update", "Vault.withdraw"]
    output = WorkerOutput(worker_type="test", attack_path=path)
    assert output.attack_path == path  # Order must be preserved, not sorted

def test_synthesis_deduplicates_same_node_higher_confidence_wins():
    """When two workers cite the same node, keep the higher confidence finding (Fix 3)."""
    output_a = WorkerOutput(
        worker_type="attack",
        evidence_node_ids=["Vault.withdraw"],
        attack_path=["Vault.deposit", "Vault.withdraw"],
        confidence=80
    )
    output_b = WorkerOutput(
        worker_type="attack",
        evidence_node_ids=["Vault.withdraw"],
        attack_path=["Vault.deposit", "Vault.withdraw"],
        confidence=45
    )
    result = synthesize_worker_outputs([output_a, output_b])
    assert len(result) == 1
    assert result[0]["confidence"] == 80

def test_synthesis_keeps_non_overlapping_findings():
    """Workers finding different nodes should both survive synthesis (Fix 3)."""
    output_a = WorkerOutput(
        worker_type="attack",
        evidence_node_ids=["Vault.withdraw"],
        attack_path=["Vault.deposit", "Vault.withdraw"],
        confidence=75
    )
    output_b = WorkerOutput(
        worker_type="access_control",
        evidence_node_ids=["Vault.setOwner"],
        attack_path=["Vault.setOwner"],
        confidence=85
    )
    result = synthesize_worker_outputs([output_a, output_b])
    assert len(result) == 2

def test_synthesis_confidence_tie_keeps_first():
    """On exact confidence tie, keep first received (Fix 3)."""
    output_a = WorkerOutput(
        worker_type="attack",
        evidence_node_ids=["Vault.withdraw"],
        attack_path=["Vault.withdraw"],
        confidence=70,
        hypothesis="Reentrancy via withdraw"
    )
    output_b = WorkerOutput(
        worker_type="attack",
        evidence_node_ids=["Vault.withdraw"],
        attack_path=["Vault.withdraw"],
        confidence=70,
        hypothesis="Unprotected mutator in withdraw"
    )
    result = synthesize_worker_outputs([output_a, output_b])
    assert len(result) == 1
    assert result[0]["hypothesis"] == "Reentrancy via withdraw"

def test_synthesis_empty_inputs_returns_empty():
    """No workers, no findings (Fix 3)."""
    result = synthesize_worker_outputs([])
    assert result == []

def test_synthesis_single_worker_passthrough():
    """Single worker output passes through unchanged (Fix 3)."""
    output = WorkerOutput(
        worker_type="attack",
        evidence_node_ids=["Vault.withdraw"],
        attack_path=["Vault.deposit", "Vault.withdraw"],
        confidence=90,
        hypothesis="Classic reentrancy"
    )
    result = synthesize_worker_outputs([output])
    assert len(result) == 1
    assert result[0]["confidence"] == 90
    assert result[0]["hypothesis"] == "Classic reentrancy"

import warnings

@pytest.mark.asyncio
async def test_lead_researcher_node_alias_emits_deprecation_warning():
    """Verify the alias fires a deprecation warning (Fix 4)."""
    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")
        # Call the alias with minimal valid state
        with patch("src.agents.lead_agent.coordinator_node") as mock_coord:
            await lead_researcher_node(state={})
            assert mock_coord.called
            
        # Note: We expect at least one warning, and it should be DeprecationWarning
        assert len(w) >= 1
        assert any(issubclass(warn.category, DeprecationWarning) for warn in w)
        assert any("deprecated" in str(warn.message).lower() for warn in w)

