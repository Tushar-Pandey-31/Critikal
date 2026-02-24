import pytest
import json
import warnings
from unittest.mock import MagicMock, patch
from langchain_core.messages import AIMessage, HumanMessage, SystemMessage
from src.agents.lead_agent import (
    lead_researcher_node,
    coordinator_node,
    get_llm,
    set_tools,
    _repo_name_from_url,
    _finding_priority,
)
from src.utils.node_ids import normalize_node_id

@patch("src.agents.lead_agent.ChatGoogleGenerativeAI")
def test_get_llm(mock_chat):
    """1. Test LLM initialization (Fix 1 - Option A)."""
    # Test without tools
    set_tools([])
    llm = get_llm(model_name="gemini-test")
    assert llm is not None
    mock_chat.assert_called()
    
    # Test with tools
    mock_tool = MagicMock()
    set_tools([mock_tool])
    llm_with_tools = get_llm(model_name="gemini-test")
    
    # Verify bind_tools was called on the instance returned by ChatGoogleGenerativeAI
    mock_chat.return_value.bind_tools.assert_called_with([mock_tool])

@patch("src.agents.lead_agent.get_llm")
@pytest.mark.asyncio
async def test_coordinator_node_json_output(mock_get_llm):
    """2. Test coordinator parsing JSON output (Fix 1 - Option A)."""
    mock_response_content = """
    ```json
    {
        "analysis_summary": {
            "strategy": "Analyze reentrancy"
        },
        "vulnerability_leads": [
            {
                "function": "Vault.withdraw",
                "type": "Reentrancy",
                "confidence": 0.9
            }
        ],
        "target_nodes": ["Vault.withdraw"],
        "escalation_needed": false
    }
    ```
    """
    mock_llm_instance = MagicMock()
    mock_llm_instance.invoke.return_value = AIMessage(content=mock_response_content)
    mock_llm_instance.invoke.return_value.tool_calls = []
    mock_get_llm.return_value = mock_llm_instance
    
    state = {
        "messages": [],
        "vulnerability_leads": [],
        "target_nodes": [],
        "worker_outputs": [],
        "graph": MagicMock()
    }
    
    result = await coordinator_node(state)
    assert len(result["vulnerability_leads"]) == 1
    assert result["strategy"] == "Analyze reentrancy"
    assert "Vault.withdraw" in result["target_nodes"]

@patch("src.agents.lead_agent.get_llm")
@pytest.mark.asyncio
async def test_coordinator_node_tool_call(mock_get_llm):
    """3. Test coordinator tool routing (Fix 1 - Option A)."""
    # DELETED: Old test for get_function_context.
    # New Lead Agent (Coordinator) uses get_high_risk_hotspots.
    
    mock_llm_instance = MagicMock()
    mock_llm_instance.invoke.return_value = AIMessage(
        content="", 
        tool_calls=[{"name": "get_high_risk_hotspots", "args": {}, "id": "call_1"}]
    )
    mock_get_llm.return_value = mock_llm_instance
    
    state = {"messages": [], "worker_outputs": [], "graph": MagicMock()}
    result = await coordinator_node(state)
    
    assert len(result["messages"]) == 1
    assert result["messages"][0].tool_calls[0]["name"] == "get_high_risk_hotspots"

@pytest.mark.asyncio
async def test_lead_researcher_node_alias_warning():
    """4. Verify lead_researcher_node fires deprecation warning (Fix 4)."""
    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")
        # Call with mock state to avoid LLM call in this unit test
        # We only care that the warning fires before it calls coordinator_node
        with patch("src.agents.lead_agent.coordinator_node") as mock_coord:
            await lead_researcher_node(state={})
            assert mock_coord.called
            
        assert len(w) >= 1
        assert issubclass(w[0].category, DeprecationWarning)
        assert "deprecated" in str(w[0].message).lower()


def test_normalized_id_matching_for_lead_and_finding():
    lead_id = normalize_node_id("Vault.withdraw")
    finding_id = normalize_node_id("Vault::withdraw")
    assert lead_id == finding_id == "Vault::withdraw"


def test_repo_name_from_url_strips_git_suffix():
    assert _repo_name_from_url("https://github.com/org/repo.git") == "repo"
    assert _repo_name_from_url("https://github.com/org/repo") == "repo"


def test_finding_priority_sorts_by_confidence_then_severity():
    """TestWriter processes findings in confidence-descending order."""
    from src.models.finding import Finding, FindingStatus

    low = Finding(
        id="1", hotspot_node_id="A::a", vulnerability_class="x", title="", hypothesis="",
        evidence_nodes=[], attack_path=[], status=FindingStatus.DRAFT, confidence=70,
        impact="", preconditions=[], affected_contract="A", affected_function="a",
        severity_estimate="MEDIUM", severity="MEDIUM",
    )
    high = Finding(
        id="2", hotspot_node_id="B::b", vulnerability_class="x", title="", hypothesis="",
        evidence_nodes=[], attack_path=[], status=FindingStatus.DRAFT, confidence=90,
        impact="", preconditions=[], affected_contract="B", affected_function="b",
        severity_estimate="HIGH", severity="HIGH",
    )
    mid = Finding(
        id="3", hotspot_node_id="C::c", vulnerability_class="x", title="", hypothesis="",
        evidence_nodes=[], attack_path=[], status=FindingStatus.DRAFT, confidence=80,
        impact="", preconditions=[], affected_contract="C", affected_function="c",
        severity_estimate="CRITICAL", severity="CRITICAL",
    )
    # Same confidence: CRITICAL before HIGH
    same_conf_high = Finding(
        id="4", hotspot_node_id="D::d", vulnerability_class="x", title="", hypothesis="",
        evidence_nodes=[], attack_path=[], status=FindingStatus.DRAFT, confidence=80,
        impact="", preconditions=[], affected_contract="D", affected_function="d",
        severity_estimate="HIGH", severity="HIGH",
    )
    findings = [low, high, mid, same_conf_high]
    sorted_findings = sorted(findings, key=_finding_priority)
    confs = [f.confidence for f in sorted_findings]
    assert confs == [90, 80, 80, 70]
    assert sorted_findings[1].severity_estimate == "CRITICAL"
    assert sorted_findings[2].severity_estimate == "HIGH"
