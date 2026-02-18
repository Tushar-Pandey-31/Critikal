import pytest
import json
import warnings
from unittest.mock import MagicMock, patch
from langchain_core.messages import AIMessage, HumanMessage, SystemMessage
from src.agents.lead_agent import (
    lead_researcher_node, 
    coordinator_node,
    get_llm, 
    set_tools
)

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
