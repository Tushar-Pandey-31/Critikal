import pytest
from unittest.mock import MagicMock, patch
from langchain_core.messages import AIMessage, HumanMessage
from src.agents.lead_agent import lead_researcher_node, get_llm, set_tools


@patch("src.agents.lead_agent.ChatGoogleGenerativeAI")
def test_get_llm(mock_chat):
    """Test LLM initialization."""
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
def test_lead_researcher_node(mock_get_llm):
    """Test the lead agent node logic with a mocked LLM response."""
    
    # 1. Test normal JSON response
    mock_response_content = """
    ```json
    {
        "vulnerability_leads": [
            {
                "function": "Vault.withdraw",
                "type": "Reentrancy",
                "confidence": 0.9,
                "reasoning": "External call before state update."
            }
        ],
        "target_nodes": ["Vault.withdraw", "Vault.balance"]
    }
    ```
    """
    mock_llm_instance = MagicMock()
    mock_llm_instance.invoke.return_value = AIMessage(content=mock_response_content)
    # Ensure tool_calls is empty for this test case
    mock_llm_instance.invoke.return_value.tool_calls = []
    
    mock_get_llm.return_value = mock_llm_instance
    
    # Input state
    state = {
        "messages": [HumanMessage(content="Here is the graph summary for Vault.sol")],
        "vulnerability_leads": [],
        "target_nodes": [],
        "human_feedback": None
    }
    
    # Run node
    result = lead_researcher_node(state)
    
    # Verify outputs
    assert len(result["vulnerability_leads"]) == 1
    assert result["vulnerability_leads"][0]["function"] == "Vault.withdraw"
    assert "Vault.withdraw" in result["target_nodes"]
    
    # 2. Test Tool Call response
    mock_tool_call_response = AIMessage(content="", tool_calls=[{"name": "get_function_context", "args": {"node_id": "Foo"}, "id": "call_123"}])
    mock_llm_instance.invoke.return_value = mock_tool_call_response
    
    result_tool = lead_researcher_node(state)
    assert len(result_tool["messages"]) == 1
    assert result_tool["messages"][0].tool_calls[0]["name"] == "get_function_context"

