import os
from datetime import datetime
from typing import List, Any
from dotenv import load_dotenv

load_dotenv() # Load environment variables from .env if present

from langchain_core.messages import SystemMessage, HumanMessage
from src.agents.state import AgentState

# Optional import to avoid hard crash if not installed, though it should be.
try:
    from langchain_google_genai import ChatGoogleGenerativeAI
except ImportError:
    ChatGoogleGenerativeAI = None

SYSTEM_PROMPT = """You are a Senior Smart Contract Security Researcher participating in a "Plan-and-Execute" system.
Your goal is to identify "vulnerability leads" (potential bugs) in a codebase represented by a Knowlege Graph validation summary.
You do NOT have access to the full source code yet. You only see a high-level summary of the contract's structure.

Your output must be a valid JSON object with the following structure:
{
    "vulnerability_leads": [
        {
            "function": "ContractName.functionName",
            "type": "VulnerabilityType (e.g., Reentrancy, AccessControl)",
            "confidence": 0.8,
            "reasoning": "Brief explanation of why this is suspicious based on the summary."
        }
    ],
    "target_nodes": ["ContractName.functionName", "ContractName.stateVar"] 
}

Focus on:
1. Functions that lack access control (e.g., missing onlyOwner).
2. State changes in external functions.
3. Raw call/delegatecall usage.
4. Token transfers without reentrancy guards.

If you see no obvious vulnerabilities, return an empty list for "vulnerability_leads" but still suggest "target_nodes" to investigate further.
"""


_TOOLS = []

def set_tools(tools: List[Any]):
    """Sets the tools available to the Lead Agent."""
    global _TOOLS
    _TOOLS = tools

def get_llm(model_name: str = os.getenv("MODEL_NAME", "gemini-2.5-flash"), temperature: float = 0.0):
    """
    Returns a configured LLM instance. 
    Defaults to Gemini 2.5 Flash, but can be configured.
    """
    if not ChatGoogleGenerativeAI:
        raise ImportError("langchain-google-genai is not installed. Please install it.")
    
    # Ensure api key is set in env or let langchain handle it
    if "GOOGLE_API_KEY" not in os.environ:
        print("WARNING: GOOGLE_API_KEY not found in environment. LLM calls may fail.")

    llm = ChatGoogleGenerativeAI(model=model_name, temperature=temperature)
    if _TOOLS:
        return llm.bind_tools(_TOOLS)
    return llm

def lead_researcher_node(state: AgentState):
    """
    The Lead Agent node.
    Analyzes the current state (graph summary) and generates vulnerability leads.
    """
    messages = state.get("messages", [])
    
    llm = get_llm()
    
    # Construct the prompt
    prompt = [SystemMessage(content=SYSTEM_PROMPT)]
    if messages:
        prompt.extend(messages)
    else:
        # Fallback if no messages yet
        prompt.append(HumanMessage(content="Please analyze the available graph summary."))

    # Invoke LLM
    response = llm.invoke(prompt)
    
    # Check if the LLM decided to call a tool
    if response.tool_calls:
        return {"messages": [response]}

    # Parsing logic for final answer (if not calling a tool)
    import json
    try:
        content = response.content
        # Strip code blocks if present
        if "```json" in content:
            content = content.split("```json")[1].split("```")[0].strip()
        elif "```" in content:
            content = content.split("```")[1].split("```")[0].strip()
            
        data = json.loads(content)
        
        leads = data.get("vulnerability_leads", [])
        targets = data.get("target_nodes", [])
        
        return {
            "vulnerability_leads": leads,
            "target_nodes": targets,
            "messages": [response]
        }
    except Exception as e:
        # If it's just a text response or tool call that wasn't caught (unlikely with .tool_calls check)
        # We might want to just return the message
        return {
            "messages": [response]
        }

