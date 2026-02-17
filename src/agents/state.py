from typing import TypedDict, Annotated, List, Any, Optional
from langchain_core.messages import BaseMessage
from langgraph.graph import add_messages
from langgraph.checkpoint.memory import MemorySaver

class AgentState(TypedDict):
    messages: Annotated[List[BaseMessage], add_messages]
    vulnerability_leads: List[dict[str, Any]]
    target_nodes: List[str]
    human_feedback: Optional[str]

def get_checkpointer() -> MemorySaver:
    """Returns a configured MemorySaver checkpointer."""
    return MemorySaver()
