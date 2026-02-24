from typing import TypedDict, Annotated, List, Any, Optional
from langchain_core.messages import BaseMessage
from langgraph.graph import add_messages
from langgraph.checkpoint.memory import MemorySaver

class AgentState(TypedDict):
    messages: Annotated[List[BaseMessage], add_messages]
    vulnerability_leads: List[dict[str, Any]]
    target_nodes: List[str]
    human_feedback: Optional[str]
    # Phase 4: Multi-Agent Orchestration fields
    graph: Any                             # nx.DiGraph
    recon_context: dict[str, Any]          # Output from Recon Worker
    findings: List[Any]                    # List of Finding objects
    worker_outputs: List[dict[str, Any]]   # Collected WorkerOutput dicts
    strategy: Optional[str]                # Current coordinator strategy text
    pending_workers: List[str]             # Worker types queued for execution
    repo_url: Optional[str]
    contract_names: List[str]
    contract_addresses: dict[str, str]
    escalate: bool                         # Escalation decision

def get_checkpointer() -> MemorySaver:
    """Returns a configured MemorySaver checkpointer."""
    return MemorySaver()
