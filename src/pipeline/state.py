from typing import Annotated, Any, TypedDict

from langchain_core.messages import BaseMessage
from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import add_messages


class AgentState(TypedDict):
    messages: Annotated[list[BaseMessage], add_messages]
    vulnerability_leads: list[dict[str, Any]]
    target_nodes: list[str]
    human_feedback: str | None
    # Phase 4: Multi-Agent Orchestration fields
    graph: Any  # nx.DiGraph
    recon_context: dict[str, Any]  # Output from Recon Worker
    findings: list[Any]  # List of Finding objects
    worker_outputs: list[dict[str, Any]]  # Collected WorkerOutput dicts
    strategy: str | None  # Current coordinator strategy text
    pending_workers: list[str]  # Worker types queued for execution
    repo_url: str | None
    contract_names: list[str]
    contract_addresses: dict[str, str]
    escalate: bool  # Escalation decision


def get_checkpointer() -> MemorySaver:
    """Returns a configured MemorySaver checkpointer."""
    return MemorySaver()
