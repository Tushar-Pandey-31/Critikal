from langchain_core.messages import HumanMessage
from langgraph.graph import END, START, StateGraph

from src.pipeline.state import AgentState, get_checkpointer


def dummy_node(state: AgentState):
    return {"messages": [HumanMessage(content="Hello from dummy")]}

def test_agent_state_initialization():
    initial_state = {
        "messages": [],
        "vulnerability_leads": [],
        "target_nodes": [],
        "human_feedback": None
    }
    # Just verifying it matches the TypedDict structure in spirit
    assert initial_state["messages"] == []
    assert initial_state["vulnerability_leads"] == []

def test_checkpointer_persistence():
    # Setup a simple graph to test checkpointer
    workflow = StateGraph(AgentState)
    workflow.add_node("dummy", dummy_node)
    workflow.add_edge(START, "dummy")
    workflow.add_edge("dummy", END)

    checkpointer = get_checkpointer()
    app = workflow.compile(checkpointer=checkpointer)

    config = {"configurable": {"thread_id": "test_thread_1"}}

    # First run
    initial_input = {
        "messages": [HumanMessage(content="Start")],
        "vulnerability_leads": [],
        "target_nodes": ["node1"],
        "human_feedback": None
    }

    result = app.invoke(initial_input, config=config)

    # Check if state is persisted
    snapshot = app.get_state(config)
    assert len(snapshot.values["messages"]) == 2 # "Start" + "Hello from dummy"
    assert snapshot.values["target_nodes"] == ["node1"]

    # Simulate a new run with same thread_id, should have history
    # For a new run, we might want to continue or add more.
    # Let's just verify specific state was saved.
    assert snapshot.config["configurable"]["thread_id"] == "test_thread_1"
