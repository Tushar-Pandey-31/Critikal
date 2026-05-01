"""
Tests for the TokenCounter utility module.
"""

import pytest
from src.utils.token_counter import TokenCounter, get_token_counter


@pytest.fixture(autouse=True)
def reset_singleton():
    """Reset the TokenCounter singleton between tests."""
    tc = get_token_counter()
    tc.reset()
    yield
    tc.reset()


class TestTokenCounterBasic:
    def test_singleton(self):
        """get_token_counter always returns the same instance."""
        a = get_token_counter()
        b = get_token_counter()
        assert a is b

    def test_record_and_get_summary(self):
        tc = get_token_counter()
        tc.record(
            "TestAgent", "gemini-3-flash-preview",
            "Hello world prompt", "Response text",
        )
        summary = tc.get_summary()

        assert len(summary["agents"]) == 1
        agent = summary["agents"][0]
        assert agent["agent_name"] == "TestAgent"
        assert agent["model"] == "gemini-3-flash-preview"
        assert agent["call_count"] == 1
        assert agent["input_chars"] == len("Hello world prompt")
        assert agent["output_chars"] == len("Response text")
        assert agent["input_tokens"] > 0
        assert agent["output_tokens"] > 0
        assert agent["estimated_cost_usd"] > 0

    def test_multiple_agents(self):
        tc = get_token_counter()
        tc.record("AgentA", "gemini-3-flash-preview", "prompt a", "response a")
        tc.record("AgentB", "gemini-3-flash-preview", "prompt b", "response b")
        tc.record("AgentA", "gemini-3-flash-preview", "prompt a2", "response a2")

        summary = tc.get_summary()
        assert len(summary["agents"]) == 2

        total = summary["total"]
        assert total["call_count"] == 3

        # Find AgentA
        agent_a = next(a for a in summary["agents"] if a["agent_name"] == "AgentA")
        assert agent_a["call_count"] == 2

    def test_total_aggregation(self):
        tc = get_token_counter()
        tc.record("AgentA", "gemini-3-flash-preview", "a" * 100, "b" * 50)
        tc.record("AgentB", "gemini-3-flash-preview", "c" * 200, "d" * 100)

        total = tc.get_summary()["total"]
        assert total["call_count"] == 2
        assert total["input_chars"] == 300
        assert total["output_chars"] == 150
        # Tokens estimated via char/4 rule
        assert total["input_tokens"] == 75
        assert total["output_tokens"] == 37

    def test_reset_clears_data(self):
        tc = get_token_counter()
        tc.record("AgentA", "gemini-3-flash-preview", "prompt", "response")
        assert tc.get_summary()["total"]["call_count"] == 1
        tc.reset()
        assert tc.get_summary()["total"]["call_count"] == 0
        assert len(tc.get_summary()["agents"]) == 0


class TestTokenCounterMetadata:
    def test_extracts_real_tokens_from_metadata(self):
        tc = get_token_counter()
        metadata = {
            "usage_metadata": {
                "input_tokens": 500,
                "output_tokens": 200,
            }
        }
        tc.record("AgentA", "gemini-3-flash-preview", "prompt", "resp", metadata)

        agent = tc.get_summary()["agents"][0]
        assert agent["input_tokens"] == 500
        assert agent["output_tokens"] == 200
        assert agent["total_tokens"] == 700

    def test_falls_back_to_char_estimation(self):
        tc = get_token_counter()
        tc.record("AgentA", "gemini-3-flash-preview", "x" * 400, "y" * 200, None)

        agent = tc.get_summary()["agents"][0]
        assert agent["input_tokens"] == 100   # 400 / 4
        assert agent["output_tokens"] == 50   # 200 / 4

    def test_cost_estimation(self):
        tc = get_token_counter()
        metadata = {
            "usage_metadata": {
                "input_tokens": 1_000_000,
                "output_tokens": 1_000_000,
            }
        }
        tc.record("AgentA", "gemini-3-flash-preview", "p", "r", metadata)

        agent = tc.get_summary()["agents"][0]
        # gemini-3-flash-preview: $0.15/M input + $0.60/M output = $0.75
        assert abs(agent["estimated_cost_usd"] - 0.75) < 0.01

    def test_empty_inputs(self):
        tc = get_token_counter()
        tc.record("AgentA", "gemini-3-flash-preview", "", "", None)

        agent = tc.get_summary()["agents"][0]
        assert agent["input_chars"] == 0
        assert agent["output_chars"] == 0
        assert agent["input_tokens"] == 0
        assert agent["output_tokens"] == 0

    def test_elapsed_seconds_present(self):
        tc = get_token_counter()
        tc.record("AgentA", "gemini-3-flash-preview", "p", "r")
        summary = tc.get_summary()
        assert "elapsed_seconds" in summary
        assert summary["elapsed_seconds"] >= 0

    def test_agents_sorted_by_cost(self):
        tc = get_token_counter()
        tc.record("CheapAgent", "gemini-3-flash-preview", "a", "b")
        tc.record("ExpensiveAgent", "gemini-3-flash-preview", "x" * 10000, "y" * 5000)

        agents = tc.get_summary()["agents"]
        assert agents[0]["agent_name"] == "ExpensiveAgent"
        assert agents[1]["agent_name"] == "CheapAgent"
