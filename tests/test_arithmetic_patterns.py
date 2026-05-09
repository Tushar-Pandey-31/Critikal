"""
Epic 8.2 — Arithmetic Pattern Detection Tests

Tests division-before-multiply, unchecked arithmetic, and unsafe cast
detection on function source_code strings.
"""

import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

from src.graph import GraphBuilder
from utils.graph_queries import GraphQueries

# ════════════════════════════════════════════════════════════
#  Inline Solidity Source Fragments
# ════════════════════════════════════════════════════════════

SRC_DIV_BEFORE_MUL = """
function calculateFee(uint256 amount, uint256 rate) external returns (uint256) {
    return (amount / 1000) * rate;
}
"""

SRC_MUL_BEFORE_DIV = """
function calculateFee(uint256 amount, uint256 rate) external returns (uint256) {
    return (amount * rate) / 1000;
}
"""

SRC_LITERAL_DIV_MUL = """
function constant() external pure returns (uint256) {
    return (100 / 5) * 3;
}
"""

SRC_UNCHECKED_WRITE = """
function increment(uint256 x) external {
    unchecked {
        counter += x;
    }
}
"""

SRC_UNCHECKED_NO_WRITE = """
function computeOnly(uint256 a, uint256 b) external pure returns (uint256) {
    unchecked {
        return a + b;
    }
}
"""

SRC_UNSAFE_CAST_UINT_INT = """
function convert(int256 x) external returns (uint256) {
    return uint256(int256(x));
}
"""

SRC_UNSAFE_CAST_INT_UINT = """
function convert(uint256 x) external returns (int256) {
    return int256(uint256(x));
}
"""

SRC_SAFE_CAST = """
function convert(uint128 x) external returns (uint256) {
    return uint256(x);
}
"""

SRC_ALL_THREE = """
function dangerous(uint256 amount, int256 val) external {
    uint256 fee = (amount / 1000) * rate;
    unchecked {
        counter += fee;
    }
    int256 converted = int256(uint256(val));
    results[msg.sender] = converted;
}
"""

SRC_CLEAN = """
function transfer(address to, uint256 amount) external returns (bool) {
    balances[msg.sender] -= amount;
    balances[to] += amount;
    return true;
}
"""

SRC_DIV_MUL_MULTILINE = """
function calcReward(uint256 balance, uint256 totalSupply, uint256 reward) external returns (uint256) {
    return (balance /
        totalSupply) * reward;
}
"""

SRC_UNCHECKED_NESTED = """
function doubleUnchecked(uint256 a) external {
    unchecked {
        uint256 b = a + 1;
        unchecked {
            counter += b;
        }
    }
}
"""

SRC_VIEW_DIV_MUL = """
function previewFee(uint256 amount, uint256 rate) external view returns (uint256) {
    return (amount / 1000) * rate;
}
"""


# ════════════════════════════════════════════════════════════
#  Helper
# ════════════════════════════════════════════════════════════


def _make_builder(functions: dict) -> tuple:
    builder = GraphBuilder()
    for node_id, props in functions.items():
        contract = node_id.split("::")[0]
        if not builder.graph.has_node(contract):
            builder.graph.add_node(contract, type="contract", name=contract, tier="CORE")
        builder.graph.add_node(
            node_id,
            type="function",
            **{
                "name": node_id.split("::")[-1],
                "contract": contract,
                "source_code": props.get("source_code", ""),
                "is_external_entry": props.get("is_external_entry", True),
                "writes_state": props.get("writes_state", False),
                "risk_score": props.get("risk_score", 0),
                "risk_categories": list(props.get("risk_categories", [])),
                "state_variables_written": props.get("state_variables_written", []),
                "is_view_or_pure": props.get("is_view_or_pure", False),
                "is_constructor": False,
                "visibility": props.get("visibility", "external"),
                "stateMutability": props.get("stateMutability", "nonpayable"),
            },
        )
        builder.graph.add_edge(contract, node_id, relationship="DEFINES")
    builder._detect_arithmetic_patterns()
    return builder, builder.graph, GraphQueries(builder.graph)


# ════════════════════════════════════════════════════════════
#  Tests
# ════════════════════════════════════════════════════════════


class TestArithmeticPatterns:
    def test_div_before_mul_detected(self):
        _, g, _ = _make_builder({"A::calculateFee": {"source_code": SRC_DIV_BEFORE_MUL}})
        assert g.nodes["A::calculateFee"]["division_before_multiplication"] is True

    def test_mul_before_div_not_flagged(self):
        _, g, _ = _make_builder({"A::calculateFee": {"source_code": SRC_MUL_BEFORE_DIV}})
        assert g.nodes["A::calculateFee"]["division_before_multiplication"] is False

    def test_literal_div_mul_not_flagged(self):
        _, g, _ = _make_builder({"A::constant": {"source_code": SRC_LITERAL_DIV_MUL}})
        assert g.nodes["A::constant"]["division_before_multiplication"] is False

    def test_unchecked_block_detected(self):
        _, g, _ = _make_builder({"A::increment": {"source_code": SRC_UNCHECKED_WRITE, "writes_state": True}})
        assert g.nodes["A::increment"]["has_unchecked_arithmetic"] is True

    def test_unchecked_with_write(self):
        _, g, _ = _make_builder({"A::increment": {"source_code": SRC_UNCHECKED_WRITE, "writes_state": True}})
        d = g.nodes["A::increment"]
        assert d["unchecked_with_state_write"] is True
        assert d["arithmetic_risk_score"] >= 50

    def test_unchecked_no_write(self):
        _, g, _ = _make_builder({"A::computeOnly": {"source_code": SRC_UNCHECKED_NO_WRITE, "writes_state": False}})
        d = g.nodes["A::computeOnly"]
        assert d["has_unchecked_arithmetic"] is True
        assert d["unchecked_with_state_write"] is False

    def test_unsafe_cast_uint_to_int(self):
        _, g, _ = _make_builder({"A::convert": {"source_code": SRC_UNSAFE_CAST_UINT_INT}})
        assert g.nodes["A::convert"]["unsafe_type_cast"] is True

    def test_unsafe_cast_int_to_uint(self):
        _, g, _ = _make_builder({"A::convert": {"source_code": SRC_UNSAFE_CAST_INT_UINT}})
        assert g.nodes["A::convert"]["unsafe_type_cast"] is True

    def test_safe_cast_not_flagged(self):
        _, g, _ = _make_builder({"A::convert": {"source_code": SRC_SAFE_CAST}})
        assert g.nodes["A::convert"]["unsafe_type_cast"] is False

    def test_score_accumulates(self):
        _, g, _ = _make_builder({"A::dangerous": {"source_code": SRC_ALL_THREE, "writes_state": True}})
        assert g.nodes["A::dangerous"]["arithmetic_risk_score"] == 125

    def test_score_zero_clean_function(self):
        _, g, _ = _make_builder({"A::transfer": {"source_code": SRC_CLEAN}})
        assert g.nodes["A::transfer"]["arithmetic_risk_score"] == 0

    def test_risk_categories_populated(self):
        _, g, _ = _make_builder({"A::dangerous": {"source_code": SRC_ALL_THREE, "writes_state": True}})
        cats = g.nodes["A::dangerous"]["risk_categories"]
        assert "unchecked_arithmetic" in cats
        assert "division_before_multiplication" in cats
        assert "unsafe_type_cast" in cats

    def test_div_mul_multiline(self):
        _, g, _ = _make_builder({"A::calcReward": {"source_code": SRC_DIV_MUL_MULTILINE}})
        assert g.nodes["A::calcReward"]["division_before_multiplication"] is True

    def test_unchecked_nested(self):
        _, g, _ = _make_builder({"A::doubleUnchecked": {"source_code": SRC_UNCHECKED_NESTED, "writes_state": True}})
        assert g.nodes["A::doubleUnchecked"]["has_unchecked_arithmetic"] is True

    def test_hotspot_from_arithmetic(self):
        builder, g, queries = _make_builder(
            {
                "A::dangerous": {
                    "source_code": SRC_ALL_THREE,
                    "writes_state": True,
                    "risk_score": 0,
                }
            }
        )
        g.nodes["A::dangerous"]["structural_score"] = 50
        g.nodes["A::dangerous"]["exploitability_score"] = 40
        g.nodes["A::dangerous"]["final_score"] = g.nodes["A::dangerous"]["risk_score"]
        hotspots = queries.get_high_risk_hotspots(min_score=70)
        node_ids = [h.node_id for h in hotspots]
        assert "A::dangerous" in node_ids

    def test_no_source_code_safe(self):
        _, g, _ = _make_builder({"A::empty": {"source_code": ""}})
        d = g.nodes["A::empty"]
        assert d["division_before_multiplication"] is False
        assert d["has_unchecked_arithmetic"] is False
        assert d["unsafe_type_cast"] is False
        assert d["arithmetic_risk_score"] == 0

    def test_view_function_arithmetic(self):
        _, g, queries = _make_builder(
            {
                "A::previewFee": {
                    "source_code": SRC_VIEW_DIV_MUL,
                    "is_view_or_pure": True,
                    "stateMutability": "view",
                }
            }
        )
        assert g.nodes["A::previewFee"]["division_before_multiplication"] is True
        g.nodes["A::previewFee"]["structural_score"] = 50
        g.nodes["A::previewFee"]["exploitability_score"] = 40
        g.nodes["A::previewFee"]["final_score"] = g.nodes["A::previewFee"]["risk_score"]
        hotspots = queries.get_high_risk_hotspots(min_score=1)
        assert "A::previewFee" not in [h.node_id for h in hotspots]

    def test_pipeline_order(self):
        """Runs after _detect_oracle_patterns — writes_state available."""
        _, g, _ = _make_builder({"A::increment": {"source_code": SRC_UNCHECKED_WRITE, "writes_state": True}})
        assert g.nodes["A::increment"]["unchecked_with_state_write"] is True
