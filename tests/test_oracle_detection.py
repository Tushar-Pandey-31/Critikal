"""
Epic 8.1 — Oracle Usage Detection Tests

Tests oracle pattern detection on function source_code strings.
Uses a lightweight graph fixture (no Slither needed) since
_detect_oracle_patterns only reads node properties.
"""

import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

from src.graph import GraphBuilder
from utils.graph_queries import GraphQueries

# ════════════════════════════════════════════════════════════
#  Inline Solidity Source Fragments
# ════════════════════════════════════════════════════════════

SRC_UNISWAP_V2_SPOT = """
function getPrice(address token) external returns (uint256) {
    (uint112 reserve0, uint112 reserve1,) = pair.getReserves();
    return reserve1 * 1e18 / reserve0;
}
"""

SRC_UNISWAP_V3_SPOT = """
function getSqrtPrice() external view returns (uint160) {
    (uint160 sqrtPriceX96,,,,,,) = pool.slot0();
    return sqrtPriceX96;
}
"""

SRC_CHAINLINK = """
function getLatestPrice() external view returns (int256) {
    (,int256 price,,,) = AggregatorV3Interface(feed).latestRoundData();
    return price;
}
"""

SRC_SPOT_PLUS_CHAINLINK = """
function getHybridPrice() external view returns (uint256) {
    (uint112 r0, uint112 r1,) = pair.getReserves();
    (,int256 chainlinkPrice,,,) = AggregatorV3Interface(feed).latestRoundData();
    return uint256(chainlinkPrice);
}
"""

SRC_TWAP_SHORT_WINDOW = """
function getTwapPrice(address token) external view returns (uint256) {
    uint32 window = 600;
    (int24 tick,) = OracleLibrary.consult(pool, window);
    return OracleLibrary.getQuoteAtTick(tick, 1e18, token, WETH);
}
"""

SRC_TWAP_LONG_WINDOW = """
function getTwapPrice(address token) external view returns (uint256) {
    uint32 window = 3600;
    (int24 tick,) = OracleLibrary.consult(pool, window);
    return OracleLibrary.getQuoteAtTick(tick, 1e18, token, WETH);
}
"""

SRC_INTERNAL_SPOT = """
function _getPrice() internal returns (uint256) {
    (uint112 r0, uint112 r1,) = pair.getReserves();
    return r1 * 1e18 / r0;
}
"""

SRC_BALANCER_SPOT = """
function getBalancerPrice() external returns (uint256) {
    (address[] memory tokens, uint256[] memory balances,) = vault.getPoolTokens(poolId);
    return balances[0] * 1e18 / balances[1];
}
"""

SRC_RESERVE_DIRECT = """
function checkReserve() external view returns (uint112) {
    return IUniswapV2Pair(pair).reserve0;
}
"""

SRC_MULTI_ORACLE = """
function getMultiPrice() external returns (uint256) {
    (uint112 r0, uint112 r1,) = pair.getReserves();
    (uint160 sqrtPriceX96,,,,,,) = pool.slot0();
    return r1 * 1e18 / r0;
}
"""

SRC_CLEAN = """
function transfer(address to, uint256 amount) external returns (bool) {
    balances[msg.sender] -= amount;
    balances[to] += amount;
    return true;
}
"""

SRC_TWAP_ONLY = """
function getTwapOnly() external view returns (uint256) {
    return OracleLibrary.consult(pool, 1800);
}
"""


# ════════════════════════════════════════════════════════════
#  Helper: build minimal graph with function nodes
# ════════════════════════════════════════════════════════════


def _make_builder(functions: dict) -> tuple:
    """
    functions: dict of node_id -> {source_code, is_external_entry, ...}
    Returns (builder, graph, queries).
    """
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
    builder._detect_oracle_patterns()
    return builder, builder.graph, GraphQueries(builder.graph)


# ════════════════════════════════════════════════════════════
#  Tests
# ════════════════════════════════════════════════════════════


class TestOracleDetection:
    def test_getReserves_flagged_as_spot(self):
        _, g, _ = _make_builder({"A::getPrice": {"source_code": SRC_UNISWAP_V2_SPOT}})
        assert g.nodes["A::getPrice"]["uses_spot_price_oracle"] is True

    def test_slot0_flagged_as_spot(self):
        _, g, _ = _make_builder({"A::getSqrtPrice": {"source_code": SRC_UNISWAP_V3_SPOT}})
        assert g.nodes["A::getSqrtPrice"]["uses_spot_price_oracle"] is True

    def test_chainlink_flagged_as_safe(self):
        _, g, _ = _make_builder({"A::getLatestPrice": {"source_code": SRC_CHAINLINK}})
        assert g.nodes["A::getLatestPrice"]["uses_safe_oracle"] is True

    def test_chainlink_no_manipulation_risk(self):
        _, g, _ = _make_builder({"A::getLatestPrice": {"source_code": SRC_CHAINLINK}})
        assert g.nodes["A::getLatestPrice"]["oracle_manipulation_risk"] is False

    def test_spot_plus_chainlink_no_risk(self):
        _, g, _ = _make_builder({"A::getHybridPrice": {"source_code": SRC_SPOT_PLUS_CHAINLINK}})
        d = g.nodes["A::getHybridPrice"]
        assert d["uses_spot_price_oracle"] is True
        assert d["uses_safe_oracle"] is True
        assert d["oracle_manipulation_risk"] is False

    def test_twap_no_risk_by_default(self):
        _, g, _ = _make_builder({"A::getTwapOnly": {"source_code": SRC_TWAP_ONLY}})
        d = g.nodes["A::getTwapOnly"]
        assert d["uses_twap_oracle"] is True
        assert d["oracle_manipulation_risk"] is False

    def test_twap_short_window_flagged(self):
        _, g, _ = _make_builder({"A::getTwapPrice": {"source_code": SRC_TWAP_SHORT_WINDOW}})
        assert g.nodes["A::getTwapPrice"]["twap_window_short"] is True

    def test_twap_long_window_safe(self):
        _, g, _ = _make_builder({"A::getTwapPrice": {"source_code": SRC_TWAP_LONG_WINDOW}})
        assert g.nodes["A::getTwapPrice"]["twap_window_short"] is False

    def test_internal_spot_no_risk(self):
        _, g, _ = _make_builder(
            {
                "A::_getPrice": {
                    "source_code": SRC_INTERNAL_SPOT,
                    "is_external_entry": False,
                }
            }
        )
        d = g.nodes["A::_getPrice"]
        assert d["uses_spot_price_oracle"] is True
        assert d["oracle_manipulation_risk"] is False

    def test_external_spot_risk(self):
        _, g, _ = _make_builder({"A::getPrice": {"source_code": SRC_UNISWAP_V2_SPOT}})
        assert g.nodes["A::getPrice"]["oracle_manipulation_risk"] is True

    def test_risk_score_plus_120(self):
        _, g, _ = _make_builder({"A::getPrice": {"source_code": SRC_UNISWAP_V2_SPOT, "risk_score": 10}})
        assert g.nodes["A::getPrice"]["risk_score"] == 10 + 120

    def test_risk_category_added(self):
        _, g, _ = _make_builder({"A::getPrice": {"source_code": SRC_UNISWAP_V2_SPOT}})
        assert "oracle_manipulation" in g.nodes["A::getPrice"]["risk_categories"]

    def test_balancer_spot_flagged(self):
        _, g, _ = _make_builder({"A::getBalancerPrice": {"source_code": SRC_BALANCER_SPOT}})
        d = g.nodes["A::getBalancerPrice"]
        assert d["uses_spot_price_oracle"] is True
        assert "balancer_spot" in d["oracle_sources"]

    def test_oracle_sources_list_populated(self):
        _, g, _ = _make_builder({"A::getPrice": {"source_code": SRC_UNISWAP_V2_SPOT}})
        assert "uniswap_v2_spot" in g.nodes["A::getPrice"]["oracle_sources"]

    def test_no_oracle_no_fields(self):
        _, g, _ = _make_builder({"A::transfer": {"source_code": SRC_CLEAN}})
        d = g.nodes["A::transfer"]
        assert d["uses_spot_price_oracle"] is False
        assert d["uses_safe_oracle"] is False
        assert d["uses_twap_oracle"] is False
        assert d["oracle_sources"] == []
        assert d["oracle_manipulation_risk"] is False

    def test_hotspot_surfaced(self):
        builder, g, queries = _make_builder(
            {
                "A::getPrice": {
                    "source_code": SRC_UNISWAP_V2_SPOT,
                    "risk_score": 0,
                    "writes_state": True,
                }
            }
        )
        g.nodes["A::getPrice"]["structural_score"] = 50
        g.nodes["A::getPrice"]["exploitability_score"] = 40
        g.nodes["A::getPrice"]["final_score"] = g.nodes["A::getPrice"]["risk_score"]
        hotspots = queries.get_high_risk_hotspots(min_score=70)
        node_ids = [h.node_id for h in hotspots]
        assert "A::getPrice" in node_ids

    def test_library_contract_excluded(self):
        builder, g, queries = _make_builder(
            {
                "Lib::getPrice": {
                    "source_code": SRC_UNISWAP_V2_SPOT,
                    "risk_score": 0,
                    "writes_state": True,
                }
            }
        )
        g.nodes["Lib"]["tier"] = "LIBRARY"
        g.nodes["Lib::getPrice"]["structural_score"] = 50
        g.nodes["Lib::getPrice"]["exploitability_score"] = 40
        g.nodes["Lib::getPrice"]["final_score"] = g.nodes["Lib::getPrice"]["risk_score"]
        hotspots = queries.get_high_risk_hotspots(min_score=70)
        node_ids = [h.node_id for h in hotspots]
        assert "Lib::getPrice" not in node_ids

    def test_uniswap_v2_fork_detected(self):
        _, g, _ = _make_builder({"A::checkReserve": {"source_code": SRC_RESERVE_DIRECT}})
        d = g.nodes["A::checkReserve"]
        assert d["uses_spot_price_oracle"] is True
        assert "uniswap_v2_spot" in d["oracle_sources"]

    def test_multiple_oracle_types(self):
        _, g, _ = _make_builder({"A::getMultiPrice": {"source_code": SRC_MULTI_ORACLE}})
        sources = g.nodes["A::getMultiPrice"]["oracle_sources"]
        assert "uniswap_v2_spot" in sources
        assert "uniswap_v3_spot" in sources

    def test_pipeline_position(self):
        """Oracle detection runs after _classify_external_calls,
        so is_external_entry is already populated."""
        _, g, _ = _make_builder(
            {
                "A::getPrice": {
                    "source_code": SRC_UNISWAP_V2_SPOT,
                    "is_external_entry": True,
                }
            }
        )
        assert g.nodes["A::getPrice"]["oracle_manipulation_risk"] is True
