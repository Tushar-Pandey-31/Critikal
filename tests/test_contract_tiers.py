"""
Epic 7 — Contract Tier Classification Tests

Tests:
  Story 7.1 — Tier assignment heuristics (CORE, FACTORY, LIBRARY, INFRA)
  Story 7.2 — Tier-weighted impact scoring
"""

import os
import sys

import pytest

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

from analysis_engine import AnalysisEngine
from src.graph import GraphBuilder
from utils.graph_queries import GraphQueries


@pytest.fixture(scope="module")
def graph_and_queries():
    repo_path = os.path.join(os.getcwd(), "tests", "contracts")
    engine = AnalysisEngine()
    slither_obj = engine.run_analysis(repo_path)
    assert slither_obj is not None, "Slither analysis failed"

    builder = GraphBuilder()
    builder.build_graph(slither_obj)
    queries = GraphQueries(builder.graph)
    return builder.graph, queries


# ════════════════════════════════════════════════════════════
#  Story 7.1 — Tier Classification Heuristics
# ════════════════════════════════════════════════════════════


class TestTierClassification:
    def test_every_contract_has_tier(self, graph_and_queries):
        graph, _ = graph_and_queries
        for nid, ndata in graph.nodes(data=True):
            if ndata.get("type") != "contract":
                continue
            assert "tier" in ndata, f"Contract {nid} missing 'tier' property"
            assert ndata["tier"] in ("CORE", "FACTORY", "LIBRARY", "INFRA"), (
                f"Contract {nid} has invalid tier: {ndata['tier']}"
            )

    def test_factory_tier(self, graph_and_queries):
        """TierFactory creates TierChild via `new` → FACTORY."""
        graph, _ = graph_and_queries
        if not graph.has_node("TierFactory"):
            pytest.skip("TierFactory not in graph")
        assert graph.nodes["TierFactory"]["tier"] == "FACTORY"

    def test_library_tier_solidity_library(self, graph_and_queries):
        """TierMathLib is declared with `library` keyword → LIBRARY."""
        graph, _ = graph_and_queries
        if not graph.has_node("TierMathLib"):
            pytest.skip("TierMathLib not in graph")
        assert graph.nodes["TierMathLib"]["tier"] == "LIBRARY"

    def test_library_tier_interface(self, graph_and_queries):
        """ITierCallback is an interface → LIBRARY."""
        graph, _ = graph_and_queries
        if not graph.has_node("ITierCallback"):
            pytest.skip("ITierCallback not in graph")
        assert graph.nodes["ITierCallback"]["tier"] == "LIBRARY"

    def test_core_tier(self, graph_and_queries):
        """TierCore has external entries + makes external calls → CORE."""
        graph, _ = graph_and_queries
        if not graph.has_node("TierCore"):
            pytest.skip("TierCore not in graph")
        assert graph.nodes["TierCore"]["tier"] == "CORE"

    def test_infra_tier(self, graph_and_queries):
        """TierInfra has external entries but no external calls → INFRA."""
        graph, _ = graph_and_queries
        if not graph.has_node("TierInfra"):
            pytest.skip("TierInfra not in graph")
        assert graph.nodes["TierInfra"]["tier"] == "INFRA"

    def test_child_contract_not_factory(self, graph_and_queries):
        """TierChild is a simple contract created by TierFactory; it should
        NOT be FACTORY itself (it doesn't create other contracts)."""
        graph, _ = graph_and_queries
        if not graph.has_node("TierChild"):
            pytest.skip("TierChild not in graph")
        assert graph.nodes["TierChild"]["tier"] != "FACTORY"

    def test_is_library_flag_set(self, graph_and_queries):
        graph, _ = graph_and_queries
        if not graph.has_node("TierMathLib"):
            pytest.skip("TierMathLib not in graph")
        assert graph.nodes["TierMathLib"].get("is_library") is True

    def test_is_interface_flag_set(self, graph_and_queries):
        graph, _ = graph_and_queries
        if not graph.has_node("ITierCallback"):
            pytest.skip("ITierCallback not in graph")
        assert graph.nodes["ITierCallback"].get("is_interface") is True


# ════════════════════════════════════════════════════════════
#  Story 7.1 — Query API
# ════════════════════════════════════════════════════════════


class TestTierQuery:
    def test_get_contract_tiers_returns_all(self, graph_and_queries):
        _, queries = graph_and_queries
        tiers = queries.get_contract_tiers()
        assert len(tiers) > 0

    def test_filter_by_tier(self, graph_and_queries):
        _, queries = graph_and_queries
        cores = queries.get_contract_tiers(tier="CORE")
        for c in cores:
            assert c["tier"] == "CORE"

    def test_factory_in_query(self, graph_and_queries):
        _, queries = graph_and_queries
        factories = queries.get_contract_tiers(tier="FACTORY")
        names = [f["contract"] for f in factories]
        assert "TierFactory" in names

    def test_library_in_query(self, graph_and_queries):
        _, queries = graph_and_queries
        libs = queries.get_contract_tiers(tier="LIBRARY")
        names = [l["contract"] for l in libs]
        assert "TierMathLib" in names


# ════════════════════════════════════════════════════════════
#  Story 7.2 — Tier-Weighted Risk Scoring
# ════════════════════════════════════════════════════════════


class TestTierWeightedRisk:
    def test_core_gets_impact_boost(self, graph_and_queries):
        """Functions in CORE contracts should have ≥20 impact_score
        (the tier bonus alone is 20)."""
        graph, _ = graph_and_queries
        for nid, ndata in graph.nodes(data=True):
            if ndata.get("type") != "function":
                continue
            cname = ndata.get("contract", "")
            cdata = graph.nodes.get(cname, {})
            if cdata.get("tier") != "CORE":
                continue
            if ndata.get("is_view_or_pure") or ndata.get("is_constructor"):
                continue
            impact = ndata.get("impact_score", 0)
            assert impact >= 20, f"{nid} in CORE contract should have impact >= 20, got {impact}"

    def test_factory_impact_reduced(self, graph_and_queries):
        """A FACTORY function with otherwise-moderate risk should have
        its impact reduced by 25 compared to INFRA baseline."""
        graph, _ = graph_and_queries

        factory_impacts = []
        infra_impacts = []
        for nid, ndata in graph.nodes(data=True):
            if ndata.get("type") != "function":
                continue
            cname = ndata.get("contract", "")
            cdata = graph.nodes.get(cname, {})
            tier = cdata.get("tier")
            if tier == "FACTORY":
                factory_impacts.append(ndata.get("impact_score", 0))
            elif tier == "INFRA":
                infra_impacts.append(ndata.get("impact_score", 0))

        if not factory_impacts:
            pytest.skip("No FACTORY functions found")

        avg_factory = sum(factory_impacts) / len(factory_impacts)
        assert avg_factory < 25, (
            f"Average FACTORY impact {avg_factory} should be suppressed (−25 adjustment should keep it low)"
        )

    def test_impact_never_negative(self, graph_and_queries):
        """Impact score must be clamped to >= 0 after tier adjustment."""
        graph, _ = graph_and_queries
        for nid, ndata in graph.nodes(data=True):
            if ndata.get("type") != "function":
                continue
            assert ndata.get("impact_score", 0) >= 0, f"{nid} has negative impact_score: {ndata.get('impact_score')}"

    def test_core_outranks_factory(self, graph_and_queries):
        """Given comparable structural risk, CORE functions should have
        higher final_score than FACTORY functions."""
        graph, _ = graph_and_queries

        core_scores = []
        factory_scores = []
        for nid, ndata in graph.nodes(data=True):
            if ndata.get("type") != "function":
                continue
            if ndata.get("is_view_or_pure") or ndata.get("is_constructor"):
                continue
            cname = ndata.get("contract", "")
            cdata = graph.nodes.get(cname, {})
            tier = cdata.get("tier")
            final = ndata.get("final_score", 0)
            if tier == "CORE" and final > 0:
                core_scores.append(final)
            elif tier == "FACTORY" and final > 0:
                factory_scores.append(final)

        if not core_scores or not factory_scores:
            pytest.skip("Need both CORE and FACTORY functions with non-zero score")

        max_core = max(core_scores)
        max_factory = max(factory_scores)
        assert max_core > max_factory, (
            f"Highest CORE score ({max_core}) should exceed highest FACTORY score ({max_factory})"
        )


# ════════════════════════════════════════════════════════════
#  Backward Compatibility
# ════════════════════════════════════════════════════════════


class TestBackwardCompat:
    def test_existing_contract_properties_intact(self, graph_and_queries):
        """is_upgradeable and name should still be present on contract nodes."""
        graph, _ = graph_and_queries
        for nid, ndata in graph.nodes(data=True):
            if ndata.get("type") != "contract":
                continue
            assert "name" in ndata
            assert "is_upgradeable" in ndata
