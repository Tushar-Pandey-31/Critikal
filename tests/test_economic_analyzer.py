import networkx as nx

from src.economic_analyzer import EconomicAnalyzer


def _make_function(
    g: nx.DiGraph,
    contract: str,
    name: str,
    has_taint_risk: bool = False,
    uses_ratio_math: bool = False,
    uses_division: bool = False,
    updates_reward_index: bool = False,
    writes_total_supply: bool = False,
    mints_shares_proportionally: bool = False,
    is_protected: bool = False,
    cap_enforcement_flags: list = None,
):
    fid = f"{contract}::{name}"
    if cap_enforcement_flags is None:
        cap_enforcement_flags = []

    g.add_node(
        fid,
        type="function",
        name=name,
        contract=contract,
        has_taint_risk=has_taint_risk,
        uses_ratio_math=uses_ratio_math,
        uses_division=uses_division,
        updates_reward_index=updates_reward_index,
        writes_total_supply=writes_total_supply,
        mints_shares_proportionally=mints_shares_proportionally,
        is_protected=is_protected,
        cap_enforcement_flags=cap_enforcement_flags,
    )
    return fid


class TestEconomicAnalyzer:
    def test_denominator_manipulation(self):
        g = nx.DiGraph()
        s1 = _make_function(g, "Pool", "swap", has_taint_risk=True, uses_ratio_math=True)

        analyzer = EconomicAnalyzer(g)
        chain_desc = {"steps": [s1]}
        score = analyzer.evaluate_chain_economic_impact(chain_desc)

        assert score == 1.2
        assert "DENOMINATOR_MANIPULATION_RISK" in chain_desc["economic_distortion_flags"]

    def test_share_inflation_scenario(self):
        g = nx.DiGraph()
        s1 = _make_function(
            g,
            "Vault",
            "deposit",
            has_taint_risk=True,
            mints_shares_proportionally=True,
            is_protected=False,  # unprotected -> implies missing cap
        )

        analyzer = EconomicAnalyzer(g)
        chain_desc = {"steps": [s1]}
        score = analyzer.evaluate_chain_economic_impact(chain_desc)

        assert score == 1.5
        assert "UNBOUNDED_MINT_RISK" in chain_desc["economic_distortion_flags"]
        assert g.nodes[s1].get("unbounded_inflation_risk") is True

    def test_reward_index_drift_scenario(self):
        g = nx.DiGraph()
        s1 = _make_function(
            g, "Farm", "updateReward", has_taint_risk=True, updates_reward_index=True, uses_division=True
        )

        analyzer = EconomicAnalyzer(g)
        chain_desc = {"steps": [s1]}
        score = analyzer.evaluate_chain_economic_impact(chain_desc)

        assert score == 1.1
        assert "PRECISION_DRIFT_RISK" in chain_desc["economic_distortion_flags"]

    def test_unbounded_mint_without_cap(self):
        g = nx.DiGraph()
        # Even if protected, if MISSING_CAP_ENFORCEMENT is present, it's a risk
        s1 = _make_function(
            g,
            "Token",
            "mint",
            has_taint_risk=True,
            writes_total_supply=True,
            is_protected=True,
            cap_enforcement_flags=["MISSING_CAP_ENFORCEMENT"],
        )

        analyzer = EconomicAnalyzer(g)
        chain_desc = {"steps": [s1]}
        score = analyzer.evaluate_chain_economic_impact(chain_desc)

        assert score == 1.5
        assert "UNBOUNDED_MINT_RISK" in chain_desc["economic_distortion_flags"]

    def test_false_positive_guard_safe_math(self):
        g = nx.DiGraph()
        # Has ratio math and unbounded mint, but NO taint risk
        s1 = _make_function(
            g,
            "SafeVault",
            "deposit",
            has_taint_risk=False,
            uses_ratio_math=True,
            writes_total_supply=True,
            is_protected=False,
        )

        analyzer = EconomicAnalyzer(g)
        chain_desc = {"steps": [s1]}
        score = analyzer.evaluate_chain_economic_impact(chain_desc)

        # Should remain 1.0 because attacker cannot influence it
        assert score == 1.0
        assert len(chain_desc["economic_distortion_flags"]) == 0

    def test_capped_maximum_score(self):
        g = nx.DiGraph()
        # Multiple distortions in the same node
        s1 = _make_function(
            g,
            "VulnerableEngine",
            "exploitMe",
            has_taint_risk=True,
            uses_ratio_math=True,  # +0.2
            updates_reward_index=True,  # +0.1
            uses_division=True,
            writes_total_supply=True,  # +0.5
            is_protected=False,
        )

        analyzer = EconomicAnalyzer(g)
        chain_desc = {"steps": [s1]}
        score = analyzer.evaluate_chain_economic_impact(chain_desc)

        # Combined multiplier would be 1.0 + 0.2 + 0.1 + 0.5 = 1.8
        # But it must be capped at 1.5
        assert score == 1.5
        flags = chain_desc["economic_distortion_flags"]
        assert "DENOMINATOR_MANIPULATION_RISK" in flags
        assert "PRECISION_DRIFT_RISK" in flags
        assert "UNBOUNDED_MINT_RISK" in flags
