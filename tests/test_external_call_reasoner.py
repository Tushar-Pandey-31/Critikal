import networkx as nx

from src.graph import GraphBuilder


def _add_contract(g: nx.DiGraph, name: str):
    g.add_node(name, type="contract", name=name)


def _add_func(g: nx.DiGraph, contract: str, name: str, **kwargs) -> str:
    func_id = f"{contract}.{name}"
    data = {
        "type": "function",
        "name": name,
        "contract": contract,
        "is_external_entry": kwargs.get("is_external_entry", True),
        **kwargs,
    }
    g.add_node(func_id, **data)
    return func_id


def _run_analyzer(g: nx.DiGraph):
    builder = GraphBuilder()
    builder.graph = g
    builder._analyze_external_call_risks()


class TestExternalCallReasoner:
    def test_harmless_erc20_transfer(self):
        g = nx.DiGraph()
        _add_contract(g, "DeFi")
        _add_contract(g, "ERC20")
        f = _add_func(g, "DeFi", "deposit", reentrancy_risk=True)  # Has low level reentrancy match
        target = _add_func(g, "ERC20", "transferFrom")
        g.add_edge(
            f, target, relationship="EXTERNAL_CALL", target_expression="token.transferFrom", return_value_checked=True
        )

        _run_analyzer(g)

        # Token transfer matched with reentrancy should get 10pts instead of 45pts.
        assert "TOKEN_TRANSFER" in g.nodes[f]["external_call_classes"]
        assert g.nodes[f]["external_call_risk_score"] == 10
        assert "EXTERNAL_DEPENDENCY_RISK" not in g.nodes[f]["external_risk_tags"]

    def test_untrusted_call_before_update(self):
        g = nx.DiGraph()
        _add_contract(g, "Vuln")
        f = _add_func(g, "Vuln", "withdraw", reentrancy_risk=True, state_write_after_external_call=True)
        target = _add_func(g, "Unknown", "fallback")
        g.add_edge(
            f,
            target,
            relationship="EXTERNAL_CALL",
            target_expression="msg.sender.call{value: 1}()",
            return_value_checked=True,
        )

        _run_analyzer(g)

        # LOW_LEVEL_CALL + Write After Call + Reentrancy = 45pts (reentrancy) + 30pts (dep risk)
        assert "LOW_LEVEL_CALL" in g.nodes[f]["external_call_classes"]
        assert "REENTRANCY_RISK" in g.nodes[f]["external_risk_tags"]
        assert "EXTERNAL_DEPENDENCY_RISK" in g.nodes[f]["external_risk_tags"]
        assert g.nodes[f]["external_call_risk_score"] == 75

    def test_oracle_read(self):
        g = nx.DiGraph()
        _add_contract(g, "DeFi")
        f = _add_func(g, "DeFi", "checkPrice")
        target = _add_func(g, "Oracle", "latestRoundData")
        g.add_edge(
            f,
            target,
            relationship="EXTERNAL_CALL",
            target_expression="oracle.latestRoundData()",
            return_value_checked=True,
        )

        _run_analyzer(g)

        assert "ORACLE" in g.nodes[f]["external_call_classes"]
        assert g.nodes[f]["external_call_risk_score"] == 0
        assert "EXTERNAL_DEPENDENCY_RISK" not in g.nodes[f]["external_risk_tags"]

    def test_unchecked_risky_call(self):
        g = nx.DiGraph()
        _add_contract(g, "Vuln")
        f = _add_func(g, "Vuln", "badCall")
        target = _add_func(g, "Unknown", "doSomething")
        g.add_edge(
            f, target, relationship="EXTERNAL_CALL", target_expression="target.call(data)", return_value_checked=False
        )

        _run_analyzer(g)

        assert "LOW_LEVEL_CALL" in g.nodes[f]["external_call_classes"]
        assert "UNCHECKED_RETURN" in g.nodes[f]["external_risk_tags"]
        # Assuming NO write after call here. Just the unchecked risky call.
        # But risky calls by default trigger EXTERNAL_DEPENDENCY_RISK.
        assert "EXTERNAL_DEPENDENCY_RISK" in g.nodes[f]["external_risk_tags"]
        assert g.nodes[f]["external_call_risk_score"] == 55  # 25 for unchecked risky + 30 for dep risk

    def test_tainted_safe_call_becomes_risky(self):
        g = nx.DiGraph()
        _add_contract(g, "Vuln")
        f = _add_func(g, "Vuln", "adminCall", has_taint_risk=True)  # Admin passes tainted target
        target = _add_func(g, "Unknown", "anyFunc")
        # Let's say it's standard call syntax, but untrusted target
        g.add_edge(
            f,
            target,
            relationship="EXTERNAL_CALL",
            target_expression="target(addr).callFunc()",
            return_value_checked=True,
        )

        _run_analyzer(g)

        assert "UNTRUSTED_CONTRACT" in g.nodes[f]["external_call_classes"]
        assert "EXTERNAL_DEPENDENCY_RISK" in g.nodes[f]["external_risk_tags"]
        assert g.nodes[f]["external_call_risk_score"] == 30
