from src.models.finding import Finding


def _make_finding(tags: list[str], rag_conf=0, cons_conf=0, llm_conf=70) -> Finding:
    return Finding(
        id="test-val",
        hotspot_node_id="A::B",
        affected_contract="A",
        affected_function="B",
        vulnerability_class="test",
        hypothesis="test",
        attack_path=[],
        evidence_nodes=[],
        confidence=llm_conf,
        severity_estimate="HIGH",
        impact="test",
        title="test",
        evidence_tags=tags,
        confidence_evidence=llm_conf,
        confidence_consensus=cons_conf,
        confidence_rag_match=rag_conf,
    )


class TestMechanicalScoring:
    def test_poc_pass_gives_high_evidence_score(self):
        f = _make_finding(tags=["[POC-PASS]"], llm_conf=0)
        # POC-PASS weight is 1.0.
        # score = 1.0*0.40 + 0*0.30 + 0*0.30 = 0.40 -> 40
        assert f.compute_mechanical_confidence() == 40

    def test_llm_only_gives_low_score(self):
        f = _make_finding(tags=["[LLM-ONLY]"], llm_conf=50)
        # LLM-ONLY weight is 0.2
        # score = 0.2*0.40 + 0*0.30 + 0.5*0.30 = 0.08 + 0.15 = 0.23 -> 23
        assert f.compute_mechanical_confidence() == 23

    def test_graph_signal_boosts_score(self):
        f = _make_finding(tags=["[GRAPH-SIGNAL]", "[CODE]"], llm_conf=100)
        # Max weight is [CODE] = 0.8
        # score = 0.8*0.40 + 0*0.30 + 1.0*0.30 = 0.32 + 0.30 = 0.62 -> 62
        assert f.compute_mechanical_confidence() == 62

    def test_composite_formula_correct(self):
        f = _make_finding(tags=["[PROD-ONCHAIN]", "[RAG-MATCH]"], rag_conf=100, cons_conf=100, llm_conf=100)
        # PROD-ONCHAIN weight is 1.0 (RAG no longer in formula)
        # score = 1.0*0.40 + 1.0*0.30 + 1.0*0.30 = 1.0 -> 100
        assert f.compute_mechanical_confidence() == 100

    def test_no_tags_defaults_to_point_two(self):
        f = _make_finding(tags=[], llm_conf=0)
        # No tags -> 0.2 * 0.40 = 0.08 -> 8
        assert f.compute_mechanical_confidence() == 8
