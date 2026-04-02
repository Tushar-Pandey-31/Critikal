import pytest
import asyncio
from src.models.finding import Finding
from src.knowledge.rag_system import rag_mandatory_sweep
import src.knowledge.rag_system

class MockFinding:
    def __init__(self, v_class="test", hyp="test", confidence=50):
        self.vulnerability_class = v_class
        self.hypothesis = hyp
        self.affected_contract = "TestContract"
        self.affected_function = "testFunc"
        self.confidence = confidence
        self.evidence_tags = []

def mock_search_results(query: str, k: int = 3):
    if "zero_matches" in query:
        return []
    if "five_matches" in query:
        return [{"content": "x"*50, "source": "s1"}] * 5
    return [{"content": "x"*50, "source": "s1"}]

@pytest.fixture(autouse=True)
def mock_rag_db(monkeypatch):
    monkeypatch.setattr(src.knowledge.rag_system, "HAS_RAG", True)
    monkeypatch.setattr(src.knowledge.rag_system, "vector_db", True)
    monkeypatch.setattr(src.knowledge.rag_system, "search_security_knowledge", mock_search_results)

@pytest.mark.asyncio
async def test_all_findings_receive_rag_score():
    findings = [MockFinding(), MockFinding()]
    result = await rag_mandatory_sweep(findings)
    assert len(result) == 2
    assert hasattr(result[0], "confidence_rag_match")
    assert hasattr(result[1], "confidence_rag_match")

@pytest.mark.asyncio
async def test_zero_matches_gives_zero_rag_confidence():
    f = MockFinding(v_class="zero_matches")
    result = await rag_mandatory_sweep([f])
    assert result[0].confidence_rag_match == 0
    assert "[RAG-MATCH]" not in result[0].evidence_tags

@pytest.mark.asyncio
async def test_five_matches_gives_full_rag_confidence():
    f = MockFinding(v_class="five_matches")
    result = await rag_mandatory_sweep([f])
    assert result[0].confidence_rag_match == 100
    assert "[RAG-MATCH]" in result[0].evidence_tags

@pytest.mark.asyncio
async def test_rag_match_tag_added():
    f = MockFinding(v_class="normal_match")
    result = await rag_mandatory_sweep([f])
    assert result[0].confidence_rag_match == 40
    assert "[RAG-MATCH]" in result[0].evidence_tags
