from dataclasses import dataclass, field
from typing import Any, List, Dict


@dataclass
class Hotspot:
    node_id: str
    contract: str
    function: str
    risk_score: int
    risk_categories: List[str]
    signals: Dict[str, Any]
    priority: str
    structural_score: int = 0
    exploitability_score: int = 0
    impact_score: int = 0
    final_score: int = 0
    tier: str = "INFRA"

    @property
    def node_name(self) -> str:
        return self.node_id
