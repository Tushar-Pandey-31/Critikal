from dataclasses import dataclass
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

    @property
    def node_name(self) -> str:
        return self.node_id
