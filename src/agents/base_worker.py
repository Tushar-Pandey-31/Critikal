"""
WorkerAgent base class for the multi-agent orchestration layer.

All specialist workers (reentrancy, access control, logic, etc.) extend
WorkerAgent and implement the `run()` coroutine. The Lead Agent (Coordinator)
spawns workers via asyncio.gather() and collects WorkerOutput objects.
"""

import os
from abc import ABC, abstractmethod
from typing import Any, Optional
from pydantic import BaseModel, Field, field_validator


class WorkerTask(BaseModel):
    """Specification of a task for a worker to perform."""
    task_id: str
    task_type: str
    hotspot: Optional[Any] = None  # Hotspot object
    context: dict[str, Any] = Field(default_factory=dict)
    budget_tokens: int = 5000


class WorkerOutput(BaseModel):
    """Uniform output contract for every worker agent."""

    worker_type: str
    task_id: str | None = None
    hypothesis: str | None = None
    
    # Unordered set of ALL graph nodes cited as evidence
    evidence_node_ids: list[str] = Field(default_factory=list)
    
    # Ordered execution path — ["Contract.entryFunc", "Contract.helperA", "Contract.vulnFunc"]
    attack_path: list[str] = Field(default_factory=list)

    confidence: int = Field(default=0)
    raw_output: dict[str, Any] = Field(default_factory=dict)

    @field_validator('confidence')
    @classmethod
    def confidence_in_range(cls, v):
        if not 0 <= v <= 100:
            raise ValueError(f"Confidence must be 0-100, got {v}")
        return v


class WorkerAgent(ABC):
    """
    Abstract base class that every specialist worker must extend.
    """

    model_name: str = os.environ.get("WORKER_MODEL_NAME", "gemini-3-flash-preview")

    @abstractmethod
    def get_worker_type(self) -> str:
        """Returns the type of the worker (e.g., 'attack_hypothesis')."""
        ...

    @abstractmethod
    async def run(self, task: WorkerTask) -> WorkerOutput:
        """
        Execute the worker's analysis task.
        """
        ...
