"""
Tool abstraction layer for the Critikal agent.

Every capability the agent can invoke — pipeline stages, shell commands,
file operations, graph queries — implements the Tool ABC. This is the
foundation that the query loop, TUI, and permission system build on.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from src.agent.context import ToolContext


class PermissionLevel(Enum):
    """How dangerous is this tool invocation?"""

    NONE = "none"  # Pure info, no side effects (graph queries)
    READ_ONLY = "read_only"  # Reads filesystem/network, no mutations
    WRITE = "write"  # Writes files
    EXECUTE = "execute"  # Runs shell commands or LLM calls
    DANGEROUS = "dangerous"  # Destructive ops, mainnet interactions


@dataclass
class ToolResult:
    """Uniform output from any tool execution."""

    output: str
    is_error: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def success(cls, output: str, **metadata) -> "ToolResult":
        return cls(output=output, metadata=metadata)

    @classmethod
    def error(cls, message: str, **metadata) -> "ToolResult":
        return cls(output=message, is_error=True, metadata=metadata)


class Tool(ABC):
    """
    Abstract base class for all agent tools.

    Each tool declares its name, description, permission level, and
    JSON Schema for input validation. The query loop converts these
    to the LLM's tool_use format automatically.
    """

    @abstractmethod
    def name(self) -> str:
        """Unique tool identifier (e.g., 'run_slither', 'bash')."""
        ...

    @abstractmethod
    def description(self) -> str:
        """Human-readable description shown to the LLM."""
        ...

    @abstractmethod
    def permission_level(self) -> PermissionLevel:
        """Permission required to execute this tool."""
        ...

    @abstractmethod
    def input_schema(self) -> dict:
        """JSON Schema describing the tool's input parameters."""
        ...

    @abstractmethod
    async def execute(self, params: dict, ctx: "ToolContext") -> ToolResult:
        """
        Execute the tool with the given parameters.

        Args:
            params: Validated input matching input_schema().
            ctx: Shared execution context (working dir, graph, findings, etc.)

        Returns:
            ToolResult with output text and optional metadata.
        """
        ...

    def to_llm_schema(self) -> dict:
        """Convert to the tool definition format expected by LLM APIs."""
        return {
            "type": "function",
            "function": {
                "name": self.name(),
                "description": self.description(),
                "parameters": self.input_schema(),
            },
        }

    def is_available(self, ctx: "ToolContext") -> bool:
        """
        Whether this tool should be offered to the LLM in the current context.
        Override to hide tools when prerequisites aren't met
        (e.g., hide Slither tools when no graph is loaded).
        """
        return True
