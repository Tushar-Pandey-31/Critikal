"""
Graph query tools — Expose GraphQueries methods directly to the agent.

Wraps: GraphQueries.get_function_context(), find_state_mutators(), get_modifiers()
"""

from src.agent.context import ToolContext
from src.agent.tool import PermissionLevel, Tool, ToolResult


class FunctionContextTool(Tool):

    def name(self) -> str:
        return "get_function_context"

    def description(self) -> str:
        return (
            "Get a function's source code and its immediate neighbors (callers, callees, "
            "state variables read/written). Use this to understand what a specific "
            "function does and how it connects to the rest of the codebase."
        )

    def permission_level(self) -> PermissionLevel:
        return PermissionLevel.NONE

    def input_schema(self) -> dict:
        return {
            "type": "object",
            "properties": {
                "node_id": {
                    "type": "string",
                    "description": "Function node ID (e.g., 'Contract.functionName')",
                },
            },
            "required": ["node_id"],
        }

    def is_available(self, ctx: ToolContext) -> bool:
        return ctx.has_graph()

    async def execute(self, params: dict, ctx: ToolContext) -> ToolResult:
        if "input" in params and isinstance(params["input"], dict):
            params = params["input"]
        import json

        from src.utils.graph_queries import get_graph_queries

        node_id = params.get("node_id") or params.get("function") or params.get("id") or ""
        if not node_id:
            return ToolResult.error(f"Missing 'node_id'. Got keys: {list(params.keys())}")

        queries = get_graph_queries(ctx.graph)
        try:
            result = queries.get_function_context(node_id)
            return ToolResult.success(json.dumps(result, indent=2, default=str))
        except Exception as e:
            return ToolResult.error(f"Failed to get function context: {e}")


class StateMutatorsTool(Tool):

    def name(self) -> str:
        return "find_state_mutators"

    def description(self) -> str:
        return (
            "Find all functions that write to a specific state variable. "
            "Use this to trace who can modify critical state."
        )

    def permission_level(self) -> PermissionLevel:
        return PermissionLevel.NONE

    def input_schema(self) -> dict:
        return {
            "type": "object",
            "properties": {
                "variable_name": {
                    "type": "string",
                    "description": "State variable node ID (e.g., 'Contract::balances')",
                },
            },
            "required": ["variable_name"],
        }

    def is_available(self, ctx: ToolContext) -> bool:
        return ctx.has_graph()

    async def execute(self, params: dict, ctx: ToolContext) -> ToolResult:
        if "input" in params and isinstance(params["input"], dict):
            params = params["input"]
        from src.utils.graph_queries import get_graph_queries

        var_name = params.get("variable_name") or params.get("variable") or params.get("name") or ""
        if not var_name:
            return ToolResult.error(f"Missing 'variable_name'. Got keys: {list(params.keys())}")

        queries = get_graph_queries(ctx.graph)
        try:
            mutators = queries.find_state_mutators(var_name)
            if not mutators:
                return ToolResult.success(f"No functions write to '{var_name}'.")
            return ToolResult.success(
                f"Functions that modify '{var_name}':\n"
                + "\n".join(f"  - {m}" for m in mutators)
            )
        except Exception as e:
            return ToolResult.error(f"Failed: {e}")


class ModifiersTool(Tool):

    def name(self) -> str:
        return "get_modifiers"

    def description(self) -> str:
        return (
            "List all security modifiers applied to a function "
            "(e.g., onlyOwner, nonReentrant, whenNotPaused)."
        )

    def permission_level(self) -> PermissionLevel:
        return PermissionLevel.NONE

    def input_schema(self) -> dict:
        return {
            "type": "object",
            "properties": {
                "function_id": {
                    "type": "string",
                    "description": "Function node ID (e.g., 'Contract.withdraw')",
                },
            },
            "required": ["function_id"],
        }

    def is_available(self, ctx: ToolContext) -> bool:
        return ctx.has_graph()

    async def execute(self, params: dict, ctx: ToolContext) -> ToolResult:
        if "input" in params and isinstance(params["input"], dict):
            params = params["input"]
        from src.utils.graph_queries import get_graph_queries

        func_id = params.get("function_id") or params.get("function") or params.get("id") or ""
        if not func_id:
            return ToolResult.error(f"Missing 'function_id'. Got keys: {list(params.keys())}")

        queries = get_graph_queries(ctx.graph)
        try:
            modifiers = queries.get_modifiers(func_id)
            if not modifiers:
                return ToolResult.success(f"No modifiers on '{func_id}'.")
            return ToolResult.success(
                f"Modifiers on '{func_id}':\n"
                + "\n".join(f"  - {m}" for m in modifiers)
            )
        except Exception as e:
            return ToolResult.error(f"Failed: {e}")
