"""
QueryLoop — the agentic reasoning loop.

Sends messages to an LLM with tools, interprets tool_use responses,
executes tools, feeds results back, and continues until end_turn or
budget exhaustion.

Inspired by Claude Code's query.ts:
  - AsyncGenerator-style streaming (MESSAGE_CHUNK events)
  - Multi-layer error recovery (retry, fallback model, reactive compact)
  - Tool result budget enforcement
  - Turn chain tracking

Provider-agnostic: uses langchain ChatModel for any LLM that supports
tool calling (Anthropic, Google, OpenAI, xAI, etc.).
"""

import asyncio
import json
import logging
import os
import time
import traceback
from typing import Any

from src.agent.tool import Tool, ToolResult
from src.agent.context import ToolContext
from src.agent.events import Event, EventType
from src.agent.auto_compact import AutoCompactor
from src.agent.permissions import PermissionHandler
from src.agent.system_prompt import build_system_prompt

logger = logging.getLogger(__name__)

DEFAULT_MODEL = "claude-sonnet-4-6"
DEFAULT_MAX_TURNS = 200

# ── Recovery constants (from Claude Code spec) ──
MAX_RETRIES = 3
RETRY_BASE_DELAY_S = 2.0  # exponential: 2s, 4s, 8s
MAX_OUTPUT_TOKENS_RECOVERY_LIMIT = 3
TOOL_RESULT_BUDGET_CHARS = 80_000  # max chars per tool result sent back

# Known error patterns
PROMPT_TOO_LONG_PATTERNS = (
    "prompt is too long",
    "maximum context length",
    "token limit exceeded",
    "context_length_exceeded",
    "too many tokens",
    "request too large",
)

RATE_LIMIT_PATTERNS = (
    "rate limit",
    "rate_limit",
    "429",
    "too many requests",
    "quota exceeded",
    "resource exhausted",
    "overloaded",
)

# Fallback model chain
FALLBACK_MODELS = {
    "claude-sonnet-4-6": "gemini-3-flash-preview",
    "claude-opus-4-6": "claude-sonnet-4-6",
    "grok-3": "gemini-3-flash-preview",
}


class QueryLoop:
    """
    Core agentic loop. Provider-agnostic via langchain ChatModel.

    Flow per turn:
        1. Check auto-compact
        2. Call LLM with tools (streaming)
        3. If stop_reason == end_turn → return text
        4. If stop_reason == tool_use → execute tools, append results, loop
        5. Check budget
        6. On error → retry with backoff / fallback model / reactive compact
    """

    def __init__(
        self,
        tools: list[Tool],
        ctx: ToolContext,
        model: str | None = None,
        max_turns: int = DEFAULT_MAX_TURNS,
        permission_handler: PermissionHandler | None = None,
        fallback_model: str | None = None,
    ):
        self.ctx = ctx
        self.model = model or os.getenv("AGENT_MODEL_NAME", DEFAULT_MODEL)
        self.max_turns = max_turns
        self.tools = {t.name(): t for t in tools}
        self.all_tools = tools
        self.messages: list[dict[str, Any]] = []
        self.compactor = AutoCompactor(self.model)
        self.permissions = permission_handler or PermissionHandler()
        self.fallback_model = fallback_model or FALLBACK_MODELS.get(self.model)

        # Publish the permission handler on the context so sub-agents
        # spawned via SpawnAgentTool inherit the parent's policy rather
        # than silently escalating to auto-approve.
        if getattr(ctx, "permission_handler", None) is None:
            ctx.permission_handler = self.permissions

        # Recovery state
        self._current_model = self.model
        self._max_output_recovery_count = 0
        self._has_attempted_reactive_compact = False

        # LLM cache (per model)
        self._llm_cache: dict[str, Any] = {}
        self._system_prompt = ""

    async def _get_llm(self, model: str | None = None):
        """Lazily initialize the LLM. Caches per model name."""
        model = model or self._current_model
        if model not in self._llm_cache:
            from src.llm.providers import get_worker_llm
            temperature = float(os.getenv("AGENT_TEMPERATURE", "0.0"))
            self._llm_cache[model] = get_worker_llm(
                model_name=model,
                temperature=temperature,
            )
        return self._llm_cache[model]

    def _get_available_tools(self) -> list[Tool]:
        """Return tools that are available in the current context."""
        return [t for t in self.all_tools if t.is_available(self.ctx)]

    def _build_tool_schemas(self) -> list[dict]:
        """Build langchain-compatible tool definitions."""
        available = self._get_available_tools()
        schemas = []
        for tool in available:
            schema = {
                "name": tool.name(),
                "description": tool.description(),
                "parameters": tool.input_schema(),
            }
            schemas.append(schema)
        return schemas

    async def run(self, user_message: str) -> str:
        """
        Run the agentic loop with a user message.

        Returns the final assistant text response.
        """
        # Build system prompt (refreshed each run for state changes)
        available_tools = self._get_available_tools()
        self._system_prompt = build_system_prompt(available_tools, self.ctx)

        # Inject relevant memories from previous sessions if available
        if self.ctx.memory:
            try:
                relevant = self.ctx.memory.find_relevant(user_message, top_k=5)
                if relevant:
                    memory_section = self.ctx.memory.format_for_prompt(relevant)
                    self._system_prompt += "\n\n" + memory_section
                    logger.info(f"[memory] Injected {len(relevant)} relevant memories into prompt")
            except Exception as e:
                logger.warning(f"[memory] Failed to inject memories: {e}")

        # Add user message
        self.messages.append({"role": "user", "content": user_message})

        for turn in range(self.max_turns):
            self.ctx.current_turn = turn

            # 1. Auto-compact check — proactive (75%) first, reactive (90%) fallback
            all_msgs = [{"role": "system", "content": self._system_prompt}] + self.messages
            if self.compactor.should_compact(all_msgs):
                await self.compactor.compact(self.messages)
                await self._emit(EventType.COMPACT, {"turn": turn, "kind": "reactive"})
            elif self.compactor.should_micro_compact(all_msgs):
                await self.compactor.compact(self.messages)
                await self._emit(EventType.COMPACT, {"turn": turn, "kind": "proactive"})

            # 2. Call LLM with retry + fallback + recovery
            try:
                response = await self._call_llm_with_recovery()
            except Exception as e:
                logger.error(f"LLM call failed on turn {turn} after all retries: {e}")
                await self._emit(EventType.ERROR, {"error": str(e), "turn": turn})
                # Report which model(s) failed so "credentials not found"
                # isn't blamed on the wrong provider.
                detail = (
                    f"model={self._current_model}"
                    if self._current_model == self.model
                    else f"fallback={self._current_model} (original={self.model})"
                )
                return f"Error: LLM call failed after retries [{detail}]: {e}"

            # 3. Parse response
            assistant_text, tool_calls = self._parse_response(response)

            # Emit the full assistant text (for non-streaming fallback)
            if assistant_text:
                await self._emit(EventType.MESSAGE_COMPLETE, {
                    "text": assistant_text, "turn": turn,
                })

            # If there are no tool calls, we're done
            if not tool_calls:
                self.messages.append({"role": "assistant", "content": assistant_text})
                await self._emit(EventType.TURN_COMPLETE, {
                    "turn": turn, "text": assistant_text[:200],
                })
                return assistant_text

            # 4. Execute tool calls
            self.messages.append({
                "role": "assistant",
                "content": assistant_text,
                "tool_calls": tool_calls,
            })

            tool_results = await self._execute_tool_calls(tool_calls)

            # Apply tool result budget — truncate oversized results
            tool_results = self._apply_tool_result_budget(tool_results)

            # Append tool results as tool message
            self.messages.append({
                "role": "tool",
                "content": tool_results,
            })

            # 5. Budget check
            if self.ctx.cost_tracker and self.ctx.cost_tracker.is_over_budget():
                await self._emit(EventType.ERROR, {"error": "Budget exceeded"})
                return (
                    f"Budget exceeded (${self.ctx.cost_tracker.session_cost:.2f} / "
                    f"${self.ctx.cost_tracker.budget_usd:.2f}). Stopping."
                )

            # 6. Periodic memory extraction
            if self.ctx.memory and self.ctx.memory.should_extract(turn):
                try:
                    await self.ctx.memory.extract_and_store(self.messages, turn)
                except Exception as e:
                    logger.warning(f"[memory] Extraction failed (non-fatal): {e}")

            await self._emit(EventType.TURN_COMPLETE, {"turn": turn})

        return "Max turns reached. Stopping."

    # ══════════════════════════════════════════════════════════════════
    #  LLM call with streaming + error recovery
    # ══════════════════════════════════════════════════════════════════

    async def _call_llm_with_recovery(self) -> Any:
        """
        Call the LLM with multi-layer error recovery:
          1. Try streaming call
          2. On rate limit: retry with exponential backoff (up to 3x)
          3. On prompt too long: reactive compact, then retry
          4. On max_output_tokens: increment budget, retry (up to 3x)
          5. On persistent failure: switch to fallback model
        """
        last_error = None

        for attempt in range(MAX_RETRIES):
            try:
                return await self._call_llm_streaming()
            except Exception as e:
                last_error = e
                error_str = str(e).lower()

                # ── Rate limit → backoff and retry ──
                if any(p in error_str for p in RATE_LIMIT_PATTERNS):
                    delay = RETRY_BASE_DELAY_S * (2 ** attempt)
                    logger.warning(
                        f"Rate limit on attempt {attempt + 1}/{MAX_RETRIES}. "
                        f"Retrying in {delay:.0f}s..."
                    )
                    await self._emit(EventType.STATUS, {
                        "message": f"Rate limited. Retrying in {delay:.0f}s...",
                    })
                    await asyncio.sleep(delay)
                    continue

                # ── Prompt too long → reactive compact ──
                if any(p in error_str for p in PROMPT_TOO_LONG_PATTERNS):
                    if not self._has_attempted_reactive_compact:
                        logger.warning("Prompt too long — attempting reactive compact...")
                        await self._emit(EventType.STATUS, {
                            "message": "Context too large. Compacting...",
                        })
                        self._has_attempted_reactive_compact = True
                        success = await self.compactor.compact(self.messages)
                        if success:
                            await self._emit(EventType.COMPACT, {"reactive": True})
                            continue
                    # Compact failed or already tried — try fallback model
                    if self.fallback_model and self._current_model != self.fallback_model:
                        logger.warning(
                            f"Switching to fallback model: {self.fallback_model}"
                        )
                        await self._emit(EventType.STATUS, {
                            "message": f"Switching to {self.fallback_model}...",
                        })
                        self._current_model = self.fallback_model
                        continue
                    raise  # No recovery possible

                # ── Max output tokens → increase budget ──
                if "max_output_tokens" in error_str or "maximum output" in error_str:
                    self._max_output_recovery_count += 1
                    if self._max_output_recovery_count <= MAX_OUTPUT_TOKENS_RECOVERY_LIMIT:
                        logger.warning(
                            f"Max output tokens hit (recovery {self._max_output_recovery_count}/"
                            f"{MAX_OUTPUT_TOKENS_RECOVERY_LIMIT}). Retrying..."
                        )
                        continue
                    raise

                # ── Unknown error → try fallback model on last attempt ──
                if attempt == MAX_RETRIES - 2 and self.fallback_model and self._current_model != self.fallback_model:
                    brief = _short_err(e)
                    logger.warning(
                        f"Error on attempt {attempt + 1}: {e}. "
                        f"Switching to fallback: {self.fallback_model}"
                    )
                    # Surface the *reason* we're switching — otherwise
                    # users just see "Trying fallback..." with no context.
                    await self._emit(EventType.STATUS, {
                        "message": (
                            f"{self._current_model} failed ({brief}). "
                            f"Trying {self.fallback_model}..."
                        ),
                    })
                    self._current_model = self.fallback_model
                    continue

                # ── Generic retry with backoff ──
                delay = RETRY_BASE_DELAY_S * (2 ** attempt)
                logger.warning(
                    f"LLM error on attempt {attempt + 1}/{MAX_RETRIES}: {e}. "
                    f"Retrying in {delay:.0f}s..."
                )
                await asyncio.sleep(delay)

        raise last_error or RuntimeError("All retry attempts exhausted")

    async def _call_llm_streaming(self) -> Any:
        """
        Call the LLM using streaming (astream) and emit MESSAGE_CHUNK events.
        Falls back to ainvoke if streaming is not supported.
        """
        from langchain_core.messages import (
            SystemMessage, HumanMessage, AIMessage, ToolMessage,
        )

        llm = await self._get_llm()

        # Convert message format to langchain messages
        lc_messages = [SystemMessage(content=self._system_prompt)]

        for msg in self.messages:
            role = msg["role"]
            content = msg.get("content", "")

            if role == "user":
                lc_messages.append(HumanMessage(content=content))
            elif role == "assistant":
                tool_calls = msg.get("tool_calls", [])
                if tool_calls:
                    lc_tool_calls = []
                    for tc in tool_calls:
                        lc_tool_calls.append({
                            "id": tc["id"],
                            "name": tc["name"],
                            "args": tc["args"],
                        })
                    ai_msg = AIMessage(
                        content=content or "",
                        tool_calls=lc_tool_calls,
                    )
                    lc_messages.append(ai_msg)
                else:
                    lc_messages.append(AIMessage(content=content))
            elif role == "tool":
                results = msg.get("content", [])
                if isinstance(results, list):
                    for result in results:
                        lc_messages.append(ToolMessage(
                            content=result.get("content", ""),
                            tool_call_id=result.get("tool_call_id", ""),
                        ))
                else:
                    lc_messages.append(HumanMessage(content=str(results)))

        # Bind tools and invoke
        tool_schemas = self._build_tool_schemas()
        if tool_schemas:
            llm_with_tools = llm.bind_tools(tool_schemas)
        else:
            llm_with_tools = llm

        # ── Try streaming first ──
        try:
            full_response = None
            streamed_text = []

            async for chunk in llm_with_tools.astream(lc_messages):
                if full_response is None:
                    full_response = chunk
                else:
                    full_response = full_response + chunk

                # Emit text + thinking chunks for real-time TUI updates.
                # Anthropic extended thinking arrives as type="thinking" blocks;
                # without this branch the user watches the spinner and thinks
                # the agent is stuck.
                text_delta = ""
                thinking_delta = ""
                if hasattr(chunk, "content"):
                    if isinstance(chunk.content, str):
                        text_delta = chunk.content
                    elif isinstance(chunk.content, list):
                        for block in chunk.content:
                            if not isinstance(block, dict):
                                continue
                            btype = block.get("type")
                            if btype == "text":
                                text_delta += block.get("text", "")
                            elif btype == "thinking":
                                thinking_delta += block.get("thinking", "") or block.get("text", "")

                if thinking_delta:
                    await self._emit(EventType.MESSAGE_CHUNK, {
                        "text": thinking_delta,
                        "kind": "thinking",
                    })
                if text_delta:
                    streamed_text.append(text_delta)
                    await self._emit(EventType.MESSAGE_CHUNK, {
                        "text": text_delta,
                        "kind": "text",
                    })

            if full_response is None:
                raise RuntimeError("Empty stream response from LLM")

        except (NotImplementedError, TypeError, AttributeError):
            # Streaming not supported — fall back to ainvoke
            logger.debug("Streaming not supported, falling back to ainvoke")
            full_response = await llm_with_tools.ainvoke(lc_messages)

        # Track cost
        if self.ctx.cost_tracker and hasattr(full_response, "usage_metadata"):
            usage = full_response.usage_metadata
            if usage:
                self.ctx.cost_tracker.record(
                    self._current_model,
                    usage.get("input_tokens", 0),
                    usage.get("output_tokens", 0),
                )
                await self._emit(EventType.COST_UPDATE, {
                    "cost": self.ctx.cost_tracker.session_cost,
                })

        return full_response

    def _parse_response(self, response: Any) -> tuple[str, list[dict]]:
        """
        Parse a langchain AIMessage into text and tool calls.

        Returns (text, tool_calls) where tool_calls is a list of
        {"id": str, "name": str, "args": dict}.
        """
        text = ""
        tool_calls = []

        # Extract text content
        if hasattr(response, "content"):
            content = response.content
            if isinstance(content, str):
                text = content
            elif isinstance(content, list):
                text_parts = []
                for block in content:
                    if isinstance(block, dict) and block.get("type") == "text":
                        text_parts.append(block["text"])
                    elif isinstance(block, str):
                        text_parts.append(block)
                text = "\n".join(text_parts)

        # Extract tool calls
        if hasattr(response, "tool_calls") and response.tool_calls:
            for tc in response.tool_calls:
                tool_calls.append({
                    "id": tc.get("id", f"call_{id(tc)}"),
                    "name": tc["name"],
                    "args": tc.get("args", {}),
                })

        return text, tool_calls

    async def _execute_tool_calls(self, tool_calls: list[dict]) -> list[dict]:
        """Execute tool calls and return results."""
        results = []

        for tc in tool_calls:
            tool_name = tc["name"]
            tool_id = tc["id"]
            args = tc.get("args", {})

            tool = self.tools.get(tool_name)
            if not tool:
                results.append({
                    "tool_call_id": tool_id,
                    "content": f"Error: unknown tool '{tool_name}'",
                })
                continue

            # Permission check
            allowed = await self.permissions.check(tool, args, self.ctx)
            if not allowed:
                results.append({
                    "tool_call_id": tool_id,
                    "content": f"Permission denied for '{tool_name}' ({tool.permission_level().value}).",
                })
                continue

            # PreToolUse hook — may block the call
            hooks = getattr(self.ctx, "hooks", None)
            if hooks is not None and hooks.has("PreToolUse"):
                hook_result = await hooks.fire(
                    "PreToolUse",
                    tool_name=tool_name,
                    payload={"tool": tool_name, "args": args},
                )
                if hook_result.blocked:
                    await self._emit(EventType.STATUS, {
                        "message": f"PreToolUse hook blocked {tool_name}: {hook_result.reason[:200]}",
                    })
                    results.append({
                        "tool_call_id": tool_id,
                        "content": (
                            f"[BLOCKED by PreToolUse hook] {hook_result.reason}"
                        ),
                    })
                    continue

            # Emit tool start event
            await self._emit(EventType.TOOL_START, {
                "tool": tool_name,
                "args_summary": _summarize_args(args),
            })

            # Execute
            start_time = time.monotonic()
            try:
                result = await tool.execute(args, self.ctx)
            except Exception as e:
                logger.error(f"Tool '{tool_name}' raised: {e}", exc_info=True)
                result = ToolResult.error(f"Tool execution error: {e}")

            elapsed = time.monotonic() - start_time

            # Emit tool complete event
            await self._emit(EventType.TOOL_COMPLETE, {
                "tool": tool_name,
                "elapsed_s": round(elapsed, 2),
                "is_error": result.is_error,
                "output_preview": result.output[:200],
            })

            # PostToolUse hook — advisory; exit codes don't block
            if hooks is not None and hooks.has("PostToolUse"):
                await hooks.fire(
                    "PostToolUse",
                    tool_name=tool_name,
                    payload={
                        "tool": tool_name,
                        "args": args,
                        "is_error": result.is_error,
                        "output_preview": result.output[:500],
                    },
                )

            content = result.output
            if result.is_error:
                content = f"[ERROR] {content}"

            results.append({
                "tool_call_id": tool_id,
                "content": content,
            })

        return results

    def _apply_tool_result_budget(self, results: list[dict]) -> list[dict]:
        """
        Enforce tool result size budget.
        Truncate oversized results to prevent context overflow.
        Inspired by Claude Code's applyToolResultBudget().
        """
        budgeted = []
        for result in results:
            content = result.get("content", "")
            if len(content) > TOOL_RESULT_BUDGET_CHARS:
                # Keep head and tail for context
                head = content[:TOOL_RESULT_BUDGET_CHARS // 2]
                tail = content[-(TOOL_RESULT_BUDGET_CHARS // 4):]
                truncated_chars = len(content) - len(head) - len(tail)
                content = (
                    f"{head}\n\n"
                    f"... [truncated {truncated_chars:,} characters] ...\n\n"
                    f"{tail}"
                )
                result = {**result, "content": content}
            budgeted.append(result)
        return budgeted

    async def _emit(self, event_type: EventType, data: dict):
        """Emit an event to the event bus if available."""
        if self.ctx.event_bus:
            await self.ctx.event_bus.emit(Event(type=event_type, data=data))

    def get_conversation_stats(self) -> dict:
        """Return stats about the current conversation."""
        return {
            "messages": len(self.messages),
            "turns": self.ctx.current_turn,
            "model": self._current_model,
            "original_model": self.model,
            "tools_available": len(self._get_available_tools()),
            "findings": len(self.ctx.findings),
            "compactor": self.compactor.stats,
            "recovery": {
                "max_output_recoveries": self._max_output_recovery_count,
                "reactive_compact_attempted": self._has_attempted_reactive_compact,
                "using_fallback": self._current_model != self.model,
            },
        }


def _short_err(e: Exception, limit: int = 160) -> str:
    """Collapse a provider exception to a single short line for user-facing messages."""
    msg = str(e).replace("\n", " ").strip()
    if len(msg) > limit:
        msg = msg[:limit] + "..."
    return msg or type(e).__name__


def _summarize_args(args: dict) -> str:
    """Create a short summary of tool args for events."""
    if not args:
        return ""
    parts = []
    for k, v in args.items():
        val = str(v)
        if len(val) > 50:
            val = val[:50] + "..."
        parts.append(f"{k}={val}")
    return ", ".join(parts)
