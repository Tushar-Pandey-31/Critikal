"""
WebSearchTool — web search with a pluggable backend.

Discovering URLs (docs, exploit writeups, Etherscan pages, similar
incidents) was a gap: `web_fetch` assumes you already know the URL.
This tool closes that gap.

Backend selection (env):
  WEB_SEARCH_PROVIDER   'parallel' | (future: 'tavily' | 'brave' | ...)
                        If unset, defaults to 'parallel' when PARALLEL_API_KEY
                        is present; otherwise the tool returns a clear error.
  PARALLEL_API_KEY      Required for the Parallel backend.
                        Get one at https://platform.parallel.ai → Settings.
"""

import asyncio
import json
import logging
import os
from typing import Any

from src.agent.tool import Tool, ToolResult, PermissionLevel
from src.agent.context import ToolContext

logger = logging.getLogger(__name__)

DEFAULT_MAX_RESULTS = 5
DEFAULT_TIMEOUT = 30
MAX_MAX_RESULTS = 20
PARALLEL_SEARCH_ENDPOINT = "https://api.parallel.ai/v1beta/search"


class WebSearchTool(Tool):
    """Search the web. Returns a ranked list of {url, title, excerpt}."""

    def name(self) -> str:
        return "web_search"

    def description(self) -> str:
        return (
            "Search the web and return a ranked list of URLs with titles "
            "and excerpts. Use when you need to DISCOVER URLs: protocol "
            "documentation, audit reports, exploit writeups, Etherscan "
            "pages, similar past incidents, CVEs. For URLs you already "
            "know, use web_fetch. Backend is configurable via "
            "WEB_SEARCH_PROVIDER (default: Parallel AI)."
        )

    def permission_level(self) -> PermissionLevel:
        return PermissionLevel.READ_ONLY

    def input_schema(self) -> dict:
        return {
            "type": "object",
            "properties": {
                "objective": {
                    "type": "string",
                    "description": (
                        "Natural-language description of what you're trying "
                        "to find (e.g. 'recent reentrancy exploits in lending "
                        "protocols, 2024-2025'). Prefer this over 'queries' "
                        "unless you need exact-match control."
                    ),
                },
                "queries": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": (
                        "Optional keyword-style search queries. Max 5. "
                        "At least one of 'objective' or 'queries' is required."
                    ),
                },
                "max_results": {
                    "type": "integer",
                    "description": f"Max results to return (default {DEFAULT_MAX_RESULTS}, cap {MAX_MAX_RESULTS}).",
                    "default": DEFAULT_MAX_RESULTS,
                },
                "include_domains": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Restrict results to these domains (e.g. ['etherscan.io', 'github.com']).",
                },
                "exclude_domains": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Exclude these domains.",
                },
                "after_date": {
                    "type": "string",
                    "description": "Only include pages published on/after this date (YYYY-MM-DD).",
                },
            },
        }

    async def execute(self, params: dict, ctx: ToolContext) -> ToolResult:
        if "input" in params and isinstance(params["input"], dict):
            params = params["input"]

        objective = (params.get("objective") or "").strip()
        queries = params.get("queries") or []
        if isinstance(queries, str):
            queries = [queries]
        if not objective and not queries:
            return ToolResult.error(
                "Missing input. Provide 'objective' (natural language) "
                "or 'queries' (keyword list)."
            )

        max_results = params.get("max_results", DEFAULT_MAX_RESULTS)
        if not isinstance(max_results, int) or max_results < 1:
            max_results = DEFAULT_MAX_RESULTS
        max_results = min(max_results, MAX_MAX_RESULTS)

        include_domains = params.get("include_domains") or []
        exclude_domains = params.get("exclude_domains") or []
        after_date = (params.get("after_date") or "").strip() or None

        provider = _select_provider()
        if provider == "parallel":
            return await _search_parallel(
                objective=objective,
                queries=queries,
                max_results=max_results,
                include_domains=include_domains,
                exclude_domains=exclude_domains,
                after_date=after_date,
            )
        if provider == "none":
            return ToolResult.error(
                "web_search is not configured. Set PARALLEL_API_KEY in .env "
                "(or set WEB_SEARCH_PROVIDER to a supported backend)."
            )
        return ToolResult.error(
            f"Unknown WEB_SEARCH_PROVIDER '{provider}'. Supported: parallel."
        )


def _select_provider() -> str:
    """Pick the backend. Explicit env wins; else parallel if key exists."""
    explicit = os.getenv("WEB_SEARCH_PROVIDER", "").strip().lower()
    if explicit:
        return explicit
    if os.getenv("PARALLEL_API_KEY"):
        return "parallel"
    return "none"


async def _search_parallel(
    *,
    objective: str,
    queries: list[str],
    max_results: int,
    include_domains: list[str],
    exclude_domains: list[str],
    after_date: str | None,
) -> ToolResult:
    api_key = os.getenv("PARALLEL_API_KEY")
    if not api_key:
        return ToolResult.error(
            "PARALLEL_API_KEY is not set. Add it to .env (from "
            "https://platform.parallel.ai Settings → API Keys)."
        )

    try:
        import aiohttp
    except ImportError:
        return ToolResult.error(
            "aiohttp is required for web_search. Run: pip install aiohttp"
        )

    body: dict[str, Any] = {"max_results": max_results}
    if objective:
        body["objective"] = objective
    if queries:
        body["search_queries"] = queries[:5]

    source_policy: dict[str, Any] = {}
    if include_domains:
        source_policy["include_domains"] = include_domains
    if exclude_domains:
        source_policy["exclude_domains"] = exclude_domains
    if after_date:
        source_policy["after_date"] = after_date
    if source_policy:
        body["source_policy"] = source_policy

    headers = {
        "x-api-key": api_key,
        "Content-Type": "application/json",
    }

    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(
                PARALLEL_SEARCH_ENDPOINT,
                json=body,
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=DEFAULT_TIMEOUT),
            ) as resp:
                status = resp.status
                raw = await resp.text()

                if status in (401, 403):
                    return ToolResult.error(
                        f"Parallel auth failed (HTTP {status}). Check PARALLEL_API_KEY. "
                        f"Body: {raw[:200]}"
                    )
                if status == 429:
                    return ToolResult.error(
                        f"Parallel rate limit (HTTP 429, 600/min cap). "
                        f"Retry after a pause. Body: {raw[:200]}"
                    )
                if status >= 400:
                    return ToolResult.error(
                        f"Parallel search HTTP {status}. Body: {raw[:400]}"
                    )

                try:
                    data = json.loads(raw)
                except json.JSONDecodeError as e:
                    return ToolResult.error(
                        f"Parallel returned non-JSON: {e}. Body: {raw[:400]}"
                    )

    except asyncio.TimeoutError:
        return ToolResult.error(f"Parallel request timed out after {DEFAULT_TIMEOUT}s.")
    except Exception as e:
        return ToolResult.error(f"Parallel request failed: {e}")

    results = data.get("results") or []
    warnings = data.get("warnings") or []
    search_id = data.get("search_id")

    if not results:
        msg = "No results."
        if warnings:
            msg += " Warnings: " + "; ".join(str(w) for w in warnings)
        return ToolResult.success(
            msg, provider="parallel", search_id=search_id, result_count=0,
        )

    formatted = _format_parallel_results(
        results, objective=objective, queries=queries, warnings=warnings,
    )
    return ToolResult.success(
        formatted,
        provider="parallel",
        search_id=search_id,
        result_count=len(results),
    )


def _format_parallel_results(
    results: list[dict],
    *,
    objective: str,
    queries: list[str],
    warnings: list,
) -> str:
    """Render results as a compact numbered list the LLM can parse."""
    out: list[str] = []
    if objective:
        out.append(f"Objective: {objective}")
    if queries:
        out.append(f"Queries: {queries}")
    out.append(f"Results: {len(results)}")
    if warnings:
        out.append(f"Warnings: {'; '.join(str(w) for w in warnings)}")
    out.append("")

    for i, r in enumerate(results, 1):
        url = r.get("url", "")
        title = r.get("title") or ""
        date = r.get("publish_date") or ""
        excerpts = r.get("excerpts")

        header = f"[{i}] {title}".strip()
        out.append(header if header != f"[{i}]" else f"[{i}]")
        out.append(f"    {url}")
        if date:
            out.append(f"    Published: {date}")

        # Parallel may return excerpts as a list[str] or a single string.
        excerpt_text = _join_excerpts(excerpts)
        if excerpt_text:
            out.append("    Excerpt:")
            for line in excerpt_text.split("\n"):
                out.append(f"      {line}" if line else "")
        out.append("")

    return "\n".join(out).rstrip()


def _join_excerpts(excerpts: Any) -> str:
    if not excerpts:
        return ""
    if isinstance(excerpts, str):
        return excerpts.strip()
    if isinstance(excerpts, list):
        parts = []
        for e in excerpts:
            if isinstance(e, str):
                s = e.strip()
            elif isinstance(e, dict):
                s = str(e.get("text") or e.get("content") or "").strip()
            else:
                s = str(e).strip()
            if s:
                parts.append(s)
        return "\n\n".join(parts)
    return str(excerpts)
