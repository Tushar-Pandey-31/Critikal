# Contributing to Critikal

Thanks for your interest. Critikal is early; expect rough edges and be
ready to read source.

## Development setup

```bash
git clone https://github.com/Tushar-Pandey-31/critikal && cd critikal
poetry install
cp .env.example .env   # add at least one LLM API key
poetry run pytest tests/ -m "not integration"
```

Python 3.12 is required (`>=3.12.1,<3.13`). The full toolchain for PoC
generation also needs Foundry, Node.js 20, and `solc-select` — easiest
via the provided `Dockerfile`.

## Pull request checklist

- [ ] Tests pass: `poetry run pytest tests/ -m "not integration"`
- [ ] New behavior has a unit test. Security-sensitive tool changes
      (`bash_tool`, `file_write_tool`, `sandbox_tool`, `deploy_tool`)
      need a test that covers the refusal / sandbox path.
- [ ] No new hardcoded model IDs in tool code — route through
      `src/pipeline_config.py` or an env var with a clear default.
- [ ] No new provider-specific imports outside `src/llm/providers.py`.
      The codebase is provider-agnostic; keep it that way.
- [ ] `.env.example` updated if you added an env var.
- [ ] `README.md` / `architecture.md` updated if you added a tool,
      worker, or pipeline stage.

## Code layout (quick map)

- `src/cli.py` — entry point dispatcher.
- `src/agent/` — Claude Code-style agentic loop, tools, permissions,
  memory, cost tracking. **This is the product.**
- `src/pipeline/workers/` — specialized worker agents invoked by pipeline
  tools (recon, jury, depth, test writer, …).
- `src/pipeline/lead_agent.py` + `src/main.py` — deprecated legacy
  LangGraph pipeline, reachable only via `critikal --legacy`. Do not
  add features here.
- `src/graph/ (modular)` — Slither → NetworkX graph construction.
- `src/tui/` — Textual TUI.
- `tests/` — unit tests; mark LLM-hitting tests with
  `@pytest.mark.integration` so they are skipped in CI.

See `AI_CONTEXT.md` for a denser architecture reference and `architecture.md`
for the long version.

## Reporting bugs

Open a GitHub issue with:
- Critikal commit SHA.
- Target repo (URL or minimal reproducer).
- Exact CLI invocation.
- Relevant section of `~/.critikal/logs/tui_session.log` or the headless
  stdout.

Security vulnerabilities in Critikal itself go through `SECURITY.md`, not
public issues.

## Style

- Keep functions small; prefer a new module over growing an existing one
  past ~500 lines.
- Type hints on public functions.
- No emojis in source (user-facing reports are fine).
- Comments explain *why*, not *what*.
