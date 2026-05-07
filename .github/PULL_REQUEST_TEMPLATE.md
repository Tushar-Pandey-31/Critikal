# What

One-paragraph summary of the change.

# Why

Motivation. Bug, feature, refactor, perf — link an issue if there is one.

# Test plan

- [ ] `poetry run pytest tests/ -m "not integration and not uses_rag"` passes
- [ ] `poetry run ruff check src/ tests/` clean
- [ ] If this changes a worker / pipeline tool: ran `critikal --repo <URL>` end-to-end on at least one real target
- [ ] If this changes a security-sensitive tool (`bash`, `file_write`, `sandbox_run`, `deploy_contract`): added/updated the refusal-path test

# Checklist

- [ ] No new hardcoded model IDs outside `src/pipeline_config.py`
- [ ] No new provider-specific imports outside `src/llm/providers.py`
- [ ] `.env.example` updated if a new env var was added
- [ ] `README.md` / `architecture.md` updated if a tool, worker, or pipeline stage changed
