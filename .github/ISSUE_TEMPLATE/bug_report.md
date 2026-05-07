---
name: Bug report
about: Critikal misbehaved on a real run
labels: bug
---

**Critikal commit / version**
e.g. `git rev-parse HEAD` or the tag you installed

**Target repo**
URL or minimal reproducer (ideally a small repo we can `git clone`)

**Exact CLI invocation**
```
critikal --repo ... --headless "..." --model ...
```

**What happened**
What did Critikal output? Was the failure during ingest, recon, attack,
TestWriter, or report generation?

**What you expected**
Briefly: what should it have done instead?

**Logs**
Attach the relevant section of `~/.critikal/logs/tui_session.log` (TUI mode)
or the headless stdout. Redact API keys.

**Environment**
- OS:
- Python:
- Foundry / solc-select / Node:
- Models routed (which `*_MODEL_NAME` env vars are set):
