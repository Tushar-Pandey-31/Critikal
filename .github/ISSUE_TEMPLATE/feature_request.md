---
name: Feature request
about: Propose a new pipeline stage, worker, tool, or detector
labels: enhancement
---

**Problem**
What does Critikal miss / get wrong today? A concrete example helps a lot —
a finding it should have flagged, a worker that's too noisy, a tool the
agent keeps reaching for and not finding.

**Proposal**
What you'd add/change. Stage in the pipeline, new worker, new agent tool,
scoring tweak, etc.

**Alternatives considered**
Other approaches you ruled out, and why.

**Scope check**
- [ ] Provider-agnostic (no new hardcoded model IDs outside `pipeline_config`).
- [ ] Doesn't expand the agent's permission surface (no new shell or
      network capabilities without a permission gate).
