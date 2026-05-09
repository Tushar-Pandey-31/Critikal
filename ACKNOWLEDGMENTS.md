# Acknowledgments

## Pashov (skills repo)

The first-principles assumption-violation methodology used in `AssumptionWorker`, the
cross-function execution trace methodology in `ExecutionTraceWorker`, and the 4-gate
pre-filter design in `JuryWorker` were developed with inspiration from the agent prompts
and reasoning frameworks in [pashov/skills](https://github.com/pashov/skills).
No source code was copied — the methodology was adapted and re-implemented independently
for the smart-contract security domain.

## Agent Architecture

The multi-turn agentic loop architecture — including the tool execution model,
read-before-write file safety, context compaction, the memory/dream system, hook
lifecycle events, and the permission-gating model — was developed with awareness of
patterns established in modern agentic coding systems, including Anthropic's Claude Code.
No source code was copied. These are general agentic loop patterns re-implemented in Python.

## DeFiHackLabs / SunWeb3Sec

The historical exploit corpus used for RAG retrieval was scraped from
[DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs). Each scraped record
stamps `"source": "DeFiHackLabs"`. See `scripts/scrape_exploits.py`.

## SCONE Benchmark

The benchmark suite referenced in `benchmarks/` is based on the
[SCONE](https://github.com/safety-research/SCONE) dataset from safety-research.
See `benchmarks/SCONE_README.md` for the upstream license and citation.

## Solodit

Historical audit findings used for RAG knowledge base construction were sourced from
[Solodit](https://solodit.xyz/). Critikal does not redistribute Solodit data directly.
