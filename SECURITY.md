# Security Policy

## Reporting a Vulnerability

Critikal is an offensive security research tool. If you find a vulnerability
**in Critikal itself** (not in the targets it audits), please report it
privately.

- **Preferred:** open a [GitHub security advisory](https://github.com/Tushar-Pandey-31/critikal/security/advisories/new).
- **Alternative:** email the maintainers (see `pyproject.toml` authors field).

Please include:
- A description of the issue and its impact.
- Steps to reproduce (or a PoC if possible).
- The Critikal version / commit you tested.
- Whether the issue affects a user's host (e.g., sandbox escape, credential
  exfiltration from `.env`) or only the quality of findings.

We aim to acknowledge reports within 72 hours and ship a fix or mitigation
within 30 days for high-impact issues. Please do not file public issues or
pull requests for undisclosed vulnerabilities.

## Scope

In scope:
- Sandbox escapes from the `bash`, `sandbox_run`, or `deploy_contract` tools.
- Path traversal or arbitrary file write via `file_write` / `file_edit`.
- Credential leakage in logs, reports, or tool output.
- Prompt-injection vectors that cause Critikal to exfiltrate secrets or run
  unintended destructive shell commands against the host.
- Dependency vulnerabilities in pinned runtime deps.

Out of scope:
- False positives / false negatives in audit findings — file a normal issue.
- Issues in the target repositories Critikal analyzes.
- Model-provider downtime or API errors.

## Safe Usage

Critikal executes LLM-generated shell commands and Foundry tests. Run it in
a container or a throwaway VM when analysing code you don't trust. Never
point it at production credentials, private keys, or mainnet RPC URLs that
can sign transactions.
