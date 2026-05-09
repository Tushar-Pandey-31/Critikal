"""
Fuzz Generator Worker — Constructs property-based invariant tests
using Foundry for highly critical findings.
"""

from __future__ import annotations

import asyncio
import logging
import re

from src.models.finding import Finding
from src.pipeline.base_worker import WorkerAgent, WorkerOutput, WorkerTask
from src.pipeline.workers.test_writer_sandbox import SandboxManager

logger = logging.getLogger(__name__)


class FuzzGeneratorWorker(WorkerAgent):
    """
    Generates Foundry invariant tests to fuzz-prove edge cases
    around identified critical vulnerabilities.
    """

    MAX_ATTEMPTS = 3
    LLM_TIMEOUT = 300

    def __init__(self, llm_client, graph=None):
        self.llm_client = llm_client
        self.graph = graph

    def get_worker_type(self) -> str:
        return "fuzz-generator"

    async def run(self, task: WorkerTask) -> WorkerOutput:
        finding: Finding | None = task.context.get("finding")
        if not finding:
            return WorkerOutput(
                worker_type=self.get_worker_type(), confidence=0, raw_output={"error": "Missing finding in context"}
            )

        poc_code = task.context.get("poc_code", "")
        repo_path = task.context.get("repo_path")
        sandbox = task.context.get("sandbox", SandboxManager(repo_path=repo_path))

        # Grab source code for context
        real_sources = self._collect_repo_sources(repo_path, finding) if repo_path else {}

        last_error = ""
        attempts = 0
        error_history = []

        print(f"\n  [Fuzzer] === START === {finding.hotspot_node_id}")
        print(f"  [Fuzzer] Vulnerability: {finding.vulnerability_class}")

        while attempts < self.MAX_ATTEMPTS:
            attempts += 1
            print(f"  [Fuzzer] ── Attempt {attempts}/{self.MAX_ATTEMPTS} ──")

            prompt = self._build_prompt(finding, poc_code, real_sources, error_history)

            try:
                response = await asyncio.wait_for(
                    asyncio.to_thread(self.llm_client.invoke, prompt), timeout=self.LLM_TIMEOUT
                )
                content = response.content if hasattr(response, "content") else str(response)

                fuzz_code = self._extract_code(content)
                if not fuzz_code:
                    error_history.append("Failed to extract valid Solidity block from LLM.")
                    continue

                # Write and execute invariant test
                test_path = sandbox.get_test_path()
                fuzz_dest = f"{test_path.parent}/FuzzTest.t.sol"
                sandbox.write_test_file(fuzz_dest, fuzz_code)
                print(f"  [Fuzzer] Wrote test file: {fuzz_dest}")

                # We specifically match invariant_ tests
                build_res = sandbox.run_forge_build()
                if not build_res.success:
                    print("  [Fuzzer] Build failed")
                    error_history.append(f"Compile Error:\n{build_res.logs[:1000]}")
                    continue

                test_res = sandbox.run("forge test --match-test invariant_ -vvv")
                if test_res.success:
                    print("  [Fuzzer] Invariant test passed! (No violation found)")
                    return WorkerOutput(
                        worker_type=self.get_worker_type(),
                        confidence=finding.confidence,
                        hypothesis=finding.hypothesis,
                        evidence_node_ids=[e.node_id for e in finding.evidence_nodes],
                        attack_path=finding.attack_path,
                        raw_output={
                            "fuzz_code": fuzz_code,
                            "compiled": True,
                            "violation_found": False,
                            "attempts": attempts,
                            "logs": test_res.logs,
                        },
                    )
                else:
                    print("  [Fuzzer] INVARIANT BROKEN! Fuzzing successful.")
                    # A broken invariant is a successful fuzz test for a bug!
                    # Boost confidence since we proved it with fuzzing
                    boosted_conf = min(100, finding.confidence + 20)
                    return WorkerOutput(
                        worker_type=self.get_worker_type(),
                        confidence=boosted_conf,
                        hypothesis=finding.hypothesis,
                        evidence_node_ids=[e.node_id for e in finding.evidence_nodes],
                        attack_path=finding.attack_path,
                        raw_output={
                            "fuzz_code": fuzz_code,
                            "compiled": True,
                            "violation_found": True,
                            "attempts": attempts,
                            "logs": test_res.logs,
                        },
                    )

            except Exception as e:
                logger.error(f"[Fuzzer] LLM or execution error: {e}")
                error_history.append(f"Exception: {e}")

        # If we exit the loop, we failed to fuzz
        print(f"  [Fuzzer] Failed to generate working fuzz test after {self.MAX_ATTEMPTS} attempts.")
        return WorkerOutput(
            worker_type=self.get_worker_type(),
            confidence=finding.confidence,  # Unchanged
            hypothesis=finding.hypothesis,
            evidence_node_ids=[e.node_id for e in finding.evidence_nodes],
            attack_path=finding.attack_path,
            raw_output={
                "fuzz_code": None,
                "compiled": False,
                "violation_found": False,
                "attempts": attempts,
                "logs": last_error,
            },
        )

    def _build_prompt(self, finding: Finding, poc_code: str, sources: dict[str, str], errors: list[str]) -> list[dict]:
        sys_msg = (
            "You are Critikal's elite Fuzzing & Invariant Testing Engine.\n"
            "Your job is to write a Foundry stateless invariant test (Handler-based) or standard stateful fuzz test "
            "to demonstrate that a critical vulnerability exists.\n\n"
            "INVARIANT TEMPLATE GUIDELINES:\n"
            "- Vault/DeFi: assert(totalShares * sharePrice >= totalAssets)\n"
            "- Token Supply: assert(totalSupply() <= MAX_SUPPLY)\n"
            "- Access Control: assert(owner() == expectedOwner)\n"
            "- Balance Accounting: assert(sum(balances) == address(this).balance)\n\n"
            "Return ONLY valid standard Solidity code enclosed in ```solidity ... ```. Define any interfaces you need inline. "
            "Do NOT import anything except forge-std/Test.sol."
        )

        user_msg = f"Target Contract: {finding.affected_contract}\nTarget Function: {finding.affected_function}\n"
        user_msg += f"Vulnerability Class: {finding.vulnerability_class}\n"
        user_msg += f"Hypothesis:\n{finding.hypothesis}\n\n"

        if poc_code:
            user_msg += f"Existing PoC Exploit for reference:\n```solidity\n{poc_code}\n```\n\n"

        if sources:
            user_msg += "TARGET SOURCE CODE:\n====================\n"
            for f, c in sources.items():
                user_msg += f"--- {f} ---\n{c}\n\n"

        if errors:
            user_msg += "PREVIOUS ATTEMPT ERRORS:\n====================\n"
            for e in errors:
                user_msg += f"{e}\n---\n"

        user_msg += "Write a complete Foundry test contract named `FuzzTest` inheriting from `Test` with an `invariant_...` or `testFuzz_...` function."

        return [{"role": "system", "content": sys_msg}, {"role": "user", "content": user_msg}]

    def _extract_code(self, text: str) -> str:
        match = re.search(r"```(?:solidity|sol)(.*?)```", text, re.DOTALL | re.IGNORECASE)
        if match:
            return match.group(1).strip()

        if "pragma solidity" in text:
            return text.strip()
        return ""

    def _collect_repo_sources(self, repo_path: str | None, finding: Finding) -> dict[str, str]:
        if not repo_path:
            return {}

        from pathlib import Path

        src = {}
        target_name = finding.affected_contract

        if not target_name:
            return src

        p = Path(repo_path)
        for f in p.rglob("*.sol"):
            if "test" in str(f).lower() or "mock" in str(f).lower() or "lib/" in str(f).lower():
                continue
            if target_name.lower() in f.name.lower():
                try:
                    src[f.name] = f.read_text(encoding="utf-8")
                except Exception:
                    pass
        return src
