import re
import json
from typing import Any, Tuple

from src.agents.base_worker import WorkerAgent, WorkerTask, WorkerOutput
from src.models.finding import Finding
from src.agents.workers.test_writer_sandbox import SandboxManager
from src.agents.workers.test_writer_prompts import TEST_WRITER_SYSTEM_PROMPT


class TestWriterWorker(WorkerAgent):
    MAX_ATTEMPTS = 6

    def __init__(self, llm_client, graph=None):
        self.llm_client = llm_client
        self.graph = graph

    def get_worker_type(self) -> str:
        return "test-writer"

    def _extract_test_code(self, response: str) -> str:
        match = re.search(r"```(?:solidity|sol)\n(.*?)\n```", response, re.IGNORECASE | re.DOTALL)
        if match:
            return match.group(1).strip()
        match = re.search(r"```\n(.*?)\n```", response, re.DOTALL)
        if match:
            return match.group(1).strip()
        return response.strip()

    async def _compile_and_test(self, test_code: str) -> Tuple[bool, bool, str | None, str]:
        sandbox = SandboxManager()
        try:
            sandbox.setup_foundry_project()
            sandbox.write_test_file("test/ExploitTest.t.sol", test_code)
            
            build_res = sandbox.run("forge build")
            if not build_res.success:
                return False, False, f"Build Failed: {build_res.stderr or build_res.stdout}", ""
                
            test_res = sandbox.run("forge test --match-test test_exploit -vvv")
            test_logs = (test_res.stdout or "") + "\n" + (test_res.stderr or "")
            
            exploit_success = "[PASS]" in test_logs or "exploit succeeded" in test_logs.lower()
            return True, exploit_success, None, test_logs
        except Exception as e:
            return False, False, str(e), ""
        finally:
            sandbox.cleanup()

    def _build_prompt(self, finding: Finding, relevant_code: dict[str, str], error_history: list[str]) -> list[dict[str, str]]:
        code_snippets = "\n".join(
            [f"--- Snippet: {node_id} ---\n{code}" for node_id, code in relevant_code.items()]
        )

        error_context = ""
        if error_history:
            error_context = "Previous attempts failed. Fix these errors:\n" + "\n".join(error_history[-3:])

        user_content = (
            f"Vulnerability Class: {finding.vulnerability_class}\n"
            f"Hypothesis: {finding.hypothesis}\n"
            f"Attack Path: {' -> '.join(finding.attack_path)}\n\n"
            f"Relevant Code:\n{code_snippets}\n\n"
            f"{error_context}\n"
            "Generate a complete Foundry test that proves this vulnerability."
        )

        return [
            {"role": "system", "content": TEST_WRITER_SYSTEM_PROMPT},
            {"role": "user", "content": user_content}
        ]

    async def run(self, task: WorkerTask) -> WorkerOutput:
        finding = task.context.get("finding")

        # === FIX FOR LIST FROM COORDINATOR ===
        if isinstance(finding, list):
            print(f"[TestWriterWorker] Received {len(finding)} findings → using first one")
            finding = finding[0] if finding else None

        if not finding or not isinstance(finding, Finding):
            return WorkerOutput(
                worker_type=self.get_worker_type(),
                confidence=0,
                raw_output={"error": "Missing or invalid finding"}
            )

        relevant_code = task.context.get("relevant_code", {})
        attempts = 0
        error_history = []
        compiled = False
        exploit_success = False
        test_code_generated = None
        test_logs = ""

        while attempts < self.MAX_ATTEMPTS:
            attempts += 1
            prompt = self._build_prompt(finding, relevant_code, error_history)

            try:
                if hasattr(self.llm_client, "ainvoke"):
                    response = await self.llm_client.ainvoke(prompt)
                else:
                    response = self.llm_client.invoke(prompt)

                content = response.content if hasattr(response, "content") else str(response)
            
                if isinstance(content, list):
                    content = "".join([c.get("text", "") if isinstance(c, dict) else str(c) for c in content])
                
                test_code_generated = self._extract_test_code(content)

                if not test_code_generated:
                    error_history.append("No code returned by LLM")
                    continue

                compiled, exploit_success, test_error, logs = await self._compile_and_test(test_code_generated)
                test_logs = logs

                if compiled and exploit_success:
                    break

                if test_error:
                    error_history.append(test_error)
                else:
                    error_history.append("Test did not pass exploit check")

            except Exception as e:
                print(f"[TestWriterWorker] LLM call failed: {e}")
                error_history.append(str(e))

        # Confidence adjustment
        original_conf = getattr(finding, "confidence", 50)
        adjustment = 60 if (compiled and exploit_success) else 20 if compiled else -40
        final_confidence = max(0, min(100, original_conf + adjustment))

        return WorkerOutput(
            worker_type=self.get_worker_type(),
            task_id=task.task_id,
            confidence=final_confidence,
            raw_output={
                "compiled": compiled,
                "exploit_success": exploit_success,
                "test_code": test_code_generated,
                "test_logs": test_logs,
                "attempts": attempts,
                "last_error": error_history[-1] if error_history else None
            }
        )