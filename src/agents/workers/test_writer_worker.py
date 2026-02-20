import re
from typing import Any, Tuple

from src.agents.base_worker import WorkerAgent, WorkerTask, WorkerOutput
from src.models.finding import Finding
from src.agents.workers.test_writer_sandbox import SandboxManager
from src.agents.workers.test_writer_prompts import TEST_WRITER_SYSTEM_PROMPT


class TestWriterWorker(WorkerAgent):
    """
    Worker responsible for generating, compiling, and running exploit tests
    to prove or disprove a given vulnerability hypothesis.
    """

    MAX_ATTEMPTS = 6

    def __init__(self, llm_client, graph=None):
        """
        Args:
            llm_client: The LangChain LLM client.
            graph: Optional graph instance (not strictly needed, but accepted for interface compatibility).
        """
        self.llm_client = llm_client
        self.graph = graph

    def get_worker_type(self) -> str:
        return "test-writer"

    def _extract_test_code(self, response: str) -> str:
        """Robustly parse markdown blocks looking for ```solidity"""
        match = re.search(r"```(?:solidity|sol)\n(.*?)\n```", response, re.IGNORECASE | re.DOTALL)
        if match:
            return match.group(1).strip()
        # Fallback if no language specified
        match = re.search(r"```\n(.*?)\n```", response, re.DOTALL)
        if match:
            return match.group(1).strip()
        return response.strip()

    async def _compile_and_test(self, test_code: str) -> Tuple[bool, bool, str | None]:
        """
        Compiles and tests execution within a sandboxed Foundry environment.
        Returns:
            (compiled: bool, exploit_success: bool, error_message: str | None)
        """
        sandbox = SandboxManager()
        try:
            sandbox.setup_foundry_project()
            sandbox.write_test_file("test/ExploitTest.t.sol", test_code)
            
            build_res = sandbox.run("forge build")
            if not build_res.success:
                return False, False, f"Build Failed:\n{build_res.stderr or build_res.stdout}"
                
            test_res = sandbox.run("forge test --match-test test_exploit -vvv")
            if not test_res.success:
                return True, False, f"Test Failed:\n{test_res.stderr or test_res.stdout}"
                
            return True, True, None
        except Exception as e:
            return False, False, f"Sandbox error: {str(e)}"
        finally:
            sandbox.cleanup()

    def _build_prompt(self, finding: Finding, relevant_code: dict[str, str], error_history: list[str]) -> list[dict[str, str]]:
        code_snippets = "\n".join(
            [f"--- Snippet: {node_id} ---\n{code}" for node_id, code in relevant_code.items()]
        )

        error_context = ""
        if error_history:
            error_context = "CRITICAL: Previous attempts failed with the following errors. You MUST fix these:\n"
            for i, err in enumerate(error_history):
                # Ensure we don't blow up context size if errors are massive
                truncated_err = err[:1000] + ("..." if len(err) > 1000 else "")
                error_context += f"Attempt {i+1} Error:\n{truncated_err}\n"
            error_context += "\n"

        user_content = (
            f"Vulnerability Class: {finding.vulnerability_class}\n"
            f"Hypothesis: {finding.hypothesis}\n"
            f"Attack Path: {' -> '.join(finding.attack_path)}\n\n"
            f"Relevant Code:\n{code_snippets}\n\n"
            f"{error_context}"
            "Generate the test_code to prove this vulnerability."
        )

        return [
            {"role": "system", "content": TEST_WRITER_SYSTEM_PROMPT},
            {"role": "user", "content": user_content}
        ]

    async def run(self, task: WorkerTask) -> WorkerOutput:
        """
        Executes the Test Writer loop.
        """
        finding = task.context.get("finding")
        relevant_code = task.context.get("relevant_code", {})
        
        if not finding or not isinstance(finding, Finding):
            return WorkerOutput(
                worker_type=self.get_worker_type(),
                confidence=0,
                raw_output={"error": "Missing or invalid 'finding' in task context"}
            )

        attempts = 0
        last_error = None
        compiled = False
        exploit_success = False
        test_code_generated = None

        error_history = []

        while attempts < self.MAX_ATTEMPTS:
            attempts += 1
            
            prompt = self._build_prompt(finding, relevant_code, error_history)
            
            try:
                # Assuming ainovke works similarly to other workers (e.g., AttackHypothesisWorker)
                if hasattr(self.llm_client, "ainvoke"):
                    response = await self.llm_client.ainvoke(prompt)
                else:
                    response = self.llm_client.invoke(prompt)

                content = response.content
                test_code_generated = self._extract_test_code(content)
                
                if not test_code_generated:
                    last_error = "LLM did not return any code."
                    error_history.append(last_error)
                    continue

                # Try to compile and test
                compiled, exp_success, test_error = await self._compile_and_test(test_code_generated)
                exploit_success = exp_success
                
                if not compiled or not exploit_success:
                    last_error = test_error or "Compilation or exploit failed without specific error"
                    error_history.append(last_error)
                    continue
                
                # If we get here, it compiled and succeeded
                last_error = None
                break

            except Exception as e:
                last_error = f"Unexpected execution error: {str(e)}"
                error_history.append(last_error)
                continue

        # Clamp confidence sum to 0-100
        original_conf = finding.confidence
        if exploit_success:
            final_confidence = 100
        else:
            final_confidence = original_conf

        return WorkerOutput(
            worker_type=self.get_worker_type(),
            confidence=final_confidence,
            raw_output={
                "compiled": compiled,
                "exploit_success": exploit_success,
                "test_code": test_code_generated,
                "attempts": attempts,
                "last_error": last_error
            }
        )
