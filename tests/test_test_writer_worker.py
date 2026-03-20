import pytest
import json
from unittest.mock import MagicMock

from src.agents.workers.test_writer_worker import TestWriterWorker
from src.agents.base_worker import WorkerTask
from src.models.finding import Finding, FindingStatus

@pytest.fixture
def mock_llm():
    """TestWriter uses sync invoke() via to_thread, not ainvoke()."""
    llm = MagicMock()
    return llm

@pytest.fixture
def dummy_finding():
    return Finding(
        id="f1",
        hotspot_node_id="Contract::vuln",
        vulnerability_class="custom_vuln",
        title="Test Finding",
        hypothesis="Hypothesis text",
        evidence_nodes=[],
        attack_path=["Contract::entry", "Contract::vuln"],
        status=FindingStatus.UNCONFIRMED,
        confidence=50,
        impact="High",
        severity_estimate="HIGH",
        affected_contract="Contract",
        affected_function="vuln"
    )

def test_extends_worker_agent(mock_llm):
    worker = TestWriterWorker(llm_client=mock_llm)
    assert worker.get_worker_type() == "test-writer"
    assert worker.MAX_ATTEMPTS == 6

@pytest.mark.asyncio
async def test_missing_finding_in_context(mock_llm):
    worker = TestWriterWorker(llm_client=mock_llm)
    task = WorkerTask(task_id="t1", task_type="test_write", context={})
    output = await worker.run(task)
    
    assert output.confidence == 0
    assert "error" in output.raw_output
    assert "Missing or invalid finding" in output.raw_output["error"]

@pytest.mark.asyncio
async def test_happy_path(mock_llm, dummy_finding, monkeypatch, tmp_path):
    mock_llm.invoke.return_value = MagicMock(content="```solidity\npragma solidity ^0.8.0; contract ExploitTest { function test_exploit() public {} }\n```")
    
    mock_sandbox = MagicMock()
    mock_sandbox.tmp_dir = tmp_path
    mock_sandbox.get_test_path.return_value = "test"
    # Single forge test call per attempt (compile + test combined)
    mock_sandbox.run.return_value = MagicMock(success=True, stdout="[PASS]", stderr="")
    monkeypatch.setattr("src.agents.workers.test_writer_worker.SandboxManager", lambda repo_path=None: mock_sandbox)
    
    worker = TestWriterWorker(llm_client=mock_llm)
    
    task = WorkerTask(
        task_id="t1", 
        task_type="test_write", 
        context={"finding": dummy_finding, "relevant_code": {}}
    )
    
    output = await worker.run(task)
    
    assert output.confidence == 100  # exploit success -> 50 + 60 = 110 clamp 100
    assert output.raw_output["compiled"] is True
    assert output.raw_output["exploit_success"] is True
    assert "function test_exploit()" in output.raw_output["test_code"]
    assert output.raw_output["attempts"] == 1
    assert output.raw_output["last_error"] is None

@pytest.mark.asyncio
async def test_compile_fail_then_succeed(mock_llm, dummy_finding, monkeypatch, tmp_path):
    # LLM will be called twice. Mock its responses.
    responses = [
        MagicMock(content="```solidity\npragma solidity ^0.8.0; contract ExploitTest { function test_exploit() public { invalid; } }\n```"),
        MagicMock(content="```solidity\npragma solidity ^0.8.0; contract ExploitTest { function test_exploit() public {} }\n```")
    ]
    mock_llm.invoke.side_effect = responses
    
    mock_sandbox = MagicMock()
    mock_sandbox.tmp_dir = tmp_path
    mock_sandbox.get_test_path.return_value = "test"
    # Single forge test call per attempt:
    mock_sandbox.run.side_effect = [
        MagicMock(success=False, stdout="Compiler run failed", stderr="Syntax error"), # attempt 1: compile error
        MagicMock(success=True, stdout="[PASS]", stderr="")  # attempt 2: success
    ]
    monkeypatch.setattr("src.agents.workers.test_writer_worker.SandboxManager", lambda repo_path=None: mock_sandbox)
    
    worker = TestWriterWorker(llm_client=mock_llm)
    
    task = WorkerTask(task_id="t1", task_type="test", context={"finding": dummy_finding})
    output = await worker.run(task)
    
    assert output.raw_output["attempts"] == 2
    assert "function test_exploit()" in output.raw_output["test_code"]
    assert output.raw_output["compiled"] is True
    assert output.raw_output["exploit_success"] is True
    assert output.confidence == 100 # Exploit success -> 100

@pytest.mark.asyncio
async def test_max_attempts_exceeded(mock_llm, dummy_finding, monkeypatch, tmp_path):
    mock_llm.invoke.return_value = MagicMock(content="```sol\npragma solidity ^0.8.0; contract ExploitTest { function test_exploit() public { invalid; } }\n```")
    
    mock_sandbox = MagicMock()
    mock_sandbox.tmp_dir = tmp_path
    mock_sandbox.get_test_path.return_value = "test"
    mock_sandbox.run.return_value = MagicMock(success=False, stdout="Compiler run failed", stderr="Compiler Error")
    monkeypatch.setattr("src.agents.workers.test_writer_worker.SandboxManager", lambda repo_path=None: mock_sandbox)
    
    worker = TestWriterWorker(llm_client=mock_llm)
    monkeypatch.setattr(worker, "_collect_repo_sources", lambda *a, **kw: {"Mock.sol": "contract Mock {}"})
    
    task = WorkerTask(task_id="t1", task_type="test", context={"finding": dummy_finding})
    output = await worker.run(task)
    
    assert output.raw_output["attempts"] == 6
    assert output.raw_output["compiled"] is False
    assert "Build Failed" in output.raw_output["last_error"]
    assert output.confidence == 40  # 50 - 10 = 40 (compile failure penalty)

@pytest.mark.asyncio
async def test_extract_code_fallback(mock_llm, dummy_finding, monkeypatch, tmp_path):
    # Attempt 1: chatter (rejected — no Solidity markers, no sandbox call)
    # Attempt 2: valid code but build fails
    # Attempt 3: valid code, build + test pass
    valid_code = "```\npragma solidity ^0.8.0; contract ExploitTest { function test_exploit() public {} }\n```"
    responses = [
        MagicMock(content="Wait what? I am not JSON"),
        MagicMock(content=valid_code),
        MagicMock(content=valid_code),
    ]
    mock_llm.invoke.side_effect = responses

    mock_sandbox = MagicMock()
    mock_sandbox.tmp_dir = tmp_path
    mock_sandbox.get_test_path.return_value = "test"
    # Single forge test call per attempt:
    mock_sandbox.run.side_effect = [
        MagicMock(success=False, stdout="Compiler run failed", stderr="Syntax error"),  # attempt 2 compile error
        MagicMock(success=True, stdout="[PASS]", stderr=""),  # attempt 3 success
    ]
    monkeypatch.setattr("src.agents.workers.test_writer_worker.SandboxManager", lambda repo_path=None: mock_sandbox)

    worker = TestWriterWorker(llm_client=mock_llm)
    monkeypatch.setattr(worker, "_collect_repo_sources", lambda *a, **kw: {"Mock.sol": "contract Mock {}"})

    task = WorkerTask(task_id="t1", task_type="test", context={"finding": dummy_finding})
    output = await worker.run(task)

    assert output.raw_output["attempts"] == 3
    assert output.raw_output["compiled"] is True
    assert "function test_exploit()" in output.raw_output["test_code"]
    assert output.confidence == 100

@pytest.mark.asyncio
async def test_exploit_fails_but_compiles(mock_llm, dummy_finding, monkeypatch, tmp_path):
    mock_llm.invoke.return_value = MagicMock(content="```solidity\npragma solidity ^0.8.0; contract ExploitTest { function test_exploit() public {} }\n```")
    
    mock_sandbox = MagicMock()
    mock_sandbox.tmp_dir = tmp_path
    mock_sandbox.get_test_path.return_value = "test"
    # Single forge test call per attempt — compiles but exploit fails
    mock_sandbox.run.return_value = MagicMock(success=False, stdout="FAIL: revert", stderr="Test failed: Assertion Error")
    monkeypatch.setattr("src.agents.workers.test_writer_worker.SandboxManager", lambda repo_path=None: mock_sandbox)
    
    worker = TestWriterWorker(llm_client=mock_llm)
    monkeypatch.setattr(worker, "_collect_repo_sources", lambda *a, **kw: {"Mock.sol": "contract Mock {}"})
    
    task = WorkerTask(task_id="t1", task_type="test", context={"finding": dummy_finding})
    output = await worker.run(task)
    
    assert output.raw_output["attempts"] == 6  # It will retry to fix it until max attempts
    assert output.raw_output["compiled"] is True
    assert output.raw_output["exploit_success"] is False
    assert "exploit check failed" in output.raw_output["last_error"]
    assert output.confidence == 50  # 50 + 0 = 50 (compiled but exploit not proven = no boost)

@pytest.mark.asyncio
async def test_missing_test_code_key(mock_llm, dummy_finding, monkeypatch, tmp_path):
    # LLM completely fails to provide it as markdown or anything
    mock_llm.invoke.return_value = MagicMock(content="")
    mock_sandbox = MagicMock()
    mock_sandbox.tmp_dir = tmp_path
    mock_sandbox.get_test_path.return_value = "test"
    monkeypatch.setattr("src.agents.workers.test_writer_worker.SandboxManager", lambda repo_path=None: mock_sandbox)

    worker = TestWriterWorker(llm_client=mock_llm)
    monkeypatch.setattr(worker, "_collect_repo_sources", lambda *a, **kw: {"Mock.sol": "contract Mock {}"})
    
    task = WorkerTask(task_id="t1", task_type="test", context={"finding": dummy_finding})
    output = await worker.run(task)
    
    assert output.raw_output["attempts"] == 6
    assert "No Solidity code returned by LLM" in output.raw_output["last_error"]

def test_extract_test_code_direct():
    worker = TestWriterWorker(llm_client=None)
    
    # 1. solidity case
    res1 = worker._extract_test_code("Here is the code:\n```solidity\ncontract A {}\n```")
    assert res1 == "contract A {}"
    
    # 2. sol case
    res2 = worker._extract_test_code("```sol\ncontract B {}\n```")
    assert res2 == "contract B {}"
    
    # 3. unmarked case
    res3 = worker._extract_test_code("```\ncontract C {}\n```")
    assert res3 == "contract C {}"
    
    # 4. full fallback
    res4 = worker._extract_test_code("contract D {}")
    assert res4 == "contract D {}"


def test_extract_test_code_rejects_chatter():
    worker = TestWriterWorker(llm_client=None)
    assert worker._extract_test_code("Wait what? I am not JSON") == ""


def test_has_exact_test_exploit():
    worker = TestWriterWorker(llm_client=None)
    assert worker._has_exact_test_exploit("function test_exploit() public {}")
    assert not worker._has_exact_test_exploit("function test_exploit_reentrancy() public {}")


@pytest.mark.asyncio
async def test_exit_code_takes_precedence_for_exploit_success(mock_llm, dummy_finding, monkeypatch, tmp_path):
    mock_llm.invoke.return_value = MagicMock(content="```solidity\npragma solidity ^0.8.0; contract ExploitTest { function test_exploit() public {} }\n```")
    mock_sandbox = MagicMock()
    mock_sandbox.tmp_dir = tmp_path
    mock_sandbox.get_test_path.return_value = "test"
    # Single forge test call: exit code False but [PASS] in logs — exit code should win
    mock_sandbox.run.return_value = MagicMock(success=False, stdout="[PASS]", stderr="")
    monkeypatch.setattr("src.agents.workers.test_writer_worker.SandboxManager", lambda repo_path=None: mock_sandbox)

    worker = TestWriterWorker(llm_client=mock_llm)
    output = await worker.run(WorkerTask(task_id="t_exit_code", task_type="test", context={"finding": dummy_finding}))
    assert output.raw_output["exploit_success"] is False


def test_fetch_rag_context_injects_into_prompt_when_rag_available(dummy_finding, monkeypatch):
    """RAG content appears in prompt when search_security_knowledge returns results."""
    mock_rag_results = [
        {"content": "Reentrancy exploit pattern: use vm.prank before external call.", "source": "audit.pdf"},
    ]

    def mock_search(query: str, k: int = 3):
        return mock_rag_results

    monkeypatch.setattr(
        "src.knowledge.rag_system.search_security_knowledge",
        mock_search,
    )

    worker = TestWriterWorker(llm_client=None)
    prompt = worker._build_prompt(
        dummy_finding,
        relevant_code={},
        error_history=[],
    )
    user_content = prompt[1]["content"]
    assert "SECURITY KNOWLEDGE" in user_content
    assert "Reentrancy exploit pattern" in user_content or "audit.pdf" in user_content


def test_fetch_rag_context_empty_when_rag_unavailable(dummy_finding, monkeypatch):
    """No RAG block when search returns empty."""
    monkeypatch.setattr(
        "src.knowledge.rag_system.search_security_knowledge",
        lambda q, k=3: [],
    )

    worker = TestWriterWorker(llm_client=None)
    rag = worker._fetch_rag_context(dummy_finding)
    assert rag == ""


# ── Remappings Parser ────────────────────────────────────────────

def test_parse_toml_remappings_inline_array():
    """Standard Foundry foundry.toml with remappings = [...] inline array."""
    toml = '''[profile.default]
src = "src"
out = "out"
libs = ["lib"]
remappings = [
    "controller/=lib/controller/src/",
    "forge-std/=lib/forge-std/src/",
    "solmate/=lib/solmate/src/",
]
test = "src/test"
'''
    result = TestWriterWorker._parse_toml_remappings(toml)
    assert result == {
        "controller/": "lib/controller/src/",
        "forge-std/": "lib/forge-std/src/",
        "solmate/": "lib/solmate/src/",
    }


def test_parse_toml_remappings_single_line():
    """All remappings on one line."""
    toml = 'remappings = ["a/=b/", "c/=d/"]'
    result = TestWriterWorker._parse_toml_remappings(toml)
    assert result == {"a/": "b/", "c/": "d/"}


def test_parse_toml_remappings_empty():
    """No remappings key at all."""
    toml = '[profile.default]\nsrc = "src"\n'
    result = TestWriterWorker._parse_toml_remappings(toml)
    assert result == {}


# ── Auto-Correct Imports ─────────────────────────────────────────

def test_auto_correct_imports_fixes_bad_path(tmp_path):
    """Bad import path is corrected to the actual file location in sandbox."""
    (tmp_path / "src" / "utils").mkdir(parents=True)
    (tmp_path / "src" / "utils" / "Errors.sol").write_text("library Errors {}")

    sandbox = MagicMock()
    sandbox.tmp_dir = tmp_path

    code = 'import "out/Errors.sol";'
    worker = TestWriterWorker(llm_client=None)
    result = worker._auto_correct_imports(code, sandbox, {})
    assert 'import "src/utils/Errors.sol";' in result


def test_auto_correct_imports_skips_valid_paths(tmp_path):
    """Already-valid import paths are left alone."""
    (tmp_path / "src" / "core").mkdir(parents=True)
    (tmp_path / "src" / "core" / "Token.sol").write_text("contract Token {}")

    sandbox = MagicMock()
    sandbox.tmp_dir = tmp_path

    code = 'import "src/core/Token.sol";'
    worker = TestWriterWorker(llm_client=None)
    result = worker._auto_correct_imports(code, sandbox, {})
    assert result == code


def test_auto_correct_imports_skips_remapped(tmp_path):
    """Remapped prefixes (forge-std/, solmate/) are not modified."""
    sandbox = MagicMock()
    sandbox.tmp_dir = tmp_path

    code = 'import "forge-std/Test.sol";\nimport "solmate/tokens/ERC20.sol";'
    remappings = {"forge-std/": "lib/forge-std/src/", "solmate/": "lib/solmate/src/"}
    worker = TestWriterWorker(llm_client=None)
    result = worker._auto_correct_imports(code, sandbox, remappings)
    assert result == code


def test_auto_correct_imports_no_match_leaves_unchanged(tmp_path):
    """If no matching file found in sandbox, the import is left as-is."""
    sandbox = MagicMock()
    sandbox.tmp_dir = tmp_path

    code = 'import "nonexistent/Foo.sol";'
    worker = TestWriterWorker(llm_client=None)
    result = worker._auto_correct_imports(code, sandbox, {})
    assert result == code


def test_auto_correct_imports_named_import_syntax(tmp_path):
    """Handles import {X} from 'path' syntax."""
    (tmp_path / "src" / "utils").mkdir(parents=True)
    (tmp_path / "src" / "utils" / "Helpers.sol").write_text("library Helpers {}")

    sandbox = MagicMock()
    sandbox.tmp_dir = tmp_path

    code = 'import {Helpers} from "wrong/Helpers.sol";'
    worker = TestWriterWorker(llm_client=None)
    result = worker._auto_correct_imports(code, sandbox, {})
    assert 'from "src/utils/Helpers.sol"' in result


def test_auto_correct_prefers_collected_paths(tmp_path):
    """When collected_paths is given, auto-correct should use those paths
    instead of the rglob fallback (avoids mapping to wrong file)."""
    # Both src/core/Registry.sol and src/tokens/utils/Registry.sol exist
    (tmp_path / "src" / "core").mkdir(parents=True)
    (tmp_path / "src" / "core" / "Registry.sol").write_text("contract Registry {}")
    (tmp_path / "src" / "tokens" / "utils").mkdir(parents=True)
    (tmp_path / "src" / "tokens" / "utils" / "Registry.sol").write_text("abstract contract Registry {}")

    sandbox = MagicMock()
    sandbox.tmp_dir = tmp_path

    code = 'import "out/Registry.sol";'
    worker = TestWriterWorker(llm_client=None)
    result = worker._auto_correct_imports(
        code, sandbox, {},
        collected_paths=["src/core/Registry.sol"],
    )
    assert 'import "src/core/Registry.sol";' in result


def test_auto_correct_is_file_not_dir(tmp_path):
    """candidate.is_file() should return False for directories like out/X.sol/
    so auto-correction still fires even when Foundry build artifacts exist."""
    (tmp_path / "out" / "Registry.sol").mkdir(parents=True)
    (tmp_path / "out" / "Registry.sol" / "Registry.json").write_text("{}")
    (tmp_path / "src" / "core").mkdir(parents=True)
    (tmp_path / "src" / "core" / "Registry.sol").write_text("contract Registry {}")

    sandbox = MagicMock()
    sandbox.tmp_dir = tmp_path

    code = 'import "out/Registry.sol";'
    worker = TestWriterWorker(llm_client=None)
    result = worker._auto_correct_imports(code, sandbox, {})
    assert 'import "src/core/Registry.sol";' in result


def test_auto_correct_collected_paths_avoids_duplicate(tmp_path):
    """When the LLM writes out/ERC20.sol and both src/tokens/utils/ERC20.sol
    and lib/solmate/src/tokens/ERC20.sol exist, collected_paths should steer
    toward the correct one (e.g. NOT the local copy that would clash)."""
    (tmp_path / "src" / "tokens" / "utils").mkdir(parents=True)
    (tmp_path / "src" / "tokens" / "utils" / "ERC20.sol").write_text("abstract contract ERC20 {}")
    (tmp_path / "lib" / "solmate" / "src" / "tokens").mkdir(parents=True)
    (tmp_path / "lib" / "solmate" / "src" / "tokens" / "ERC20.sol").write_text("abstract contract ERC20 {}")

    sandbox = MagicMock()
    sandbox.tmp_dir = tmp_path

    code = 'import "out/ERC20.sol";'
    worker = TestWriterWorker(llm_client=None)
    # Collected paths only contain the local one we actually traversed
    result = worker._auto_correct_imports(
        code, sandbox, {"solmate/": "lib/solmate/src/"},
        collected_paths=["src/tokens/utils/ERC20.sol"],
    )
    assert 'import "src/tokens/utils/ERC20.sol";' in result


# ── Import Cheat Sheet ──────────────────────────────────────────

def test_generate_import_cheatsheet():
    """Cheat sheet includes forge-std, local sources, and lib imports."""
    worker = TestWriterWorker(llm_client=None)
    sources = {
        "src/core/AccountManager.sol": "...",
        "src/utils/Errors.sol": "...",
    }
    lib_imports = {"controller/core/IControllerFacade.sol", "solmate/tokens/ERC20.sol"}

    sheet = worker._generate_import_cheatsheet(sources, lib_imports)

    assert 'import "forge-std/Test.sol";' in sheet
    assert 'import "src/core/AccountManager.sol";' in sheet
    assert 'import "src/utils/Errors.sol";' in sheet
    assert 'import "controller/core/IControllerFacade.sol";' in sheet
    assert 'import "solmate/tokens/ERC20.sol";' in sheet


def test_generate_import_cheatsheet_no_duplicates():
    """forge-std/Test.sol should not appear twice."""
    worker = TestWriterWorker(llm_client=None)
    sources = {"src/core/A.sol": "..."}
    sheet = worker._generate_import_cheatsheet(sources, None)
    assert sheet.count('forge-std/Test.sol') == 1


# ── Cache Clearing ───────────────────────────────────────────────

def test_clear_forge_cache(tmp_path):
    """Verifies that _clear_forge_cache removes out/ and cache/ directories."""
    worker = TestWriterWorker(llm_client=None)
    sandbox = MagicMock()
    sandbox.tmp_dir = tmp_path

    out_dir = tmp_path / "out"
    cache_dir = tmp_path / "cache"

    out_dir.mkdir()
    (out_dir / "test.json").write_text("{}")

    cache_dir.mkdir()
    (cache_dir / "test.json").write_text("{}")

    assert out_dir.exists()
    assert cache_dir.exists()

    worker._clear_forge_cache(sandbox)

    assert not out_dir.exists()
    assert not cache_dir.exists()


# ── Problem 1: Anchored contract-definition matching ──────────────

def test_collect_repo_sources_exact_match(tmp_path):
    """
    _collect_repo_sources must pick the file that DEFINES 'contract Pool'
    not a file that merely mentions 'Pool' in a comment or base-contract list.
    """
    # File that only *mentions* Pool (e.g. a registry that imports it)
    mention_file = tmp_path / "src" / "PoolAddressesProviderRegistry.sol"
    mention_file.parent.mkdir(parents=True)
    mention_file.write_text(
        "// SPDX-License-Identifier: MIT\n"
        "pragma solidity ^0.8.10;\n"
        "// Manages Pool addresses\n"
        "contract PoolAddressesProviderRegistry {\n"
        "    address public pool;\n"
        "}\n"
    )

    # File that actually DEFINES 'contract Pool'
    define_file = tmp_path / "src" / "protocol" / "pool" / "Pool.sol"
    define_file.parent.mkdir(parents=True, exist_ok=True)
    define_file.write_text(
        "// SPDX-License-Identifier: MIT\n"
        "pragma solidity ^0.8.10;\n"
        "contract Pool {\n"
        "    function setReserveInterestRateStrategyAddress() external {}\n"
        "}\n"
    )

    finding = Finding(
        id="f1",
        hotspot_node_id="Pool::setReserveInterestRateStrategyAddress",
        vulnerability_class="access-control",
        title="T",
        hypothesis="H",
        evidence_nodes=[],
        attack_path=[],
        status=FindingStatus.UNCONFIRMED,
        confidence=80,
        impact="High",
        severity_estimate="HIGH",
        affected_contract="Pool",
        affected_function="setReserveInterestRateStrategyAddress",
    )

    worker = TestWriterWorker(llm_client=None)
    sources = worker._collect_repo_sources(finding, str(tmp_path), remappings={})

    assert sources, "Should have found at least one source file"
    collected_paths = list(sources.keys())
    # The defining file must be the first entry; the registry must NOT be present
    assert any("Pool.sol" in p for p in collected_paths), (
        f"Expected Pool.sol in collected sources, got: {collected_paths}"
    )
    assert not any("PoolAddressesProviderRegistry" in p for p in collected_paths), (
        f"Registry file should NOT be collected; got: {collected_paths}"
    )


# ── Problem 2A: Error history deduplication ───────────────────────

@pytest.mark.asyncio
async def test_error_history_dedup_on_repeated_missing_test_exploit(
    mock_llm, dummy_finding, monkeypatch, tmp_path
):
    """
    When test_exploit() is missing on two consecutive attempts the error_history
    should REPLACE the last entry, not grow to length 2.
    """
    # LLM returns code without test_exploit on first two calls,
    # then valid code on the third.
    no_test_code = (
        "```solidity\n"
        "pragma solidity ^0.8.0;\n"
        "interface ITarget { function foo() external; }\n"
        "```"
    )
    valid_code = (
        "```solidity\n"
        "pragma solidity ^0.8.0;\n"
        "import \"forge-std/Test.sol\";\n"
        "contract ExploitTest is Test {\n"
        "    function setUp() public {}\n"
        "    function test_exploit() public {}\n"
        "}\n"
        "```"
    )
    mock_llm.invoke.side_effect = [
        MagicMock(content=no_test_code),
        MagicMock(content=no_test_code),
        MagicMock(content=valid_code),
    ]

    mock_sandbox = MagicMock()
    mock_sandbox.tmp_dir = tmp_path
    mock_sandbox.get_test_path.return_value = "test"
    # Only called after test_exploit() IS present (third attempt)
    mock_sandbox.run.return_value = MagicMock(success=True, stdout="[PASS]", stderr="")
    monkeypatch.setattr(
        "src.agents.workers.test_writer_worker.SandboxManager",
        lambda repo_path=None: mock_sandbox,
    )

    worker = TestWriterWorker(llm_client=mock_llm)
    # Return a non-empty source so the worker enters standard mode (MAX_ATTEMPTS=6)
    # Empty sources triggers MOCK mode which caps at 2 attempts — not enough for this test.
    _fake_src = {"src/Contract.sol": "pragma solidity ^0.8.0; contract Contract {}"}
    monkeypatch.setattr(worker, "_collect_repo_sources", lambda *a, **kw: _fake_src)
    monkeypatch.setattr(worker, "_collect_minimal_sources", lambda *a, **kw: _fake_src)
    monkeypatch.setattr(worker, "_fetch_rag_context", lambda *a, **kw: "")
    monkeypatch.setattr(worker, "_fetch_error_rag_context", lambda *a, **kw: "")

    task = WorkerTask(
        task_id="t_dedup",
        task_type="test_write",
        context={"finding": dummy_finding, "relevant_code": {}},
    )
    output = await worker.run(task)

    assert output.raw_output["attempts"] == 3
    assert output.raw_output["exploit_success"] is True


# ── Problem 2B: Minimal prompt activates after 2 consecutive misses ──

def test_build_minimal_prompt_structure(dummy_finding):
    """
    _build_minimal_prompt returns a 2-message list with a system + user role.
    The user message must contain the contract name and 'test_exploit'.
    """
    worker = TestWriterWorker(llm_client=None)
    jury_brief = {
        "what_to_prove": "setReserveInterestRateStrategyAddress is callable by anyone",
        "attack_steps": ["Call setReserveInterestRateStrategyAddress directly"],
        "what_success_looks_like": "call succeeds without revert",
    }
    source = "contract Pool { function setReserveInterestRateStrategyAddress() external {} }"

    messages = worker._build_minimal_prompt(dummy_finding, source, jury_brief)

    assert len(messages) == 2
    assert messages[0]["role"] == "system"
    assert messages[1]["role"] == "user"
    system_text = messages[0]["content"]
    user_text = messages[1]["content"]
    # Must insist on test_exploit()
    assert "test_exploit" in system_text
    # Must include the what_to_prove directive
    assert "setReserveInterestRateStrategyAddress is callable by anyone" in user_text
    # Must include the source code
    assert "contract Pool" in user_text


@pytest.mark.asyncio
async def test_minimal_prompt_activates_after_2_misses(
    mock_llm, dummy_finding, monkeypatch, tmp_path
):
    """
    After 2 consecutive test_exploit() missing failures, use_minimal_prompt
    is set to True and _build_minimal_prompt() is called on the third attempt.
    """
    no_test_code = (
        "```solidity\n"
        "pragma solidity ^0.8.0;\n"
        "interface IFoo { function bar() external; }\n"
        "```"
    )
    valid_code = (
        "```solidity\n"
        "pragma solidity ^0.8.0;\n"
        "import \"forge-std/Test.sol\";\n"
        "contract ExploitTest is Test {\n"
        "    function setUp() public {}\n"
        "    function test_exploit() public {}\n"
        "}\n"
        "```"
    )
    mock_llm.invoke.side_effect = [
        MagicMock(content=no_test_code),  # attempt 1: miss #1
        MagicMock(content=no_test_code),  # attempt 2: miss #2 → triggers minimal
        MagicMock(content=valid_code),    # attempt 3: minimal prompt, valid response
    ]

    mock_sandbox = MagicMock()
    mock_sandbox.tmp_dir = tmp_path
    mock_sandbox.get_test_path.return_value = "test"
    mock_sandbox.run.return_value = MagicMock(success=True, stdout="[PASS]", stderr="")
    monkeypatch.setattr(
        "src.agents.workers.test_writer_worker.SandboxManager",
        lambda repo_path=None: mock_sandbox,
    )

    minimal_prompt_calls: list[dict] = []
    worker = TestWriterWorker(llm_client=mock_llm)

    # Patch _build_minimal_prompt to record calls while still delegating
    _orig = worker._build_minimal_prompt
    def _recording_minimal_prompt(finding, source_code, jury_brief):
        result = _orig(finding, source_code, jury_brief)
        minimal_prompt_calls.append({"source_code": source_code, "result": result})
        return result
    monkeypatch.setattr(worker, "_build_minimal_prompt", _recording_minimal_prompt)

    # Return a non-empty source so the worker enters standard mode (MAX_ATTEMPTS=6)
    # Empty sources triggers MOCK mode which caps at 2 attempts — not enough for this test.
    _fake_src = {"src/Contract.sol": "pragma solidity ^0.8.0; contract Contract {}"}
    monkeypatch.setattr(worker, "_collect_repo_sources", lambda *a, **kw: _fake_src)
    monkeypatch.setattr(worker, "_collect_minimal_sources", lambda *a, **kw: _fake_src)
    monkeypatch.setattr(worker, "_fetch_rag_context", lambda *a, **kw: "")
    monkeypatch.setattr(worker, "_fetch_error_rag_context", lambda *a, **kw: "")

    task = WorkerTask(
        task_id="t_minimal",
        task_type="test_write",
        context={"finding": dummy_finding, "relevant_code": {}},
    )
    output = await worker.run(task)

    assert output.raw_output["attempts"] == 3
    assert output.raw_output["exploit_success"] is True
    # _build_minimal_prompt must have been called exactly once (on attempt 3)
    assert len(minimal_prompt_calls) == 1, (
        f"Expected _build_minimal_prompt called once, got {len(minimal_prompt_calls)}"
    )
