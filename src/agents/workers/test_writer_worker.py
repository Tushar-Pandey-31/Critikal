import asyncio
import os
import re
import logging
import shutil
import time
from pathlib import Path

logger = logging.getLogger(__name__)

from src.agents.base_worker import WorkerAgent, WorkerTask, WorkerOutput
from src.models.finding import Finding
from src.agents.workers.test_writer_sandbox import SandboxManager
from src.agents.workers.test_writer_prompts import (
    TEST_WRITER_SYSTEM_PROMPT,
    TEST_WRITER_REAL_SOURCE_SYSTEM_PROMPT,
    BRIDGE_MODE_SYSTEM_PROMPT,
)
from src.agents.workers.bridge_interface_generator import (
    generate_bridge_interfaces,
    resolve_deploy_code_path,
)

# ── Error taxonomy for targeted fix prompts ─────────────────────────────────

_ERROR_RULES: list[tuple[str, str]] = [
    (
        r"7006|Cannot set option.*value.*non-payable",
        "PAYABLE FIX (Error 7006): You called a function with {value: X} but the interface "
        "function is not marked `payable`.\n"
        "The BridgeInterfaces.sol stub is missing `payable`. Do NOT import BridgeInterfaces.sol.\n"
        "Fix: Define your OWN inline interface in your test file with `payable` on every "
        "function that sends or receives ETH:\n\n"
        "  WRONG (causes 7006):\n"
        "    interface ITarget {\n"
        "        function myFunc() external;\n"
        "    }\n\n"
        "  CORRECT:\n"
        "    interface ITarget {\n"
        "        function myFunc() external payable;\n"
        "    }\n\n"
        "Rule: ANY function you call with {value: X} MUST be `external payable` in the interface.\n"
        "Do NOT import BridgeInterfaces.sol — define this interface yourself inline.",
    ),
    (
        r"9553",
        "CAST FIX (Error 9553): You passed a contract-typed variable where `address` is expected.\n"
        "Fix: Wrap every contract argument with explicit cast: `func(myContract)` → `func(address(myContract))`.\n"
        "This applies to ALL function calls, not just one.",
    ),
    (
        r"3656",
        "ABSTRACT FIX (Error 3656): You are implementing an interface that has functions you didn't define, "
        "OR you marked a contract abstract that Solidity 0.5.x doesn't support.\n"
        "Fix: DO NOT inherit from ComptrollerInterface, InterestRateModel, or any large interface.\n"
        "Write a minimal STANDALONE mock contract with only the 3-4 functions actually called in your test:\n"
        "  contract MockComptroller {\n"
        "      bool public constant isComptroller = true;\n"
        "      function mintAllowed(address,address,uint256) external returns (uint256) { return 0; }\n"
        "  }",
    ),
    (
        r"incompatible versions|Found incompatible",
        "BRIDGE VIOLATION (incompatible versions): You imported a legacy .sol file directly into your test.\n"
        "Fix: REMOVE ALL imports from contracts/ or src/. Use ONLY:\n"
        "  import \"forge-std/Test.sol\";\n"
        "  import \"./BridgeInterfaces.sol\";\n"
        "Deploy legacy contracts via deployCode(), NOT import. This is mandatory in bridge mode.",
    ),
    (
        r"Identifier already declared|2333",
        "DUPLICATE IDENTIFIER FIX (Error 2333): You have a duplicate identifier in AttackContract.sol.\n\n"
        "MOST COMMON CAUSE: You declared `bool public exploitSucceeded` (which auto-creates a getter)\n"
        "AND ALSO wrote `function exploitSucceeded()`. Remove the function — the public variable\n"
        "is sufficient. `bool public exploitSucceeded;` already provides `exploitSucceeded()` as a getter.\n\n"
        "OTHER CAUSE: You defined the same interface or contract name TWICE in your file.\n"
        "Fix: Define each interface EXACTLY ONCE, at the top of the file, before AttackContract.\n\n"
        "CORRECT structure:\n"
        "  pragma solidity ^0.8.0;\n"
        "  interface ITarget {            ← define ONCE here\n"
        "      function myFunc() external payable;\n"
        "  }\n"
        "  contract AttackContract {      ← then the contract\n"
        "      bool public exploitSucceeded;  ← NO explicit function for this\n"
        "      ITarget target;\n"
        "      ...\n"
        "  }                              ← NO second interface or function exploitSucceeded()\n"
    ),
    (
        r"uint256\(.*address\)|explicit type conversion.*address.*uint256",
        "CAST FIX (address→uint256): In Solidity 0.8+, address cannot cast directly to uint256.\n"
        "Fix: Use two-step cast: `uint256(uint160(someAddress))` instead of `uint256(someAddress)`.",
    ),
    (
        r"Member.*not found.*after argument-dependent|9582",
        "INTERFACE FIX (Error 9582): A function you are calling does not exist on the interface.\n"
        "Fix: Define the missing function signature INLINE in your test file. Do not rely on BridgeInterfaces.sol "
        "for functions it doesn't have — add them yourself:\n"
        "  interface IMyContract {\n"
        "      function missingFunction(...) external returns (...);\n"
        "  }",
    ),
    (
        r"Declaration.*not found|Undeclared identifier|7920",
        "DECLARATION FIX: A variable, function, or type is used but not declared.\n"
        "Fix: Check that all variables are declared before use, all interfaces are defined, "
        "and all imported contracts actually export the name you are using.",
    ),
    (
        r"Function.*not found in.*BridgeInterfaces|not found.*BridgeInterfaces",
        "BRIDGE INTERFACE FIX: BridgeInterfaces.sol is missing a function you need.\n"
        "Fix: Do NOT import BridgeInterfaces.sol at all. Define ALL interfaces you need "
        "INLINE in your test file with pragma ^0.8.0. Only import forge-std/Test.sol.",
    ),
    (
        r"contract.*should be marked as abstract|4614|cannot be instantiated",
        "ABSTRACT CONTRACT FIX (Error 4614): You are calling `new X()` on an abstract contract.\n"
        "Fix: Write a minimal CONCRETE subclass at file level before ExploitTest:\n"
        "  contract ConcreteX is AbstractX {\n"
        "      // implement all required functions\n"
        "  }\n"
        "Then deploy ConcreteX, not AbstractX.",
    ),
]

_GUARD_PATTERNS: list[str] = [
    "market may only be initialized once",
    "only admin may initialize",
    "already initialized",
    "Initializable: contract is already initialized",
    "contract is already initialized",
    "has already been initialized",
    "initialization function",
]

# Solidity patterns that indicate a time-lock guard on withdraw/collect
_TIMELOCK_PATTERNS: list[re.Pattern] = [
    re.compile(r'\bunlockTime\b', re.IGNORECASE),
    re.compile(r'\blockTime\b', re.IGNORECASE),
    re.compile(r'\block_time\b', re.IGNORECASE),
    re.compile(r'now\s*[><=]+\s*\w*[Tt]ime', re.IGNORECASE),
    re.compile(r'block\.timestamp\s*[><=]+\s*\w*[Tt]ime', re.IGNORECASE),
    re.compile(r'\w*[Tt]ime\s*[><=]+\s*now', re.IGNORECASE),
    re.compile(r'\w*[Tt]ime\s*[><=]+\s*block\.timestamp', re.IGNORECASE),
    re.compile(r'require\s*\(.*[Tt]ime.*\)', re.IGNORECASE),
]

def _detect_timelock_in_source(source_code: str) -> bool:
    """Return True if any time-lock guard pattern is found in the Solidity source."""
    for pattern in _TIMELOCK_PATTERNS:
        if pattern.search(source_code):
            return True
    return False


def _classify_compile_error(error_text: str) -> str | None:
    """
    Match error text against known patterns and return a targeted fix directive.
    Returns None if no specific rule matches (caller falls back to generic error).
    """
    for pattern, directive in _ERROR_RULES:
        if re.search(pattern, error_text, re.IGNORECASE):
            return f"TARGETED FIX REQUIRED — read this carefully before writing any code:\n{directive}"
    return None


def _detect_guard_hit(test_logs: str) -> bool:
    """
    Returns True if the test failed because a real guard blocked the exploit.
    These are FALSIFICATION signals — no point retrying.
    """
    logs_lower = test_logs.lower()
    return any(p.lower() in logs_lower for p in _GUARD_PATTERNS)


def _detect_timelock_failure(test_logs: str) -> bool:
    """
    Returns True if the forge trace shows a time-lock silent no-op:
    the collect/withdraw call returns immediately with [Stop] and no state change.
    Signature: very low gas (< 5000) on the withdraw call after a deposit succeeds.
    """
    lines = test_logs.splitlines()
    for i, line in enumerate(lines):
        # Look for the withdraw/collect call that terminates immediately
        if re.search(r'(Collect|CashOut|withdraw)\s*\(', line, re.IGNORECASE):
            # Check if the next non-empty line is just a ← [Stop] with tiny gas
            for j in range(i + 1, min(i + 5, len(lines))):
                next_line = lines[j].strip()
                if next_line and '←' in next_line and '[Stop]' in next_line:
                    # Extract gas number from the call line, e.g. [2802]
                    gas_match = re.search(r'\[(\d+)\]', line)
                    if gas_match and int(gas_match.group(1)) < 10_000:
                        return True
                    break
    return False


class TestWriterWorker(WorkerAgent):
    MAX_ATTEMPTS = 6
    LLM_TIMEOUT = int(os.getenv("TEST_WRITER_LLM_TIMEOUT", "600"))  # 10 min default

    def __init__(self, llm_client, graph=None):
        self.llm_client = llm_client
        self.graph = graph

    def get_worker_type(self) -> str:
        return "test-writer"

    def _format_error_history(self, error_history: list[str]) -> str:
        if not error_history:
            return ""
        last_err = error_history[-1]
        import_fix_hint = ""
        if "src/src" in last_err or ("6275" in last_err and "not found" in last_err.lower()):
            import_fix_hint = "IMPORT FIX: Use project-root paths like \"src/core/X.sol\", NOT \"../src/core/X.sol\".\n\n"
        seen = set()
        key_errors = []
        for err in error_history[-3:]:
            lines = err.split("\n")
            for line in lines:
                line = line.strip()
                if not line or len(line) < 10:
                    continue
                if "Error (" in line or "ParserError" in line or "Compiler run failed" in line:
                    continue
                if "--> " in line or "|" in line:
                    if line not in seen:
                        seen.add(line)
                        key_errors.append(line)
                elif "error" in line.lower() or "Error" in line:
                    short = line[:120]
                    if short not in seen:
                        seen.add(short)
                        key_errors.append(line[:200])
            if len(key_errors) >= 15:
                break
        if not key_errors:
            return import_fix_hint + "\n\nPrevious attempts failed. Fix the errors from the last attempt.\n" + "\n---\n".join(error_history[-2:])
        return import_fix_hint + "\n\n=== FIX THESE ERRORS (from previous attempt) ===\n" + "\n".join(key_errors[-12:])

    def _extract_test_code(self, response: str) -> str:
        # Normalize line endings
        response = response.replace("\r\n", "\n")
        # Try fenced code blocks with language tag
        match = re.search(r"```(?:solidity|sol|Solidity)\s*\n(.*?)\n\s*```", response, re.IGNORECASE | re.DOTALL)
        if match:
            return match.group(1).strip()
        # Try fenced code block without language tag
        match = re.search(r"```\s*\n(.*?)\n\s*```", response, re.DOTALL)
        if match:
            code = match.group(1).strip()
            if "pragma solidity" in code or "contract " in code:
                return code
        # Last resort: extract from pragma to last closing brace
        pragma_match = re.search(r"(pragma solidity.*)", response, re.DOTALL)
        if pragma_match:
            candidate = pragma_match.group(1).strip()
            # Find the last closing brace
            last_brace = candidate.rfind("}")
            if last_brace > 0:
                return candidate[:last_brace + 1].strip()
        # Raw response might be Solidity directly
        candidate = response.strip()
        solidity_markers = ("pragma solidity", "contract ", "function ", "import ")
        if any(marker in candidate for marker in solidity_markers):
            return candidate
        return ""

    @staticmethod
    def _deduplicate_interfaces(solidity_code: str) -> str:
        """
        Remove duplicate interface definitions from LLM-generated Solidity.
        The LLM sometimes defines the same interface twice in AttackContract.sol.
        Keep only the FIRST occurrence of each interface name.
        """
        import re
        
        # Match full interface blocks: interface IFoo { ... }
        # Uses a simple brace-counting approach since regex can't handle nested braces
        seen_interfaces: set[str] = set()
        result_lines = []
        lines = solidity_code.split('\n')
        
        i = 0
        while i < len(lines):
            line = lines[i]
            # Check if this line starts an interface definition
            m = re.match(r'^\s*interface\s+(\w+)\s*\{?\s*$', line)
            if m:
                iface_name = m.group(1)
                if iface_name in seen_interfaces:
                    # Skip this duplicate interface block entirely
                    # Find the closing brace at the same nesting level
                    depth = line.count('{') - line.count('}')
                    i += 1
                    while i < len(lines) and depth > 0:
                        depth += lines[i].count('{') - lines[i].count('}')
                        i += 1
                    # Skip the closing brace line too if depth hit 0
                    continue
                else:
                    seen_interfaces.add(iface_name)
                    result_lines.append(line)
                    # If opening brace is on same line, track depth
                    depth = line.count('{') - line.count('}')
                    if depth > 0:
                        i += 1
                        while i < len(lines) and depth > 0:
                            depth += lines[i].count('{') - lines[i].count('}')
                            result_lines.append(lines[i])
                            i += 1
                        continue
            else:
                result_lines.append(line)
            i += 1
        
        return '\n'.join(result_lines)

    @staticmethod
    def _fix_exploit_succeeded_conflict(solidity_code: str) -> str:
        """
        Remove explicit `function exploitSucceeded()` when `bool public exploitSucceeded`
        already exists. The public variable auto-generates a getter with the same
        signature, so having both causes Error 2333 (Identifier already declared).
        """
        import re

        has_public_var = bool(re.search(
            r'\bbool\s+public\s+exploitSucceeded\b', solidity_code
        ))
        if not has_public_var:
            return solidity_code

        has_explicit_fn = bool(re.search(
            r'\bfunction\s+exploitSucceeded\s*\(', solidity_code
        ))
        if not has_explicit_fn:
            return solidity_code

        lines = solidity_code.split('\n')
        result_lines = []
        i = 0
        while i < len(lines):
            line = lines[i]
            if re.match(r'\s*function\s+exploitSucceeded\s*\(', line):
                depth = line.count('{') - line.count('}')
                if depth > 0:
                    i += 1
                    while i < len(lines) and depth > 0:
                        depth += lines[i].count('{') - lines[i].count('}')
                        i += 1
                    continue
                elif '{' not in line:
                    i += 1
                    while i < len(lines):
                        depth += lines[i].count('{') - lines[i].count('}')
                        if depth > 0:
                            i += 1
                            while i < len(lines) and depth > 0:
                                depth += lines[i].count('{') - lines[i].count('}')
                                i += 1
                            break
                        i += 1
                    continue
                else:
                    i += 1
                    continue
            else:
                result_lines.append(line)
            i += 1

        return '\n'.join(result_lines)

    def _has_exact_test_exploit(self, code: str) -> bool:
        return bool(re.search(r"\bfunction\s+test_exploit\s*\(", code))

    def _check_test_authenticity(
        self,
        test_code: str,
        target_contract: str,
        is_legacy: bool,
    ) -> tuple[bool, str]:
        """
        Checks whether the test actually deploys the real contract or a mock the LLM wrote.

        Returns (is_authentic, reason_string).

        Rules:
        1. Bridge mode tests MUST contain deployCode() — if absent, LLM deployed a mock.
        2. Any contract definition in the test file that fuzzy-matches the target name
           (but isn't the target itself) is a mock shadow → fabricated.
        """
        # Rule 1: bridge mode requires deployCode()
        if is_legacy and "deployCode(" not in test_code:
            return False, (
                f"FABRICATED: bridge mode test contains no deployCode() call. "
                f"The LLM deployed its own mock instead of the real {target_contract}. "
                f"You MUST use: address deployed = deployCode(\"<path>:{target_contract}\");"
            )

        # Rule 2: look for contract definitions that shadow the target
        # Strip comments first to avoid false positives in NatSpec
        stripped = TestWriterWorker._strip_solidity_comments(test_code)
        defined_contracts = re.findall(r'\bcontract\s+(\w+)', stripped)

        # These names are always allowed — they are the test infrastructure
        allowed = {"ExploitTest", "AttackContract", "Attacker", "Exploit"}

        target_lower = target_contract.lower()
        target_parts = [p for p in re.split(r'[_A-Z]', target_contract) if len(p) > 3]

        for name in defined_contracts:
            if name in allowed:
                continue
            if name == target_contract:
                # LLM re-defined the target contract itself — clear fabrication
                return False, (
                    f"FABRICATED: test defines `contract {name}` which is the target contract itself. "
                    f"You must NOT redefine {target_contract} in the test file. "
                    f"Deploy the real contract via deployCode() or direct import."
                )
            name_lower = name.lower()
            # Fuzzy: Mock + target name, or target name embedded in mock name
            if "mock" in name_lower or "fake" in name_lower or "dummy" in name_lower:
                if target_lower in name_lower or any(p in name_lower for p in target_parts if p):
                    return False, (
                        f"FABRICATED: test defines `contract {name}` which is a mock of the target {target_contract}. "
                        f"You must NOT write your own mock of the target. "
                        f"Deploy the real contract via deployCode() or direct import and test against it."
                    )

        return True, "AUTHENTIC"

    def _generate_test_scaffold(
        self,
        finding: "Finding",
        deploy_path: str,
        is_legacy: bool,
        target_pragma: str | None,
        bytecode_hex: str | None = None,
        dep_bytecodes: dict[str, str] | None = None,
        ctor_inputs: list[dict] | None = None,
        hardcoded_addrs: list[str] | None = None,
        addr_setters: list[str] | None = None,
        warp_seconds: int = 0,
    ) -> str:
        """
        Generate ExploitTest.t.sol from a fixed template.
        This is YOUR CODE, not LLM output.

        If bytecode_hex is provided (legacy pre-compiled contract), deploys
        via inline assembly.  Otherwise uses Foundry's deployCode().
        When dep_bytecodes and ctor_inputs are provided, deploys dependency
        contracts first and passes their addresses as constructor args.
        """
        pragma = "^0.8.0" if is_legacy else (target_pragma or "^0.8.17")
        contract = finding.affected_contract
        vuln = (finding.vulnerability_class or "").lower()
        is_reentrancy = "reentrancy" in vuln or "cei" in vuln

        if is_reentrancy:
            pre_state = "uint256 targetBefore = address(target).balance;"
            assertion = (
                'assertGt(address(attacker).balance, 0, "attacker drained nothing");\n'
                '        assertLt(address(target).balance, targetBefore, '
                '"target balance unchanged");'
            )
        elif "access_control" in vuln or "unprotected" in vuln:
            pre_state = "// capture pre-state"
            assertion = (
                'assertTrue(attacker.exploitSucceeded(), '
                '"access control exploit failed");'
            )
        elif "overflow" in vuln or "underflow" in vuln or "arithmetic" in vuln:
            pre_state = "uint256 balanceBefore = address(target).balance;"
            assertion = (
                'assertTrue(attacker.exploitSucceeded(), '
                '"arithmetic exploit failed");'
            )
        else:
            pre_state = "uint256 stateBefore = address(target).balance;"
            assertion = 'assertTrue(attacker.exploitSucceeded(), "exploit failed");'

        bridge_import = ""

        if bytecode_hex:
            deploy_block, init_block = self._build_legacy_deploy_block(
                bytecode_hex, dep_bytecodes or {}, ctor_inputs or [],
                hardcoded_addrs or [], addr_setters or [],
            )
        else:
            deploy_block = f'address targetAddr = deployCode("{deploy_path}");'
            init_block = ""

        deal_target = ""
        if is_reentrancy:
            deal_target = "\n        vm.deal(target, 10 ether);"

        warp_line = ""
        if warp_seconds > 0:
            warp_line = f"\n        vm.warp(block.timestamp + {warp_seconds});"

        return f"""// SPDX-License-Identifier: UNLICENSED
// AUTO-GENERATED SCAFFOLD — do not edit
// LLM writes AttackContract.sol only. This file is fixed.
pragma solidity {pragma};
import "forge-std/Test.sol";
{bridge_import}
import "./AttackContract.sol";

contract ExploitTest is Test {{
    address target;
    AttackContract attacker;

    function setUp() public {{
        {deploy_block}
        target = targetAddr;{init_block}{deal_target}
        attacker = new AttackContract(target);
        vm.deal(address(attacker), 10 ether);
    }}

    function test_exploit() public {{
        {pre_state}{warp_line}
        attacker.execute();
        {assertion}
    }}
}}
"""

    @staticmethod
    def _build_legacy_deploy_block(
        bytecode_hex: str,
        dep_bytecodes: dict[str, str],
        ctor_inputs: list[dict],
        hardcoded_addrs: list[str] | None = None,
        addr_setters: list[str] | None = None,
    ) -> tuple[str, str]:
        """Build inline-assembly deployment code for legacy contracts.

        Returns (deploy_block, init_block):
          deploy_block — deploys deps + target
          init_block   — vm.etch at hardcoded addrs + call setters on target
        """
        hardcoded_addrs = hardcoded_addrs or []
        addr_setters = addr_setters or []
        usable_deps = {
            name: bc for name, bc in dep_bytecodes.items() if len(bc) > 0
        }

        lines: list[str] = []
        dep_vars: list[str] = []

        # Deploy dependency contracts
        for i, (dep_name, dep_bc) in enumerate(usable_deps.items()):
            var = f"_dep{i}"
            lines.append(
                f'bytes memory {var}Bc = hex"{dep_bc}";\n'
                f"        address {var};\n"
                f"        assembly {{ {var} := create(0, add({var}Bc, 0x20), mload({var}Bc)) }}"
            )
            dep_vars.append(var)

        # vm.etch dep code at hardcoded addresses
        etch_lines: list[str] = []
        if dep_vars and hardcoded_addrs:
            for hc_addr in hardcoded_addrs:
                etch_lines.append(
                    f"vm.etch({hc_addr}, {dep_vars[0]}.code);"
                )

        # Build target deployment
        addr_param_count = sum(
            1 for inp in ctor_inputs if inp.get("type") == "address"
        )

        if addr_param_count > 0 and dep_vars:
            ctor_arg_parts: list[str] = []
            dep_idx = 0
            for inp in ctor_inputs:
                if inp.get("type") == "address" and dep_idx < len(dep_vars):
                    ctor_arg_parts.append(dep_vars[dep_idx])
                    dep_idx += 1
                elif inp.get("type", "").startswith(("uint", "int")):
                    ctor_arg_parts.append(f'{inp["type"]}(0)')
                elif inp.get("type") == "bool":
                    ctor_arg_parts.append("false")
                elif inp.get("type") == "address":
                    ctor_arg_parts.append("address(0)")
                else:
                    ctor_arg_parts.append(f'{inp["type"]}(0)')

            ctor_args_str = ", ".join(ctor_arg_parts)
            target_deploy = (
                f'bytes memory _bc = hex"{bytecode_hex}";\n'
                f"        bytes memory _args = abi.encode({ctor_args_str});\n"
                f"        bytes memory _deployData = bytes.concat(_bc, _args);\n"
                f"        address targetAddr;\n"
                f"        assembly {{ targetAddr := create(0, add(_deployData, 0x20), mload(_deployData)) }}\n"
                f'        require(targetAddr != address(0), "legacy deploy failed");'
            )
        else:
            target_deploy = (
                f'bytes memory _bc = hex"{bytecode_hex}";\n'
                f"        address targetAddr;\n"
                f"        assembly {{ targetAddr := create(0, add(_bc, 0x20), mload(_bc)) }}\n"
                f'        require(targetAddr != address(0), "legacy deploy failed");'
            )

        # Assemble deploy_block
        all_deploy: list[str] = []
        if lines:
            all_deploy.append("\n        ".join(lines))
        if etch_lines:
            all_deploy.append("\n        ".join(etch_lines))
        all_deploy.append(target_deploy)
        deploy_block = "\n        ".join(all_deploy)

        # Build init_block: call address setters on target
        init_parts: list[str] = []
        if addr_setters and dep_vars:
            for setter_sig in addr_setters:
                init_parts.append(
                    f'target.call(abi.encodeWithSignature("{setter_sig}", {dep_vars[0]}));'
                )

        init_block = ""
        if init_parts:
            init_block = "\n        " + "\n        ".join(init_parts)

        return deploy_block, init_block

    def _build_attack_only_prompt(
        self,
        finding: "Finding",
        error_history: list[str],
        real_sources: dict[str, str] | None,
        deploy_path: str,
        is_legacy: bool,
        target_pragma: str | None,
        skip_rag: bool = False,
        warp_seconds: int = 0,
        exploit_sequence: list | None = None,
    ) -> list[dict[str, str]]:
        """
        Prompt that asks LLM to write ONLY AttackContract.sol.
        ExploitTest.t.sol is already written by _generate_test_scaffold().
        """
        error_context = self._format_error_history(error_history)
        pragma = "^0.8.0" if is_legacy else (target_pragma or "^0.8.17")
        contract = finding.affected_contract

        timelock_section = ""
        if warp_seconds > 0:
            timelock_section = f"""
══════════════════════════════════════════════════
TIME-LOCK GUARD DETECTED — READ CAREFULLY
══════════════════════════════════════════════════
This contract has a time-lock: the deposit/Put function sets `unlockTime = now + lockDuration`.
The withdraw/Collect function silently returns (NO revert) if `now <= unlockTime`.

The scaffold has already called `vm.warp(block.timestamp + {warp_seconds})` BEFORE execute() runs.
The EVM clock is already past any reasonable lock period when your execute() is called.

Your execute() MUST:
  1. Call the DEPOSIT function (Put/deposit) with _lockTime = 0 (if it takes a lockTime arg)
     This registers your account. Since vm.warp already ran, now > unlockTime = now + 0.
  2. Call the WITHDRAW/COLLECT function — now > unlockTime is TRUE, so it will proceed
  3. Re-enter inside receive() to drain more ETH each callback

DO NOT call vm.warp inside AttackContract — the scaffold handles this.
CRITICAL: If Put(uint _lockTime) exists, pass _lockTime = 0 — NOT any positive value.
══════════════════════════════════════════════════
"""
        source_section = timelock_section
        if real_sources:
            source_section += (
                "\n=== REAL CONTRACT SOURCE "
                "(READ ONLY — understand logic, do not import) ===\n"
            )
            for path, code in real_sources.items():
                source_section += f"// {path}\n{code}\n\n"

        rag = "" if skip_rag else self._fetch_rag_context(finding)
        err_rag = "" if skip_rag else (
            self._fetch_error_rag_context(error_history) if error_history else ""
        )

        system = f"""You are an expert smart-contract exploit developer.
You must write ONLY AttackContract.sol — the attack logic contract.

══════════════════════════════════════════════════
WHAT YOU ARE WRITING
══════════════════════════════════════════════════
A single Solidity file: AttackContract.sol

It MUST contain exactly:
  contract AttackContract {{
      constructor(address _target) {{ ... }}
      receive() external payable {{}}        ← MANDATORY always
      fallback() external payable {{}}       ← MANDATORY always
      function execute() external {{ ... }}    ← NOT payable, funded via vm.deal
      bool public exploitSucceeded;          ← auto-generates getter, NO explicit function
  }}

CRITICAL: `bool public exploitSucceeded;` auto-generates a getter function.
Do NOT also define `function exploitSucceeded()` — that causes Error 2333 (duplicate identifier).
Use the public variable ONLY. Set it to true inside your logic when the exploit succeeds.

══════════════════════════════════════════════════
WHAT YOU ARE NOT WRITING
══════════════════════════════════════════════════
- Do NOT write ExploitTest.t.sol — already generated
- Do NOT write setUp() or test_exploit() — already in scaffold
- Do NOT import forge-std/Test.sol
- Do NOT define or deploy {contract} — it is passed to your constructor
- Do NOT write a mock of {contract}

══════════════════════════════════════════════════
PRAGMA AND IMPORTS
══════════════════════════════════════════════════
pragma solidity {pragma};
// No imports needed — define interface inline

══════════════════════════════════════════════════
INLINE INTERFACE (define at file level, before AttackContract)
══════════════════════════════════════════════════
Define a minimal interface for {contract} with ONLY the functions you call.
Mark ETH-receiving functions as payable:

  interface I{contract} {{
      function depositFunction() external payable;
      function withdrawFunction(uint256 _am) external payable;
      // Replace depositFunction/withdrawFunction with the REAL function names
      // from the target contract. Do NOT assume Deposit/Collect — read the signatures.
  }}

══════════════════════════════════════════════════
CRITICAL — DO NOT REDEFINE INTERFACES FROM BridgeInterfaces.sol:
══════════════════════════════════════════════════
  The scaffold does NOT import BridgeInterfaces.sol in two-file mode.
  You are free to define any interface you need inline in AttackContract.sol.
  Just make sure you only define each interface ONCE.
  If you define `interface I{contract}` at line 5, do NOT define it again at line 50.

══════════════════════════════════════════════════
REENTRANCY PATTERN
══════════════════════════════════════════════════
The reentrancy loop lives in receive(), not execute().
execute() seeds the deposit and triggers the first withdraw.
The loop continues through receive() callbacks:

  bool public exploitSucceeded;
  uint256 reentryCount;
  uint256 constant MAX_REENTRY = 3;
  I{contract} target;

  constructor(address _target) {{
      target = I{contract}(_target);
  }}

  receive() external payable {{
      if (reentryCount < MAX_REENTRY && address(target).balance >= 1 ether) {{
          reentryCount++;
          target.withdrawFunction(1 ether);
      }} else {{
          exploitSucceeded = true;
      }}
  }}

  fallback() external payable {{}}

  function execute() external {{
      reentryCount = 0;
      target.depositFunction{{value: 1 ether}}();
      target.withdrawFunction(1 ether);
  }}

IMPORTANT: Replace depositFunction/withdrawFunction with the REAL function names
from the target contract. Do NOT use Deposit/Collect unless those are the actual names.

══════════════════════════════════════════════════
FUNDING — HOW THE CONTRACT GETS ETH
══════════════════════════════════════════════════
The scaffold calls vm.deal(address(attacker), 10 ether) in setUp().
Your contract already has 10 ETH when execute() is called.
execute() is called WITHOUT msg.value — do NOT check msg.value.

WRONG (will always revert):
  require(msg.value >= 1 ether, "need ether");

RIGHT (use existing balance):
  target.depositFunction{{value: 1 ether}}();   // spends from balance

Do NOT add ANY require() or if-check on msg.value in execute().
The ETH is in address(this).balance, not msg.value.

CRITICAL: `bool public exploitSucceeded` auto-generates a getter function.
Do NOT also define `function exploitSucceeded()` — that causes Error 2333.

══════════════════════════════════════════════════
TARGET INFO
══════════════════════════════════════════════════
Contract: {contract}
Function: {finding.affected_function}
Vulnerability: {finding.vulnerability_class}
Hypothesis: {finding.hypothesis}
"""

        user = (
            f"{source_section}"
            f"{rag}\n"
            f"{err_rag}\n"
            f"{error_context}\n\n"
            "Write AttackContract.sol. "
            "Output ONLY the Solidity code in a ```solidity block."
        )

        return [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ]

    _AUTOCORRECT_IMPORT_RE = re.compile(
        r'import\s+"([^"]+)"\s*;|import\s+\{[^}]+\}\s+from\s+"([^"]+)"\s*;'
    )

    def _auto_correct_imports(
        self,
        test_code: str,
        sandbox: "SandboxManager",
        remappings: dict[str, str],
        collected_paths: list[str] | None = None,
    ) -> str:
        skip_prefixes = {"forge-std/", "ds-test/", "lib/"}
        skip_prefixes.update(alias for alias in remappings if alias.endswith("/"))
        corrections: list[tuple[str, str]] = []
        for m in self._AUTOCORRECT_IMPORT_RE.finditer(test_code):
            import_path = m.group(1) or m.group(2)
            if not import_path:
                continue
            if any(import_path.startswith(p) for p in skip_prefixes):
                continue
            candidate = sandbox.tmp_dir / import_path
            if candidate.is_file():
                continue
            filename = Path(import_path).name
            if collected_paths:
                matches_from_collected = [p for p in collected_paths if Path(p).name == filename]
                if matches_from_collected:
                    correct_path = matches_from_collected[0]
                    if correct_path != import_path:
                        corrections.append((import_path, correct_path))
                    continue
            matches = list(sandbox.tmp_dir.rglob(filename))
            valid = [f for f in matches if "lib" not in f.parts and "out" not in f.parts and "cache" not in f.parts]
            if not valid:
                continue
            best = valid[0]
            for v in valid:
                rel = str(v.relative_to(sandbox.tmp_dir)).replace("\\", "/")
                if rel.startswith("src/"):
                    best = v
                    break
            correct_path = str(best.relative_to(sandbox.tmp_dir)).replace("\\", "/")
            if correct_path != import_path:
                corrections.append((import_path, correct_path))
        for bad, good in corrections:
            test_code = test_code.replace(f'"{bad}"', f'"{good}"')
        if corrections:
            fixed = ", ".join(f"{b}->{g}" for b, g in corrections)
            logger.info(f"[TestWriter] Auto-corrected imports: {fixed}")
        return test_code

    _IMPORT_RE = re.compile(
        r'import\s+(?:"([^"]+)"|{[^}]+}\s+from\s+"([^"]+)")\s*;',
        re.MULTILINE
    )
    _MAX_DEP_FILES = 12
    _MAX_TOTAL_CHARS = 60_000
    _TARGET_FILE_CAP = 6000
    _INTERFACE_FILE_CAP = 4000
    _IMPL_FILE_CAP = 3000

    def _resolve_import_path(self, import_path: str, remappings: dict[str, str], repo: Path, from_file: Path | None = None) -> Path | None:
        path_str = import_path.strip()
        if not path_str:
            return None
        for alias, target in sorted(remappings.items(), key=lambda x: -len(x[0])):
            alias_stripped = alias.rstrip("/")
            if path_str.startswith(alias_stripped + "/") or path_str == alias_stripped:
                path_str = target.rstrip("/") + path_str[len(alias_stripped):]
                break
        if path_str.startswith("./") or path_str.startswith("../"):
            if not from_file or not from_file.parent:
                return None
            resolved = (from_file.parent / path_str).resolve()
            try:
                path_str = str(resolved.relative_to(repo.resolve())).replace("\\", "/")
            except ValueError:
                return None
        if path_str.startswith("lib/") or "/lib/" in path_str:
            return None
        candidate = repo / path_str
        if candidate.exists() and candidate.suffix == ".sol":
            return candidate
        return None

    def _parse_imports(self, content: str) -> list[str]:
        paths = []
        for m in self._IMPORT_RE.finditer(content):
            p1, p2 = m.group(1), m.group(2)
            p = (p1 or p2 or "").strip()
            if p and p not in paths:
                paths.append(p)
        return paths

    def _is_interface_file(self, content: str, path: str) -> bool:
        if "interface/" in path.replace("\\", "/"):
            return True
        return "interface " in content and "contract " not in content[:500]

    @staticmethod
    def _strip_solidity_comments(source: str) -> str:
        """
        Remove single-line (// ...) and multi-line (/* ... */) comments.
        Must happen before any regex analysis to avoid false positives from
        comment text like '// This is because abstract contract Foo...'.
        """
        # Remove /* ... */ blocks first (they can span lines)
        source = re.sub(r'/\*.*?\*/', ' ', source, flags=re.DOTALL)
        # Remove // ... to end of line
        source = re.sub(r'//[^\n]*', ' ', source)
        return source

    @staticmethod
    def _detect_pragma(sources: dict[str, str]) -> str | None:
        """
        Find the pragma solidity version used in the collected source files.
        Scans all files (not just the first) so we catch the target contract's
        pragma even when the first collected file is an interface with no pragma.

        Returns the raw version constraint string, e.g. '=0.7.6', '^0.8.17',
        or None if no pragma found.
        """
        pragma_re = re.compile(r'pragma\s+solidity\s+([^;]+);')
        for source in sources.values():
            m = pragma_re.search(source)
            if m:
                version_str = m.group(1).strip()
                # Skip very permissive ranges that don't pin a version
                if version_str not in ("", ">=0.5.0", ">=0.4.0"):
                    return version_str
        return None

    @staticmethod
    def _parse_pragma_major_minor(pragma_str: str) -> tuple[int, int]:
        """Extract (major, minor) from pragma strings like '^0.5.16', '>=0.6.0'."""
        match = re.search(r'(\d+)\.(\d+)', pragma_str)
        if match:
            return int(match.group(1)), int(match.group(2))
        return 0, 8

    def _build_bridge_prompt(
        self,
        finding: Finding,
        relevant_code: dict[str, str],
        error_history: list[str],
        bridge_interfaces_src: str,
        deploy_paths: dict[str, str],
        contract_signatures: dict[str, str] | None = None,
        real_sources: dict[str, str] | None = None,
        skip_rag: bool = False,
        exploit_sequence: list | None = None,
    ) -> list[dict[str, str]]:
        """Build the LLM prompt for bridge mode (legacy Solidity repos)."""
        error_context = self._format_error_history(error_history)

        source_section = ""

        # Deploy path hints
        source_section += "\n=== DEPLOY PATHS (use these exact strings in deployCode()) ===\n"
        for contract_name, path in sorted(deploy_paths.items()):
            source_section += f'  deployCode("{path}")  // deploys {contract_name}\n'
        source_section += "\n"

        # Bridge interfaces content
        source_section += "\n=== BridgeInterfaces.sol (already written to test/ — just import \"./BridgeInterfaces.sol\") ===\n"
        source_section += bridge_interfaces_src + "\n"

        # Starter template
        target_contract = finding.affected_contract
        target_path = deploy_paths.get(target_contract, f"contracts/{target_contract}.sol:{target_contract}")
        source_section += "\n=== STARTER TEMPLATE (use this structure) ===\n"
        source_section += f"pragma solidity ^0.8.0;\n"
        source_section += f'import "forge-std/Test.sol";\n'
        source_section += f'import "./BridgeInterfaces.sol";\n\n'
        source_section += f"contract ExploitTest is Test {{\n"
        source_section += f"    I{target_contract} target;\n\n"
        source_section += f"    function setUp() public {{\n"
        source_section += f'        address deployed = deployCode("{target_path}");\n'
        source_section += f"        target = I{target_contract}(deployed);\n"
        source_section += f"    }}\n\n"
        source_section += f"    function test_exploit() public {{\n"
        source_section += f"        // your exploit here\n"
        source_section += f"    }}\n"
        source_section += f"}}\n\n"

        # Contract signatures for reference
        if contract_signatures:
            source_section += "\n=== CONTRACT SIGNATURES (for reference — call via interface) ===\n"
            for fn_name, sig in sorted(contract_signatures.items()):
                source_section += f"  {fn_name}: {sig}\n"
            source_section += "\n"

        # Real source as READ-ONLY context (not for import)
        if real_sources:
            source_section += "\n=== REAL CONTRACT SOURCE (READ-ONLY CONTEXT — do NOT import these files) ===\n"
            source_section += "Use this to understand the contract logic, constructor args, and function behavior.\n\n"
            for rel_path, code in real_sources.items():
                source_section += f"// File: {rel_path}\n{code}\n\n"

        rag_context = "" if skip_rag else self._fetch_rag_context(finding)
        error_rag = "" if skip_rag else (self._fetch_error_rag_context(error_history) if error_history else "")

        exploit_seq_str = ""
        if exploit_sequence:
            steps_text = "\n".join(
                f"  Step {s.get('step', i+1)}: [{s.get('role', '?')}] {s.get('node', '?')}" 
                for i, s in enumerate(exploit_sequence)
            )
            exploit_seq_str = f"## Pre-Computed Exploit Chain (from graph)\n{steps_text}\n\nUse this chain to guide your test.\n\n"

        user_content = (
            f"Vulnerability Class: {finding.vulnerability_class}\n"
            f"Affected Contract: {finding.affected_contract}\n"
            f"Affected Function: {finding.affected_function}\n"
            f"Hypothesis: {finding.hypothesis}\n"
            f"Attack Path: {' -> '.join(finding.attack_path)}\n"
            f"Impact: {finding.impact}\n"
            f"{exploit_seq_str}"
            f"{source_section}"
            f"{rag_context}\n"
            f"{error_rag}\n"
            f"{error_context}\n\n"
            "Generate a complete Foundry test using the VERSION BRIDGE PATTERN that proves this vulnerability."
        )

        return [
            {"role": "system", "content": BRIDGE_MODE_SYSTEM_PROMPT},
            {"role": "user", "content": user_content}
        ]

    def _collect_repo_sources(self, finding: Finding, repo_path: str | None, remappings: dict[str, str], _lib_imports_out: set[str] | None = None) -> dict[str, str]:
        if not repo_path:
            return {}
        repo = Path(repo_path)
        if not repo.exists():
            return {}
        contract_name = finding.affected_contract
        target_path: Path | None = None
        for search_dir in ["src", "contracts", "."]:
            base = repo / search_dir
            if not base.exists():
                continue
            for sol_file in base.rglob("*.sol"):
                if "lib" in sol_file.parts:
                    continue
                try:
                    content = sol_file.read_text(encoding='utf-8', errors='replace')
                    if f"contract {contract_name}" in content or f"contract {contract_name} " in content:
                        target_path = sol_file
                        break
                except Exception:
                    continue
            if target_path:
                break
        if not target_path and self.graph is not None:
            graph_source = self.graph.nodes.get(contract_name, {}).get("source_file", "")
            if graph_source:
                candidate = repo / graph_source
                if not candidate.exists():
                    candidate = repo / Path(graph_source.replace("\\", "/"))
                if candidate.exists():
                    target_path = candidate
                    logger.info(
                        f"[TestWriter] Resolved {contract_name} via graph source_file: {graph_source}"
                    )
        if not target_path:
            return {}
        collected: dict[str, str] = {}
        to_visit: list[Path] = [target_path]
        seen: set[str] = set()
        total_chars = 0
        while to_visit and len(collected) < self._MAX_DEP_FILES and total_chars < self._MAX_TOTAL_CHARS:
            current = to_visit.pop(0)
            rel = str(current.relative_to(repo)).replace("\\", "/")
            if rel in seen:
                continue
            seen.add(rel)
            try:
                content = current.read_text(encoding='utf-8', errors='replace')
            except Exception:
                continue
            is_target = current == target_path
            is_interface = self._is_interface_file(content, rel)
            cap = self._TARGET_FILE_CAP if is_target else (self._INTERFACE_FILE_CAP if is_interface else self._IMPL_FILE_CAP)
            if len(content) > cap:
                content = content[:cap] + "\n... [truncated]"
            collected[rel] = content
            total_chars += len(content)
            for imp in self._parse_imports(content):
                resolved = self._resolve_import_path(imp, remappings, repo, from_file=current)
                if resolved:
                    rel_resolved = str(resolved.relative_to(repo)).replace("\\", "/")
                    if rel_resolved not in seen:
                        if "interface/" in rel_resolved:
                            to_visit.insert(0, resolved)
                        else:
                            to_visit.append(resolved)
                elif _lib_imports_out is not None:
                    _lib_imports_out.add(imp)
        return collected

    def _collect_minimal_sources(self, finding: Finding, repo_path: str | None, remappings: dict[str, str], _lib_imports_out: set[str] | None = None) -> dict[str, str]:
        """BUG-004 fix: delegate to _collect_repo_sources with reduced limits instead of duplicating 60 lines."""
        # Temporarily reduce limits for a minimal collection
        saved_max_files = self._MAX_DEP_FILES
        saved_max_chars = self._MAX_TOTAL_CHARS
        try:
            self._MAX_DEP_FILES = 6
            self._MAX_TOTAL_CHARS = 30_000
            return self._collect_repo_sources(finding, repo_path, remappings, _lib_imports_out=_lib_imports_out)
        finally:
            self._MAX_DEP_FILES = saved_max_files
            self._MAX_TOTAL_CHARS = saved_max_chars

    def _get_repo_file_manifest(self, repo_path: str | None) -> list[str]:
        if not repo_path:
            return []
        repo = Path(repo_path)
        if not repo.exists():
            return []
        paths: list[str] = []
        for d in ["src", "contracts", "."]:
            base = repo / d
            if not base.exists():
                continue
            for f in base.rglob("*.sol"):
                if "lib" in f.parts:
                    continue
                rel = str(f.relative_to(repo)).replace("\\", "/")
                if rel not in paths:
                    paths.append(rel)
        return sorted(paths)

    def _generate_import_cheatsheet(self, real_sources: dict[str, str], lib_imports: set[str] | None = None) -> str:
        lines: list[str] = ['import "forge-std/Test.sol";']
        seen: set[str] = {"forge-std/Test.sol"}
        for path in real_sources:
            if path not in seen:
                seen.add(path)
                lines.append(f'import "{path}";')
        if lib_imports:
            for imp in sorted(lib_imports):
                if imp not in seen:
                    seen.add(imp)
                    lines.append(f'import "{imp}";')
        return "\n".join(lines)

    @staticmethod
    def _parse_toml_remappings(content: str) -> dict[str, str]:
        # Try stdlib tomllib first (Python 3.11+), fall back to manual parsing
        try:
            import tomllib
            data = tomllib.loads(content)
            raw_remappings = data.get("profile", {}).get("default", {}).get("remappings", [])
            if not raw_remappings:
                raw_remappings = data.get("remappings", [])
            remappings: dict[str, str] = {}
            for entry in raw_remappings:
                if isinstance(entry, str) and "=" in entry:
                    alias, target = entry.split("=", 1)
                    if alias.strip():
                        remappings[alias.strip()] = target.strip()
            return remappings
        except (ImportError, Exception):
            pass

        # Fallback: manual line-by-line parsing for Python < 3.11
        remappings: dict[str, str] = {}
        in_remappings = False
        for line in content.splitlines():
            stripped = line.strip()
            if not in_remappings:
                if "remappings" in stripped and "=" in stripped:
                    in_remappings = True
                    after_eq = stripped.split("=", 1)[1]
                    for entry in after_eq.replace("[", "").replace("]", "").split(","):
                        entry = entry.strip().strip('"').strip("'").strip()
                        if "=" in entry:
                            alias, target = entry.split("=", 1)
                            if alias.strip():
                                remappings[alias.strip()] = target.strip()
                    if "]" in after_eq:
                        break
                continue
            if stripped == "]" or stripped.startswith("]"):
                break
            if stripped.startswith("["):
                break
            entry = stripped.strip('",').strip("'").strip()
            if "=" in entry:
                alias, target = entry.split("=", 1)
                if alias.strip():
                    remappings[alias.strip()] = target.strip()
        return remappings

    def _get_remappings_from_repo(self, repo_path: str | None) -> dict[str, str]:
        if not repo_path:
            return {}
        repo = Path(repo_path)
        remap_file = repo / "remappings.txt"
        if remap_file.exists():
            remappings: dict[str, str] = {}
            for line in remap_file.read_text().splitlines():
                line = line.strip()
                if "=" in line:
                    alias, target = line.split("=", 1)
                    remappings[alias.strip()] = target.strip()
            return remappings
        toml_file = repo / "foundry.toml"
        if toml_file.exists():
            return self._parse_toml_remappings(toml_file.read_text())
        return {}

    def _find_real_source(self, finding: Finding, repo_path: str | None) -> dict[str, str]:
        return self._collect_repo_sources(finding, repo_path, {})

    def _detect_repo_contract_conflicts(self, repo_path: str | None) -> dict:
        """
        Pre-analyzes the repo ONCE before the first LLM attempt.

        Detects:
          - Naming conflicts: same contract name in >1 file → Error (2333)
          - Abstract contracts: cannot instantiate with `new X()` → Error (4614)

        Comments are stripped before analysis to prevent false positives from
        prose like '// This is because abstract contract Foo handles X...'.
        The regex is anchored to line-start to avoid matching mid-line identifiers.
        """
        if not repo_path:
            return {
                "naming_conflicts": [], "abstract_contracts": [],
                "conflict_warnings": "", "abstract_warnings": "",
            }

        repo = Path(repo_path)
        name_to_files: dict[str, list[str]] = {}
        abstract_contracts: list[str] = []

        # Anchored to line start: only matches actual Solidity contract declarations.
        # Group 1: optional 'abstract ' keyword. Group 2: contract identifier.
        contract_decl_re = re.compile(
            r'^\s*(abstract\s+)?contract\s+([A-Za-z_]\w*)\b',
            re.MULTILINE
        )
        # Forge-std base names that legitimately appear in every project
        skip_names = {
            "Test", "Script", "console", "console2",
            "stdError", "stdMath", "StdAssertions", "StdChains",
            "StdCheats", "StdUtils", "Vm", "DSTest",
        }

        for search_dir in ["src", "contracts", "."]:
            base = repo / search_dir
            if not base.exists():
                continue
            for sol_file in base.rglob("*.sol"):
                if "lib" in sol_file.parts or "node_modules" in sol_file.parts:
                    continue
                try:
                    raw = sol_file.read_text(encoding="utf-8", errors="replace")
                    # Strip comments BEFORE regex matching — prevents false hits from
                    # NatSpec, inline notes, or commented-out declarations.
                    stripped = self._strip_solidity_comments(raw)
                    rel = str(sol_file.relative_to(repo)).replace("\\", "/")
                    for m in contract_decl_re.finditer(stripped):
                        is_abstract = bool(m.group(1))
                        name = m.group(2)
                        if name in skip_names:
                            continue
                        name_to_files.setdefault(name, []).append(rel)
                        if is_abstract and name not in abstract_contracts:
                            abstract_contracts.append(name)
                except Exception:
                    continue

        conflicts = {n: f for n, f in name_to_files.items() if len(f) > 1}

        conflict_warnings = ""
        if conflicts:
            lines = [
                "=== NAMING CONFLICT WARNINGS ===",
                "The following contract names are defined in MULTIPLE files in this repo.",
                "Importing more than one causes Error (2333): 'Identifier already declared'.",
                "ONLY import ONE file per contract name. Prefer the path in IMPORT CHEAT SHEET.",
                "",
            ]
            for name, files in conflicts.items():
                lines.append(f"  CONTRACT '{name}' defined in:")
                for f in files:
                    lines.append(f"    - {f}")
                lines.append(f"  → Import ONLY ONE of the above for '{name}'.")
            conflict_warnings = "\n".join(lines)

        abstract_warnings = ""
        if abstract_contracts:
            lines = [
                "=== ABSTRACT CONTRACT WARNINGS ===",
                "These contracts are abstract — `new X(...)` will cause Error (4614).",
                "Do NOT instantiate them directly. Options:",
                "  a) Find a concrete subclass in AVAILABLE CONTRACTS and deploy that instead.",
                "  b) Write a minimal concrete subclass at FILE LEVEL before ExploitTest.",
                "",
            ]
            for name in abstract_contracts:
                lines.append(f"  - {name}")
            abstract_warnings = "\n".join(lines)

        return {
            "naming_conflicts": list(conflicts.keys()),
            "abstract_contracts": abstract_contracts,
            "conflict_warnings": conflict_warnings,
            "abstract_warnings": abstract_warnings,
        }

    def _fetch_rag_context(self, finding: Finding) -> str:
        from src.knowledge.rag_system import search_security_knowledge
        queries = [
            f"{finding.vulnerability_class} exploit Foundry test pattern",
            f"Solidity {finding.vulnerability_class} vulnerability proof of concept",
            "Foundry vm.prank vm.deal cheatcodes exploit test",
        ]
        if finding.hypothesis:
            queries.append(f"{finding.hypothesis[:80]} exploit")
        all_results = []
        for q in queries[:3]:
            results = search_security_knowledge(q, k=3)
            all_results.extend(results)
        if not all_results:
            return ""
        seen = set()
        lines = []
        for r in all_results[:5]:
            content = r.get("content", "")[:600]
            if content and content not in seen:
                seen.add(content)
                src = r.get("source", "Unknown")
                lines.append(f"--- Source: {src}\n{content}\n")
        return "\n=== SECURITY KNOWLEDGE (use for correct Solidity patterns) ===\n" + "\n".join(lines)

    def _fetch_error_rag_context(self, error_history: list[str]) -> str:
        if not error_history:
            return ""
        from src.knowledge.rag_system import search_security_knowledge
        last_err = error_history[-1]
        codes = re.findall(r"Warning \((\d+)\)|Error \((\d+)\)|error (\d+):", last_err)
        codes = [c for t in codes for c in t if c]
        phrases = []
        if "virtual modifier" in last_err or "8429" in last_err:
            phrases.append("Solidity virtual modifier deprecated fix")
        if "memory-safe-assembly" in last_err or "2424" in last_err:
            phrases.append("Solidity memory-safe-assembly Natspec deprecated fix")
        if "import" in last_err.lower() and "not found" in last_err.lower():
            phrases.append("Solidity import path Foundry remapping")
        if "6275" in last_err or "src/src" in last_err or ("not found" in last_err and "import" in last_err.lower()):
            phrases.append("Solidity Foundry import path project root src/core not ../src")
        if "Source" in last_err and "not found" in last_err:
            phrases.append("Solidity import project-root-relative path")
        if "function" in last_err.lower() and "not found" in last_err.lower():
            phrases.append("Solidity function signature Foundry test")
        for code in codes[:2]:
            phrases.append(f"Solidity compiler error {code} fix")
        all_results = []
        for q in phrases[:3]:
            results = search_security_knowledge(q, k=2)
            all_results.extend(results)
        if not all_results:
            return ""
        seen = set()
        lines = []
        for r in all_results[:5]:
            content = r.get("content", "")[:500]
            if content and content not in seen:
                seen.add(content)
                src = r.get("source", "Unknown")
                lines.append(f"--- {src}\n{content}\n")
        return "\n=== ERROR FIX HINTS (from RAG — apply to fix the build) ===\n" + "\n".join(lines)

    def _build_prompt(
        self,
        finding: Finding,
        relevant_code: dict[str, str],
        error_history: list[str],
        real_sources: dict[str, str] | None = None,
        remappings: dict[str, str] | None = None,
        contract_signatures: dict[str, str] | None = None,
        repo_manifest: list[str] | None = None,
        skip_rag: bool = False,
        import_cheatsheet: str | None = None,
        repo_conflicts: dict | None = None,
        target_pragma: str | None = None,
        exploit_sequence: list | None = None,
    ) -> list[dict[str, str]]:

        has_real_source = bool(real_sources)
        system_prompt = TEST_WRITER_REAL_SOURCE_SYSTEM_PROMPT if has_real_source else TEST_WRITER_SYSTEM_PROMPT
        error_context = self._format_error_history(error_history)

        # Conflict/abstract warnings go first so LLM reads them before any source
        conflict_block = ""
        if repo_conflicts and has_real_source:
            if repo_conflicts.get("conflict_warnings"):
                conflict_block += "\n\n" + repo_conflicts["conflict_warnings"] + "\n"
            if repo_conflicts.get("abstract_warnings"):
                conflict_block += "\n" + repo_conflicts["abstract_warnings"] + "\n"

        source_section = conflict_block

        # Pragma warning — pinned version must match across all imported files
        if target_pragma and has_real_source:
            source_section += (
                f"\n=== PRAGMA VERSION (MANDATORY) ===\n"
                f"The target contract uses: pragma solidity {target_pragma};\n"
                f"Your test file MUST start with exactly: pragma solidity {target_pragma};\n"
                f"Do NOT use ^0.8.0, ^0.8.17, or any other version. "
                f"Mismatched pragmas cause 'Found incompatible versions' build failure.\n\n"
            )

        if has_real_source:
            if import_cheatsheet:
                source_section += "\n\n=== IMPORT CHEAT SHEET (copy these verbatim, do NOT invent paths) ===\n"
                source_section += import_cheatsheet + "\n"
                source_section += "\nONLY use imports listed above. NEVER import from out/, cache/, or artifacts/.\n"
                source_section += "Do NOT use ../src/... — that causes 'src/src/...' when test is in src/test/.\n\n"

            first_path = list(real_sources.keys())[0] if real_sources else "src/core/Contract.sol"
            pragma_line = f"pragma solidity {target_pragma};" if target_pragma else "pragma solidity ^0.8.17;"
            source_section += "\n=== STARTER TEMPLATE (use this structure) ===\n"
            source_section += f'// {pragma_line}\n'
            source_section += f'// import "forge-std/Test.sol";\n'
            source_section += f'// import "{first_path}";\n'
            source_section += f'// contract ExploitTest is Test {{\n'
            source_section += f'//     function setUp() public {{ /* deploy real contracts */ }}\n'
            source_section += f'//     function test_exploit() public {{ /* attack logic */ }}\n'
            source_section += f'// }}\n\n'

            if repo_manifest:
                source_section += "\n=== AVAILABLE CONTRACTS IN REPO (import these real contracts, never mock) ===\n"
                for p in repo_manifest[:30]:
                    source_section += f"  {p}\n"
                source_section += "\n"

            if contract_signatures:
                source_section += "\n=== CONTRACT SIGNATURES (use these exact signatures) ===\n"
                for fn_name, sig in sorted(contract_signatures.items()):
                    source_section += f"  {fn_name}: {sig}\n"
                source_section += "\n"

            source_section += "\n=== REAL CONTRACT SOURCE FILES ===\n"
            source_section += "These are the ACTUAL source files. Import and deploy these real contracts.\n\n"
            for rel_path, code in real_sources.items():
                source_section += f"// File: {rel_path}\n{code}\n\n"

            if remappings:
                source_section += "\n=== FOUNDRY REMAPPINGS ===\n"
                source_section += "Use these import aliases:\n"
                for alias, target in remappings.items():
                    source_section += f"  {alias} => {target}\n"

        elif relevant_code:
            source_section += "\n\n=== CODE SNIPPETS FROM KNOWLEDGE GRAPH ===\n"
            if contract_signatures:
                source_section += "=== CONTRACT SIGNATURES ===\n"
                for fn_name, sig in sorted(contract_signatures.items()):
                    source_section += f"  {fn_name}: {sig}\n"
                source_section += "\n"
            source_section += "(Note: These are extracted snippets, not full source files. Synthesize mock contracts as needed.)\n\n"
            for node_id, code in relevant_code.items():
                source_section += f"--- Snippet: {node_id} ---\n{code}\n\n"

        rag_context = "" if skip_rag else self._fetch_rag_context(finding)
        error_rag = "" if skip_rag else (self._fetch_error_rag_context(error_history) if error_history else "")

        user_content = (
            f"Vulnerability Class: {finding.vulnerability_class}\n"
            f"Affected Contract: {finding.affected_contract}\n"
            f"Affected Function: {finding.affected_function}\n"
            f"Hypothesis: {finding.hypothesis}\n"
            f"Attack Path: {' -> '.join(finding.attack_path)}\n"
            f"Impact: {finding.impact}\n"
            f"{source_section}"
            f"{rag_context}\n"
            f"{error_rag}\n"
            f"{error_context}\n\n"
            "Generate a complete Foundry test that proves this vulnerability."
        )

        return [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_content}
        ]

    async def run(self, task: WorkerTask) -> WorkerOutput:
        finding = task.context.get("finding")
        if isinstance(finding, list):
            finding = finding[0] if finding else None
        if not finding or not isinstance(finding, Finding):
            print(f"  [TestWriter] ERROR: Missing or invalid finding in task context")
            return WorkerOutput(
                worker_type=self.get_worker_type(),
                confidence=0,
                raw_output={"error": "Missing or invalid finding"}
            )

        relevant_code = task.context.get("relevant_code", {})
        repo_path = task.context.get("repo_path")
        contract_signatures = task.context.get("contract_signatures", {}) or {}

        print(f"\n{'='*70}")
        print(f"  [TestWriter] === START === {finding.affected_contract}::{finding.affected_function}")
        print(f"  [TestWriter] Vulnerability: {finding.vulnerability_class}  |  Confidence: {finding.confidence}")
        print(f"  [TestWriter] Repo path: {repo_path}")
        print(f"  [TestWriter] Relevant code snippets: {len(relevant_code)}  |  Contract signatures: {len(contract_signatures)}")

        remappings = self._get_remappings_from_repo(repo_path)
        if remappings:
            print(f"  [TestWriter] Loaded {len(remappings)} remappings from repo")

        lib_imports: set[str] = set()
        real_sources_full = self._collect_repo_sources(finding, repo_path, remappings, _lib_imports_out=lib_imports)
        real_sources_minimal = self._collect_minimal_sources(finding, repo_path, remappings, _lib_imports_out=lib_imports)
        repo_manifest = self._get_repo_file_manifest(repo_path) if repo_path else []

        import_cheatsheet = self._generate_import_cheatsheet(
            real_sources_full or real_sources_minimal, lib_imports,
        ) if (real_sources_full or real_sources_minimal) else None

        if real_sources_full:
            total_chars = sum(len(v) for v in real_sources_full.values())
            print(f"  [TestWriter] Collected FULL sources: {len(real_sources_full)} files ({total_chars} chars)")
            for p in list(real_sources_full.keys())[:8]:
                print(f"    - {p}  ({len(real_sources_full[p])} chars)")
            print(f"  [TestWriter] Collected MINIMAL sources: {len(real_sources_minimal)} files")
            logger.info(f"[TestWriter] Found real source + deps for {finding.affected_contract}: {len(real_sources_full)} files (minimal: {len(real_sources_minimal)})")
        else:
            print(f"  [TestWriter] No real source found for {finding.affected_contract} — using MOCK mode")
            logger.info(f"[TestWriter] No real source found for {finding.affected_contract}, using mock mode")

        if lib_imports:
            print(f"  [TestWriter] Lib imports detected: {sorted(lib_imports)[:10]}")
        if repo_manifest:
            print(f"  [TestWriter] Repo manifest: {len(repo_manifest)} .sol files")

        # Detect pragma by scanning ALL collected sources (not just the first file).
        sources_to_check = real_sources_full or real_sources_minimal
        target_pragma = self._detect_pragma(sources_to_check) if sources_to_check else None
        if target_pragma:
            print(f"  [TestWriter] Detected pragma: {target_pragma}")
            logger.info(f"[TestWriter] Detected target pragma: {target_pragma}")
        else:
            print(f"  [TestWriter] No pragma detected — LLM will use default")
            logger.info(f"[TestWriter] No pragma detected — LLM will use default")

        # Determine if we need bridge mode (legacy Solidity < 0.8)
        is_legacy = False
        bridge_interfaces_src = ""
        deploy_paths: dict[str, str] = {}
        if target_pragma:
            major, minor = self._parse_pragma_major_minor(target_pragma)
            is_legacy = major == 0 and minor < 8

        # Two-file mode: bridge mode uses ReX architecture.
        # LLM writes AttackContract.sol, scaffold generates ExploitTest.t.sol.
        use_two_file_mode = is_legacy

        if is_legacy:
            print(f"  [TestWriter] BRIDGE MODE activated (pragma {target_pragma} is pre-0.8)")

            # Collect signatures for all contracts referenced in the finding
            from src.utils.graph_queries import get_contract_signatures as _get_sigs
            bridge_contracts = [finding.affected_contract]
            if self.graph is not None:
                for node_id, nd in self.graph.nodes(data=True):
                    if nd.get("type") == "contract" and nd.get("contract") == finding.affected_contract:
                        continue
                    if nd.get("type") == "function" and nd.get("contract") and nd.get("contract") != finding.affected_contract:
                        cname = nd["contract"]
                        if cname not in bridge_contracts:
                            bridge_contracts.append(cname)
                            if len(bridge_contracts) >= 10:
                                break

            all_sigs: dict[str, dict[str, str]] = {}
            for cname in bridge_contracts:
                if self.graph is not None:
                    sigs = _get_sigs(self.graph, cname)
                    if sigs:
                        all_sigs[cname] = sigs

            bridge_interfaces_src = generate_bridge_interfaces(
                bridge_contracts, all_sigs, graph=self.graph,
            )
            for cname in bridge_contracts:
                deploy_paths[cname] = resolve_deploy_code_path(cname, repo_manifest, real_sources_full)

            print(f"  [TestWriter] Generated bridge interfaces for {len(bridge_contracts)} contracts")
            print(f"  [TestWriter] Deploy paths: {deploy_paths}")
        else:
            print(f"  [TestWriter] Standard mode (pragma {target_pragma or 'default'} is 0.8+)")

        # Pre-analyze repo for naming conflicts and abstract contracts.
        repo_conflicts = self._detect_repo_contract_conflicts(
            repo_path if real_sources_full else None
        )
        if repo_conflicts["naming_conflicts"]:
            print(f"  [TestWriter] Naming conflicts: {repo_conflicts['naming_conflicts']}")
            logger.info(f"[TestWriter] Naming conflicts detected: {repo_conflicts['naming_conflicts']}")
        if repo_conflicts["abstract_contracts"]:
            print(f"  [TestWriter] Abstract contracts: {repo_conflicts['abstract_contracts']}")
            logger.info(f"[TestWriter] Abstract contracts detected: {repo_conflicts['abstract_contracts']}")

        # Detect time-lock guard in real source — requires vm.warp() before exploit
        has_timelock = False
        warp_seconds = 0
        all_source_text = "\n".join((real_sources_full or real_sources_minimal or {}).values())
        if all_source_text and _detect_timelock_in_source(all_source_text):
            has_timelock = True
            warp_seconds = 3601  # 1 hour + 1 second — clears any reasonable lock
            print(f"  [TestWriter] TIME-LOCK detected in source — scaffold will vm.warp(+{warp_seconds}s)")
            logger.info(f"[TestWriter] Time-lock guard detected — injecting vm.warp(+{warp_seconds}s) into scaffold")

        attempts = 0
        error_history: list[str] = []
        compiled = False
        exploit_success = False
        test_code_generated = None
        test_logs = ""
        persistent_error_codes: dict[str, int] = {}

        use_repo = repo_path if real_sources_full else None
        sandbox = SandboxManager(repo_path=use_repo)
        try:
            sandbox.setup_foundry_project()

            # EXTRA SAFETY: force forge install if forge-std is still missing
            if not (sandbox.tmp_dir / "lib" / "forge-std" / "src" / "Test.sol").exists():
                print(f"  [TestWriter] forge-std still missing after setup — forcing _ensure_foundry_deps()")
                logger.info("[TestWriter] forge-std missing — forcing lib/ copy")
                sandbox._ensure_foundry_deps()

            # Bridge mode: write BridgeInterfaces.sol and override foundry.toml
            precompiled_data: dict[str, dict] = {}
            if is_legacy:
                primary_sources = real_sources_full or real_sources_minimal
                target_source_rel = next(iter(primary_sources), None) if primary_sources else None
                deploy_paths, precompiled_data = sandbox.setup_bridge_mode_toml(
                    deploy_paths=deploy_paths,
                    target_contract=finding.affected_contract,
                    target_source_path=target_source_rel,
                )
                bridge_path = sandbox.tmp_dir / "test" / "BridgeInterfaces.sol"
                bridge_path.parent.mkdir(parents=True, exist_ok=True)
                bridge_path.write_text(bridge_interfaces_src)
                print(f"  [Sandbox] Wrote BridgeInterfaces.sol ({len(bridge_interfaces_src)} chars)")

            # Two-file mode: write the fixed scaffold before the attempt loop starts.
            # The LLM will never touch this file.
            if use_two_file_mode:
                target_deploy_path = deploy_paths.get(finding.affected_contract, "")
                pc = precompiled_data.get(finding.affected_contract, {})
                scaffold_code = self._generate_test_scaffold(
                    finding, target_deploy_path, is_legacy, target_pragma,
                    bytecode_hex=pc.get("bytecode"),
                    dep_bytecodes=pc.get("dep_bytecodes", {}),
                    ctor_inputs=pc.get("ctor_inputs", []),
                    hardcoded_addrs=pc.get("hardcoded_addrs", []),
                    addr_setters=pc.get("addr_setters", []),
                    warp_seconds=warp_seconds,
                )
                test_path = sandbox.get_test_path()
                scaffold_dest = f"{test_path}/ExploitTest.t.sol"
                sandbox.write_test_file(scaffold_dest, scaffold_code)
                print(
                    f"  [TestWriter] TWO-FILE MODE: scaffold written "
                    f"({len(scaffold_code)} chars) → {target_deploy_path}"
                )

            effective_max = self.MAX_ATTEMPTS
            if not real_sources_full:
                effective_max = min(2, self.MAX_ATTEMPTS)
                print(f"  [TestWriter] MOCK mode — limited to {effective_max} attempts (no real source available)")

            print(f"  [TestWriter] Starting attempt loop (max={effective_max}, LLM timeout={self.LLM_TIMEOUT}s)")

            while attempts < effective_max:
                attempts += 1
                print(f"\n  [TestWriter] ── Attempt {attempts}/{effective_max} {'(BRIDGE)' if is_legacy else ''} ──")

                # ┌─────────────────────────────────────────────────────────────┐
                # │  Phoenix Template-First: attempt 1 uses deterministic PoC  │
                # └─────────────────────────────────────────────────────────────┘
                _used_template = False
                if attempts == 1 and not is_legacy:
                    from src.agents.workers.poc_templates import get_template_for_vuln
                    vuln_class = finding.vulnerability_class or ""
                    _template_fn = get_template_for_vuln(vuln_class)
                    if _template_fn:
                        deploy_path_for_template = deploy_paths.get(
                            finding.affected_contract,
                            f"src/{finding.affected_contract}.sol",
                        )
                        template_pragma = target_pragma or "^0.8.20"
                        test_code_generated = _template_fn(
                            finding, deploy_path_for_template,
                            finding.affected_contract, template_pragma,
                        )
                        print(
                            f"  [TestWriter] Using deterministic template for "
                            f"'{vuln_class}' ({len(test_code_generated)} chars)"
                        )
                        _used_template = True
                    else:
                        print(
                            f"  [TestWriter] No template for '{vuln_class}' — "
                            f"using LLM on attempt 1"
                        )

                if not _used_template:
                    # ── Original LLM path ──
                    sources_for_attempt = real_sources_full if attempts >= 3 else real_sources_minimal
                    source_mode = "FULL" if attempts >= 3 else "MINIMAL"
                    print(f"  [TestWriter] Source mode: {source_mode} ({len(sources_for_attempt) if sources_for_attempt else 0} files)")
                    logger.info(f"[TestWriter] Attempt {attempts}/{effective_max} building prompt...")

                if _used_template:
                    # ── Template-first path: write + compile + test directly ──
                    if use_two_file_mode:
                        test_path = sandbox.get_test_path()
                        attack_path = test_path.parent / "AttackContract.sol"
                        attack_path.write_text(test_code_generated, encoding='utf-8')
                    else:
                        test_path = sandbox.get_test_path()
                        sandbox.write_test_file(test_code_generated)
                    print(f"  [TestWriter] Template written to {test_path}")

                    build_res = sandbox.run_forge_build()
                    if build_res.success:
                        print(f"  [TestWriter] Template compiled successfully!")
                        test_res = sandbox.run_forge_test()
                        test_logs = test_res.logs if hasattr(test_res, 'logs') else ""
                        if test_res.success:
                            print(f"  [TestWriter] Template test PASSED — exploit proven!")
                            compiled = True
                            exploit_success = True
                            break
                        else:
                            print(f"  [TestWriter] Template compiled but test failed — falling through to LLM")
                            error_history.append(f"Template compiled but test failed.\nLogs:\n{test_logs[:400]}")
                    else:
                        build_err = build_res.logs if hasattr(build_res, 'logs') else str(build_res)
                        print(f"  [TestWriter] Template failed to compile — errors will seed LLM attempt")
                        error_history.append(
                            f"[Phoenix template attempt] Compilation failed:\n{build_err[:600]}\n\n"
                            f"Template code:\n{test_code_generated[:1500]}"
                        )
                    continue

                # ── Original LLM path (unchanged indentation) ──
                # Bridge-aware error escalation: if LLM broke rules, inject correction
                if is_legacy and error_history:
                    last_err = error_history[-1]
                    if "incompatible versions" in last_err.lower():
                        error_history[-1] = (
                            "CRITICAL: You imported a legacy .sol file directly. This is FORBIDDEN in bridge mode.\n"
                            "REMOVE ALL imports from contracts/. Use ONLY forge-std/Test.sol and ./BridgeInterfaces.sol.\n"
                            "Deploy legacy contracts with deployCode(), NOT import.\n\n" + last_err
                        )
                    elif "BridgeInterfaces.sol" in last_err:
                        error_history[-1] = (
                            "BridgeInterfaces.sol has a compilation error. Do NOT import BridgeInterfaces.sol.\n"
                            "Instead, define all interfaces you need INLINE in your test file (pragma ^0.8.0).\n"
                            "Only import forge-std/Test.sol. Define minimal interfaces for the functions you call.\n\n"
                            + last_err
                        )
                    elif "DeclarationError" in last_err:
                        error_history[-1] = (
                            "A function or type is missing from BridgeInterfaces.sol. "
                            "Define any missing interfaces inline in your test file (pragma ^0.8.0).\n\n" + last_err
                        )

                if use_two_file_mode:
                    prompt = self._build_attack_only_prompt(
                        finding,
                        error_history,
                        real_sources=sources_for_attempt,
                        deploy_path=deploy_paths.get(finding.affected_contract, ""),
                        is_legacy=is_legacy,
                        target_pragma=target_pragma,
                        skip_rag=(attempts == 1),
                        warp_seconds=warp_seconds,
                        exploit_sequence=task.context.get("exploit_sequence"),
                    )
                elif is_legacy:
                    prompt = self._build_bridge_prompt(
                        finding,
                        relevant_code,
                        error_history,
                        bridge_interfaces_src=bridge_interfaces_src,
                        deploy_paths=deploy_paths,
                        contract_signatures=contract_signatures,
                        real_sources=sources_for_attempt,
                        skip_rag=(attempts == 1),
                        exploit_sequence=task.context.get("exploit_sequence"),
                    )
                else:
                    prompt = self._build_prompt(
                        finding,
                        relevant_code,
                        error_history,
                        real_sources=sources_for_attempt,
                        remappings=remappings,
                        contract_signatures=contract_signatures,
                        repo_manifest=repo_manifest,
                        skip_rag=(attempts == 1),
                        import_cheatsheet=import_cheatsheet,
                        repo_conflicts=repo_conflicts,
                        target_pragma=target_pragma,
                        exploit_sequence=task.context.get("exploit_sequence"),
                    )
                prompt_chars = sum(len(m.get("content", "")) for m in prompt)
                print(f"  [TestWriter] Prompt built: {len(prompt)} messages, {prompt_chars} total chars (RAG={'skip' if attempts==1 else 'on'})")

                try:
                    print(f"  [TestWriter] Calling LLM at {time.strftime('%H:%M:%S')} (timeout={self.LLM_TIMEOUT}s)...")
                    logger.info(
                        f"[TestWriter] Attempt {attempts}/{effective_max} "
                        f"calling LLM for '{finding.affected_contract}::{finding.affected_function}' "
                        f"at {time.strftime('%H:%M:%S')} (timeout={self.LLM_TIMEOUT}s)..."
                    )
                    t_llm = time.time()
                    response = await asyncio.wait_for(
                        asyncio.to_thread(self.llm_client.invoke, prompt),
                        timeout=self.LLM_TIMEOUT
                    )
                    llm_elapsed = time.time() - t_llm
                    content = response.content if hasattr(response, "content") else str(response)
                    if isinstance(content, list):
                        content = "".join([c.get("text", "") if isinstance(c, dict) else str(c) for c in content])
                    print(f"  [TestWriter] LLM responded in {llm_elapsed:.1f}s ({len(content)} chars)")

                    # ── Token tracking ──
                    try:
                        from src.utils.token_counter import get_token_counter
                        input_text = "\n".join(m.get("content", "") for m in prompt)
                        get_token_counter().record(
                            "TestWriterWorker", "gemini-2.5-flash",
                            input_text, content,
                            getattr(response, "response_metadata", None),
                        )
                    except Exception:
                        pass  # Never let tracking break the pipeline

                    test_code_generated = self._extract_test_code(content)
                    if not test_code_generated:
                        print(f"  [TestWriter] SKIP: No extractable Solidity code in LLM response")
                        print(f"  [TestWriter]   Response preview: {content[:150]}...")
                        logger.info(f"[TestWriter] Attempt {attempts}: LLM returned NO extractable Solidity code.")
                        logger.info(f"[TestWriter]   Response preview: {content[:200]}...")
                        error_history.append("No Solidity code returned by LLM")
                        continue

                    print(f"  [TestWriter] Extracted test code: {len(test_code_generated)} chars, {test_code_generated.count(chr(10))+1} lines")
                    funcs = re.findall(r'function\s+(\w+)\s*\(', test_code_generated)
                    print(f"  [TestWriter] Functions found: {funcs}")

                    original_len = len(test_code_generated)
                    test_code_generated = self._deduplicate_interfaces(test_code_generated)
                    test_code_generated = self._fix_exploit_succeeded_conflict(test_code_generated)
                    if len(test_code_generated) != original_len:
                        print(f"  [TestWriter] Deduplicated AttackContract: {original_len} → {len(test_code_generated)} chars")

                    if use_two_file_mode:
                        # LLM wrote AttackContract.sol — validate it has the right structure
                        if not re.search(r'\bcontract\s+AttackContract\b', test_code_generated):
                            print(f"  [TestWriter] SKIP: Missing 'contract AttackContract' — retrying")
                            error_history.append(
                                "The file must define 'contract AttackContract'. Do not rename it."
                            )
                            continue
                        if not re.search(r'\bfunction\s+execute\s*\(', test_code_generated):
                            print(f"  [TestWriter] SKIP: Missing 'function execute()' — retrying")
                            error_history.append(
                                "AttackContract must include 'function execute() external payable'."
                            )
                            continue
                        # Write only the attack contract — scaffold is already written
                        test_path = sandbox.get_test_path()
                        test_file = f"{test_path}/AttackContract.sol"
                        sandbox.write_test_file(test_file, test_code_generated)
                        print(
                            f"  [TestWriter] Wrote AttackContract.sol "
                            f"({len(test_code_generated)} chars)"
                        )
                    else:
                        if not self._has_exact_test_exploit(test_code_generated):
                            print(f"  [TestWriter] SKIP: Missing 'function test_exploit()' — retrying")
                            logger.info(f"[TestWriter] Attempt {attempts}: Missing 'function test_exploit()' in generated code.")
                            if funcs:
                                logger.info(f"[TestWriter]   Found functions: {funcs}")
                            error_history.append("Generated test must include function test_exploit() exactly.")
                            continue

                        if not is_legacy and not use_two_file_mode:
                            test_code_generated = self._auto_correct_imports(
                                test_code_generated, sandbox, remappings,
                                collected_paths=list(sources_for_attempt.keys()) if sources_for_attempt else None,
                            )

                        test_path = sandbox.get_test_path()
                        test_file = f"{test_path}/ExploitTest.t.sol"
                        sandbox.write_test_file(test_file, test_code_generated)

                    # ── Compile & Test in one step ──────────────────
                    forge_cmd = (
                        "forge test --match-test test_exploit -vvvv"
                        " --ignored-error-codes 8429 --ignored-error-codes 2424"
                    )
                    print(f"  [TestWriter] Running forge test...")
                    test_res = sandbox.run(forge_cmd)
                    test_logs = (test_res.stdout or "") + "\n" + (test_res.stderr or "")

                    # Distinguish compilation failure from test failure
                    is_compile_error = (
                        "Compiler run failed" in test_logs
                        or "Error (" in test_logs
                        or "ParserError" in test_logs
                        or "Found incompatible versions" in test_logs
                        or "Error: Compilation failed" in test_logs
                        or "Error: Solc" in test_logs
                    )

                    if not test_res.success and is_compile_error:
                        err_lines = [
                            ln for ln in test_logs.splitlines()
                            if ("Error" in ln and "Warning" not in ln)
                            or ln.strip().startswith("-->")
                            or ln.strip().startswith("|")
                        ]
                        if not err_lines:
                            err_lines = [ln for ln in test_logs[:2000].splitlines()
                                         if ln.strip() and "Warning:" not in ln]
                        short_err = "\n".join(err_lines[:20]) if err_lines else test_logs[:600]

                        print(f"  [TestWriter] COMPILE FAILED (attempt {attempts}):")
                        for line in short_err.splitlines()[:10]:
                            print(f"    {line}")
                        logger.info(f"[TestWriter] Attempt {attempts} build error:\n{short_err}")

                        # ── Classify error and inject targeted fix directive ──────────────
                        targeted_fix = _classify_compile_error(short_err)
                        if targeted_fix:
                            print(f"  [TestWriter] Error classified — injecting targeted fix")
                            error_entry = f"{targeted_fix}\n\nFull compiler output:\n{short_err}"
                        else:
                            error_entry = f"Build Failed:\n{short_err}"

                        # ── Loop detection: same error code appearing 2+ times ───────────
                        error_codes_this_attempt = re.findall(r'Error \((\d+)\)', short_err)
                        for code in error_codes_this_attempt:
                            persistent_error_codes[code] = persistent_error_codes.get(code, 0) + 1

                        looping_codes = [c for c, n in persistent_error_codes.items() if n >= 2]
                        if looping_codes:
                            loop_msg = (
                                f"\n\nLOOP DETECTED — Error(s) {looping_codes} appeared "
                                f"{max(persistent_error_codes.get(c, 0) for c in looping_codes)} times in a row. "
                                f"Your current approach is NOT working. You MUST completely change strategy:\n"
                                f"- If you inherited a large interface → drop it, write minimal standalone mock\n"
                                f"- If you used contract types as function arguments → switch all to address\n"
                                f"- If you imported from contracts/ or src/ → stop, use deployCode() only\n"
                                f"- If you wrote a mock of the target contract → stop, deploy the real one\n"
                                f"Do not repeat any pattern from your previous attempts."
                            )
                            error_entry += loop_msg
                            print(f"  [TestWriter] Loop detected on error codes {looping_codes} — injecting strategy switch")

                        error_history.append(error_entry)
                        compiled = False
                        out_dir = Path(sandbox.tmp_dir) / "out"
                        if out_dir.exists():
                            shutil.rmtree(out_dir, ignore_errors=True)
                        continue

                    compiled = True
                    passed_by_logs = "[PASS]" in test_logs or "exploit succeeded" in test_logs.lower()
                    exploit_success = test_res.success and passed_by_logs

                    print(f"  [TestWriter] COMPILED OK  |  forge_success={test_res.success}  |  [PASS] in logs={passed_by_logs}  |  exploit_success={exploit_success}")
                    print(f"  [TestWriter] FORGE STDOUT:\n{test_res.stdout}")   


                    if exploit_success:
                        # ── Authenticity gate ─────────────────────────────────────────────
                        if use_two_file_mode:
                            # Authenticity guaranteed by architecture —
                            # LLM only wrote AttackContract.sol, never touched deployCode()
                            authentic = True
                            auth_reason = "AUTHENTIC (two-file mode)"
                        else:
                            authentic, auth_reason = self._check_test_authenticity(
                                test_code_generated,
                                finding.affected_contract,
                                is_legacy,
                            )
                        if not authentic:
                            print(f"  [TestWriter] FABRICATED PROOF REJECTED: {auth_reason}")
                            logger.info(f"[TestWriter] Attempt {attempts}: Fabricated proof detected — {auth_reason}")
                            exploit_success = False
                            error_history.append(
                                f"FABRICATED TEST REJECTED — your test did not test the real contract:\n"
                                f"{auth_reason}\n\n"
                                f"You MUST:\n"
                                f"  1. Deploy the real {finding.affected_contract} via deployCode() (bridge mode) "
                                f"or direct import (standard mode)\n"
                                f"  2. NOT define `contract {finding.affected_contract}` or any mock of it in your test\n"
                                f"  3. Test the actual deployed contract, not a fictional version you wrote yourself\n"
                            )
                            continue

                        print(f"  [TestWriter] EXPLOIT PROVEN (authentic) on attempt {attempts}!")
                        for line in test_logs.splitlines():
                            if "[PASS]" in line or "test_exploit" in line:
                                print(f"    {line.strip()}")
                        break

                    # Show why test failed even though it compiled
                    print(f"  [TestWriter] Test compiled but exploit FAILED")
                    fail_lines = [ln for ln in test_logs.splitlines() if "[FAIL]" in ln or "Error" in ln or "revert" in ln.lower()]
                    for line in fail_lines[:5]:
                        print(f"    {line.strip()}")

                    # ── Time-lock silent no-op detection ─────────────────────────────────
                    if _detect_timelock_failure(test_logs):
                        print(f"  [TestWriter] TIME-LOCK SILENT NO-OP detected in trace")
                        logger.info(f"[TestWriter] Attempt {attempts}: Time-lock silent no-op — warp needed")
                        if not has_timelock:
                            # Wasn't caught at source-scan time — escalate warp now
                            has_timelock = True
                            warp_seconds = 3601
                            # Rewrite scaffold with warp injected
                            if use_two_file_mode:
                                target_deploy_path = deploy_paths.get(finding.affected_contract, "")
                                pc = precompiled_data.get(finding.affected_contract, {})
                                scaffold_code = self._generate_test_scaffold(
                                    finding, target_deploy_path, is_legacy, target_pragma,
                                    bytecode_hex=pc.get("bytecode"),
                                    dep_bytecodes=pc.get("dep_bytecodes", {}),
                                    ctor_inputs=pc.get("ctor_inputs", []),
                                    hardcoded_addrs=pc.get("hardcoded_addrs", []),
                                    addr_setters=pc.get("addr_setters", []),
                                    warp_seconds=warp_seconds,
                                )
                                scaffold_dest = f"{sandbox.get_test_path()}/ExploitTest.t.sol"
                                sandbox.write_test_file(scaffold_dest, scaffold_code)
                                print(f"  [TestWriter] Rewrote scaffold with vm.warp(+{warp_seconds}s)")
                        error_history.append(
                            f"TIME-LOCK GUARD: The contract has a time-lock (unlockTime / lockTime). "
                            f"The withdraw/collect call returned immediately with no state change — "
                            f"this is because `now > unlockTime` was FALSE.\n"
                            f"The scaffold now calls vm.warp(block.timestamp + {warp_seconds}) before execute().\n"
                            f"Your AttackContract.execute() MUST:\n"
                            f"  1. Call the DEPOSIT function (Put/deposit) to register the attacker's account\n"
                            f"  2. NOT call vm.warp — time is already advanced by the scaffold\n"
                            f"  3. Call the WITHDRAW function (Collect/CashOut) — time is now past the lock\n"
                            f"  4. Re-enter inside receive() to drain more ETH\n"
                            f"Logs:\n{test_logs[:300]}"
                        )
                        continue

                    # ── Guard hit detection ───────────────────────────────────────────────
                    if _detect_guard_hit(test_logs):
                        print(f"  [TestWriter] GUARD CONFIRMED — real protection exists, exploit is falsified")
                        print(f"  [TestWriter] Stopping early — no point retrying against a real guard")
                        logger.info(f"[TestWriter] Attempt {attempts}: Guard hit detected — FALSIFIED. Stopping.")
                        # compiled=True intentional: guard hit is useful signal, confidence adjustment should be 0 not -10
                        # Mark as compiled (we got useful signal) but not proven
                        # Break so the loop exits and we return compiled=True, exploit_success=False
                        break

                    error_history.append(f"Test compiled but exploit check failed.\nLogs:\n{test_logs[:400]}")
                    logger.info(f"[TestWriter] Attempt {attempts}: Test compiled but exploit FAILED.")
                    logger.info(f"[TestWriter]   test_res.success={test_res.success}, passed_by_logs={passed_by_logs}")
                    if test_logs:
                        logger.info(f"[TestWriter]   Logs: {test_logs[:300]}...")

                except asyncio.TimeoutError:
                    msg = f"LLM call timed out after {self.LLM_TIMEOUT}s"
                    print(f"  [TestWriter] TIMEOUT: {msg}")
                    logger.info(f"[TestWriterWorker] {msg}")
                    error_history.append(msg)
                except Exception as e:
                    print(f"  [TestWriter] ERROR: {e}")
                    logger.info(f"[TestWriterWorker] LLM call failed: {e}")
                    error_history.append(str(e))

        finally:
            # BUG-005 fix: save exploit artifacts before cleanup on success
            if exploit_success and test_code_generated:
                try:
                    proven_dir = Path("proven_exploits")
                    proven_dir.mkdir(exist_ok=True)
                    task_slug = task.task_id.replace("/", "_").replace("::", "_")[:60]
                    artifact_path = proven_dir / f"{task_slug}.t.sol"
                    artifact_path.write_text(test_code_generated, encoding='utf-8')
                    print(f"  [TestWriter] Saved proven exploit artifact: {artifact_path}")
                except Exception as e:
                    print(f"  [TestWriter] Warning: could not save proven exploit artifact: {e}")
                    logger.info(f"[TestWriter] Warning: could not save proven exploit artifact: {e}")
            sandbox.cleanup()

        original_conf = getattr(finding, "confidence", 50)
        if compiled and exploit_success:
            adjustment = 60
        elif compiled:
            adjustment = 0
        else:
            adjustment = -10
        final_confidence = max(0, min(100, original_conf + adjustment))

        print(f"  [TestWriter] === RESULT === {finding.affected_contract}::{finding.affected_function}")
        print(f"  [TestWriter]   Mode: {'BRIDGE' if is_legacy else 'STANDARD'}  |  Attempts: {attempts}/{effective_max}")
        print(f"  [TestWriter]   Compiled: {compiled}  |  Exploit proven: {exploit_success}")
        print(f"  [TestWriter]   Confidence: {original_conf} -> {final_confidence} (adjustment={adjustment:+d})")
        print(f"  [TestWriter]   Used real source: {bool(real_sources_full)}")
        if error_history:
            print(f"  [TestWriter]   Last error: {error_history[-1][:150]}")
        print(f"{'='*70}\n")

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
                "last_error": error_history[-1] if error_history else None,
                "used_real_source": bool(real_sources_full),
                "bridge_mode": is_legacy,
            }
        )