"""
Deterministic Harness Builder — Phase A of the TestWriter pipeline.

Builds a compilable Foundry test harness (setUp + imports + deployment)
WITHOUT LLM involvement.  The LLM only writes the test_exploit() body.

Approach:
  1. Run `forge build` in the sandbox (already happens during setup)
  2. Read the ABI from out/Contract.sol/Contract.json
  3. Extract constructor params deterministically from ABI
  4. Generate minimal mocks for address/interface dependencies
  5. Build a compilable setUp() with correct deployment
  6. Verify compilation BEFORE calling the LLM

Inspired by PoCo (KTH, 2025) and the `forge inspect` ABI artifact approach.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════
#  Data classes
# ═══════════════════════════════════════════════════════════════════

@dataclass
class ConstructorParam:
    name: str
    type: str           # e.g. "address", "uint256", "bool", "bytes32"
    components: list     # for tuple types

    @property
    def is_address(self) -> bool:
        return self.type == "address"

    @property
    def is_numeric(self) -> bool:
        return self.type.startswith(("uint", "int"))

    @property
    def is_bool(self) -> bool:
        return self.type == "bool"

    @property
    def is_bytes(self) -> bool:
        return self.type.startswith("bytes")

    @property
    def is_string(self) -> bool:
        return self.type == "string"


@dataclass
class ConstructorInfo:
    params: list[ConstructorParam]
    source: str             # "abi_artifact" | "graph" | "regex" | "none"
    is_payable: bool = False
    is_abstract: bool = False
    raw_signature: str = ""


@dataclass
class HarnessResult:
    """Output of the harness builder."""
    harness_code: str           # Complete ExploitTest.t.sol with placeholder
    exploit_prompt: str         # Focused prompt for LLM (exploit body only)
    compiled: bool              # Whether the harness compiled successfully
    compile_error: str          # Error message if compilation failed
    constructor_info: ConstructorInfo
    target_import: str          # e.g. 'import "src/Vault.sol";'
    deploy_statement: str       # e.g. 'target = new Vault(address(mock), 100);'
    available_state: dict       # Variables the LLM can use in test_exploit()
    mock_code: str              # Mock contracts defined at file level
    is_legacy: bool             # Whether bridge mode (deployCode) is used

    # Placeholder marker in harness_code
    PLACEHOLDER = "// __EXPLOIT_BODY_PLACEHOLDER__"

    def inject_exploit(self, exploit_body: str, helper_contracts: str = "") -> str:
        """Inject LLM-generated exploit body into the harness."""
        code = self.harness_code
        if helper_contracts:
            # Insert helper contracts before the ExploitTest contract
            marker = "contract ExploitTest is Test {"
            code = code.replace(marker, f"{helper_contracts}\n\n{marker}")
        return code.replace(self.PLACEHOLDER, exploit_body)


# ═══════════════════════════════════════════════════════════════════
#  Harness Builder
# ═══════════════════════════════════════════════════════════════════

class HarnessBuilder:
    """
    Builds a deterministic, compilable Foundry test harness for a Finding.

    Uses the ABI-first approach:
      1. Read compiled ABI from forge build artifacts (out/ directory)
      2. Extract constructor parameters from ABI JSON
      3. Generate setUp() deterministically
      4. Compile and verify before handing off to LLM
    """

    def __init__(self, graph, sandbox=None):
        """
        Args:
            graph:   NetworkX graph with contract/function nodes
            sandbox: SandboxManager instance for running forge commands
        """
        self.graph = graph
        self.sandbox = sandbox

    # ─── Public API ──────────────────────────────────────────────────

    def build(
        self,
        finding,
        collected_sources: dict[str, str],
        is_legacy: bool,
        pragma: str | None,
        deploy_path: str = "",
        contract_signatures: dict[str, str] | None = None,
    ) -> HarnessResult:
        """
        Build a compilable harness for the given finding.

        Args:
            finding:              Finding object with affected_contract, vulnerability_class, etc.
            collected_sources:    Dict of {relative_path: source_code} from _collect_repo_sources
            is_legacy:            True if contract uses pre-0.8 Solidity
            pragma:               Detected pragma version (e.g. "^0.8.17")
            deploy_path:          For legacy: deployCode path (e.g. "contracts/X.sol:X")
            contract_signatures:  Dict of function name → signature string
        """
        contract_name = finding.affected_contract
        vuln_class = (finding.vulnerability_class or "").lower()
        target_pragma = "^0.8.0" if is_legacy else (pragma or "^0.8.17")

        # Step 1: Extract constructor info
        ctor = self._extract_constructor_info(
            contract_name, collected_sources, deploy_path
        )
        logger.info(
            f"[Harness] Constructor for {contract_name}: "
            f"{len(ctor.params)} params, source={ctor.source}, "
            f"abstract={ctor.is_abstract}"
        )
        print(f"  [Harness] Constructor: {ctor.raw_signature or '()'} "
              f"[{ctor.source}] abstract={ctor.is_abstract}")

        # Step 2: Determine target import path
        target_import = self._resolve_target_import(
            contract_name, collected_sources, is_legacy
        )

        # Step 3: Generate mocks for constructor dependencies
        mock_code, mock_vars = self._generate_mocks(ctor, contract_name)

        # Step 4: Generate deployment statement
        deploy_stmt = self._generate_deploy_statement(
            contract_name, ctor, mock_vars, is_legacy, deploy_path
        )

        # Step 5: Build available state variables
        available_state = self._build_available_state(
            contract_name, ctor, mock_vars, is_legacy
        )

        # Step 6: Generate harness code
        harness_code = self._render_harness(
            contract_name=contract_name,
            target_import=target_import,
            mock_code=mock_code,
            deploy_stmt=deploy_stmt,
            pragma=target_pragma,
            is_legacy=is_legacy,
            vuln_class=vuln_class,
            available_state=available_state,
        )

        # Step 7: Build the exploit-body-only prompt
        exploit_prompt = self._build_exploit_prompt(
            finding=finding,
            available_state=available_state,
            collected_sources=collected_sources,
            contract_signatures=contract_signatures or {},
        )

        # Step 8: Try to compile the harness
        compiled = False
        compile_error = ""
        if self.sandbox:
            compiled, compile_error = self._verify_compilation(harness_code)
            if not compiled:
                print(f"  [Harness] Initial compilation failed, attempting auto-fix...")
                harness_code, compiled, compile_error = self._auto_fix_harness(
                    harness_code, compile_error, contract_name, ctor,
                    collected_sources, is_legacy, deploy_path
                )

        return HarnessResult(
            harness_code=harness_code,
            exploit_prompt=exploit_prompt,
            compiled=compiled,
            compile_error=compile_error,
            constructor_info=ctor,
            target_import=target_import,
            deploy_statement=deploy_stmt,
            available_state=available_state,
            mock_code=mock_code,
            is_legacy=is_legacy,
        )

    # ─── Constructor Extraction ──────────────────────────────────────

    def _extract_constructor_info(
        self,
        contract_name: str,
        collected_sources: dict[str, str],
        deploy_path: str = "",
    ) -> ConstructorInfo:
        """
        Extract constructor info using multiple strategies:
          1. Forge build artifacts (ABI JSON) — most reliable
          2. Graph nodes — if Slither parsed it
          3. Source regex — fallback
        """
        # Strategy 1: ABI from forge build artifacts
        ctor = self._try_abi_artifact(contract_name)
        if ctor:
            return ctor

        # Strategy 2: Graph node
        ctor = self._try_graph_node(contract_name)
        if ctor:
            return ctor

        # Strategy 3: Source regex
        target_source = self._find_target_source(contract_name, collected_sources)
        if target_source:
            ctor = self._try_source_regex(contract_name, target_source)
            if ctor:
                return ctor
            # Check if abstract
            is_abstract = bool(re.search(
                rf'\babstract\s+contract\s+{re.escape(contract_name)}\b',
                target_source
            ))
            if is_abstract:
                return ConstructorInfo(
                    params=[], source="regex", is_abstract=True,
                    raw_signature="abstract"
                )

        # Default: zero-arg constructor
        return ConstructorInfo(params=[], source="none")

    def _try_abi_artifact(self, contract_name: str) -> ConstructorInfo | None:
        """Read constructor from forge build artifacts in out/ directory."""
        if not self.sandbox:
            return None

        # Try common artifact paths
        candidates = [
            f"out/{contract_name}.sol/{contract_name}.json",
            f"out/src/{contract_name}.sol/{contract_name}.json",
            f"out/contracts/{contract_name}.sol/{contract_name}.json",
        ]

        for rel_path in candidates:
            artifact_path = self.sandbox.tmp_dir / rel_path
            if not artifact_path.exists():
                continue

            try:
                data = json.loads(artifact_path.read_text(encoding="utf-8"))
                abi = data.get("abi", [])

                # Check if abstract (no bytecode)
                bytecode = data.get("bytecode", {}).get("object", "")
                is_abstract = not bytecode or bytecode == "0x"

                # Find constructor in ABI
                ctor_entry = next(
                    (e for e in abi if e.get("type") == "constructor"), None
                )

                if ctor_entry is None:
                    # No explicit constructor = zero-arg
                    return ConstructorInfo(
                        params=[], source="abi_artifact",
                        is_abstract=is_abstract,
                        is_payable=False,
                        raw_signature="constructor()",
                    )

                params = []
                for inp in ctor_entry.get("inputs", []):
                    params.append(ConstructorParam(
                        name=inp.get("name", f"_arg{len(params)}"),
                        type=inp.get("type", "address"),
                        components=inp.get("components", []),
                    ))

                payable = ctor_entry.get("stateMutability") == "payable"
                types_str = ",".join(p.type for p in params)
                raw_sig = f"constructor({types_str})"

                logger.info(
                    f"[Harness] ABI artifact found: {rel_path} → {raw_sig}"
                )
                return ConstructorInfo(
                    params=params,
                    source="abi_artifact",
                    is_payable=payable,
                    is_abstract=is_abstract,
                    raw_signature=raw_sig,
                )
            except Exception as e:
                logger.warning(f"[Harness] Failed to parse artifact {rel_path}: {e}")
                continue

        return None

    def _try_graph_node(self, contract_name: str) -> ConstructorInfo | None:
        """Extract constructor from the knowledge graph."""
        if not self.graph:
            return None

        ctor_node = f"{contract_name}::constructor"
        if not self.graph.has_node(ctor_node):
            return None

        data = self.graph.nodes[ctor_node]
        sig = data.get("signature", "")
        source_code = data.get("source_code", "")
        is_payable = data.get("is_payable", False)

        if not sig:
            return None

        # Parse "constructor(address,uint256)" → params
        match = re.search(r'constructor\(([^)]*)\)', sig)
        if not match:
            return ConstructorInfo(
                params=[], source="graph", is_payable=is_payable,
                raw_signature=sig,
            )

        type_strs = [t.strip() for t in match.group(1).split(",") if t.strip()]
        # Try to extract names from source code
        names = self._extract_param_names(source_code, len(type_strs))

        params = []
        for i, t in enumerate(type_strs):
            name = names[i] if i < len(names) else f"_arg{i}"
            params.append(ConstructorParam(name=name, type=t, components=[]))

        return ConstructorInfo(
            params=params, source="graph", is_payable=is_payable,
            raw_signature=sig,
        )

    def _try_source_regex(self, contract_name: str, source: str) -> ConstructorInfo | None:
        """Extract constructor from source code via regex."""
        # Match constructor(type1 name1, type2 name2, ...)
        match = re.search(
            r'constructor\s*\(([^)]*)\)',
            source,
        )
        if not match:
            return None

        params_str = match.group(1).strip()
        if not params_str:
            return ConstructorInfo(
                params=[], source="regex",
                raw_signature="constructor()",
            )

        params = []
        for chunk in params_str.split(","):
            parts = chunk.strip().split()
            if len(parts) >= 2:
                # "address _oracle" or "address payable _oracle"
                ptype = parts[0]
                if parts[1] == "payable":
                    ptype = "address payable"
                    pname = parts[2] if len(parts) > 2 else f"_arg{len(params)}"
                elif parts[1] in ("memory", "calldata", "storage"):
                    pname = parts[2] if len(parts) > 2 else f"_arg{len(params)}"
                else:
                    pname = parts[-1]
                params.append(ConstructorParam(
                    name=pname, type=ptype, components=[]
                ))
            elif len(parts) == 1:
                params.append(ConstructorParam(
                    name=f"_arg{len(params)}", type=parts[0], components=[]
                ))

        types_str = ",".join(p.type for p in params)
        return ConstructorInfo(
            params=params, source="regex",
            raw_signature=f"constructor({types_str})",
        )

    # ─── Mock Generation ─────────────────────────────────────────────

    def _generate_mocks(
        self, ctor: ConstructorInfo, contract_name: str
    ) -> tuple[str, dict[str, str]]:
        """
        Generate minimal mock contracts for constructor dependencies.

        Returns:
            mock_code: Solidity code for mock contracts (file-level)
            mock_vars: Dict of param_name → mock variable name for setUp()
        """
        mock_blocks: list[str] = []
        mock_vars: dict[str, str] = {}

        for param in ctor.params:
            if not param.is_address:
                continue

            clean_name = param.name.lstrip("_")
            mock_name = f"Mock{clean_name.title()}"
            var_name = f"mock{clean_name.title()}"

            # Try to find interface functions from graph
            functions = self._get_interface_functions(clean_name)

            if functions:
                stubs = []
                for fname, freturn in functions:
                    stubs.append(
                        f"    function {fname} external pure returns ({freturn}) "
                        f"{{ return {self._default_return(freturn)}; }}"
                    )
                mock_body = "\n".join(stubs)
                mock_blocks.append(
                    f"contract {mock_name} {{\n"
                    f"    fallback() external payable {{}}\n"
                    f"    receive() external payable {{}}\n"
                    f"{mock_body}\n"
                    f"}}"
                )
            else:
                # Generic mock: just needs to exist at an address
                mock_blocks.append(
                    f"contract {mock_name} {{\n"
                    f"    fallback() external payable {{}}\n"
                    f"    receive() external payable {{}}\n"
                    f"}}"
                )

            mock_vars[param.name] = var_name

        mock_code = "\n\n".join(mock_blocks) if mock_blocks else ""
        return mock_code, mock_vars

    def _get_interface_functions(self, name_hint: str) -> list[tuple[str, str]]:
        """Try to find common interface functions from the graph."""
        if not self.graph:
            return []

        # Look for interface nodes that match the param name
        candidates = []
        name_lower = name_hint.lower()
        for node_id, data in self.graph.nodes(data=True):
            if data.get("type") != "contract":
                continue
            node_lower = node_id.lower()
            if (name_lower in node_lower or node_lower in name_lower) and \
               data.get("is_interface", False):
                candidates.append(node_id)

        if not candidates:
            return []

        # Get functions from the first matching interface
        iface = candidates[0]
        functions = []
        for _, target, edge_data in self.graph.out_edges(iface, data=True):
            if edge_data.get("relationship") == "DEFINES":
                func_data = self.graph.nodes.get(target, {})
                if func_data.get("type") == "function":
                    fname = func_data.get("name", "")
                    sig = func_data.get("signature", "")
                    if fname and not func_data.get("is_constructor"):
                        # Determine return type from signature (simplified)
                        ret = "uint256"  # default
                        functions.append((fname, ret))
        return functions[:5]  # Limit to 5 stubs

    # ─── Deployment ──────────────────────────────────────────────────

    def _generate_deploy_statement(
        self,
        contract_name: str,
        ctor: ConstructorInfo,
        mock_vars: dict[str, str],
        is_legacy: bool,
        deploy_path: str,
    ) -> str:
        """Generate the deployment statement for setUp()."""
        args = self._build_constructor_args(ctor, mock_vars)

        if is_legacy:
            if args:
                return (
                    f'address targetAddr = deployCode("{deploy_path}", '
                    f'abi.encode({args}));\n'
                    f'        target = targetAddr;'
                )
            return (
                f'address targetAddr = deployCode("{deploy_path}");\n'
                f'        target = targetAddr;'
            )
        else:
            if ctor.is_abstract:
                return (
                    f"// {contract_name} is abstract — cannot deploy directly.\n"
                    f"        // TODO: deploy a concrete subclass or use deployCode\n"
                    f"        revert(\"abstract contract\");"
                )
            if args:
                return f"{contract_name} targetInstance = new {contract_name}({args});\n        target = address(targetInstance);"
            return f"{contract_name} targetInstance = new {contract_name}();\n        target = address(targetInstance);"

    def _build_constructor_args(
        self, ctor: ConstructorInfo, mock_vars: dict[str, str]
    ) -> str:
        """Build comma-separated constructor arguments."""
        if not ctor.params:
            return ""

        parts = []
        for p in ctor.params:
            if p.name in mock_vars:
                parts.append(f"address({mock_vars[p.name]})")
            elif p.is_address:
                parts.append("address(0)")
            elif p.is_numeric:
                # Use sensible defaults based on name heuristics
                name_lower = p.name.lower()
                if "fee" in name_lower or "bps" in name_lower:
                    parts.append("100")  # 1% in bps
                elif "decimals" in name_lower:
                    parts.append("18")
                elif "rate" in name_lower:
                    parts.append("1e18")
                elif "max" in name_lower:
                    parts.append("type(uint256).max")
                else:
                    parts.append("0")
            elif p.is_bool:
                parts.append("false")
            elif p.is_string:
                parts.append('""')
            elif p.is_bytes:
                if p.type == "bytes32":
                    parts.append('bytes32(0)')
                else:
                    parts.append('""')
            else:
                parts.append(f"{p.type}(0)")

        return ", ".join(parts)

    # ─── Harness Rendering ───────────────────────────────────────────

    def _render_harness(
        self,
        contract_name: str,
        target_import: str,
        mock_code: str,
        deploy_stmt: str,
        pragma: str,
        is_legacy: bool,
        vuln_class: str,
        available_state: dict,
    ) -> str:
        """Render the complete ExploitTest.t.sol."""
        imports = 'import "forge-std/Test.sol";'
        if target_import and not is_legacy:
            imports += f'\n{target_import}'

        # Mock variable declarations
        mock_decl_lines = ""
        for var_name, var_type in available_state.get("mock_declarations", {}).items():
            mock_decl_lines += f"    {var_type} public {var_name};\n"

        # Mock deployment in setUp
        mock_deploy_lines = ""
        for var_name, var_type in available_state.get("mock_declarations", {}).items():
            mock_deploy_lines += f"        {var_name} = new {var_type}();\n"

        state_header = self._format_state_comment(available_state)

        return f"""// SPDX-License-Identifier: UNLICENSED
// AUTO-GENERATED HARNESS — Phase A (deterministic)
// LLM writes ONLY the test_exploit() body.
pragma solidity {pragma};

{imports}

{mock_code}

contract ExploitTest is Test {{
    address public target;
{mock_decl_lines}    address attacker = makeAddr("attacker");
    address victim = makeAddr("victim");

    function setUp() public {{
{mock_deploy_lines}        {deploy_stmt}
        vm.deal(attacker, 100 ether);
        vm.deal(victim, 100 ether);
        vm.deal(target, 10 ether);
    }}

    function test_exploit() public {{
{state_header}
        {HarnessResult.PLACEHOLDER}
    }}
}}
"""

    # ─── Exploit Prompt ──────────────────────────────────────────────

    def _build_exploit_prompt(
        self,
        finding,
        available_state: dict,
        collected_sources: dict[str, str],
        contract_signatures: dict[str, str],
    ) -> str:
        """Build a focused prompt for the LLM to write ONLY the exploit body."""

        # Format available state
        state_lines = []
        for var_name, var_desc in available_state.get("variables", {}).items():
            state_lines.append(f"  - {var_name}: {var_desc}")
        state_section = "\n".join(state_lines) if state_lines else "  - target: address (deployed contract)"

        # Format function signatures
        sig_lines = []
        for fname, fsig in contract_signatures.items():
            sig_lines.append(f"  {fsig}")
        sig_section = "\n".join(sig_lines[:30]) if sig_lines else "  (no signatures available)"

        # Full target source (NEVER truncated)
        target_source = ""
        for path, code in collected_sources.items():
            target_source += f"// ── {path} ──\n{code}\n\n"
            if len(target_source) > 80_000:  # Safety valve
                target_source += "// ... (additional files omitted for context limit)\n"
                break

        hypothesis = getattr(finding, "hypothesis", "") or ""
        vuln_class = finding.vulnerability_class or ""
        affected_func = getattr(finding, "affected_function", "") or ""
        attack_path = getattr(finding, "attack_path", []) or []
        attack_path_str = " → ".join(attack_path) if attack_path else "(not specified)"

        return f"""You are writing ONLY the body of test_exploit().
The setUp() function is already written and compiles successfully.
DO NOT write imports, pragma, setUp(), or contract ExploitTest.

═══════════════════════════════════════════════════
AVAILABLE STATE (set up in setUp)
═══════════════════════════════════════════════════
{state_section}

═══════════════════════════════════════════════════
AVAILABLE CHEATCODES
═══════════════════════════════════════════════════
  vm.prank(addr)        — next call comes from addr
  vm.startPrank(addr)   — all subsequent calls from addr (until stopPrank)
  vm.stopPrank()        — stop pranking
  vm.deal(addr, amount) — set ETH balance
  vm.warp(timestamp)    — set block.timestamp
  vm.roll(blockNum)     — set block.number
  vm.store(addr, slot, val) — write to storage slot
  vm.load(addr, slot)   — read storage slot
  makeAddr("name")      — create deterministic address

═══════════════════════════════════════════════════
VULNERABILITY
═══════════════════════════════════════════════════
  Class:     {vuln_class}
  Function:  {affected_func}
  Hypothesis: {hypothesis}
  Attack Path: {attack_path_str}

═══════════════════════════════════════════════════
CONTRACT FUNCTION SIGNATURES
═══════════════════════════════════════════════════
{sig_section}

═══════════════════════════════════════════════════
TARGET CONTRACT SOURCE (full, untruncated)
═══════════════════════════════════════════════════
{target_source}

═══════════════════════════════════════════════════
OUTPUT FORMAT
═══════════════════════════════════════════════════
Output TWO code blocks:

1. HELPER CONTRACTS (optional — for reentrancy callbacks, flash loan receivers, etc.)
   Output at file-level, they'll be inserted before ExploitTest:

```solidity
// HELPERS
contract Attacker {{
    ...
}}
```

2. EXPLOIT BODY (required — goes inside test_exploit()):

```solidity
// EXPLOIT
vm.startPrank(attacker);
...
assertGt(attacker.balance, 0, "exploit failed");
```

RULES:
- The target contract is deployed at `target` (address).
- To call functions, cast: ContractType(target).functionName(...)
- If the vulnerability requires role impersonation, use vm.prank().
- ALWAYS end with an assertion that FAILS if the exploit doesn't work.
- If you define helper contracts, they receive `target` as constructor arg.
"""

    # ─── Compilation & Auto-Fix ──────────────────────────────────────

    def _verify_compilation(self, harness_code: str) -> tuple[bool, str]:
        """Write harness to sandbox and attempt compilation."""
        test_dir = self.sandbox.tmp_dir / "test"
        test_dir.mkdir(parents=True, exist_ok=True)
        test_file = test_dir / "ExploitTest.t.sol"
        test_file.write_text(harness_code, encoding="utf-8")

        result = self.sandbox.run(
            "forge build --no-cache"
            " --ignored-error-codes 8429"
            " --ignored-error-codes 2424"
        )

        if result.success:
            print(f"  [Harness] ✓ Harness compiled successfully")
            return True, ""

        error = (result.stderr or "") + "\n" + (result.stdout or "")
        print(f"  [Harness] ✗ Harness compilation failed: {error[:200]}")
        return False, error

    def _auto_fix_harness(
        self,
        harness_code: str,
        error: str,
        contract_name: str,
        ctor: ConstructorInfo,
        collected_sources: dict[str, str],
        is_legacy: bool,
        deploy_path: str,
    ) -> tuple[str, bool, str]:
        """
        Attempt deterministic fixes for common compilation errors.
        Returns (fixed_code, compiled, error).
        """
        fixes_applied = 0

        # Fix 1: "Found incompatible versions" → switch to bridge mode
        if "incompatible" in error.lower() and not is_legacy:
            print(f"  [Harness] Auto-fix: switching to deployCode (incompatible versions)")
            # Remove direct import, use deployCode
            harness_code = re.sub(
                rf'import\s+"[^"]*{re.escape(contract_name)}[^"]*";\s*\n',
                "",
                harness_code,
            )
            # Replace new X() with deployCode()
            old_deploy = f"new {contract_name}("
            if old_deploy in harness_code:
                dp = deploy_path or f"src/{contract_name}.sol:{contract_name}"
                if ctor.params:
                    args = self._build_constructor_args(ctor, {})
                    new_deploy = f'deployCode("{dp}", abi.encode({args}))'
                else:
                    new_deploy = f'deployCode("{dp}")'
                harness_code = harness_code.replace(
                    f"{contract_name} targetInstance = {old_deploy}",
                    f"address targetAddr = {new_deploy}",
                )
                # Fix: remove the ";target = address(targetInstance);" line
                harness_code = harness_code.replace(
                    "target = address(targetInstance);",
                    "target = targetAddr;"
                )
            fixes_applied += 1

        # Fix 2: Wrong number of constructor args → try zero-arg
        if "6160" in error or "wrong number" in error.lower():
            print(f"  [Harness] Auto-fix: trying zero-arg constructor")
            # Replace constructor call with zero args
            harness_code = re.sub(
                rf'new {re.escape(contract_name)}\([^)]+\)',
                f'new {contract_name}()',
                harness_code,
            )
            fixes_applied += 1

        # Fix 3: Abstract contract → use deployCode
        if "4614" in error or "abstract" in error.lower():
            print(f"  [Harness] Auto-fix: abstract contract, switching to deployCode")
            dp = deploy_path or f"src/{contract_name}.sol:{contract_name}"
            harness_code = re.sub(
                rf'new {re.escape(contract_name)}\([^)]*\)',
                f'deployCode("{dp}")',
                harness_code,
            )
            fixes_applied += 1

        if fixes_applied == 0:
            return harness_code, False, error

        # Re-compile
        compiled, new_error = self._verify_compilation(harness_code)
        return harness_code, compiled, new_error

    # ─── Helpers ─────────────────────────────────────────────────────

    def _resolve_target_import(
        self, contract_name: str, collected_sources: dict[str, str],
        is_legacy: bool,
    ) -> str:
        """Determine the import statement for the target contract."""
        if is_legacy:
            return ""  # Bridge mode: no direct import

        for path in collected_sources:
            # The first entry in collected_sources is the target file
            return f'import "{path}";'
        return ""

    def _find_target_source(
        self, contract_name: str, collected_sources: dict[str, str]
    ) -> str | None:
        """Find the source code of the target contract."""
        regex = re.compile(
            rf'^(?:abstract\s+)?contract\s+{re.escape(contract_name)}[\s({{]',
            re.MULTILINE,
        )
        for path, code in collected_sources.items():
            if regex.search(code):
                return code
        return None

    def _extract_param_names(self, source_code: str, count: int) -> list[str]:
        """Extract parameter names from constructor source code."""
        match = re.search(r'constructor\s*\(([^)]*)\)', source_code)
        if not match:
            return []
        params_str = match.group(1)
        names = []
        for chunk in params_str.split(","):
            parts = chunk.strip().split()
            if len(parts) >= 2:
                name = parts[-1]
                if name in ("memory", "calldata", "storage", "payable"):
                    name = parts[-2] if len(parts) > 2 else f"_arg{len(names)}"
                names.append(name)
        return names

    def _build_available_state(
        self, contract_name: str, ctor: ConstructorInfo,
        mock_vars: dict[str, str], is_legacy: bool,
    ) -> dict:
        """Build the available state dict for the LLM prompt."""
        variables = {
            "target": f"address — deployed {contract_name}",
            "attacker": "address — has 100 ETH (use vm.prank to impersonate)",
            "victim": "address — has 100 ETH",
        }

        mock_declarations = {}
        for param_name, var_name in mock_vars.items():
            clean = param_name.lstrip("_")
            mock_type = f"Mock{clean.title()}"
            variables[var_name] = f"{mock_type} — mock for constructor param '{param_name}'"
            mock_declarations[var_name] = mock_type

        return {
            "variables": variables,
            "mock_declarations": mock_declarations,
        }

    def _format_state_comment(self, available_state: dict) -> str:
        """Format state variables as a Solidity comment block."""
        lines = ["        // ═══ AVAILABLE STATE ═══"]
        for var_name, desc in available_state.get("variables", {}).items():
            lines.append(f"        // {var_name}: {desc}")
        lines.append("        // ═══════════════════════")
        return "\n".join(lines)

    @staticmethod
    def _default_return(type_str: str) -> str:
        """Generate a default return value for a Solidity type."""
        t = type_str.strip()
        if t.startswith("uint") or t.startswith("int"):
            return "0"
        if t == "bool":
            return "false"
        if t == "address":
            return "address(0)"
        if t == "string":
            return '""'
        if t.startswith("bytes"):
            return '""' if t == "bytes" else f"{t}(0)"
        return "0"
