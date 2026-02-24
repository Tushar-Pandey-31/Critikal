// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title AccessControlTest
 * @notice Test contract for Stories 2.2.1–2.2.4 — Access Control Modeling
 * @dev Covers: owner pattern, role mapping, hasRole, boolean flags,
 *      tx.origin, inline require, unprotected mutators, multi-modifier
 */
contract AccessControlTest {
    // ===== State Variables =====
    address public owner;
    mapping(address => bool) public admins;
    mapping(bytes32 => mapping(address => bool)) public roles;
    bool public paused;
    uint256 public treasuryBalance;
    uint256 public counter;
    uint256 public unguardedValue;

    bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");

    constructor() {
        owner = msg.sender;
        paused = false;
    }

    // ===== Modifiers =====

    /// @notice Classic owner check via msg.sender
    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    /// @notice Role-mapping admin check
    modifier onlyAdmin() {
        require(admins[msg.sender], "Not admin");
        _;
    }

    /// @notice Boolean flag guard
    modifier whenNotPaused() {
        require(!paused, "Contract is paused");
        _;
    }

    /// @notice Dangerous tx.origin check (cosmetic/insecure)
    modifier onlyTxOrigin() {
        require(tx.origin == owner, "tx.origin not owner");
        _;
    }

    // ===== hasRole pattern =====
    function hasRole(bytes32 role, address account) public view returns (bool) {
        return roles[role][account];
    }

    modifier onlyRole(bytes32 role) {
        require(hasRole(role, msg.sender), "Missing role");
        _;
    }

    // ===== Protected Functions =====

    /// @notice Protected by onlyOwner — should be detected as protected
    function setOwner(address newOwner) public onlyOwner {
        owner = newOwner;
    }

    /// @notice Protected by onlyAdmin — role mapping pattern
    function adminWithdraw(uint256 amount) external onlyAdmin {
        treasuryBalance -= amount;
    }

    /// @notice Protected by whenNotPaused — boolean flag
    function pausableTransfer(uint256 amount) public whenNotPaused {
        treasuryBalance -= amount;
    }

    /// @notice Protected by onlyTxOrigin — cosmetic/insecure
    function txOriginAction() public onlyTxOrigin {
        counter += 1;
    }

    /// @notice Protected by onlyRole — hasRole pattern
    function mint(uint256 amount) external onlyRole(MINTER_ROLE) {
        treasuryBalance += amount;
    }

    /// @notice Multiple modifiers on one function
    function protectedPausableAction() public onlyOwner whenNotPaused {
        counter += 10;
    }

    /// @notice Inline require with msg.sender — no modifier but still protected
    function inlineProtected() public {
        require(msg.sender == owner, "Not owner");
        counter += 5;
    }

    // ===== Unprotected State Mutators (SHOULD BE FLAGGED) =====

    /// @notice Public + writes state + no modifier = UNPROTECTED
    function unsafeIncrement() public {
        counter += 1;
    }

    /// @notice External + writes state + no modifier = UNPROTECTED
    function unsafeSetValue(uint256 val) external {
        unguardedValue = val;
    }

    /// @notice Payable + writes state + no modifier = HIGH RISK UNPROTECTED
    function unsafeDeposit() public payable {
        treasuryBalance += msg.value;
    }

    // ===== View / Pure (should NOT be flagged as unprotected mutators) =====

    /// @notice View function — no state mutation
    function getBalance() public view returns (uint256) {
        return treasuryBalance;
    }

    /// @notice Pure function — no state access at all
    function compute(uint256 a, uint256 b) public pure returns (uint256) {
        return a + b;
    }

    // ===== Admin management =====

    function addAdmin(address admin) public onlyOwner {
        admins[admin] = true;
    }

    function grantRole(bytes32 role, address account) public onlyOwner {
        roles[role][account] = true;
    }

    function setPaused(bool _paused) public onlyOwner {
        paused = _paused;
    }
}
