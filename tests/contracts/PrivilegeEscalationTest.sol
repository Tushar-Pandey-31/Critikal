// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract PrivilegeEscalationTest {
    address public owner;
    mapping(address => bool) public admins;
    bool public isInitialized;
    uint256 public data;

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    modifier onlyAdmin() {
        require(admins[msg.sender], "Not admin");
        _;
    }

    modifier whenInitialized() {
        require(isInitialized, "Not initialized");
        _;
    }

    constructor() {
        owner = msg.sender;
        isInitialized = true;
    }

    // VULNERABILITY: Unprotected function that overwrites owner
    // This should flag:
    // 1. owner variable as privilege_escalation_risk
    // 2. setOwner as can_escalate_privileges
    function setOwner(address newOwner) public {
        owner = newOwner;
    }

    // VULNERABILITY: Unprotected function that poisons admin mapping
    // This should flag:
    // 1. admins variable as privilege_escalation_risk
    // 2. addAdmin as can_escalate_privileges
    function addAdmin(address account) public {
        admins[account] = true;
    }

    // VULNERABILITY: Unprotected function that flips boolean guard
    // This should flag:
    // 1. isInitialized as privilege_escalation_risk
    // 2. resetInitialization as can_escalate_privileges
    function resetInitialization() public {
        isInitialized = false;
    }

    // SAFE: Protected function modifying state
    function setData(uint256 newValue) public onlyOwner {
        data = newValue;
    }

    // SAFE: Unprotected function modifying non-access-control state
    function updateData(uint256 newValue) public {
        data = newValue;
    }
}
