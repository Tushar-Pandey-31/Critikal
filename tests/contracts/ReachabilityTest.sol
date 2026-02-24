// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title ReachabilityTest
 * @notice Test contract for Story 3.3 — Reachability from External Entry
 * @dev Covers: direct external, one-hop, multi-hop, multiple callers, dead code, receive/fallback
 */
contract ReachabilityTest {
    uint256 public counter;
    uint256 public balance;
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    // ===== Pattern 1: Direct external entry (depth 0) =====
    function deposit() public payable {
        balance += msg.value;
    }

    // ===== Pattern 2: One-hop reachability (depth 1) =====
    function externalCaller() public {
        internalA();
    }

    function internalA() internal {
        counter += 1;
    }

    // ===== Pattern 3: Multi-hop reachability (depth 2) =====
    function deepCaller() public {
        midHelper();
    }

    function midHelper() internal {
        deepHelper();
    }

    function deepHelper() internal {
        counter += 10;
    }

    // ===== Pattern 4: Multiple external callers =====
    // leafHelper() is reachable from BOTH externalCaller and multiCaller
    function multiCaller() public {
        leafHelper();
    }

    function leafHelper() internal {
        balance += 1;
    }

    // externalCaller2 also calls internalA (already reachable from externalCaller)
    function externalCaller2() public {
        internalA();
        leafHelper();
    }

    // ===== Pattern 5: Dead code (unreachable) =====
    function _unusedInternal() internal {
        counter = 999;
    }

    function _alsoUnused() internal pure returns (uint256) {
        return 42;
    }

    // ===== Pattern 6: Receive/Fallback (depth 0) =====
    receive() external payable {
        balance += msg.value;
    }

    fallback() external payable {
        balance += msg.value;
    }
}
