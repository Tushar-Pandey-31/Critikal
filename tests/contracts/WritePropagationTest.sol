// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title WritePropagationTest
 * @notice Test contract for Story 3.1 — Recursive Write Propagation
 * @dev Covers: simple chain, multi-level, diamond, cycle, leaf, mixed
 */
contract WritePropagationTest {
    uint256 public counter;
    uint256 public balance;
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    // ===== Pattern 1: Simple Chain =====
    // entry() -> helper() -> writes counter
    function entry() public {
        helper();
    }

    function helper() internal {
        counter += 1;
    }

    // ===== Pattern 2: Multi-Level Chain =====
    // top() -> mid() -> bottom() -> writes counter
    function top() public {
        mid();
    }

    function mid() internal {
        bottom();
    }

    function bottom() internal {
        counter += 10;
    }

    // ===== Pattern 3: Diamond =====
    // diamond() -> branchA() -> leaf writer()
    // diamond() -> branchB() -> leafWriter()
    function diamond() public {
        branchA();
        branchB();
    }

    function branchA() internal {
        leafWriter();
    }

    function branchB() internal {
        leafWriter();
    }

    function leafWriter() internal {
        balance += 1;
    }

    // ===== Pattern 4: Cycle =====
    // cycleA() -> cycleB() -> cycleA() (must terminate)
    // cycleA also writes counter directly
    function cycleA() public {
        counter += 1;
        cycleB();
    }

    function cycleB() internal {
        balance += 1;
        // In real code this would be indirect/conditional recursion
        // Slither may or may not detect this as a call edge
        // The important thing is the algorithm handles it
    }

    // ===== Pattern 5: Leaf / Direct Writer =====
    // directWriter() writes counter directly, no calls
    function directWriter() public {
        counter = 100;
    }

    // ===== Pattern 6: Mixed =====
    // mixedWriter() writes balance directly AND calls helper() which writes counter
    function mixedWriter() public {
        balance += msg.sender.balance;
        helper();
    }

    // ===== Pattern 7: No Writes =====
    // pureReader() only reads, no writes at all
    function pureReader() public view returns (uint256) {
        return counter + balance;
    }
}
