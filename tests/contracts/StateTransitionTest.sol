// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title StateTransitionTest
 * @notice Test contract for Epic 6 — StateTransition nodes, array length mutation,
 *         and delegatecall storage collision detection.
 */
contract StateTransitionTest {
    uint256 public counter;
    address public owner;
    mapping(address => uint256) public balances;
    uint256[] public data;
    address public implementation;

    constructor() {
        owner = msg.sender;
    }

    // ===== Story 6.1: Operation Classification =====

    // assign operation
    function setCounter(uint256 _val) public {
        counter = _val;
    }

    // add operation
    function incrementCounter() public {
        counter += 1;
    }

    // sub operation
    function decrementCounter() public {
        counter -= 1;
    }

    // mapping write (assign into mapping)
    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    // array push
    function pushData(uint256 _val) public {
        data.push(_val);
    }

    // array pop — Story 6.2: array length mutation
    function popData() public {
        data.pop();
    }

    // owner / privileged variable assignment
    function setOwner(address _newOwner) public {
        owner = _newOwner;
    }

    // multiple writes in one function
    function complexWrite(uint256 _val) public {
        counter = _val;
        balances[msg.sender] = _val;
    }

    // read-only (no transitions expected)
    function readOnly() public view returns (uint256) {
        return counter;
    }

    // ===== Story 6.3: Delegatecall Storage Collision =====

    // Attacker-controlled target + state write after delegatecall
    function unsafeDelegatecall(address target) public {
        (bool success, ) = target.delegatecall("");
        require(success);
        counter += 1;
    }

    // Fixed-target delegatecall (state var target, lower risk)
    function fixedDelegatecall() public {
        (bool success, ) = implementation.delegatecall("");
        require(success);
    }

    // Delegatecall-only, no state write
    function delegatecallNoWrite(address target) public {
        (bool success, ) = target.delegatecall("");
        require(success);
    }

    // Attacker-controlled target + writes state but NOT after the call
    function delegatecallWriteBefore(address target) public {
        counter += 1;
        (bool success, ) = target.delegatecall("");
        require(success);
    }

    receive() external payable {}
}
