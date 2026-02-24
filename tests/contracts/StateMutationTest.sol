// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title StateMutationTest
 * @notice Test contract for Story 2.2 - Storage State Mutation Detection
 * @dev Tests various scenarios: state writes, mapping writes, local-only, and read-only
 */
contract StateMutationTest {
    uint public counter;
    mapping(address => uint) public balances;
    
    // Struct for testing storage reference writes
    struct User {
        uint balance;
        bool active;
    }
    mapping(address => User) public users;

    constructor() {
        counter = 0;
    }

    /**
     * @notice Writes to state variable - should have writes_state=True
     */
    function writeState() public {
        counter += 1;
    }

    /**
     * @notice Writes to mapping - should have writes_state=True
     */
    function writeMapping() public {
        balances[msg.sender] = 5;
    }

    /**
     * @notice Only manipulates local variables - should have writes_state=False
     */
    function localOnly() public pure {
        uint x = 5;
        x += 1;
        // x is local, not written to storage
    }

    /**
     * @notice Read-only view function - should have writes_state=False
     */
    function readOnly() public view returns (uint) {
        return counter;
    }
    
    /**
     * @notice Multiple writes to same variable - should count as 1 distinct write
     */
    function multipleWritesSameVar() public {
        counter += 1;
        counter += 2;
        counter = counter * 3;
    }
    
    /**
     * @notice Writes via storage reference to struct field
     * @dev Tests that struct field writes are detected
     */
    function writeViaStorageRef() public {
        User storage u = users[msg.sender];
        u.balance = 10;
        u.active = true;
    }
}

/**
 * @title ContractB
 * @notice Helper contract for cross-contract write isolation test
 */
contract ContractB {
    uint public x;
    
    function write() public {
        x = 1;
    }
}

/**
 * @title ContractA
 * @notice Tests that external calls don't propagate write metadata
 */
contract ContractA {
    ContractB public b;
    
    constructor(address _b) {
        b = ContractB(_b);
    }
    
    function callWrite() public {
        b.write();
    }
}
