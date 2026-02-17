// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title InternalCallTest
 * @notice Test contract for Story 2.3 - Internal Call Graph Construction
 * @dev Tests various internal call patterns for graph modeling
 */
contract InternalCallTest {
    uint256 public counter;
    address public owner;
    
    constructor() {
        owner = msg.sender;
    }
    
    // ===== Test 1: Simple Internal Call =====
    function a() public { 
        b(); 
    }
    
    function b() internal {}
    
    // ===== Test 2: Multiple Calls to Same Function (Deduplication) =====
    function multiCall() public {
        helper();
        helper();  // Should only create ONE CALLS edge
    }
    
    function helper() internal {}
    
    // ===== Test 3: Multi-Level Chain =====
    function chain1() public { 
        chain2(); 
    }
    
    function chain2() internal { 
        chain3(); 
    }
    
    function chain3() internal {}
    
    // ===== Test 4: Modifier Call Modeling =====
    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }
    
    function restricted() public onlyOwner {
        counter = 1;
    }
    
    // ===== Test 5: Leaf Functions =====
    function leaf() internal pure returns (uint) {
        return 42;
    }
    
    function anotherLeaf() internal view returns (uint) {
        return counter;
    }
    
    // ===== Test 6: Complex Call Pattern =====
    function complex() public {
        internalA();
        internalB();
    }
    
    function internalA() internal {
        leaf();
    }
    
    function internalB() internal {
        anotherLeaf();
    }
}

/**
 * @title OtherContract
 * @notice External contract for cross-contract call testing
 */
contract OtherContract {
    uint256 public value;
    
    function externalFunc() public {
        value = 100;
    }
}

/**
 * @title CrossContractCaller
 * @notice Tests that external calls are NOT included in internal call graph
 */
contract CrossContractCaller {
    uint256 public localVar;
    
    // Test 5: External call should be IGNORED
    function callExternal(address other) public {
        OtherContract(other).externalFunc();
        // Should have num_internal_calls == 0
    }
    
    // Mixed: internal + external
    function mixed(address other) public {
        internalHelper();  // Should be counted
        OtherContract(other).externalFunc();  // Should be ignored
    }
    
    function internalHelper() internal {
        localVar = 1;
    }
}
