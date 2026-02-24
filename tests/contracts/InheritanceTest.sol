// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title InheritanceTest
 * @dev Test contract for verifying inherited functions are correctly marked as external entries
 */

contract BaseContract {
    uint256 public baseValue;
    
    // PUBLIC function in base - should be entry point
    function basePublicFunction() public {
        baseValue = 100;
    }
    
    // EXTERNAL function in base - should be entry point
    function baseExternalFunction() external {
        baseValue = 200;
    }
    
    // INTERNAL function in base - should NOT be entry point
    function baseInternalFunction() internal {
        baseValue = 300;
    }
}

contract ChildContract is BaseContract {
    uint256 public childValue;
    
    // PUBLIC function in child - should be entry point
    function childPublicFunction() public {
        childValue = 400;
    }
    
    // Can call inherited internal function
    function useInheritedInternal() public {
        baseInternalFunction();
    }
}
