// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title AttackSurfaceTest
 * @dev Test contract with various function visibilities for external attack surface detection
 */
contract AttackSurfaceTest {
    uint256 public balance;
    
    // Constructor - should NOT be marked as external entry  
    constructor() {
        balance = 0;
    }
    
    // PUBLIC function - SHOULD be external entry point
    function publicDeposit() public payable {
        balance += msg.value;
    }
    
    // EXTERNAL function - SHOULD be external entry point
    function externalWithdraw(uint256 amount) external {
        require(amount <= balance, "Insufficient balance");
        balance -= amount;
        payable(msg.sender).transfer(amount);
    }
    
    // INTERNAL function - should NOT be external entry
    function internalHelper() internal pure returns (uint256) {
        return 42;
    }
    
    // PRIVATE function - should NOT be external entry
    function privateCompute() private pure returns (uint256) {
        return 100;
    }
    
    // PUBLIC VIEW function - SHOULD be external entry, NOT payable
    function getBalance() public view returns (uint256) {
        return balance;
    }
    
    // EXTERNAL PAYABLE function - SHOULD be external entry AND payable
    function externalPayableDeposit() external payable {
        balance += msg.value;
    }
    
    // RECEIVE function - SHOULD be external entry AND payable
    receive() external payable {
        balance += msg.value;
    }
    
    // FALLBACK function - SHOULD be external entry
    fallback() external {
        // Handle any other calls
    }
}
