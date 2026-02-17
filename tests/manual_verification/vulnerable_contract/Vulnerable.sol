// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract VulnerableVault {
    mapping(address => uint256) public balances;
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    // VULNERABILITY: Missing access control (anyone can withdraw anyone's funds or just drain)
    // Actually here it's just missing modifiers if we intended only owner or balance checks.
    // Let's make it obviously vulnerable: Anyone can withdraw ALL funds.
    function emergencyWithdraw() public {
        payable(msg.sender).transfer(address(this).balance);
    }
    
    // VULNERABILITY: Reentrancy
    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        
        // Interaction before effect
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
        
        balances[msg.sender] -= amount;
    }
}
