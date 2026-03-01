pragma solidity ^0.4.24;
contract Wallet {
    mapping(address => uint256) balances;
    function deposit() public payable { balances[msg.sender] += msg.value; }
    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount);
        msg.sender.call.value(amount)("");
        balances[msg.sender] -= amount;
    }
}
