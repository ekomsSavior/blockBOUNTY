// SPDX-License-Identifier: MIT
pragma solidity ^0.4.24;

/**
 * INTENTIONALLY VULNERABLE CONTRACT FOR TESTING
 * DO NOT USE IN PRODUCTION
 */

contract VulnerableBank {
    
    mapping(address => uint256) public balances;
    address public owner;
    
    constructor() public {
        owner = msg.sender;
    }
    
    // Vulnerability: Reentrancy
    function withdraw(uint256 _amount) public {
        require(balances[msg.sender] >= _amount);
        msg.sender.call.value(_amount)("");
        balances[msg.sender] -= _amount;
    }
    
    // Vulnerability: tx.origin
    function transferOwnership(address _newOwner) public {
        require(tx.origin == owner);
        owner = _newOwner;
    }
    
    // Vulnerability: Unprotected selfdestruct
    function destroy() public {
        selfdestruct(owner);
    }
    
    // Vulnerability: Integer overflow
    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }
    
    function getBalance() public view returns (uint256) {
        return address(this).balance;
    }
}
