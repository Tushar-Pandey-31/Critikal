// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title IERC20
 * @notice Minimal ERC20 interface for testing high-level external calls
 */
interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

/**
 * @title ExternalCallTest
 * @notice Test contract for Story 3.2 — External Call Classification
 * @dev Covers: low-level call, send, transfer, delegatecall, interface call,
 *              no external call, multiple calls, call-then-write, write-then-call,
 *              PLUS critical edge cases: multiple writes/calls, indirect writes,
 *              modifier calls, conditional writes, safe pull pattern, no-mutation calls.
 */
contract ExternalCallTest {
    uint256 public counter;
    uint256 public balance;
    address public owner;
    mapping(address => uint256) public deposits;
    IERC20 public token;

    constructor(address _token) {
        owner = msg.sender;
        token = IERC20(_token);
    }

    // ===== Pattern 1: Low-Level Call =====
    // addr.call{value:}("") — writes state AFTER
    function lowLevelCall(address payable target) public {
        (bool success, ) = target.call{value: 1 ether}("");
        require(success, "call failed");
        counter += 1; // state write AFTER external call
    }

    // ===== Pattern 2: Send =====
    // addr.send() — writes state AFTER
    function sendEther(address payable target) public {
        bool success = target.send(1 ether);
        require(success, "send failed");
        counter += 1; // state write AFTER external call
    }

    // ===== Pattern 3: Transfer =====
    // addr.transfer() — NO state write after
    function transferEther(address payable target) public {
        target.transfer(1 ether);
        // no state write after
    }

    // ===== Pattern 4: Delegatecall =====
    // addr.delegatecall("") 
    function delegateCall(address target) public {
        (bool success, ) = target.delegatecall("");
        require(success, "delegatecall failed");
    }

    // ===== Pattern 5: High-Level Call (interface) =====
    // token.transfer() — writes state AFTER
    function highLevelCall(address recipient, uint256 amount) public {
        token.transfer(recipient, amount);
        counter += 1; // state write AFTER external call
    }

    // ===== Pattern 6: No External Call =====
    // Pure internal logic only
    function noExternalCall() public {
        counter += 1;
        balance += 2;
    }

    // ===== Pattern 7: Multiple External Calls =====
    // Two different external call types
    function multipleExternalCalls(address payable target, address recipient) public {
        (bool success, ) = target.call{value: 1 ether}("");
        require(success, "call failed");
        token.transfer(recipient, 100);
        counter += 1; // state write after both calls
    }

    // ===== Pattern 8: Call Then Write (CEI Violation) =====
    // State write happens AFTER external call
    function callThenWrite(address payable target) public {
        (bool success, ) = target.call{value: deposits[msg.sender]}("");
        require(success, "call failed");
        deposits[msg.sender] = 0; // write AFTER call — reentrancy risk
    }

    // ===== Pattern 9: Write Then Call (Safe CEI Pattern) =====
    // State write happens BEFORE external call
    function writeThenCall(address payable target) public {
        uint256 amount = deposits[msg.sender];
        deposits[msg.sender] = 0; // write BEFORE call — safe
        (bool success, ) = target.call{value: amount}("");
        require(success, "call failed");
    }

    // ===== Critical Edge Case 1: Multiple Writes and Calls =====
    // Write -> Call -> Write (Violation because of second write)
    function multipleWritesAndCalls(address payable target) public {
        deposits[msg.sender] = 0; // Write 1 (Safe)
        (bool success, ) = target.call{value: 1 ether}(""); // Call
        require(success, "call failed");
        counter += 1; // Write 2 (Violation!)
    }

    // ===== Critical Edge Case 2: Write in Callee (Indirect Write) =====
    // Call -> Internal Function (writes state) -> Violation
    function writeInCallee(address payable target) public {
        (bool success, ) = target.call{value: 1 ether}(""); // Call
        require(success, "call failed");
        _updateBalance(); // Indirect Write (Violation!)
    }

    function _updateBalance() internal {
        balance += 1; // Indirect write
    }

    // ===== Critical Edge Case 3: External Call Inside Modifier =====
    // Modifier calls external -> Function writes state -> Violation
    modifier doCall(address target) {
        (bool success, ) = target.call("");
        require(success, "modifier call failed");
        _;
    }

    function modifierCallWrite(address target) public doCall(target) {
        counter += 1; // Write happens AFTER modifier's call (Violation!)
    }

    // ===== Critical Edge Case 4: Conditional Write =====
    // Write inside if block after call -> Violation
    function conditionalWrite(address payable target) public {
        (bool success, ) = target.call{value: 1 ether}("");
        if (success) {
            counter += 1; // Write inside conditional (Violation!)
        }
    }

    // ===== Critical Edge Case 5: Safe Pull Pattern =====
    // Read -> Write -> Call (Safe)
    function safePull(address payable target) public {
        uint256 amount = deposits[msg.sender];
        deposits[msg.sender] = 0; // Write
        (bool success, ) = target.call{value: amount}(""); // Call (Safe)
        require(success, "call failed");
    }

    // ===== Critical Edge Case 6: External Call With No State Mutation =====
    // Call -> No state writes anywhere (Safe)
    function externalCallNoMutation(address target) public view {
        IERC20(target).balanceOf(address(this)); // Call (view/pure) -> No mutation -> Safe
    }

    // ===== NEW: Modifier Stacking & Order Cases =====

    // Pattern 10: Body Write, Modifier POST Call (Violation)
    modifier postCall(address target) {
        _;
        (bool success, ) = target.call("");
        require(success, "post-call failed");
    }

    function bodyWriteModifierPostCall(address target) public postCall(target) {
        counter += 1; // Write happens BEFORE modifier's call (Safe in body, but overall Violation if we consider body then modifier post)
        // Actually, if body writes and then modifier post calls, that IS a potential reentrancy risk if the state isn't final.
    }

    // Pattern 11: Modifier Internal Write Safe (Write -> Call)
    modifier writeThenCallMod(address target) {
        counter += 1; // Write
        (bool success, ) = target.call(""); // Call
        require(success, "mod call failed");
        _;
    }
    function modifierInternalWriteSafe(address target) public writeThenCallMod(target) {}

    // Pattern 12: Modifier Internal Write Violation (Call -> Write)
    modifier callThenWriteMod(address target) {
        (bool success, ) = target.call(""); // Call
        require(success, "mod call failed");
        counter += 1; // Write (Violation!)
        _;
    }
    function modifierInternalWriteViolation(address target) public callThenWriteMod(target) {}

    // Pattern 13: Multiple Modifiers Stacking
    // Execution: A pre -> B pre -> Body -> B post -> A post
    modifier modA(address target) {
        (bool success, ) = target.call(""); // Call in A pre
        require(success, "A failed");
        _;
    }
    modifier modB() {
        _;
        counter += 1; // Write in B post
    }
    // Call (A pre) -> Body -> Write (B post) -> Violation
    function multipleModifiersStacking(address target) public modA(target) modB {}

    // ===== Story 1.2/1.3: transfer + write (CEI violation, NOT reentrancy) =====
    function transferThenWrite(address payable target) public {
        target.transfer(1 ether);
        counter += 1; // state write after transfer (2300 gas, not reentrant)
    }

    // ===== Story 1.2: view interface call + write (staticcall, NOT reentrancy) =====
    function viewCallThenWrite(address target) public {
        IERC20(target).balanceOf(address(this)); // staticcall (view function)
        counter += 1; // state write after staticcall
    }

    // ===== Story 1.3: send + write (CEI violation, NOT reentrancy) =====
    function sendThenWrite(address payable target) public {
        bool success = target.send(1 ether);
        require(success, "send failed");
        counter += 1; // state write after send (2300 gas, not reentrant)
    }

    // Allow contract to receive ETH
    receive() external payable {}
}
