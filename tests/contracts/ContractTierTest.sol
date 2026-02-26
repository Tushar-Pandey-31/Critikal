// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title ContractTierTest
 * @notice Contracts exercising all four tier heuristics:
 *         FACTORY, LIBRARY, CORE, INFRA.
 */

// ── FACTORY tier: creates other contracts via `new` ────────────

contract TierChild {
    uint256 public value;
    constructor(uint256 _val) {
        value = _val;
    }
}

contract TierFactory {
    TierChild[] public children;

    function create(uint256 _val) public returns (TierChild) {
        TierChild child = new TierChild(_val);
        children.push(child);
        return child;
    }
}

// ── LIBRARY tier: Solidity library ─────────────────────────────

library TierMathLib {
    function add(uint256 a, uint256 b) internal pure returns (uint256) {
        return a + b;
    }

    function sub(uint256 a, uint256 b) internal pure returns (uint256) {
        return a - b;
    }
}

// ── LIBRARY tier: interface (no implementation) ────────────────

interface ITierCallback {
    function onCallback(bytes calldata data) external returns (bool);
}

// ── CORE tier: external entries + external calls + state ───────

contract TierCore {
    uint256 public counter;
    address public target;
    ITierCallback public callback;

    constructor(address _target, address _callback) {
        target = _target;
        callback = ITierCallback(_callback);
    }

    function executeAndUpdate(bytes calldata data) public {
        callback.onCallback(data);
        counter += 1;
    }

    function withdraw(address payable to) public {
        (bool ok, ) = to.call{value: address(this).balance}("");
        require(ok);
        counter += 1;
    }

    receive() external payable {}
}

// ── INFRA tier: external entries, no external calls ────────────

contract TierInfra {
    uint256 public config;
    address public admin;

    function setConfig(uint256 _val) public {
        config = _val;
    }

    function setAdmin(address _a) public {
        admin = _a;
    }

    function getConfig() public view returns (uint256) {
        return config;
    }
}
