"""Tests for the Titan Pattern Engine (src/pattern_scanner.py)."""

import pytest
from src.pattern_scanner import scan_file, scan_all_sources, get_pattern_summary, PatternHit


class TestPatternScanner:
    """Unit tests for individual vulnerability detectors."""

    # ── ETH-001: Single-function Reentrancy ────────────────────────────
    def test_eth001_reentrancy_cei_violation(self):
        code = '''
pragma solidity ^0.8.0;
contract Vuln {
    mapping(address => uint256) public balances;
    function withdraw() public {
        uint256 bal = balances[msg.sender];
        (bool ok, ) = msg.sender.call{value: bal}("");
        require(ok);
        balances[msg.sender] = 0;
    }
}
'''
        hits = scan_file("test.sol", code)
        ids = [h.pattern_id for h in hits]
        assert "ETH-001" in ids, f"Expected ETH-001 reentrancy hit, got {ids}"
        eth001 = [h for h in hits if h.pattern_id == "ETH-001"][0]
        assert eth001.severity == "CRITICAL"
        assert eth001.category == "reentrancy"
        assert "SWC-107" == eth001.swc

    def test_eth001_no_fp_with_nonreentrant(self):
        code = '''
pragma solidity ^0.8.0;
contract Safe {
    mapping(address => uint256) public balances;
    function withdraw() public nonReentrant {
        uint256 bal = balances[msg.sender];
        (bool ok, ) = msg.sender.call{value: bal}("");
        require(ok);
        balances[msg.sender] = 0;
    }
}
'''
        hits = scan_file("test.sol", code)
        ids = [h.pattern_id for h in hits]
        assert "ETH-001" not in ids, "ReentrancyGuard should suppress ETH-001"

    # ── ETH-007: tx.origin ─────────────────────────────────────────────
    def test_eth007_tx_origin(self):
        code = '''
pragma solidity ^0.8.0;
contract Vuln {
    function isOwner() public view returns (bool) {
        require(tx.origin == owner);
        return true;
    }
}
'''
        hits = scan_file("test.sol", code)
        ids = [h.pattern_id for h in hits]
        assert "ETH-007" in ids

    # ── ETH-008: selfdestruct ──────────────────────────────────────────
    def test_eth008_selfdestruct(self):
        code = '''
contract Vuln {
    function kill() public {
        selfdestruct(payable(msg.sender));
    }
}
'''
        hits = scan_file("test.sol", code)
        ids = [h.pattern_id for h in hits]
        assert "ETH-008" in ids

    # ── ETH-013: Unchecked Arithmetic ──────────────────────────────────
    def test_eth013_unchecked_block(self):
        code = '''
pragma solidity ^0.8.0;
contract Vuln {
    function foo() public {
        unchecked { x += 1; }
    }
}
'''
        hits = scan_file("test.sol", code)
        ids = [h.pattern_id for h in hits]
        assert "ETH-013" in ids

    def test_eth013_unsafe_downcast(self):
        code = '''
pragma solidity ^0.8.0;
contract Vuln {
    function bar(uint256 x) public {
        uint8(x);
    }
}
'''
        hits = scan_file("test.sol", code)
        ids = [h.pattern_id for h in hits]
        assert "ETH-013" in ids

    # ── ETH-019: delegatecall ──────────────────────────────────────────
    def test_eth019_delegatecall(self):
        code = '''
contract Vuln {
    function upgrade(address impl) public {
        impl.delegatecall(abi.encodeWithSignature("init()"));
    }
}
'''
        hits = scan_file("test.sol", code)
        ids = [h.pattern_id for h in hits]
        assert "ETH-019" in ids

    # ── ETH-024: Oracle Manipulation ───────────────────────────────────
    def test_eth024_balance_of_pricing(self):
        code = '''
contract Vuln {
    function getPrice() public view returns (uint256) {
        return totalSupply * 1e18 / balanceOf(address(this));
    }
}
'''
        hits = scan_file("test.sol", code)
        ids = [h.pattern_id for h in hits]
        assert "ETH-024" in ids

    # ── ETH-028: Stale Oracle Data ─────────────────────────────────────
    def test_eth028_stale_oracle(self):
        code = '''
contract Vuln {
    function getPrice() public view returns (uint256) {
        (, int price,,,) = priceFeed.latestRoundData();
        return uint256(price);
    }
}
'''
        hits = scan_file("test.sol", code)
        ids = [h.pattern_id for h in hits]
        assert "ETH-028" in ids, f"Expected stale oracle hit, got {ids}"

    def test_eth028_no_fp_with_staleness_check(self):
        code = '''
contract Safe {
    function getPrice() public view returns (uint256) {
        (, int price,, uint updatedAt,) = priceFeed.latestRoundData();
        require(updatedAt > 0, "stale");
        return uint256(price);
    }
}
'''
        hits = scan_file("test.sol", code)
        ids = [h.pattern_id for h in hits]
        assert "ETH-028" not in ids, "Staleness-checked oracle should not trigger ETH-028"

    # ── ETH-057: Vault Share Inflation ─────────────────────────────────
    def test_eth057_vault_inflation(self):
        code = '''
contract Vault {
    function deposit(uint256 assets) public {
        if (totalSupply() == 0) {
            shares = assets;
        }
    }
}
'''
        hits = scan_file("test.sol", code)
        ids = [h.pattern_id for h in hits]
        assert "ETH-057" in ids

    # ── ETH-086: Broken EOA Check ──────────────────────────────────────
    def test_eth086_eoa_check(self):
        code = '''
contract Vuln {
    function doSomething() public {
        require(tx.origin == msg.sender, "not EOA");
    }
}
'''
        hits = scan_file("test.sol", code)
        ids = [h.pattern_id for h in hits]
        assert "ETH-086" in ids

    # ── scan_all_sources ───────────────────────────────────────────────
    def test_scan_all_sources_aggregates(self):
        cache = {
            "a.sol": 'function kill() public { selfdestruct(payable(msg.sender)); }',
            "b.sol": 'require(tx.origin == owner);',
            "c.txt": 'not solidity',
        }
        hits = scan_all_sources(cache)
        assert len(hits) >= 2
        ids = [h.pattern_id for h in hits]
        assert "ETH-008" in ids  # selfdestruct
        assert "ETH-007" in ids  # tx.origin

    def test_scan_all_sources_skips_non_sol(self):
        cache = {"readme.md": "selfdestruct(payable(msg.sender));"}
        hits = scan_all_sources(cache)
        assert len(hits) == 0

    # ── get_pattern_summary ────────────────────────────────────────────
    def test_pattern_summary(self):
        hits = [
            PatternHit("ETH-001", "Re", "CRITICAL", 0.9, "f", 1, "c", "d", "r", "reentrancy"),
            PatternHit("ETH-013", "Ar", "HIGH", 0.7, "f", 2, "c", "d", "r", "arithmetic"),
            PatternHit("ETH-014", "Dv", "MEDIUM", 0.6, "f", 3, "c", "d", "r", "arithmetic"),
        ]
        summary = get_pattern_summary(hits)
        assert summary["CRITICAL"] == 1
        assert summary["HIGH"] == 1
        assert summary["MEDIUM"] == 1

    # ── Metadata correctness ───────────────────────────────────────────
    def test_hit_metadata(self):
        code = '''contract V { function x() public { selfdestruct(payable(msg.sender)); } }'''
        hits = scan_file("contracts/Vuln.sol", code)
        assert len(hits) > 0
        h = hits[0]
        assert h.file == "contracts/Vuln.sol"
        assert h.line > 0
        assert len(h.code_snippet) > 0
        assert len(h.description) > 0
        assert len(h.recommendation) > 0
