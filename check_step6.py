from src.agents.workers.test_writer_worker import _classify_compile_error, _detect_guard_hit
import traceback

try:
    # Should return targeted fix string, not None
    assert _classify_compile_error("Error (9553): Invalid implicit conversion") is not None
    assert _classify_compile_error("Error (3656): contract should be marked as abstract") is not None
    assert _classify_compile_error("Found incompatible versions") is not None

    # Should return None (no rule matches)
    assert _classify_compile_error("some random unrecognized error") is None

    # Guard detection
    assert _detect_guard_hit("Error: market may only be initialized once") is True
    assert _detect_guard_hit("already initialized") is True
    assert _detect_guard_hit("[FAIL] assertion failed") is False

    print("Smoke Tests 1 Passed")
except Exception as e:
    print(traceback.format_exc())

# ---- 

try:
    from src.agents.workers.test_writer_worker import TestWriterWorker
    worker = TestWriterWorker(llm_client=None, graph=None)

    # Fabricated mock of target → should be rejected
    code_with_mock = """
    pragma solidity ^0.8.0;
    contract MockWETH {
        mapping(address => uint256) public balanceOf;
    }
    contract ExploitTest {
        function test_exploit() public {}
    }
    """
    authentic, reason = worker._check_test_authenticity(code_with_mock, "WETH", False)
    assert not authentic, f"Should have been rejected: {reason}"
    print(f"Correctly rejected: {reason}")

    # Clean test — should pass
    code_clean = """
    pragma solidity ^0.8.0;
    import "forge-std/Test.sol";
    contract AttackContract {
        constructor(address target) {}
        function execute() external {}
    }
    contract ExploitTest is Test {
        function test_exploit() public {}
    }
    """
    authentic, reason = worker._check_test_authenticity(code_clean, "WETH", False)
    assert authentic, f"Should have been accepted: {reason}"
    print(f"Correctly accepted: {reason}")

    # Bridge mode with no deployCode → should be rejected
    code_bridge_no_deploy = """
    pragma solidity ^0.8.0;
    contract MockCErc20 {}
    contract ExploitTest {
        function test_exploit() public {}
    }
    """
    authentic, reason = worker._check_test_authenticity(code_bridge_no_deploy, "CErc20", is_legacy=True)
    assert not authentic
    print(f"Correctly rejected bridge mode: {reason}")

    print("Smoke Tests 2 Passed")
except Exception as e:
    print(traceback.format_exc())
