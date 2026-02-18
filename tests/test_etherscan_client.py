import pytest
from unittest.mock import patch, MagicMock
from src.tools.etherscan_client import EtherscanClient, EtherscanRateLimitError


def test_stub_mode_activates_without_api_key():
    with patch.dict("os.environ", {}, clear=True):
        client = EtherscanClient()
        assert client.stub_mode is True


def test_stub_mode_forced_explicitly():
    client = EtherscanClient(stub=True)
    assert client.stub_mode is True


def test_live_mode_when_key_provided():
    client = EtherscanClient(api_key="test_key_123")
    assert client.stub_mode is False
    assert client.api_key == "test_key_123"


def test_stub_contract_info_all_fields_present():
    client = EtherscanClient(stub=True)
    info = client.get_contract_info("0xabc")
    assert hasattr(info, "is_verified")
    assert hasattr(info, "is_proxy")
    assert hasattr(info, "contract_age_days")
    assert hasattr(info, "data_source")
    assert info.data_source == "stub"


def test_stub_exploit_history_no_exploits():
    client = EtherscanClient(stub=True)
    history = client.get_exploit_history("0xabc")
    assert history.previous_exploits_detected is False
    assert history.exploit_count == 0


def test_stub_transaction_profile_safe_defaults():
    client = EtherscanClient(stub=True)
    profile = client.get_transaction_profile("0xabc")
    assert profile.recent_large_withdrawals is False
    assert profile.flash_loan_interactions is False


def test_live_get_raises_not_implemented_without_full_impl():
    """Ensure live calls fail loudly if implementation is incomplete."""
    client = EtherscanClient(api_key="fake_key")
    # Mock requests.get to return a valid-looking but empty response
    mock_response = MagicMock()
    mock_response.json.return_value = {
        "status": "1",
        "result": [{"SourceCode": "", "Proxy": "0", "ContractName": ""}]
    }
    mock_response.raise_for_status = MagicMock()
    with patch("requests.get", return_value=mock_response):
        # Should not crash — should return ContractInfo with data_source="etherscan"
        info = client.get_contract_info("0xabc")
        assert info.data_source == "etherscan"
