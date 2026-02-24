import pytest

from src.main import _parse_contract_addresses


def test_parse_contract_addresses_valid_json():
    parsed = _parse_contract_addresses('{"Vault":"0xabc","Token":"0xdef"}')
    assert parsed == {"Vault": "0xabc", "Token": "0xdef"}


def test_parse_contract_addresses_empty():
    assert _parse_contract_addresses(None) == {}
    assert _parse_contract_addresses("") == {}


def test_parse_contract_addresses_invalid_json():
    with pytest.raises(ValueError):
        _parse_contract_addresses("{not-json}")


def test_parse_contract_addresses_requires_object():
    with pytest.raises(ValueError):
        _parse_contract_addresses('["0xabc"]')
