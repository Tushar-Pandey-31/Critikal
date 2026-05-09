"""
Epic 8.3 — Signature Replay Detection Tests

Tests ECDSA signature validation and replay protection detection
on function source_code strings.
"""

import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

from src.graph import GraphBuilder
from utils.graph_queries import GraphQueries

# ════════════════════════════════════════════════════════════
#  Inline Solidity Source Fragments
# ════════════════════════════════════════════════════════════

SRC_ECRECOVER = """
function verify(bytes32 hash, uint8 v, bytes32 r, bytes32 s) external returns (address) {
    return ecrecover(hash, v, r, s);
}
"""

SRC_ECDSA_LIB = """
function verify(bytes32 hash, bytes memory signature) external returns (address) {
    return ECDSA.recover(hash, signature);
}
"""

SRC_NO_SIG = """
function transfer(address to, uint256 amount) external returns (bool) {
    balances[msg.sender] -= amount;
    balances[to] += amount;
    return true;
}
"""

SRC_CHAINID_PRESENT = """
function permit(address owner, address spender, uint256 value, uint256 deadline,
                uint8 v, bytes32 r, bytes32 s) external {
    bytes32 domainSeparator = keccak256(abi.encode(DOMAIN_TYPEHASH, name, block.chainid, address(this)));
    bytes32 structHash = keccak256(abi.encode(PERMIT_TYPEHASH, owner, spender, value, nonce, deadline));
    bytes32 hash = keccak256(abi.encodePacked("\\x19\\x01", domainSeparator, structHash));
    address signer = ecrecover(hash, v, r, s);
    require(signer == owner, "INVALID_SIGNER");
}
"""

SRC_CHAINID_MISSING = """
function verify(bytes32 hash, uint8 v, bytes32 r, bytes32 s) external returns (address) {
    bytes32 structHash = keccak256(abi.encode(TYPE_HASH, someValue));
    return ecrecover(structHash, v, r, s);
}
"""

SRC_NONCE_PRESENT = """
function executeWithNonce(bytes32 hash, uint8 v, bytes32 r, bytes32 s) external {
    bytes32 digest = keccak256(abi.encode(hash, nonce[msg.sender]));
    address signer = ecrecover(digest, v, r, s);
    require(signer == msg.sender, "INVALID");
}
"""

SRC_NONCE_MISSING = """
function execute(bytes32 hash, uint8 v, bytes32 r, bytes32 s) external {
    address signer = ecrecover(hash, v, r, s);
    require(signer == authorized, "INVALID");
    doAction();
}
"""

SRC_MARKS_USED_NONCE = """
function executeMetaTx(bytes32 hash, uint8 v, bytes32 r, bytes32 s) external {
    bytes32 digest = keccak256(abi.encode(hash, nonces[msg.sender], block.chainid));
    address signer = ecrecover(digest, v, r, s);
    require(signer == msg.sender);
    nonces[msg.sender]++;
}
"""

SRC_MARKS_USED_EXECUTED = """
function executeOnce(bytes32 hash, uint8 v, bytes32 r, bytes32 s) external {
    bytes32 digest = keccak256(abi.encode(hash, block.chainid));
    address signer = ecrecover(digest, v, r, s);
    require(signer == authorized);
    executed[hash] = true;
}
"""

SRC_NO_MARKS_USED = """
function verifyAndAct(bytes32 hash, uint8 v, bytes32 r, bytes32 s) external {
    bytes32 digest = keccak256(abi.encode(hash, nonce, block.chainid));
    address signer = ecrecover(digest, v, r, s);
    require(signer == authorized);
    doAction();
}
"""

SRC_FULL_PROTECTION = """
function permitFull(address owner, address spender, uint256 value, uint256 deadline,
                    uint8 v, bytes32 r, bytes32 s) external {
    bytes32 domainSeparator = keccak256(abi.encode(DOMAIN_TYPEHASH, name, block.chainid, address(this)));
    bytes32 structHash = keccak256(abi.encode(PERMIT_TYPEHASH, owner, spender, value, nonces[owner], deadline));
    bytes32 hash = keccak256(abi.encodePacked("\\x19\\x01", domainSeparator, structHash));
    address signer = ecrecover(hash, v, r, s);
    require(signer == owner, "INVALID_SIGNER");
    nonces[owner]++;
}
"""

SRC_MISSING_CHAINID = """
function permitNoChain(address owner, address spender, uint256 value,
                       uint8 v, bytes32 r, bytes32 s) external {
    bytes32 structHash = keccak256(abi.encode(PERMIT_TYPEHASH, owner, spender, value, nonces[owner]));
    bytes32 hash = keccak256(abi.encodePacked("\\x19\\x01", DOMAIN_SEPARATOR, structHash));
    address signer = ecrecover(hash, v, r, s);
    require(signer == owner);
    nonces[owner]++;
}
"""

SRC_MISSING_NONCE = """
function permitBare(address owner, address spender, uint256 value,
                    uint8 v, bytes32 r, bytes32 s) external {
    bytes32 domainSeparator = keccak256(abi.encode(DOMAIN_TYPEHASH, name, block.chainid, address(this)));
    bytes32 structHash = keccak256(abi.encode(PERMIT_TYPEHASH, owner, spender, value));
    bytes32 hash = keccak256(abi.encodePacked("\\x19\\x01", domainSeparator, structHash));
    address signer = ecrecover(hash, v, r, s);
    require(signer == owner);
    consumed[hash] = true;
}
"""

SRC_MISSING_MARKS_USED = """
function permitNoMark(address owner, address spender, uint256 value,
                      uint8 v, bytes32 r, bytes32 s) external {
    bytes32 domainSeparator = keccak256(abi.encode(DOMAIN_TYPEHASH, name, block.chainid, address(this)));
    bytes32 structHash = keccak256(abi.encode(PERMIT_TYPEHASH, owner, spender, value, nonce));
    bytes32 hash = keccak256(abi.encodePacked("\\x19\\x01", domainSeparator, structHash));
    address signer = ecrecover(hash, v, r, s);
    require(signer == owner);
    allowances[owner][spender] = value;
}
"""


# ════════════════════════════════════════════════════════════
#  Helper
# ════════════════════════════════════════════════════════════


def _make_builder(functions: dict) -> tuple:
    builder = GraphBuilder()
    for node_id, props in functions.items():
        contract = node_id.split("::")[0]
        if not builder.graph.has_node(contract):
            builder.graph.add_node(contract, type="contract", name=contract, tier="CORE")
        builder.graph.add_node(
            node_id,
            type="function",
            **{
                "name": node_id.split("::")[-1],
                "contract": contract,
                "source_code": props.get("source_code", ""),
                "is_external_entry": props.get("is_external_entry", True),
                "writes_state": props.get("writes_state", False),
                "risk_score": props.get("risk_score", 0),
                "risk_categories": list(props.get("risk_categories", [])),
                "state_variables_written": props.get("state_variables_written", []),
                "is_view_or_pure": props.get("is_view_or_pure", False),
                "is_constructor": False,
                "visibility": props.get("visibility", "external"),
                "stateMutability": props.get("stateMutability", "nonpayable"),
            },
        )
        builder.graph.add_edge(contract, node_id, relationship="DEFINES")
    builder._detect_signature_patterns()
    return builder, builder.graph, GraphQueries(builder.graph)


# ════════════════════════════════════════════════════════════
#  Tests
# ════════════════════════════════════════════════════════════


class TestSignatureDetection:
    def test_ecrecover_detected(self):
        _, g, _ = _make_builder({"A::verify": {"source_code": SRC_ECRECOVER}})
        assert g.nodes["A::verify"]["uses_signature_validation"] is True

    def test_ecdsa_library_detected(self):
        _, g, _ = _make_builder({"A::verify": {"source_code": SRC_ECDSA_LIB}})
        assert g.nodes["A::verify"]["uses_signature_validation"] is True

    def test_no_sig_no_fields(self):
        _, g, _ = _make_builder({"A::transfer": {"source_code": SRC_NO_SIG}})
        d = g.nodes["A::transfer"]
        assert d["uses_signature_validation"] is False
        assert d["signature_replay_risk"] is False

    def test_chainid_included(self):
        _, g, _ = _make_builder({"A::permit": {"source_code": SRC_CHAINID_PRESENT}})
        assert g.nodes["A::permit"]["signature_includes_chainid"] is True

    def test_chainid_missing(self):
        _, g, _ = _make_builder({"A::verify": {"source_code": SRC_CHAINID_MISSING}})
        assert g.nodes["A::verify"]["signature_includes_chainid"] is False

    def test_nonce_included(self):
        _, g, _ = _make_builder({"A::executeWithNonce": {"source_code": SRC_NONCE_PRESENT}})
        assert g.nodes["A::executeWithNonce"]["signature_includes_nonce"] is True

    def test_nonce_missing(self):
        _, g, _ = _make_builder({"A::execute": {"source_code": SRC_NONCE_MISSING}})
        assert g.nodes["A::execute"]["signature_includes_nonce"] is False

    def test_marks_used_via_mapping(self):
        _, g, _ = _make_builder(
            {
                "A::executeMetaTx": {
                    "source_code": SRC_MARKS_USED_NONCE,
                    "state_variables_written": ["A::nonces"],
                }
            }
        )
        assert g.nodes["A::executeMetaTx"]["signature_marks_used"] is True

    def test_marks_used_via_executed(self):
        _, g, _ = _make_builder(
            {
                "A::executeOnce": {
                    "source_code": SRC_MARKS_USED_EXECUTED,
                    "state_variables_written": ["A::executed"],
                }
            }
        )
        assert g.nodes["A::executeOnce"]["signature_marks_used"] is True

    def test_no_marks_used(self):
        _, g, _ = _make_builder(
            {
                "A::verifyAndAct": {
                    "source_code": SRC_NO_MARKS_USED,
                    "state_variables_written": ["A::counter"],
                }
            }
        )
        assert g.nodes["A::verifyAndAct"]["signature_marks_used"] is False

    def test_full_protection_no_risk(self):
        _, g, _ = _make_builder(
            {
                "A::permitFull": {
                    "source_code": SRC_FULL_PROTECTION,
                    "state_variables_written": ["A::nonces"],
                }
            }
        )
        assert g.nodes["A::permitFull"]["signature_replay_risk"] is False

    def test_missing_chainid_risk(self):
        _, g, _ = _make_builder(
            {
                "A::permitNoChain": {
                    "source_code": SRC_MISSING_CHAINID,
                    "state_variables_written": ["A::nonces"],
                }
            }
        )
        d = g.nodes["A::permitNoChain"]
        assert d["signature_includes_chainid"] is False
        assert d["signature_replay_risk"] is True

    def test_missing_nonce_risk(self):
        _, g, _ = _make_builder(
            {
                "A::permitBare": {
                    "source_code": SRC_MISSING_NONCE,
                    "state_variables_written": ["A::consumed"],
                }
            }
        )
        d = g.nodes["A::permitBare"]
        assert d["signature_includes_nonce"] is False
        assert d["signature_replay_risk"] is True

    def test_missing_marks_used_risk(self):
        _, g, _ = _make_builder(
            {
                "A::permitNoMark": {
                    "source_code": SRC_MISSING_MARKS_USED,
                    "state_variables_written": ["A::allowances"],
                }
            }
        )
        d = g.nodes["A::permitNoMark"]
        assert d["signature_marks_used"] is False
        assert d["signature_replay_risk"] is True

    def test_score_plus_100(self):
        _, g, _ = _make_builder({"A::verify": {"source_code": SRC_ECRECOVER, "risk_score": 10}})
        assert g.nodes["A::verify"]["risk_score"] == 10 + 100

    def test_hotspot_surfaced(self):
        builder, g, queries = _make_builder(
            {
                "A::verify": {
                    "source_code": SRC_ECRECOVER,
                    "risk_score": 0,
                    "writes_state": True,
                }
            }
        )
        g.nodes["A::verify"]["structural_score"] = 50
        g.nodes["A::verify"]["exploitability_score"] = 40
        g.nodes["A::verify"]["final_score"] = g.nodes["A::verify"]["risk_score"]
        hotspots = queries.get_high_risk_hotspots(min_score=70)
        node_ids = [h.node_id for h in hotspots]
        assert "A::verify" in node_ids
