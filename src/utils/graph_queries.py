import networkx as nx
from typing import List, Dict, Any

from src.utils.node_ids import normalize_node_id


# ════════════════════════════════════════════════════════════
#  Test Contract Filter
# ════════════════════════════════════════════════════════════

# Contract name suffixes/prefixes that identify test/mock/fuzzing artifacts.
_TEST_NAME_PATTERNS = (
    # Standard test framework patterns
    "Test",
    "Mock",
    "Echidna",
    "Fuzz",
    "Stub",
    "Helper",
    "Harness",
    "Script",
    "Invariant",
    "Handler",
    "Exploit",       # Our own generated tests
    # Common test helper contract patterns (e.g. solmate's BalanceSum, RiskyContract)
    "Sum",           # Fuzz/balance accumulators (e.g. BalanceSum)
    "Risky",         # Intentionally-risky test helpers (e.g. RiskyContract)
    "Vulnerable",    # Deliberately vulnerable contracts in test suites
    "Attacker",      # Attack simulation contracts
    "Victim",        # Test victim contracts
    "Malicious",     # Malicious actor simulations
    "Dummy",         # Placeholder implementations
    "Fake",          # Fake implementations
    "Wrong",         # Wrong return data testers (e.g. WrongReturnDataERC721Recipient)
    "Reverting",     # Reverting implementations for negative testing
    "NonCompliant",  # Non-compliant implementations for edge-case testing
    "Recipient",     # Test callback receivers (e.g. ERC721Recipient)
)

# Source path fragments that identify test/script directories.
_TEST_PATH_FRAGMENTS = (
    "/test/",
    "/tests/",
    "/mocks/",
    "/mock/",
    "/scripts/",
    "/script/",
    "/echidna/",
    "/fuzz/",
    "/fuzzing/",
    "/invariant/",
    "/e2e/",
    "/crytic/",
    "/audits/",
)


def _is_test_contract(contract_name: str, source_file: str = "") -> bool:
    """
    Returns True if the contract is a test/mock/fuzzing artifact
    that should be excluded from vulnerability analysis.

    Checks contract name suffix/prefix and source file path.
    """
    for pattern in _TEST_NAME_PATTERNS:
        if contract_name.endswith(pattern) or contract_name.startswith(pattern):
            return True
    norm_path = source_file.replace("\\", "/")
    for fragment in _TEST_PATH_FRAGMENTS:
        if fragment in norm_path:
            return True
    return False


class GraphQueries:
    def __init__(self, graph: nx.DiGraph):
        self.graph = graph

    def get_function_context(self, node_id: str) -> Dict[str, Any]:
        normalized = normalize_node_id(node_id)
        if not self.graph.has_node(normalized):
            return {"error": "Node not found", "normalized_id": normalized}
        node_data = self.graph.nodes[normalized]
        if node_data.get("type") != "function":
            return {"error": "Node is not a function"}
        callers = [
            n for n in self.graph.predecessors(normalized)
            if self.graph.get_edge_data(n, normalized).get("relationship") == "CALLS"
        ]
        callees = [
            n for n in self.graph.successors(normalized)
            if self.graph.get_edge_data(normalized, n).get("relationship") == "CALLS"
        ]
        source_code = node_data.get("source_code", "")
        return {
            "node_id": normalized,
            "source_code": source_code,
            "code": source_code,
            "callers": callers,
            "callees": callees
        }

    def find_state_mutators(self, variable_name: str) -> List[str]:
        normalized = normalize_node_id(variable_name)
        if not self.graph.has_node(normalized):
            return []
        return [
            n for n in self.graph.predecessors(normalized)
            if self.graph.get_edge_data(n, normalized).get("relationship") == "WRITES"
        ]

    def get_modifiers(self, function_id: str) -> List[str]:
        normalized = normalize_node_id(function_id)
        if not self.graph.has_node(normalized):
            return []
        return self.graph.nodes[normalized].get("modifiers", [])

    def verify_existence(self, node_name: str) -> bool:
        return self.graph.has_node(node_name)

    def get_external_entry_points(self, contract_name: str | None = None) -> List[Dict[str, Any]]:
        entry_points = []
        for node_id, node_data in self.graph.nodes(data=True):
            if node_data.get("type") == "function" and node_data.get("is_external_entry"):
                if contract_name and node_data.get("contract") != contract_name:
                    continue
                entry_points.append({
                    "node_id": node_id,
                    "name": node_data.get("name"),
                    "contract": node_data.get("contract"),
                    "visibility": node_data.get("visibility"),
                    "is_payable": node_data.get("is_payable", False),
                    "modifiers": node_data.get("modifiers", [])
                })
        return entry_points

    def get_state_mutators(self, contract_name: str | None = None) -> List[Dict[str, Any]]:
        mutators = []
        for node_id, node_data in self.graph.nodes(data=True):
            if node_data.get("type") == "function" and node_data.get("writes_state"):
                if contract_name and node_data.get("contract") != contract_name:
                    continue
                mutators.append({
                    "function_id": node_id,
                    "name": node_data.get("name"),
                    "contract_name": node_data.get("contract"),
                    "num_state_writes": node_data.get("num_state_writes", 0),
                    "state_variables_written": node_data.get("state_variables_written", []),
                    "visibility": node_data.get("visibility"),
                    "modifiers": node_data.get("modifiers", [])
                })
        return mutators

    def get_internal_calls(self, function_id: str) -> List[str]:
        if not self.graph.has_node(function_id):
            return []
        node_data = self.graph.nodes.get(function_id, {})
        if node_data.get("type") != "function":
            return []
        return node_data.get("internal_calls", [])

    def get_callers(self, function_id: str) -> List[str]:
        if not self.graph.has_node(function_id):
            return []
        return [
            n for n in self.graph.predecessors(function_id)
            if self.graph.get_edge_data(n, function_id).get("relationship") == "CALLS"
        ]

    def get_call_graph(self, contract_name: str | None = None) -> Dict[str, Any]:
        nodes = []
        edges = []
        for node_id, node_data in self.graph.nodes(data=True):
            if node_data.get("type") != "function":
                continue
            if contract_name and node_data.get("contract") != contract_name:
                continue
            nodes.append({
                "id": node_id,
                "name": node_data.get("name"),
                "contract": node_data.get("contract"),
                "is_external_entry": node_data.get("is_external_entry", False),
                "is_leaf_function": node_data.get("is_leaf_function", False),
                "num_internal_calls": node_data.get("num_internal_calls", 0)
            })
        node_ids = {n["id"] for n in nodes}
        for source, target, edge_data in self.graph.edges(data=True):
            if edge_data.get("relationship") != "CALLS":
                continue
            if source in node_ids and target in node_ids:
                edges.append({
                    "source": source,
                    "target": target,
                    "call_type": edge_data.get("call_type", "internal")
                })
        return {"nodes": nodes, "edges": edges}

    def get_modifier_details(self, modifier_name: str, contract_name: str | None = None) -> Dict[str, Any]:
        for node_id, node_data in self.graph.nodes(data=True):
            if node_data.get("type") != "modifier":
                continue
            if node_data.get("name") != modifier_name:
                continue
            if contract_name and node_data.get("contract") != contract_name:
                continue
            return {
                "node_id": node_id,
                "name": node_data.get("name"),
                "contract": node_data.get("contract"),
                "conditions": node_data.get("conditions", []),
                "accesses_state_variables": node_data.get("accesses_state_variables", []),
                "is_access_control": node_data.get("is_access_control", False),
                "access_control_pattern": node_data.get("access_control_pattern", "none")
            }
        return {"error": f"Modifier '{modifier_name}' not found"}

    def get_access_control_summary(self, contract_name: str | None = None) -> List[Dict[str, Any]]:
        results = []
        for node_id, node_data in self.graph.nodes(data=True):
            if node_data.get("type") != "function":
                continue
            if contract_name and node_data.get("contract") != contract_name:
                continue
            results.append({
                "function_id": node_id,
                "name": node_data.get("name"),
                "contract": node_data.get("contract"),
                "visibility": node_data.get("visibility"),
                "modifiers": node_data.get("modifiers", []),
                "has_access_control": node_data.get("has_access_control", False),
                "access_control_modifiers": node_data.get("access_control_modifiers", []),
                "has_inline_access_check": node_data.get("has_inline_access_check", False),
                "is_protected": node_data.get("is_protected", False),
                "writes_state": node_data.get("writes_state", False),
                "is_external_entry": node_data.get("is_external_entry", False)
            })
        return results

    def get_privileged_roles(self, contract_name: str | None = None) -> List[Dict[str, Any]]:
        roles = []
        for node_id, node_data in self.graph.nodes(data=True):
            if node_data.get("type") != "contract":
                continue
            if contract_name and node_data.get("name") != contract_name:
                continue
            for role in node_data.get("privileged_roles", []):
                roles.append({"contract": node_data.get("name"), **role})
        return roles

    def get_unprotected_mutators(self, contract_name: str | None = None) -> List[Dict[str, Any]]:
        results = []
        for node_id, node_data in self.graph.nodes(data=True):
            if node_data.get("type") != "function":
                continue
            if not node_data.get("is_unprotected_mutator"):
                continue
            if contract_name and node_data.get("contract") != contract_name:
                continue
            results.append({
                "function_id": node_id,
                "name": node_data.get("name"),
                "contract": node_data.get("contract"),
                "state_variables_written": node_data.get("state_variables_written", []),
                "risk_level": node_data.get("unprotected_risk_level", "MEDIUM"),
                "visibility": node_data.get("visibility"),
                "is_payable": node_data.get("is_payable", False)
            })
        return results

    def get_external_call_functions(self, contract_name: str | None = None) -> List[Dict[str, Any]]:
        results = []
        for node_id, node_data in self.graph.nodes(data=True):
            if node_data.get("type") != "function":
                continue
            if not node_data.get("makes_external_call"):
                continue
            if contract_name and node_data.get("contract") != contract_name:
                continue
            results.append({
                "function_id": node_id,
                "name": node_data.get("name"),
                "contract": node_data.get("contract"),
                "external_call_type": node_data.get("external_call_type", []),
                "external_call_nodes": node_data.get("external_call_nodes", []),
                "state_write_after_external_call": node_data.get("state_write_after_external_call", False),
                "state_write_after_reentrant_call": node_data.get("state_write_after_reentrant_call", False),
                "visibility": node_data.get("visibility"),
                "is_payable": node_data.get("is_payable", False),
            })
        return results

    def get_external_call_edges(self, function_id: str) -> List[Dict[str, Any]]:
        """Returns all EXTERNAL_CALL edges originating from a function."""
        if not self.graph.has_node(function_id):
            return []
        edges = []
        for _, target, data in self.graph.out_edges(function_id, data=True):
            if data.get("relationship") != "EXTERNAL_CALL":
                continue
            edges.append({
                "target": target,
                "call_type": data.get("call_type", "unknown"),
                "forwards_gas": data.get("forwards_gas", "unknown"),
                "target_expression": data.get("target_expression", ""),
                "return_value_checked": data.get("return_value_checked", False),
            })
        return edges

    def get_reentrancy_risks(self, contract_name: str | None = None) -> List[Dict[str, Any]]:
        results = []
        for node_id, node_data in self.graph.nodes(data=True):
            if node_data.get("type") != "function":
                continue
            if not node_data.get("reentrancy_risk"):
                continue
            if contract_name and node_data.get("contract") != contract_name:
                continue
            results.append({
                "function_id": node_id,
                "name": node_data.get("name"),
                "contract": node_data.get("contract"),
                "reentrancy_risk_score": node_data.get("reentrancy_risk_score", 0),
                "external_call_type": node_data.get("external_call_type", []),
                "propagated_state_variables": node_data.get("propagated_state_variables", []),
                "visibility": node_data.get("visibility"),
                "is_payable": node_data.get("is_payable", False),
            })
        return results

    def get_cei_violations(self, contract_name: str | None = None) -> List[Dict[str, Any]]:
        """Returns functions with CEI violations that are NOT reentrancy risks
        (e.g. transfer/send/staticcall before state write)."""
        results = []
        for node_id, node_data in self.graph.nodes(data=True):
            if node_data.get("type") != "function":
                continue
            if not node_data.get("cei_violation_only"):
                continue
            if contract_name and node_data.get("contract") != contract_name:
                continue
            results.append({
                "function_id": node_id,
                "name": node_data.get("name"),
                "contract": node_data.get("contract"),
                "external_call_type": node_data.get("external_call_type", []),
                "propagated_state_variables": node_data.get("propagated_state_variables", []),
                "visibility": node_data.get("visibility"),
            })
        return results

    # ════════════════════════════════════════════════════════════
    #  Epic 6 — StateTransition Queries
    # ════════════════════════════════════════════════════════════

    def get_state_transitions(
        self,
        function_id: str | None = None,
        variable_id: str | None = None,
        contract_name: str | None = None,
        operation: str | None = None,
    ) -> List[Dict[str, Any]]:
        """
        Returns StateTransition nodes with optional filters.

        Filters:
          function_id  — only transitions performed by this function
          variable_id  — only transitions affecting this variable
          contract_name — only transitions in functions belonging to this contract
          operation    — only transitions of this type (assign, add, sub, push, pop, …)
        """
        results = []
        for node_id, node_data in self.graph.nodes(data=True):
            if node_data.get("type") != "state_transition":
                continue

            if function_id and node_data.get("function") != function_id:
                continue
            if variable_id and node_data.get("variable") != variable_id:
                continue
            if operation and node_data.get("operation") != operation:
                continue

            if contract_name:
                func_id = node_data.get("function", "")
                func_data = self.graph.nodes.get(func_id, {})
                if func_data.get("contract") != contract_name:
                    continue

            results.append({
                "transition_id": node_id,
                "function": node_data.get("function"),
                "variable": node_data.get("variable"),
                "operation": node_data.get("operation"),
                "is_array_length": node_data.get("is_array_length", False),
                "is_array": node_data.get("is_array", False),
                "is_mapping": node_data.get("is_mapping", False),
                "is_owner_assignment": node_data.get("is_owner_assignment", False),
                "attacker_controlled_input": node_data.get("attacker_controlled_input", False),
                "affects_privileged_var": node_data.get("affects_privileged_var", False),
                "ir_expression": node_data.get("ir_expression", ""),
            })
        return results

    def get_array_length_mutations(
        self, contract_name: str | None = None
    ) -> List[Dict[str, Any]]:
        """
        Story 6.2: Returns functions that contain array length mutation
        primitives (pop / decrement_length on dynamic arrays).
        """
        results = []
        for node_id, node_data in self.graph.nodes(data=True):
            if node_data.get("type") != "function":
                continue
            if not node_data.get("has_array_length_mutation"):
                continue
            if contract_name and node_data.get("contract") != contract_name:
                continue
            results.append({
                "function_id": node_id,
                "name": node_data.get("name"),
                "contract": node_data.get("contract"),
                "visibility": node_data.get("visibility"),
                "is_protected": node_data.get("is_protected", False),
            })
        return results

    def get_delegatecall_storage_risks(
        self, contract_name: str | None = None
    ) -> List[Dict[str, Any]]:
        """
        Story 6.3: Returns functions flagged with DELEGATECALL_STORAGE_RISK.
        """
        results = []
        for node_id, node_data in self.graph.nodes(data=True):
            if node_data.get("type") != "function":
                continue
            if not node_data.get("delegatecall_storage_risk"):
                continue
            if contract_name and node_data.get("contract") != contract_name:
                continue
            results.append({
                "function_id": node_id,
                "name": node_data.get("name"),
                "contract": node_data.get("contract"),
                "visibility": node_data.get("visibility"),
                "external_call_type": node_data.get("external_call_type", []),
                "state_write_after_external_call": node_data.get(
                    "state_write_after_external_call", False
                ),
            })
        return results

    # ════════════════════════════════════════════════════════════
    #  Epic 7 — Contract Tier Queries
    # ════════════════════════════════════════════════════════════

    def get_contract_tiers(
        self, tier: str | None = None
    ) -> List[Dict[str, Any]]:
        """
        Returns contract-level tier classifications.

        Optional filter: pass tier='CORE' (or FACTORY, LIBRARY, INFRA)
        to return only contracts of that tier.
        """
        results = []
        for node_id, node_data in self.graph.nodes(data=True):
            if node_data.get("type") != "contract":
                continue
            contract_tier = node_data.get("tier", "INFRA")
            if tier and contract_tier != tier:
                continue
            results.append({
                "contract": node_id,
                "tier": contract_tier,
                "is_library": node_data.get("is_library", False),
                "is_interface": node_data.get("is_interface", False),
                "is_upgradeable": node_data.get("is_upgradeable", False),
            })
        return results

    # ════════════════════════════════════════════════════════════
    #  Dev Story 1 — Guard & Access Pattern Precision Queries
    # ════════════════════════════════════════════════════════════

    def get_guarded_initializers(self, contract_name: str | None = None) -> List[Dict[str, Any]]:
        """Returns functions with detected initializer guards."""
        results = []
        for node_id, node_data in self.graph.nodes(data=True):
            if node_data.get("type") != "function":
                continue
            if not node_data.get("has_initializer_guard"):
                continue
            if contract_name and node_data.get("contract") != contract_name:
                continue
            results.append({
                "function_id": node_id,
                "name": node_data.get("name"),
                "contract": node_data.get("contract"),
                "has_initializer_guard": True,
                "safe_init_pattern": node_data.get("safe_init_pattern", False),
                "has_initializer_modifier": node_data.get("has_initializer_modifier", False),
                "is_protected": node_data.get("is_protected", False),
            })
        return results

    def get_access_control_types(self, contract_name: str | None = None) -> List[Dict[str, Any]]:
        """Returns functions annotated with their access_control_type classification."""
        results = []
        for node_id, node_data in self.graph.nodes(data=True):
            if node_data.get("type") != "function":
                continue
            if contract_name and node_data.get("contract") != contract_name:
                continue
            ac_type = node_data.get("access_control_type", "none")
            if ac_type == "none":
                continue
            results.append({
                "function_id": node_id,
                "name": node_data.get("name"),
                "contract": node_data.get("contract"),
                "access_control_type": ac_type,
                "require_access_control_targets": node_data.get("require_access_control_targets", []),
                "modifier_equivalences": node_data.get("modifier_equivalences", {}),
                "is_protected": node_data.get("is_protected", False),
            })
        return results

    def get_modifier_equivalences(self, contract_name: str | None = None) -> List[Dict[str, Any]]:
        """Returns modifier nodes with their semantic category classification."""
        results = []
        for node_id, node_data in self.graph.nodes(data=True):
            if node_data.get("type") != "modifier":
                continue
            if contract_name and node_data.get("contract") != contract_name:
                continue
            results.append({
                "modifier_id": node_id,
                "name": node_data.get("name"),
                "contract": node_data.get("contract"),
                "semantic_category": node_data.get("semantic_category", "custom"),
                "is_access_control": node_data.get("is_access_control", False),
            })
        return results

    def get_safe_functions(self, contract_name: str | None = None) -> List[Dict[str, Any]]:
        """
        Returns functions considered safe due to guard patterns.
        Useful for filtering out false positives from hotspot lists.
        """
        results = []
        for node_id, node_data in self.graph.nodes(data=True):
            if node_data.get("type") != "function":
                continue
            if contract_name and node_data.get("contract") != contract_name:
                continue

            safe_reasons: list[str] = []
            if node_data.get("safe_init_pattern"):
                safe_reasons.append("SAFE_INIT_PATTERN")
            if node_data.get("has_reentrancy_guard"):
                safe_reasons.append("REENTRANCY_GUARDED")
            ac_type = node_data.get("access_control_type", "none")
            if ac_type in ("modifier", "require-based", "both"):
                safe_reasons.append(f"ACCESS_CONTROLLED({ac_type})")

            if not safe_reasons:
                continue

            results.append({
                "function_id": node_id,
                "name": node_data.get("name"),
                "contract": node_data.get("contract"),
                "safe_reasons": safe_reasons,
                "risk_categories": node_data.get("risk_categories", []),
                "final_score": node_data.get("final_score", 0),
            })
        return results

    # ════════════════════════════════════════════════════════════
    #  Dev Story 2 — Taint & Dataflow Queries
    # ════════════════════════════════════════════════════════════

    def get_taint_critical_paths(self, contract_name: str | None = None) -> List[Dict[str, Any]]:
        """Returns functions with taint flows into sensitive storage."""
        results = []
        for node_id, node_data in self.graph.nodes(data=True):
            if node_data.get("type") != "function":
                continue
            if not node_data.get("has_taint_risk"):
                continue
            if contract_name and node_data.get("contract") != contract_name:
                continue
            results.append({
                "function_id": node_id,
                "name": node_data.get("name"),
                "contract": node_data.get("contract"),
                "taint_sources": node_data.get("taint_sources", []),
                "taint_risk_types": node_data.get("taint_risk_types", []),
                "taint_critical_paths": node_data.get("taint_critical_paths", []),
                "taint_risk_score": node_data.get("taint_risk_score", 0),
                "cross_function_taint_paths": node_data.get("cross_function_taint_paths", []),
            })
        results.sort(key=lambda x: x["taint_risk_score"], reverse=True)
        return results

    def get_storage_sensitivity_tags(self, contract_name: str | None = None) -> List[Dict[str, Any]]:
        """Returns state variables with sensitivity classifications."""
        results = []
        for node_id, node_data in self.graph.nodes(data=True):
            if node_data.get("type") != "state_variable":
                continue
            if not node_data.get("is_sensitive"):
                continue
            if contract_name and node_data.get("contract") != contract_name:
                continue
            results.append({
                "variable_id": node_id,
                "name": node_data.get("name"),
                "contract": node_data.get("contract"),
                "sensitivity_tags": node_data.get("sensitivity_tags", []),
                "sensitivity_tag": node_data.get("sensitivity_tag"),
                "tainted": node_data.get("tainted", False),
                "taint_sources": node_data.get("taint_sources", []),
                "tainted_by_functions": node_data.get("tainted_by_functions", []),
            })
        return results

    def get_tainted_variables(self, contract_name: str | None = None) -> List[Dict[str, Any]]:
        """Returns state variables that receive attacker-controlled data."""
        results = []
        for node_id, node_data in self.graph.nodes(data=True):
            if node_data.get("type") != "state_variable":
                continue
            if not node_data.get("tainted"):
                continue
            if contract_name and node_data.get("contract") != contract_name:
                continue
            results.append({
                "variable_id": node_id,
                "name": node_data.get("name"),
                "contract": node_data.get("contract"),
                "sensitivity_tags": node_data.get("sensitivity_tags", []),
                "taint_sources": node_data.get("taint_sources", []),
                "tainted_by_functions": node_data.get("tainted_by_functions", []),
            })
        return results

    def get_taint_risks(
        self,
        risk_type: str | None = None,
        contract_name: str | None = None,
    ) -> List[Dict[str, Any]]:
        """
        Returns functions with specific taint risk types.

        risk_type filter: TAINT_ACCOUNTING_RISK, TAINT_CAP_BYPASS,
        TAINT_REWARD_RISK, TAINT_ACCESS_RISK, TAINT_LIQUIDITY_RISK,
        UNCHECKED_EXT_RETURN, TAINT_CRITICAL_PATH
        """
        results = []
        for node_id, node_data in self.graph.nodes(data=True):
            if node_data.get("type") != "function":
                continue
            if not node_data.get("has_taint_risk"):
                continue
            if contract_name and node_data.get("contract") != contract_name:
                continue
            func_risks = node_data.get("taint_risk_types", [])
            if risk_type and risk_type not in func_risks:
                continue
            results.append({
                "function_id": node_id,
                "name": node_data.get("name"),
                "contract": node_data.get("contract"),
                "taint_risk_types": func_risks,
                "taint_risk_score": node_data.get("taint_risk_score", 0),
                "tainted_state_writes": node_data.get("tainted_state_writes", []),
                "unchecked_external_return": node_data.get("unchecked_external_return", False),
            })
        results.sort(key=lambda x: x["taint_risk_score"], reverse=True)
        return results

    # ════════════════════════════════════════════════════════════
    #  Dev Story 3 — Cross-Function State Transition Queries
    # ════════════════════════════════════════════════════════════

    def get_state_dependencies(self, contract_name: str | None = None) -> List[Dict[str, Any]]:
        """Returns STATE_DEPENDENCY edges between functions sharing state."""
        results = []
        for src, dst, edge_data in self.graph.edges(data=True):
            if edge_data.get("relationship") != "STATE_DEPENDENCY":
                continue
            src_data = self.graph.nodes.get(src, {})
            if contract_name and src_data.get("contract") != contract_name:
                continue
            results.append({
                "writer": src,
                "reader": dst,
                "shared_variables": edge_data.get("shared_variables", []),
                "dependency_type": edge_data.get("dependency_type", ""),
                "sensitivity_overlap": edge_data.get("sensitivity_overlap", []),
            })
        return results

    def get_dangerous_sequences(self, contract_name: str | None = None) -> List[Dict[str, Any]]:
        """Returns functions with dangerous state manipulation sequences."""
        results = []
        for node_id, node_data in self.graph.nodes(data=True):
            if node_data.get("type") != "function":
                continue
            if not node_data.get("has_dangerous_sequence"):
                continue
            if contract_name and node_data.get("contract") != contract_name:
                continue
            results.append({
                "function_id": node_id,
                "name": node_data.get("name"),
                "contract": node_data.get("contract"),
                "dangerous_sequences": node_data.get("dangerous_sequences", []),
                "sequence_risk_score": node_data.get("sequence_risk_score", 0),
            })
        results.sort(key=lambda x: x["sequence_risk_score"], reverse=True)
        return results

    def get_exploit_chains(
        self,
        contract_name: str | None = None,
        min_length: int = 2,
    ) -> List[Dict[str, Any]]:
        """
        Returns auto-generated exploit chains for ExploitWriter consumption.

        Each chain contains ordered steps with function signatures
        and roles (MANIPULATE → INTERMEDIATE → EXTRACT).
        """
        results = []
        for node_id, node_data in self.graph.nodes(data=True):
            if node_data.get("type") != "function":
                continue
            if not node_data.get("is_chain_entry"):
                continue
            if contract_name and node_data.get("contract") != contract_name:
                continue
            for chain in node_data.get("exploit_chains", []):
                if chain.get("chain_length", 0) < min_length:
                    continue
                results.append({
                    "entry_function": node_id,
                    "contract": node_data.get("contract"),
                    "steps": chain.get("steps", []),
                    "exploit_sequence": chain.get("exploit_sequence", []),
                    "shared_variables": chain.get("shared_variables", []),
                    "sensitivity": chain.get("sensitivity", []),
                    "danger_types": chain.get("danger_types", []),
                    "chain_length": chain.get("chain_length", 0),
                    "chain_score": chain.get("chain_score", 0),
                })
        results.sort(key=lambda x: x["chain_score"], reverse=True)
        return results

    # ════════════════════════════════════════════════════════════
    #  Dev Story 4/5/6 — Accounting, Exploit Target, External Risk Queries
    # ════════════════════════════════════════════════════════════

    def get_accounting_invariant_risks(
        self,
        contract_name: str | None = None,
    ) -> List[Dict[str, Any]]:
        """Returns functions flagged by accounting/invariant heuristics."""
        results = []
        for node_id, node_data in self.graph.nodes(data=True):
            if node_data.get("type") != "function":
                continue
            if contract_name and node_data.get("contract") != contract_name:
                continue

            has_any = (
                node_data.get("supply_consistency_issue")
                or node_data.get("cap_enforcement_issue")
                or node_data.get("reward_drift_issue")
                or node_data.get("monotonicity_issue")
            )
            if not has_any:
                continue

            score = (
                node_data.get("supply_consistency_score", 0)
                + node_data.get("cap_enforcement_score", 0)
                + node_data.get("reward_drift_score", 0)
                + node_data.get("monotonicity_score", 0)
            )
            results.append({
                "function_id": node_id,
                "name": node_data.get("name"),
                "contract": node_data.get("contract"),
                "supply_consistency_flags": node_data.get("supply_consistency_flags", []),
                "cap_enforcement_flags": node_data.get("cap_enforcement_flags", []),
                "reward_drift_flags": node_data.get("reward_drift_flags", []),
                "monotonicity_flags": node_data.get("monotonicity_flags", []),
                "accounting_invariant_score": score,
            })
        results.sort(key=lambda x: x["accounting_invariant_score"], reverse=True)
        return results

    def get_external_call_risks(
        self,
        risk_tag: str | None = None,
        contract_name: str | None = None,
    ) -> List[Dict[str, Any]]:
        """Returns functions with external call risk tags (DS6)."""
        results = []
        for node_id, node_data in self.graph.nodes(data=True):
            if node_data.get("type") != "function":
                continue
            if contract_name and node_data.get("contract") != contract_name:
                continue
            if not node_data.get("has_external_call_risk"):
                continue

            tags = node_data.get("external_risk_tags", [])
            if risk_tag and risk_tag not in tags:
                continue

            results.append({
                "function_id": node_id,
                "name": node_data.get("name"),
                "contract": node_data.get("contract"),
                "external_risk_tags": tags,
                "external_call_risk_score": node_data.get("external_call_risk_score", 0),
                "state_write_after_external_call": node_data.get("state_write_after_external_call", False),
                "unchecked_external_return": node_data.get("unchecked_external_return", False),
            })
        results.sort(key=lambda x: x["external_call_risk_score"], reverse=True)
        return results

    def get_exploit_targets(
        self,
        min_exploit_score: int = 75,
        contract_name: str | None = None,
    ) -> List[Dict[str, Any]]:
        """
        Returns functions eligible for ExploitWriter based on DS5 scoring.
        """
        results = []
        for node_id, node_data in self.graph.nodes(data=True):
            if node_data.get("type") != "function":
                continue
            if contract_name and node_data.get("contract") != contract_name:
                continue
            exploit_score = node_data.get("exploit_target_score", 0)
            if exploit_score < min_exploit_score:
                continue
            if not node_data.get("send_to_exploit_writer", False):
                continue
            results.append({
                "function_id": node_id,
                "name": node_data.get("name"),
                "contract": node_data.get("contract"),
                "exploit_target_score": exploit_score,
                "exploit_target_threshold": node_data.get("exploit_target_threshold", 65),
                "final_score": node_data.get("final_score", node_data.get("risk_score", 0)),
                "risk_categories": node_data.get("risk_categories", []),
            })
        results.sort(key=lambda x: x["exploit_target_score"], reverse=True)
        return results

    def get_privilege_escalation_risks(self, contract_name: str | None = None) -> Dict[str, Any]:
        risky_functions = []
        risky_variables = []
        for node_id, node_data in self.graph.nodes(data=True):
            if node_data.get("type") == "function" and node_data.get("can_escalate_privileges"):
                if contract_name and node_data.get("contract") != contract_name:
                    continue
                risky_functions.append({
                    "function_id": node_id,
                    "name": node_data.get("name"),
                    "contract": node_data.get("contract"),
                    "visibility": node_data.get("visibility"),
                    "is_payable": node_data.get("is_payable", False)
                })
            if node_data.get("type") == "state_variable" and node_data.get("privilege_escalation_risk"):
                if contract_name and node_data.get("contract") != contract_name:
                    continue
                risky_variables.append({
                    "variable_id": node_id,
                    "name": node_data.get("name"),
                    "contract": node_data.get("contract"),
                    "roles_using": node_data.get("roles_using_variable", []),
                    "risky_mutators": node_data.get("risky_mutators", [])
                })
        return {"risky_functions": risky_functions, "risky_variables": risky_variables}

    def get_contract_signatures(self, contract_name: str) -> Dict[str, str]:
        result = {}
        for node_id, node_data in self.graph.nodes(data=True):
            if node_data.get("type") != "function":
                continue
            if node_data.get("contract") != contract_name:
                continue
            name = node_data.get("name", "")
            sig = node_data.get("signature", "")
            if name and sig:
                result[name] = sig
        return result

    def get_high_risk_hotspots(
        self,
        min_score: int = 70,
        min_structural: int = 40,
        min_exploitability: int = 30,
        require_exploit_target: bool = True,
    ) -> List[Any]:
        """
        Returns high-risk function hotspots using multi-dimensional gate.

        A function must pass ALL of:
          1. final_score >= min_score   (backward-compat threshold)
          2. structural_score >= min_structural
          3. exploitability_score >= min_exploitability

        This ensures CEI-only patterns without attacker control, infra
        contracts, and other false-positive-prone patterns drop below
        the hotspot threshold.

        Excludes test/mock/fuzzing contracts, view/pure functions, constructors.
        """
        from src.hotspot_engine import Hotspot

        hotspots = []
        skipped_test = 0
        skipped_gate = 0

        for node_id, data in self.graph.nodes(data=True):
            if data.get("type") != "function":
                continue

            final = data.get("final_score", data.get("risk_score", 0))
            structural = data.get("structural_score", 0)
            exploit = data.get("exploitability_score", 0)
            eligible = data.get("send_to_exploit_writer", True)

            if final < min_score:
                continue

            if require_exploit_target and not eligible:
                skipped_gate += 1
                continue

            # Multi-dimensional gate (Epic 3, Story 3.1)
            if structural < min_structural or exploit < min_exploitability:
                skipped_gate += 1
                continue

            if data.get("is_view_or_pure") or data.get("stateMutability") in ("view", "pure"):
                continue

            if data.get("is_constructor"):
                continue

            # Exclude functions with detected initializer guards (Dev Story 1).
            if data.get("has_initializer_guard") or data.get("safe_init_pattern"):
                skipped_gate += 1
                continue

            contract_name = data.get("contract", "")
            source_file = data.get("source_file", "")
            if _is_test_contract(contract_name, source_file):
                skipped_test += 1
                continue

            contract_data = self.graph.nodes.get(contract_name, {})
            if contract_data.get("tier") == "LIBRARY":
                skipped_gate += 1
                continue

            priority = "MEDIUM"
            if final >= 90:
                priority = "CRITICAL"
            elif final >= 80:
                priority = "HIGH"

            hotspots.append(Hotspot(
                node_id=node_id,
                contract=contract_name,
                function=data.get("name", node_id),
                risk_score=final,
                risk_categories=data.get("risk_categories", []),
                signals=data,
                priority=priority,
                structural_score=structural,
                exploitability_score=exploit,
                impact_score=data.get("impact_score", 0),
                final_score=final,
                tier=contract_data.get("tier", "INFRA"),
            ))

        if skipped_test:
            print(f"[GraphQueries] Skipped {skipped_test} hotspot(s) in test/mock/fuzzing contracts.")
        if skipped_gate:
            print(f"[GraphQueries] Skipped {skipped_gate} function(s) below multi-dimensional gate.")

        hotspots.sort(key=lambda x: x.risk_score, reverse=True)
        return hotspots


# ════════════════════════════════════════════════════════════
#  Standalone Functional Wrappers
# ════════════════════════════════════════════════════════════

def get_external_entry_points(graph: nx.DiGraph, contract_name: str | None = None) -> List[Dict[str, Any]]:
    return GraphQueries(graph).get_external_entry_points(contract_name)

def get_privileged_roles(graph: nx.DiGraph, contract_name: str | None = None) -> List[Dict[str, Any]]:
    return GraphQueries(graph).get_privileged_roles(contract_name)

def get_reentrancy_risks(graph: nx.DiGraph, contract_name: str | None = None) -> List[Dict[str, Any]]:
    return GraphQueries(graph).get_reentrancy_risks(contract_name)

def get_state_mutators(graph: nx.DiGraph, contract_name: str | None = None) -> List[Dict[str, Any]]:
    return GraphQueries(graph).get_state_mutators(contract_name)

def get_unprotected_mutators(graph: nx.DiGraph, contract_name: str | None = None) -> List[Dict[str, Any]]:
    return GraphQueries(graph).get_unprotected_mutators(contract_name)

def get_high_risk_hotspots(graph: nx.DiGraph, min_score: int = 70) -> List[Any]:
    return GraphQueries(graph).get_high_risk_hotspots(min_score)

def get_function_context(graph: nx.DiGraph, node_id: str) -> Dict[str, Any]:
    return GraphQueries(graph).get_function_context(node_id)

def get_internal_calls(graph: nx.DiGraph, function_id: str) -> List[str]:
    return GraphQueries(graph).get_internal_calls(function_id)

def get_callers(graph: nx.DiGraph, function_id: str) -> List[str]:
    return GraphQueries(graph).get_callers(function_id)

def get_external_call_functions(graph: nx.DiGraph, contract_name: str | None = None) -> List[Dict[str, Any]]:
    return GraphQueries(graph).get_external_call_functions(contract_name)

def get_external_call_edges(graph: nx.DiGraph, function_id: str) -> List[Dict[str, Any]]:
    return GraphQueries(graph).get_external_call_edges(function_id)

def get_cei_violations(graph: nx.DiGraph, contract_name: str | None = None) -> List[Dict[str, Any]]:
    return GraphQueries(graph).get_cei_violations(contract_name)

def get_privilege_escalation_risks(graph: nx.DiGraph, contract_name: str | None = None) -> Dict[str, Any]:
    return GraphQueries(graph).get_privilege_escalation_risks(contract_name)

def get_contract_signatures(graph: nx.DiGraph, contract_name: str) -> Dict[str, str]:
    return GraphQueries(graph).get_contract_signatures(contract_name)

def get_state_transitions(graph: nx.DiGraph, **kwargs) -> List[Dict[str, Any]]:
    return GraphQueries(graph).get_state_transitions(**kwargs)

def get_array_length_mutations(graph: nx.DiGraph, contract_name: str | None = None) -> List[Dict[str, Any]]:
    return GraphQueries(graph).get_array_length_mutations(contract_name)

def get_delegatecall_storage_risks(graph: nx.DiGraph, contract_name: str | None = None) -> List[Dict[str, Any]]:
    return GraphQueries(graph).get_delegatecall_storage_risks(contract_name)

def get_contract_tiers(graph: nx.DiGraph, tier: str | None = None) -> List[Dict[str, Any]]:
    return GraphQueries(graph).get_contract_tiers(tier)

def get_guarded_initializers(graph: nx.DiGraph, contract_name: str | None = None) -> List[Dict[str, Any]]:
    return GraphQueries(graph).get_guarded_initializers(contract_name)

def get_access_control_types(graph: nx.DiGraph, contract_name: str | None = None) -> List[Dict[str, Any]]:
    return GraphQueries(graph).get_access_control_types(contract_name)

def get_modifier_equivalences(graph: nx.DiGraph, contract_name: str | None = None) -> List[Dict[str, Any]]:
    return GraphQueries(graph).get_modifier_equivalences(contract_name)

def get_safe_functions(graph: nx.DiGraph, contract_name: str | None = None) -> List[Dict[str, Any]]:
    return GraphQueries(graph).get_safe_functions(contract_name)

def get_taint_critical_paths(graph: nx.DiGraph, contract_name: str | None = None) -> List[Dict[str, Any]]:
    return GraphQueries(graph).get_taint_critical_paths(contract_name)

def get_storage_sensitivity_tags(graph: nx.DiGraph, contract_name: str | None = None) -> List[Dict[str, Any]]:
    return GraphQueries(graph).get_storage_sensitivity_tags(contract_name)

def get_tainted_variables(graph: nx.DiGraph, contract_name: str | None = None) -> List[Dict[str, Any]]:
    return GraphQueries(graph).get_tainted_variables(contract_name)

def get_taint_risks(graph: nx.DiGraph, risk_type: str | None = None, contract_name: str | None = None) -> List[Dict[str, Any]]:
    return GraphQueries(graph).get_taint_risks(risk_type, contract_name)

def get_state_dependencies(graph: nx.DiGraph, contract_name: str | None = None) -> List[Dict[str, Any]]:
    return GraphQueries(graph).get_state_dependencies(contract_name)

def get_dangerous_sequences(graph: nx.DiGraph, contract_name: str | None = None) -> List[Dict[str, Any]]:
    return GraphQueries(graph).get_dangerous_sequences(contract_name)

def get_exploit_chains(graph: nx.DiGraph, contract_name: str | None = None, min_length: int = 2) -> List[Dict[str, Any]]:
    return GraphQueries(graph).get_exploit_chains(contract_name, min_length)

def get_accounting_invariant_risks(graph: nx.DiGraph, contract_name: str | None = None) -> List[Dict[str, Any]]:
    return GraphQueries(graph).get_accounting_invariant_risks(contract_name)

def get_external_call_risks(
    graph: nx.DiGraph,
    risk_tag: str | None = None,
    contract_name: str | None = None,
) -> List[Dict[str, Any]]:
    return GraphQueries(graph).get_external_call_risks(risk_tag, contract_name)

def get_exploit_targets(
    graph: nx.DiGraph,
    min_exploit_score: int = 75,
    contract_name: str | None = None,
) -> List[Dict[str, Any]]:
    return GraphQueries(graph).get_exploit_targets(min_exploit_score, contract_name)