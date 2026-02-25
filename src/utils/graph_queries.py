import networkx as nx
from typing import List, Dict, Any

from src.utils.node_ids import normalize_node_id


# ════════════════════════════════════════════════════════════
#  Test Contract Filter
# ════════════════════════════════════════════════════════════

# Contract name suffixes/prefixes that identify test/mock/fuzzing artifacts.
_TEST_NAME_PATTERNS = (
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
    "Exploit",   # Our own generated tests
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
                "visibility": node_data.get("visibility"),
                "is_payable": node_data.get("is_payable", False)
            })
        return results

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
                "is_payable": node_data.get("is_payable", False)
            })
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

    def get_high_risk_hotspots(self, min_score: int = 70) -> List[Any]:
        """
        Returns high-risk function hotspots, excluding:
          - Test / mock / fuzzing / echidna contracts (by name pattern or source path)
          - View/pure functions (cannot cause state damage)
          - Constructors (not callable post-deployment)
        """
        from src.hotspot_engine import Hotspot

        hotspots = []
        skipped_test = 0

        for node_id, data in self.graph.nodes(data=True):
            if data.get("type") != "function":
                continue

            risk_score = data.get("risk_score", 0)
            if risk_score < min_score:
                continue

            # Skip read-only functions
            if data.get("is_view_or_pure") or data.get("stateMutability") in ("view", "pure"):
                continue

            # Skip constructors
            if data.get("is_constructor"):
                continue

            # Skip test/mock/fuzzing/echidna contracts
            contract_name = data.get("contract", "")
            source_file = data.get("source_file", "")  # populated by graph_builder if available
            if _is_test_contract(contract_name, source_file):
                skipped_test += 1
                continue

            priority = "MEDIUM"
            if risk_score >= 90:
                priority = "CRITICAL"
            elif risk_score >= 80:
                priority = "HIGH"

            hotspots.append(Hotspot(
                node_id=node_id,
                contract=contract_name,
                function=data.get("name", node_id),
                risk_score=risk_score,
                risk_categories=data.get("risk_categories", []),
                signals=data,
                priority=priority
            ))

        if skipped_test:
            print(f"[GraphQueries] Skipped {skipped_test} hotspot(s) in test/mock/fuzzing contracts.")

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

def get_privilege_escalation_risks(graph: nx.DiGraph, contract_name: str | None = None) -> Dict[str, Any]:
    return GraphQueries(graph).get_privilege_escalation_risks(contract_name)

def get_contract_signatures(graph: nx.DiGraph, contract_name: str) -> Dict[str, str]:
    return GraphQueries(graph).get_contract_signatures(contract_name)