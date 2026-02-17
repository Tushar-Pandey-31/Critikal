import networkx as nx
import json
from slither.slither import Slither
from typing import Dict, Any

class GraphBuilder:
    def __init__(self):
        self.graph = nx.DiGraph()

    def build_graph(self, slither_obj: Slither):
        """
        Iterates through the Slither object and constructs the Knowledge Graph.
        """
        for contract in slither_obj.contracts:
            self._add_contract_node(contract)
            self._add_inheritance_edges(contract)
            
            for function in contract.functions:
                self._add_function_node(contract, function)
                self._add_edge_defines(contract, function)
                self._add_call_edges(contract, function)
                self._add_state_access_edges(contract, function)
        
        # Enrich function nodes with storage mutation metadata
        self._enrich_storage_mutations()
        
        # Enrich function nodes with internal call metadata
        self._enrich_internal_calls()


    def _add_contract_node(self, contract):
        node_id = contract.name
        metadata = {
            "type": "contract",
            "name": contract.name,
            "is_upgradeable": contract.is_upgradeable,
            # "source_mapping": contract.source_mapping # complex object, maybe store simplified version
        }
        self.graph.add_node(node_id, **metadata)

    def _add_function_node(self, contract, function):
        # Unique ID: ContractName::FunctionName
        # Handling function overloading might require adding signature, but for now simple name
        node_id = f"{contract.name}::{function.name}"
        
        # Get source code if available
        source_code = ""
        if function.source_mapping:
            try:
                src_mapping = function.source_mapping
                with open(src_mapping.filename.absolute, 'r', encoding='utf-8') as f:
                    content = f.read()
                    source_code = content[src_mapping.start:src_mapping.start + src_mapping.length]
            except Exception as e:
                # Log warning or carry on
                pass

        # Get modifiers
        modifiers = [m.name for m in function.modifiers]

        # Compute external attack surface properties
        # is_external_entry: True if function is externally callable
        # - Must be public or external visibility
        # - OR is a fallback/receive function (always externally callable)
        # - Must NOT be a constructor
        is_external_entry = (
            (
                str(function.visibility) in ["public", "external"] 
                and not function.is_constructor
            )
            or function.is_fallback
            or function.is_receive
        )
        
        # is_view_or_pure: For risk scoring - read-only vs state-changing
        is_view_or_pure = function.view or function.pure

        metadata = {
            "type": "function",
            "name": function.name,
            "contract": contract.name,
            "visibility": str(function.visibility),
            "stateMutability": function.view or function.pure, 
            "is_payable": function.payable,
            "is_constructor": function.is_constructor,
            "is_fallback": function.is_fallback,
            "is_receive": function.is_receive,
            "is_external_entry": is_external_entry,
            "is_view_or_pure": is_view_or_pure,
            "source_code": source_code,
            "modifiers": modifiers
            # "source_mapping": str(function.source_mapping)
        }
        self.graph.add_node(node_id, **metadata)

    def _add_edge_defines(self, contract, function):
        contract_id = contract.name
        function_id = f"{contract.name}::{function.name}"
        self.graph.add_edge(contract_id, function_id, relationship="DEFINES")

    def _add_inheritance_edges(self, contract):
        """
        Adds edges for inheritance: Contract -> INHERITS -> ParentContract
        """
        for parent in contract.inheritance:
            self.graph.add_edge(contract.name, parent.name, relationship="INHERITS")

    def _add_call_edges(self, contract, function):
        """
        Adds edges for internal function calls: Func_A -> CALLS -> Func_B
        
        Story 2.3: Only internal calls within the same contract or inherited contracts.
        External contract calls are excluded (Phase 4).
        """
        src_node_id = f"{contract.name}::{function.name}"
        
        # Track added edges to prevent duplicates
        added_calls = set()
        
        # Internal calls (calls to functions within the same contract or inherited)
        for internal_call in function.internal_calls:
            # internal_call is an InternalCall operation (SlithIR)
            # We need to access the .function attribute to get the target Function object
            target_func = getattr(internal_call, "function", None)
            
            if not target_func:
                continue

            # Using contract_declarer to get the defining contract
            target_contract = getattr(target_func, "contract_declarer", None)
            if not target_contract:
                target_contract = getattr(target_func, "contract", None)
            
            if not target_contract:
                # Could be a top level function or something special
                continue

            target_node_id = f"{target_contract.name}::{target_func.name}"
            
            # Deduplicate: only add edge if not already added
            if target_node_id not in added_calls:
                # Add edge with call_type metadata
                self.graph.add_edge(
                    src_node_id, 
                    target_node_id, 
                    relationship="CALLS",
                    call_type="internal"
                )
                added_calls.add(target_node_id)
        
        # Note: External calls are intentionally excluded for Story 2.3

    def _add_state_access_edges(self, contract, function):
        """
        Adds edges for state variable access: Func -> READS/WRITES -> StateVar
        """
        src_node_id = f"{contract.name}::{function.name}"

        # READS
        for state_var in function.state_variables_read:
            var_node_id = f"{state_var.contract.name}::{state_var.name}"
            
            # Add state variable node if not exists
            if not self.graph.has_node(var_node_id):
                self.graph.add_node(
                    var_node_id,
                    type="state_variable",
                    node_type="StateVariable",
                    storage_location="storage",
                    declaring_contract=state_var.contract.name,
                    name=state_var.name,
                    contract=state_var.contract.name
                )
            
            self.graph.add_edge(src_node_id, var_node_id, relationship="READS")

        # WRITES
        for state_var in function.state_variables_written:
            var_node_id = f"{state_var.contract.name}::{state_var.name}"
            
            # Add state variable node if not exists
            if not self.graph.has_node(var_node_id):
                self.graph.add_node(
                    var_node_id,
                    type="state_variable",
                    node_type="StateVariable",
                    storage_location="storage",
                    declaring_contract=state_var.contract.name,
                    name=state_var.name,
                    contract=state_var.contract.name
                )

            self.graph.add_edge(src_node_id, var_node_id, relationship="WRITES")

    def _enrich_storage_mutations(self):
        """
        Enriches function nodes with storage mutation metadata.
        
        For each function, detects direct writes to state variables and attaches:
        - writes_state: bool (True if function writes to any state variable)
        - num_state_writes: int (count of distinct state variables written)
        - state_variables_written: List[str] (IDs of state variables written)
        
        Note: This does NOT propagate writes through internal calls (Phase 3).
        Only direct WRITES edges to StateVariable nodes are counted.
        """
        for node_id, node_data in self.graph.nodes(data=True):
            # Only process function nodes
            if node_data.get("type") != "function":
                continue
            
            # Find all outgoing WRITES edges
            write_edges = [
                (target, edge_data)
                for _, target, edge_data in self.graph.out_edges(node_id, data=True)
                if edge_data.get("relationship") == "WRITES"
            ]
            
            
            # Filter to only StateVariable nodes and deduplicate
            state_writes_set = set()
            for target, _ in write_edges:
                target_data = self.graph.nodes.get(target, {})
                if target_data.get("node_type") == "StateVariable":
                    state_writes_set.add(target)
            
            # Convert to sorted list for consistent ordering
            state_writes = sorted(list(state_writes_set))
            
            self.graph.nodes[node_id]["writes_state"] = len(state_writes) > 0
            self.graph.nodes[node_id]["num_state_writes"] = len(state_writes)
            self.graph.nodes[node_id]["state_variables_written"] = state_writes

    def _enrich_internal_calls(self):
        """
        Enriches function nodes with internal call metadata.
        
        For each function, detects internal calls and attaches:
        - internal_calls: List[str] (IDs of functions called)
        - num_internal_calls: int (count of distinct functions called)
        - is_leaf_function: bool (True if no internal calls)
        
        Note: This does NOT implement recursive propagation (Phase 3).
        Only direct CALLS edges from this function are counted.
        """
        for node_id, node_data in self.graph.nodes(data=True):
            # Only process function nodes
            if node_data.get("type") != "function":
                continue
            
            # Find all outgoing CALLS edges
            call_edges = [
                target
                for _, target, edge_data in self.graph.out_edges(node_id, data=True)
                if edge_data.get("relationship") == "CALLS"
            ]
            
            # Deduplicate and sort for consistent ordering
            internal_calls = sorted(list(set(call_edges)))
            
            # Attach metadata to function node
            self.graph.nodes[node_id]["internal_calls"] = internal_calls
            self.graph.nodes[node_id]["num_internal_calls"] = len(internal_calls)
            self.graph.nodes[node_id]["is_leaf_function"] = len(internal_calls) == 0



    def export_json(self, output_path: str):
        """
        Exports the graph to a JSON file using node-link data format.
        """
        data = nx.node_link_data(self.graph)
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=4)
        print(f"Graph exported to {output_path}")

    def get_graph_stats(self):
        return {
            "nodes": self.graph.number_of_nodes(),
            "edges": self.graph.number_of_edges()
        }
