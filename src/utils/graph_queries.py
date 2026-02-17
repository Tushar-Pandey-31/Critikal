
import networkx as nx
from typing import List, Dict, Any

class GraphQueries:
    def __init__(self, graph: nx.DiGraph):
        self.graph = graph

    def get_function_context(self, node_id: str) -> Dict[str, Any]:
        """
        Returns a function's code PLUS its immediate neighbors (callers and callees).
        """
        if not self.graph.has_node(node_id):
             return {"error": "Node not found"}
        
        node_data = self.graph.nodes[node_id]
        if node_data.get("type") != "function":
             return {"error": "Node is not a function"}

        # Callers: nodes that have a CALLS edge to this node
        callers = [
            n for n in self.graph.predecessors(node_id) 
            if self.graph.get_edge_data(n, node_id).get("relationship") == "CALLS"
        ]

        # Callees: nodes that this node has a CALLS edge to
        callees = [
            n for n in self.graph.successors(node_id) 
            if self.graph.get_edge_data(node_id, n).get("relationship") == "CALLS"
        ]

        return {
            "node_id": node_id,
            "code": node_data.get("source_code", ""),
            "callers": callers,
            "callees": callees
        }

    def find_state_mutators(self, variable_name: str) -> List[str]:
        """
        Traces all functions with a WRITES edge to that variable.
        variable_name should be the node_id of the state variable, e.g., "Contract::VaName"
        """
        if not self.graph.has_node(variable_name):
            return []
        
        mutators = [
            n for n in self.graph.predecessors(variable_name) 
            if self.graph.get_edge_data(n, variable_name).get("relationship") == "WRITES"
        ]
        return mutators

    def get_modifiers(self, function_id: str) -> List[str]:
        """
        List all security modifiers (like onlyOwner or nonReentrant) applied to a node.
        """
        if not self.graph.has_node(function_id):
            return []
        
        node_data = self.graph.nodes[function_id]
        return node_data.get("modifiers", [])

    def verify_existence(self, node_name: str) -> bool:
        """
        Ensure an agent isn't hallucinating a function that doesn't exist.
        """
        return self.graph.has_node(node_name)

    def get_external_entry_points(self, contract_name: str | None = None) -> List[Dict[str, Any]]:
        """
        Returns all functions marked as external entry points.
        
        Args:
            contract_name: Optional filter by specific contract
        
        Returns:
            List of function nodes with metadata (node_id, name, contract, visibility, is_payable)
        """
        entry_points = []
        
        for node_id, node_data in self.graph.nodes(data=True):
            # Filter for function nodes that are external entry points
            if node_data.get("type") == "function" and node_data.get("is_external_entry"):
                # Apply contract filter if specified
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
        """
        Returns all functions that mutate storage state.
        
        Args:
            contract_name: Optional filter by specific contract
        
        Returns:
            List of function metadata with storage mutation info:
            - function_id: Node ID
            - name: Function name
            - contract_name: Declaring contract
            - num_state_writes: Count of state variables written
            - state_variables_written: List of written variable IDs
            - visibility: Function visibility
            - modifiers: Applied modifiers
        """
        mutators = []
        
        for node_id, node_data in self.graph.nodes(data=True):
            # Filter for function nodes that write to state
            if node_data.get("type") == "function" and node_data.get("writes_state"):
                # Apply contract filter if specified
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
        """
        Returns list of function IDs that the given function calls internally.
        
        Args:
            function_id: Node ID of the function
        
        Returns:
            List of function IDs (node_ids) that this function calls
        """
        if not self.graph.has_node(function_id):
            return []
        
        node_data = self.graph.nodes.get(function_id, {})
        if node_data.get("type") != "function":
            return []
        
        # Get from metadata (computed by _enrich_internal_calls)
        return node_data.get("internal_calls", [])
    
    def get_callers(self, function_id: str) -> List[str]:
        """
        Returns list of function IDs that call the given function.
        
        Args:
            function_id: Node ID of the function
        
        Returns:
            List of function IDs (node_ids) that call this function
        """
        if not self.graph.has_node(function_id):
            return []
        
        callers = [
            n for n in self.graph.predecessors(function_id)
            if self.graph.get_edge_data(n, function_id).get("relationship") == "CALLS"
        ]
        
        return callers
    
    def get_call_graph(self, contract_name: str | None = None) -> Dict[str, Any]:
        """
        Returns call graph structure for visualization.
        
        Args:
            contract_name: Optional filter by specific contract
        
        Returns:
            Dictionary with 'nodes' and 'edges' lists:
            - nodes: List of function metadata
            - edges: List of {source, target, call_type} dicts
        """
        nodes = []
        edges = []
        
        # Collect nodes
        for node_id, node_data in self.graph.nodes(data=True):
            if node_data.get("type") != "function":
                continue
            
            # Apply contract filter if specified
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
        
        # Collect edges
        node_ids = {n["id"] for n in nodes}
        for source, target, edge_data in self.graph.edges(data=True):
            if edge_data.get("relationship") != "CALLS":
                continue
            
            # Only include edges where both nodes are in our filtered set
            if source in node_ids and target in node_ids:
                edges.append({
                    "source": source,
                    "target": target,
                    "call_type": edge_data.get("call_type", "internal")
                })
        
        return {
            "nodes": nodes,
            "edges": edges
        }
