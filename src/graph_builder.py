import networkx as nx
import json
import re
from collections import deque
from slither.slither import Slither
from slither.core.cfg.node import NodeType
from typing import Dict, Any, List

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
        
        # Epic 6, Story 6.1: Build StateTransition nodes from Slither IR
        self._build_state_transitions(slither_obj)
        
        # Story 3.1: Propagate writes through CALLS edges
        self._propagate_writes()
        
        # Story 3.3: Compute reachability from external entries
        self._compute_reachability()
        
        # Enrich with access control intelligence (Stories 2.2.1-2.2.4)
        self._enrich_access_control(slither_obj)
        
        # Story 3.2: Classify external calls for reentrancy modeling
        self._classify_external_calls(slither_obj)
        
        # Epic 8 — Semantic vulnerability detection
        self._detect_oracle_patterns()
        self._detect_arithmetic_patterns()
        self._detect_signature_patterns()
        
        # Story 3.4: Combine everything for Deterministic Reentrancy Rule
        self._detect_reentrancy_risks()
        
        self._detect_privileged_roles()
        self._detect_unprotected_mutators()
        
        # Story 3.5: Privilege Propagation
        self._enrich_state_variable_reverse_mapping()
        self._detect_privilege_escalation()
        
        # Epic 6, Story 6.1: Enrich StateTransitions with privilege info
        self._enrich_state_transitions()
        
        # Epic 6, Story 6.2: Detect array length mutations (AlienCodex primitive)
        self._detect_array_length_mutations()
        
        # Epic 6, Story 6.3: Detect delegatecall storage collision risk
        self._detect_delegatecall_storage_risk()
        
        # Epic 7: Contract tier classification
        self._classify_contract_tiers(slither_obj)
        
        # Story 4.2: Compute final risk scores
        self._compute_global_risk_scores()


    def _add_contract_node(self, contract):
        node_id = contract.name
        metadata = {
            "type": "contract",
            "name": contract.name,
            "is_upgradeable": contract.is_upgradeable,
            "is_library": getattr(contract, "is_library", False),
            "is_interface": getattr(contract, "is_interface", False),
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

        signature = self._extract_function_signature(function)

        metadata = {
            "type": "function",
            "name": function.name,
            "contract": contract.name,
            "visibility": str(function.visibility),
            "stateMutability": "view" if function.view else ("pure" if function.pure else "nonpayable"), 
            "is_payable": function.payable,
            "is_constructor": function.is_constructor,
            "is_fallback": function.is_fallback,
            "is_receive": function.is_receive,
            "is_external_entry": is_external_entry,
            "is_view_or_pure": is_view_or_pure,
            "source_code": source_code,
            "modifiers": modifiers,
            "signature": signature or "",
        }
        self.graph.add_node(node_id, **metadata)

    def _extract_function_signature(self, function) -> str:
        """Extract Solidity-style signature: name(type1,type2) for Test Writer context."""
        try:
            params = getattr(function, "parameters", None) or getattr(function, "parameters_", [])
            if not params:
                return f"{function.name}()" if not function.is_constructor else "constructor()"
            param_types = []
            for p in params:
                t = getattr(p, "type", None)
                param_types.append(str(t) if t else "???")
            return f"{function.name}({','.join(param_types)})" if not function.is_constructor else f"constructor({','.join(param_types)})"
        except Exception:
            return ""

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
            # Slither 0.10.x: internal_calls returns raw Function/Modifier objects,
            # NOT InternalCall IR wrappers. So the object IS the target function.
            # First check if internal_call itself is a function-like object.
            target_func = None
            if hasattr(internal_call, "contract_declarer") or hasattr(internal_call, "contract"):
                # internal_call IS the function object directly
                target_func = internal_call
            else:
                # Fallback: try IR-style access (older Slither or special cases)
                target_func = getattr(internal_call, "function", None)
            
            if not target_func:
                continue

            # Skip Solidity built-ins (require, assert, revert, etc.)
            if not hasattr(target_func, "name"):
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

    # ================================================================
    # Story 3.1 — Recursive Write Propagation
    # ================================================================
    def _propagate_writes(self):
        """
        Propagates state variable writes through CALLS edges using DFS.
        
        For each function, computes the full set of state variables written
        both directly and indirectly (through internal calls). Attaches:
        - propagated_state_variables: List[str] (all state vars written, direct + indirect)
        - indirect_writes_state: bool (True if function indirectly writes state via callees)
        - propagation_depth: int (min call depth to nearest callee that writes state)
        
        Uses visited-set tracking to handle cycles safely.
        """
        cache = {}  # node_id -> frozenset of propagated state vars

        def _dfs(node_id, visited):
            if node_id in cache:
                return cache[node_id]
            if node_id in visited:
                return frozenset()  # cycle detected — return empty to break loop
            
            visited.add(node_id)
            
            node_data = self.graph.nodes.get(node_id, {})
            propagated = set(node_data.get("state_variables_written", []))

            # Traverse CALLS edges
            for _, target, edge_data in self.graph.out_edges(node_id, data=True):
                if edge_data.get("relationship") == "CALLS":
                    propagated |= _dfs(target, visited)

            visited.discard(node_id)
            result = frozenset(propagated)
            cache[node_id] = result
            return result

        # Phase 1: Compute propagated sets for all function nodes
        for node_id, node_data in self.graph.nodes(data=True):
            if node_data.get("type") != "function":
                continue
            
            direct = set(node_data.get("state_variables_written", []))
            propagated = set(_dfs(node_id, set()))
            indirect = propagated - direct

            node_data["propagated_state_variables"] = sorted(propagated)
            node_data["indirect_writes_state"] = len(indirect) > 0
            node_data["propagation_depth"] = 0  # default, computed in Phase 2

        # Phase 2: Compute propagation_depth via BFS for functions with indirect writes
        for node_id, node_data in self.graph.nodes(data=True):
            if node_data.get("type") != "function":
                continue
            if not node_data.get("indirect_writes_state"):
                continue
            
            # BFS to find minimum depth to a callee that directly writes state
            queue = deque()
            visited_bfs = {node_id}
            
            # Seed with direct callees
            for _, target, edge_data in self.graph.out_edges(node_id, data=True):
                if edge_data.get("relationship") == "CALLS" and target not in visited_bfs:
                    queue.append((target, 1))
                    visited_bfs.add(target)
            
            min_depth = 0
            while queue:
                current, depth = queue.popleft()
                current_data = self.graph.nodes.get(current, {})
                
                # Check if this callee directly writes state
                if current_data.get("writes_state", False):
                    min_depth = depth
                    break
                
                # Continue BFS through its callees
                for _, next_target, edge_data in self.graph.out_edges(current, data=True):
                    if edge_data.get("relationship") == "CALLS" and next_target not in visited_bfs:
                        queue.append((next_target, depth + 1))
                        visited_bfs.add(next_target)
            
            node_data["propagation_depth"] = min_depth

    # ================================================================
    # Story 3.3 — Reachability from External Entry
    # ================================================================
    def _compute_reachability(self):
        """
        DFS from all external entry points through CALLS edges.
        
        Marks each function node with:
        - reachable_from_external_entry: bool
        - entry_points: List[str] (which entries can reach this function)
        """
        # Collect all external entry nodes
        entry_nodes = [
            node_id for node_id, data in self.graph.nodes(data=True)
            if data.get("type") == "function" and data.get("is_external_entry", False)
        ]

        # For each function, track which entries reach it
        reached_by = {}   # node_id -> set of entry node_ids

        def _dfs_reachable(current, entry_id, visited):
            if current not in reached_by:
                reached_by[current] = set()
            reached_by[current].add(entry_id)
            
            visited.add(current)
            
            # Traverse CALLS edges
            for _, target, edge_data in self.graph.out_edges(current, data=True):
                if edge_data.get("relationship") == "CALLS" and target not in visited:
                    _dfs_reachable(target, entry_id, visited)

        # Start DFS from each external entry
        for entry in entry_nodes:
            _dfs_reachable(entry, entry, set())

        # Attach metadata to all function nodes
        for node_id, node_data in self.graph.nodes(data=True):
            if node_data.get("type") != "function":
                continue

            if node_id in reached_by:
                node_data["reachable_from_external_entry"] = True
                node_data["entry_points"] = sorted(list(reached_by[node_id]))
            else:
                node_data["reachable_from_external_entry"] = False
                node_data["entry_points"] = []

    # ================================================================
    # Story 2.2.1 — Modifier Extraction Engine
    # Story 2.2.2 — Function Access Mapping
    # ================================================================
    def _enrich_access_control(self, slither_obj: Slither):
        """
        Extracts modifiers as graph nodes and enriches function nodes
        with access control profiles.
        
        Story 2.2.1: Parses modifier definitions, extracts require/assert
        conditions, and classifies access control patterns.
        
        Story 2.2.2: Builds FunctionAccessProfile metadata on each
        function node indicating protection status.
        """
        # --- Phase 1: Extract modifier definitions and create nodes ---
        for contract in slither_obj.contracts:
            for modifier in contract.modifiers:
                mod_node_id = f"{contract.name}::modifier::{modifier.name}"
                
                # Extract conditions from modifier body
                conditions = self._extract_modifier_conditions(modifier)
                
                # Detect which state variables the modifier reads
                accessed_state_vars = []
                for sv in modifier.state_variables_read:
                    var_id = f"{sv.contract.name}::{sv.name}"
                    accessed_state_vars.append(var_id)
                
                # Classify the access control pattern
                pattern = self._classify_modifier_pattern(conditions, accessed_state_vars)
                is_access_control = pattern != "none"
                
                # --- Phase-based Execution Modeling (Story 3.2 Upgrade) ---
                pre_nodes, post_nodes = self._extract_modifier_nodes(modifier)
                
                # Extract calls and writes from pre/post nodes
                pre_segment = self._analyze_modifier_segment(pre_nodes)
                post_segment = self._analyze_modifier_segment(post_nodes)
                
                # Create modifier node
                self.graph.add_node(mod_node_id, **{
                    "type": "modifier",
                    "name": modifier.name,
                    "contract": contract.name,
                    "conditions": conditions,
                    "accesses_state_variables": accessed_state_vars,
                    "is_access_control": is_access_control,
                    "access_control_pattern": pattern,
                    "pre_segment": pre_segment,
                    "post_segment": post_segment
                })
                
                # Edge: Contract --HAS_MODIFIER--> Modifier
                self.graph.add_edge(
                    contract.name, mod_node_id,
                    relationship="HAS_MODIFIER"
                )
        
        # --- Phase 2: Build FunctionAccessProfile on each function node ---
        # Build a lookup of modifier name -> pattern for this pass
        modifier_patterns = {}  # modifier_name -> access_control_pattern
        for node_id, node_data in self.graph.nodes(data=True):
            if node_data.get("type") == "modifier":
                modifier_patterns[node_data["name"]] = node_data.get("access_control_pattern", "none")
        
        # Build a lookup of node_id -> Slither function object for IR-based analysis
        slither_func_lookup = {}
        for contract in slither_obj.contracts:
            for function in contract.functions:
                func_node_id = f"{contract.name}::{function.name}"
                slither_func_lookup[func_node_id] = function
        
        for node_id, node_data in self.graph.nodes(data=True):
            if node_data.get("type") != "function":
                continue
            
            applied_modifiers = node_data.get("modifiers", [])
            
            # Which of the applied modifiers are access-control?
            ac_modifiers = [
                m for m in applied_modifiers
                if modifier_patterns.get(m, "none") != "none"
            ]
            has_access_control = len(ac_modifiers) > 0
            
            # Detect inline require(msg.sender == X) via Slither IR
            slither_func = slither_func_lookup.get(node_id)
            has_inline_check = self._detect_inline_access_check(node_id, node_data, slither_func)
            
            is_protected = has_access_control or has_inline_check
            
            # Attach FunctionAccessProfile
            self.graph.nodes[node_id]["has_access_control"] = has_access_control
            self.graph.nodes[node_id]["access_control_modifiers"] = ac_modifiers
            self.graph.nodes[node_id]["has_inline_access_check"] = has_inline_check
            self.graph.nodes[node_id]["is_protected"] = is_protected

    def _extract_modifier_conditions(self, modifier) -> List[Dict[str, Any]]:
        """
        Parses a Slither modifier to extract require/assert conditions.
        Uses the modifier's nodes (IR) to find SolidityCall to require/assert.
        """
        conditions = []
        
        try:
            for node in modifier.nodes:
                # Check for require/assert in the node's internal calls
                for ir in node.irs:
                    ir_str = str(ir).lower()
                    
                    # Detect require() or assert() calls
                    if 'require(bool' in ir_str or 'assert(bool' in ir_str:
                        cond_type = "require" if "require" in ir_str else "assert"
                        
                        # Get the full expression from the node
                        expression_str = str(node.expression) if node.expression else str(ir)
                        
                        checks_msg_sender = "msg.sender" in expression_str
                        checks_tx_origin = "tx.origin" in expression_str
                        
                        # Try to find what variable is being compared
                        compared_variable = self._extract_compared_variable(expression_str)
                        
                        conditions.append({
                            "type": cond_type,
                            "expression": expression_str,
                            "checks_msg_sender": checks_msg_sender,
                            "checks_tx_origin": checks_tx_origin,
                            "compared_variable": compared_variable
                        })
        except Exception:
            # Graceful fallback if IR parsing fails
            pass
        
        return conditions
    
    def _extract_compared_variable(self, expression: str) -> str:
        """
        Extracts the variable being compared in an access control expression.
        e.g., 'require(msg.sender == owner)' -> 'owner'
              'require(admins[msg.sender])' -> 'admins'
        """
        
        # Pattern: msg.sender == <variable>
        match = re.search(r'msg\.sender\s*==\s*(\w+)', expression)
        if match:
            return match.group(1)
        
        # Pattern: <variable> == msg.sender
        match = re.search(r'(\w+)\s*==\s*msg\.sender', expression)
        if match:
            return match.group(1)
        
        # Pattern: tx.origin == <variable>
        match = re.search(r'tx\.origin\s*==\s*(\w+)', expression)
        if match:
            return match.group(1)
        
        # Pattern: <mapping>[msg.sender] (e.g., admins[msg.sender])
        match = re.search(r'(\w+)\[msg\.sender\]', expression)
        if match:
            return match.group(1)
        
        # Pattern: hasRole(..., msg.sender)
        if 'hasRole' in expression or 'hasrole' in expression.lower():
            return "roles"
        
        return ""
    
    def _classify_modifier_pattern(self, conditions: List[Dict], state_vars: List[str]) -> str:
        """
        Classifies the access control pattern of a modifier based on its conditions.
        Returns: 'owner_check' | 'role_mapping' | 'boolean_flag' | 'tx_origin' | 'custom' | 'none'
        """
        for cond in conditions:
            # tx.origin check — classified first (dangerous pattern)
            if cond.get("checks_tx_origin"):
                return "tx_origin"
            
            if cond.get("checks_msg_sender"):
                compared = cond.get("compared_variable", "")
                expr = cond.get("expression", "")
                
                # Mapping pattern: admins[msg.sender], roles[msg.sender]
                if '[msg.sender]' in expr or 'hasRole' in expr or 'hasrole' in expr.lower():
                    return "role_mapping"
                
                # Owner pattern: msg.sender == owner (compared to a single address variable)
                if compared and compared.lower() in ("owner", "admin", "_owner", "governance"):
                    return "owner_check"
                
                # Generic msg.sender comparison → owner_check
                if compared:
                    return "owner_check"
        
        # If modifier has conditions but no msg.sender/tx.origin → boolean flag
        if conditions:
            return "boolean_flag"
        
        return "none"
    
    def _detect_inline_access_check(self, node_id: str, node_data: Dict, slither_func=None) -> bool:
        """
        Detects inline require(msg.sender == X) patterns in function body.
        Uses Slither IR as primary detection, with source code regex fallback.
        Returns True if an inline access check is found.
        """
        # Primary: IR-based detection via Slither function nodes
        if slither_func is not None:
            try:
                for node in slither_func.nodes:
                    for ir in node.irs:
                        ir_str = str(ir).lower()
                        if 'require(bool' in ir_str or 'assert(bool' in ir_str:
                            expr_str = str(node.expression) if node.expression else str(ir)
                            if 'msg.sender' in expr_str:
                                return True
            except Exception:
                pass
        
        # Fallback: source code regex
        source = node_data.get("source_code", "")
        if source:
            if re.search(r'require\s*\(\s*msg\.sender\s*==', source):
                return True
            if re.search(r'require\s*\(\s*\w+\s*==\s*msg\.sender', source):
                return True
        
        return False

    # ================================================================
    # Story 2.2.3 — Privileged Role Detection
    # ================================================================
    def _detect_privileged_roles(self):
        """
        Identifies privileged accounts/roles from modifier patterns and
        inline checks. Builds RoleProfile structures on contract nodes.
        """
        # Collect roles from modifier nodes
        # Group by contract
        contract_roles = {}  # contract_name -> [RoleProfile]
        
        for node_id, node_data in self.graph.nodes(data=True):
            if node_data.get("type") != "modifier":
                continue
            if not node_data.get("is_access_control"):
                continue
            
            contract_name = node_data["contract"]
            mod_name = node_data["name"]
            pattern = node_data.get("access_control_pattern", "custom")
            
            # Determine role name from modifier name
            role_name = self._derive_role_name(mod_name, node_data)
            
            # Find underlying variable
            underlying_var = ""
            conditions = node_data.get("conditions", [])
            for cond in conditions:
                cv = cond.get("compared_variable", "")
                if cv:
                    # Search for the state variable node that matches this name in this contract
                    var_id = f"{contract_name}::{cv}"
                    if self.graph.has_node(var_id):
                        underlying_var = var_id
                    else:
                        # Try searching in inherited contracts
                        for node_idx, data in self.graph.nodes(data=True):
                            if data.get("type") == "state_variable" and data.get("name") == cv:
                                # Simple heuristic: if it matches name, use it
                                underlying_var = node_idx
                                break
                    if underlying_var: break
            
            # Fallback: use accessed state variables
            if not underlying_var:
                state_vars = node_data.get("accesses_state_variables", [])
                if state_vars:
                    underlying_var = state_vars[0]
            
            # Find functions protected by this modifier
            protected_functions = []
            for fn_id, fn_data in self.graph.nodes(data=True):
                if fn_data.get("type") != "function":
                    continue
                if mod_name in fn_data.get("modifiers", []):
                    protected_functions.append(fn_id)
            
            role_profile = {
                "role_name": role_name,
                "modifier_name": mod_name,
                "protected_functions": protected_functions,
                "underlying_variable": underlying_var,
                "how_verified": "modifier",
                "pattern": pattern
            }
            
            if contract_name not in contract_roles:
                contract_roles[contract_name] = []
            contract_roles[contract_name].append(role_profile)
        
        # Also detect inline-only roles (functions with inline checks but no modifier)
        for node_id, node_data in self.graph.nodes(data=True):
            if node_data.get("type") != "function":
                continue
            if not node_data.get("has_inline_access_check"):
                continue
            if node_data.get("has_access_control"):
                # Already covered by modifier-based detection
                continue
            
            contract_name = node_data.get("contract", "")
            
            # Parse source for the compared variable
            source = node_data.get("source_code", "")
            compared_var = ""
            match = re.search(r'require\s*\(\s*msg\.sender\s*==\s*(\w+)', source)
            if match:
                compared_var = match.group(1)
            else:
                match = re.search(r'require\s*\(\s*(\w+)\s*==\s*msg\.sender', source)
                if match:
                    compared_var = match.group(1)
            
            role_name = compared_var if compared_var else "inline_check"
            
            role_profile = {
                "role_name": role_name,
                "modifier_name": "",
                "protected_functions": [node_id],
                "underlying_variable": compared_var,
                "how_verified": "inline_require",
                "pattern": "owner_check"
            }
            
            if contract_name not in contract_roles:
                contract_roles[contract_name] = []
            
            # Merge into existing role if same role_name exists
            merged = False
            for existing in contract_roles[contract_name]:
                if existing["role_name"] == role_name:
                    for fn in role_profile["protected_functions"]:
                        if fn not in existing["protected_functions"]:
                            existing["protected_functions"].append(fn)
                    merged = True
                    break
            if not merged:
                contract_roles[contract_name].append(role_profile)
        
        # Attach to contract nodes
        for contract_name, roles in contract_roles.items():
            if self.graph.has_node(contract_name):
                self.graph.nodes[contract_name]["privileged_roles"] = roles
    
    def _derive_role_name(self, modifier_name: str, mod_data: Dict) -> str:
        """
        Derives a human-readable role name from a modifier name.
        e.g., 'onlyOwner' -> 'owner', 'onlyAdmin' -> 'admin', 
              'whenNotPaused' -> 'paused_flag', 'onlyRole' -> 'role'
        """
        name_lower = modifier_name.lower()
        
        if 'owner' in name_lower:
            return 'owner'
        if 'admin' in name_lower:
            return 'admin'
        if 'role' in name_lower:
            return 'role'
        if 'pause' in name_lower:
            return 'paused_flag'
        if 'txorigin' in name_lower or 'tx_origin' in name_lower:
            return 'tx_origin'
        
        # Fallback: strip 'only' prefix if present
        if name_lower.startswith('only'):
            return modifier_name[4:].lower() or modifier_name
        
        # Use the compared variable if available
        conditions = mod_data.get("conditions", [])
        for cond in conditions:
            cv = cond.get("compared_variable", "")
            if cv:
                return cv
        
        return modifier_name

    def _extract_modifier_nodes(self, modifier) -> tuple:
        """
        Traces modifier CFG and separates nodes into those before and after the placeholder.
        """
        placeholder_node = None
        for node in modifier.nodes:
            if node.type == NodeType.PLACEHOLDER:
                placeholder_node = node
                break
        
        if not placeholder_node:
            # Fallback if no placeholder: everything is pre
            return list(modifier.nodes), []

        # Find nodes "before" placeholder (reachable from ENTRYPOINT without passing placeholder)
        pre_nodes = []
        visited = set()
        queue = [modifier.entry_point]
        while queue:
            curr = queue.pop(0)
            if curr in visited or curr == placeholder_node:
                continue
            visited.add(curr)
            pre_nodes.append(curr)
            queue.extend(curr.sons)
            
        # Find nodes "after" placeholder (reachable from placeholder.sons)
        post_nodes = []
        post_visited = set()
        queue = list(placeholder_node.sons)
        while queue:
            curr = queue.pop(0)
            if curr in post_visited:
                continue
            post_visited.add(curr)
            post_nodes.append(curr)
            queue.extend(curr.sons)
            
        return pre_nodes, post_nodes

    def _analyze_modifier_segment(self, nodes: List) -> Dict[str, Any]:
        """
        Analyzes a list of CFG nodes to extract external calls and state writes.
        Enriched with EXTERNAL_CALL edge properties (Story 1.1/1.2).
        """
        segment_data = {
            "external_calls": [],
            "direct_writes": [],
            "internal_calls": [],
        }

        for idx, node in enumerate(nodes):
            for ir in node.irs:
                ir_type = type(ir).__name__
                call_type = None
                forwards_gas = "unknown"
                target_expression = ""
                resolved_target = None

                if ir_type == "LowLevelCall":
                    func_name = str(getattr(ir, "function_name", "") or "").lower()
                    if "delegatecall" in func_name:
                        call_type, forwards_gas = "delegatecall", "full"
                    elif "staticcall" in func_name:
                        call_type, forwards_gas = "staticcall", "full"
                    elif "send" in func_name:
                        call_type, forwards_gas = "send", "2300"
                    else:
                        call_type, forwards_gas = "call", "full"
                    dest = str(getattr(ir, "destination", ""))
                    target_expression = f"{dest}.{func_name}" if func_name else dest

                elif ir_type == "HighLevelCall":
                    target_func = getattr(ir, "function", None)
                    forwards_gas = "full"
                    if target_func and hasattr(target_func, "view"):
                        if getattr(target_func, "view", False) or getattr(target_func, "pure", False):
                            call_type = "staticcall"
                        else:
                            call_type = "interface"
                    else:
                        call_type = "interface"
                    if target_func:
                        tc = getattr(target_func, "contract_declarer", None) or getattr(target_func, "contract", None)
                        if tc:
                            resolved_target = f"{tc.name}::{target_func.name}"
                    dest = str(getattr(ir, "destination", ""))
                    fname = str(getattr(target_func, "name", "")) if target_func else ""
                    target_expression = f"{dest}.{fname}" if fname else dest

                elif ir_type == "Transfer":
                    call_type, forwards_gas = "transfer", "2300"
                    dest = str(getattr(ir, "destination", ""))
                    target_expression = f"{dest}.transfer"

                elif ir_type == "Send":
                    call_type, forwards_gas = "send", "2300"
                    dest = str(getattr(ir, "destination", ""))
                    target_expression = f"{dest}.send"

                if call_type:
                    segment_data["external_calls"].append({
                        "type": call_type,
                        "desc": f"{ir_type}::{str(ir)[:80]}",
                        "idx": idx,
                        "forwards_gas": forwards_gas,
                        "target_expression": target_expression,
                        "return_value_checked": True,
                        "resolved_target": resolved_target,
                    })

                if ir_type == "InternalCall":
                    target_func = getattr(ir, "function", None)
                    if target_func:
                        target_contract = getattr(target_func, "contract_declarer", None) or getattr(target_func, "contract", None)
                        if target_contract:
                            segment_data["internal_calls"].append({
                                "target_id": f"{target_contract.name}::{target_func.name}",
                                "idx": idx,
                            })

            if hasattr(node, "state_variables_written") and node.state_variables_written:
                segment_data["direct_writes"].append(idx)

        return segment_data

    # ================================================================
    # Story 2.2.4 — Unprotected Mutator Detection
    # ================================================================
    def _detect_unprotected_mutators(self):
        """
        Flags externally callable functions that mutate state without
        any access control protection.
        
        Algorithm:
          IF visibility in [public, external]
             AND writes_state == True
             AND is_protected == False
             AND NOT is_constructor
          THEN flag as UNPROTECTED_STATE_MUTATOR
        """
        for node_id, node_data in self.graph.nodes(data=True):
            if node_data.get("type") != "function":
                continue
            
            visibility = node_data.get("visibility", "")
            writes_state = node_data.get("writes_state", False)
            is_protected = node_data.get("is_protected", False)
            is_constructor = node_data.get("is_constructor", False)
            is_payable = node_data.get("is_payable", False)
            
            is_externally_callable = visibility in ["public", "external"]
            
            if (is_externally_callable 
                and writes_state 
                and not is_protected 
                and not is_constructor):
                
                # Determine risk level
                risk_level = "HIGH" if is_payable else "MEDIUM"
                
                self.graph.nodes[node_id]["is_unprotected_mutator"] = True
                self.graph.nodes[node_id]["unprotected_risk_level"] = risk_level
            else:
                self.graph.nodes[node_id]["is_unprotected_mutator"] = False
                self.graph.nodes[node_id]["unprotected_risk_level"] = "NONE"

    # ================================================================
    # Story 3.2 / Story 1.1 — External Call Classification & EXTERNAL_CALL Edges
    # ================================================================

    def _resolve_external_call_properties(self, ir, ir_type, slither_func):
        """
        Given an IR operation, determine if it is an external call and return
        its rich properties for the EXTERNAL_CALL edge.

        Returns None if not an external call, or a dict with:
        call_type, call_desc, forwards_gas, target_expression,
        return_value_checked, resolved_target
        """
        if ir_type == "LowLevelCall":
            func_name = str(getattr(ir, "function_name", "") or "").lower()
            if "delegatecall" in func_name:
                call_type, forwards_gas = "delegatecall", "full"
            elif "staticcall" in func_name:
                call_type, forwards_gas = "staticcall", "full"
            elif "send" in func_name:
                call_type, forwards_gas = "send", "2300"
            else:
                call_type, forwards_gas = "call", "full"

            dest = str(getattr(ir, "destination", ""))
            target_expression = f"{dest}.{func_name}" if func_name else dest
            return {
                "call_type": call_type,
                "call_desc": f"{ir_type}::{str(ir)[:80]}",
                "forwards_gas": forwards_gas,
                "target_expression": target_expression,
                "return_value_checked": self._check_return_value_used(ir, slither_func),
                "resolved_target": None,
            }

        if ir_type == "HighLevelCall":
            target_func = getattr(ir, "function", None)
            resolved_target = None
            call_type = "interface"
            forwards_gas = "full"

            # Story 1.2: resolve view/pure → staticcall
            if target_func and hasattr(target_func, "view"):
                if getattr(target_func, "view", False) or getattr(target_func, "pure", False):
                    call_type = "staticcall"

            if target_func:
                tc = getattr(target_func, "contract_declarer", None) or getattr(target_func, "contract", None)
                if tc:
                    resolved_target = f"{tc.name}::{target_func.name}"

            dest = str(getattr(ir, "destination", ""))
            fname = str(getattr(target_func, "name", "")) if target_func else ""
            target_expression = f"{dest}.{fname}" if fname else dest
            return {
                "call_type": call_type,
                "call_desc": f"{ir_type}::{str(ir)[:80]}",
                "forwards_gas": forwards_gas,
                "target_expression": target_expression,
                "return_value_checked": True,
                "resolved_target": resolved_target,
            }

        if ir_type == "Transfer":
            dest = str(getattr(ir, "destination", ""))
            return {
                "call_type": "transfer",
                "call_desc": f"{ir_type}::{str(ir)[:80]}",
                "forwards_gas": "2300",
                "target_expression": f"{dest}.transfer",
                "return_value_checked": True,
                "resolved_target": None,
            }

        if ir_type == "Send":
            dest = str(getattr(ir, "destination", ""))
            return {
                "call_type": "send",
                "call_desc": f"{ir_type}::{str(ir)[:80]}",
                "forwards_gas": "2300",
                "target_expression": f"{dest}.send",
                "return_value_checked": self._check_return_value_used(ir, slither_func),
                "resolved_target": None,
            }

        return None

    def _check_return_value_used(self, ir, slither_func) -> bool:
        """Check if the return value of a low-level call / send is used in require/assert.
        Handles tuple unpack pattern: LowLevelCall → TUPLE → Unpack → success → require(success).
        """
        lvalue = getattr(ir, "lvalue", None)
        if not lvalue:
            return False
        track_vars = {str(lvalue).lower()}
        passed_ir = False
        try:
            for node in slither_func.nodes:
                for ir_op in node.irs:
                    if ir_op is ir:
                        passed_ir = True
                        continue
                    if not passed_ir:
                        continue
                    op_str = str(ir_op)
                    op_lower = op_str.lower()
                    # Track Unpack destinations derived from the original lvalue
                    if type(ir_op).__name__ == "Unpack":
                        tuple_var = getattr(ir_op, "tuple", None)
                        if tuple_var and str(tuple_var).lower() in track_vars:
                            unpacked_lv = getattr(ir_op, "lvalue", None)
                            if unpacked_lv:
                                track_vars.add(str(unpacked_lv).lower())
                    # Check if any tracked variable appears in require/assert
                    if "require(bool" in op_lower or "assert(bool" in op_lower:
                        for tv in track_vars:
                            if tv in op_lower:
                                return True
        except Exception:
            pass
        return False

    @staticmethod
    def _gas_for_call_type(call_type: str) -> str:
        if call_type in ("transfer", "send"):
            return "2300"
        if call_type in ("call", "delegatecall", "interface", "staticcall"):
            return "full"
        return "unknown"

    def _classify_external_calls(self, slither_obj: Slither):
        """
        Detects external calls in each function using Slither IR and classifies them.

        Creates EXTERNAL_CALL edges in the graph (Story 1.1) with properties:
          call_type, forwards_gas, target_expression, return_value_checked

        Also detects CEI violations (state write after external call) and
        a separate flag for state writes after reentrant-capable calls only.

        Attaches to function nodes (derived from edges for backward compat):
        - makes_external_call: bool
        - external_call_nodes: List[str]
        - external_call_type: List[str]
        - state_write_after_external_call: bool
        - state_write_after_reentrant_call: bool   (Story 1.3)
        """
        slither_func_lookup = {}
        for contract in slither_obj.contracts:
            for function in contract.functions:
                func_node_id = f"{contract.name}::{function.name}"
                slither_func_lookup[func_node_id] = function

        ext_call_counter = 0

        func_nodes = [
            (nid, ndata) for nid, ndata in self.graph.nodes(data=True)
            if ndata.get("type") == "function"
        ]

        for node_id, node_data in func_nodes:

            slither_func = slither_func_lookup.get(node_id)

            # Coordinates: (phase, local_idx)
            # Phase 0: Modifiers PRE  |  Phase 1: Function Body  |  Phase 2: Modifiers POST
            external_call_events = []   # list of dicts
            state_write_events = []     # list of (phase, idx)

            applied_modifiers = node_data.get("modifiers", [])
            contract_name = node_data.get("contract", "")

            # ---- Phase 0: Modifiers PRE ----
            for m_idx, mod_name in enumerate(applied_modifiers):
                mod_node_id = f"{contract_name}::modifier::{mod_name}"
                mod_data = self.graph.nodes.get(mod_node_id, {})
                if not mod_data:
                    continue
                pre_seg = mod_data.get("pre_segment", {})
                for call in pre_seg.get("external_calls", []):
                    ct = call["type"]
                    external_call_events.append({
                        "phase": 0,
                        "local_idx": m_idx * 1000 + call["idx"],
                        "call_type": ct,
                        "call_desc": call["desc"],
                        "forwards_gas": call.get("forwards_gas", self._gas_for_call_type(ct)),
                        "target_expression": call.get("target_expression", call["desc"]),
                        "return_value_checked": call.get("return_value_checked", True),
                        "resolved_target": call.get("resolved_target"),
                    })
                for w_idx in pre_seg.get("direct_writes", []):
                    state_write_events.append((0, m_idx * 1000 + w_idx))
                for icall in pre_seg.get("internal_calls", []):
                    td = self.graph.nodes.get(icall["target_id"], {})
                    if td.get("writes_state") or len(td.get("propagated_state_variables", [])) > 0:
                        state_write_events.append((0, m_idx * 1000 + icall["idx"]))

            # ---- Phase 1: Function Body ----
            if slither_func:
                for idx, cfg_node in enumerate(slither_func.nodes):
                    for ir in cfg_node.irs:
                        ir_type = type(ir).__name__

                        props = self._resolve_external_call_properties(ir, ir_type, slither_func)
                        if props:
                            external_call_events.append({
                                "phase": 1,
                                "local_idx": idx,
                                **props,
                            })

                        if ir_type == "InternalCall":
                            target_func = getattr(ir, "function", None)
                            if target_func:
                                tc = getattr(target_func, "contract_declarer", None) or getattr(target_func, "contract", None)
                                if tc:
                                    tid = f"{tc.name}::{target_func.name}"
                                    td = self.graph.nodes.get(tid, {})
                                    if td.get("writes_state") or len(td.get("propagated_state_variables", [])) > 0:
                                        state_write_events.append((1, idx))

                    if hasattr(cfg_node, "state_variables_written") and cfg_node.state_variables_written:
                        state_write_events.append((1, idx))

            # ---- Phase 2: Modifiers POST (reverse order) ----
            for m_idx, mod_name in enumerate(reversed(applied_modifiers)):
                mod_node_id = f"{contract_name}::modifier::{mod_name}"
                mod_data = self.graph.nodes.get(mod_node_id, {})
                if not mod_data:
                    continue
                post_seg = mod_data.get("post_segment", {})
                for call in post_seg.get("external_calls", []):
                    ct = call["type"]
                    external_call_events.append({
                        "phase": 2,
                        "local_idx": m_idx * 1000 + call["idx"],
                        "call_type": ct,
                        "call_desc": call["desc"],
                        "forwards_gas": call.get("forwards_gas", self._gas_for_call_type(ct)),
                        "target_expression": call.get("target_expression", call["desc"]),
                        "return_value_checked": call.get("return_value_checked", True),
                        "resolved_target": call.get("resolved_target"),
                    })
                for w_idx in post_seg.get("direct_writes", []):
                    state_write_events.append((2, m_idx * 1000 + w_idx))
                for icall in post_seg.get("internal_calls", []):
                    td = self.graph.nodes.get(icall["target_id"], {})
                    if td.get("writes_state") or len(td.get("propagated_state_variables", [])) > 0:
                        state_write_events.append((2, m_idx * 1000 + icall["idx"]))

            # ---- Create EXTERNAL_CALL edges (Story 1.1) ----
            for ev in external_call_events:
                resolved = ev.get("resolved_target")
                if resolved and self.graph.has_node(resolved) and not self.graph.has_edge(node_id, resolved):
                    target_node_id = resolved
                else:
                    target_node_id = f"__ext::{node_id}::{ext_call_counter}"
                    self.graph.add_node(target_node_id,
                        type="external_target",
                        target_expression=ev["target_expression"],
                    )
                    ext_call_counter += 1

                self.graph.add_edge(node_id, target_node_id,
                    relationship="EXTERNAL_CALL",
                    call_type=ev["call_type"],
                    forwards_gas=ev["forwards_gas"],
                    target_expression=ev["target_expression"],
                    return_value_checked=ev["return_value_checked"],
                )

            # ---- CEI Violation Detection ----
            makes_external_call = len(external_call_events) > 0
            state_write_after = False
            state_write_after_reentrant = False

            if makes_external_call and state_write_events:
                first_call_coord = min((ev["phase"], ev["local_idx"]) for ev in external_call_events)
                for wc in state_write_events:
                    if wc > first_call_coord:
                        state_write_after = True
                        break

            reentrant_events = [
                ev for ev in external_call_events
                if ev["call_type"] in ("call", "delegatecall") and ev["forwards_gas"] != "2300"
            ]
            if reentrant_events and state_write_events:
                first_reentrant_coord = min((ev["phase"], ev["local_idx"]) for ev in reentrant_events)
                for wc in state_write_events:
                    if wc > first_reentrant_coord:
                        state_write_after_reentrant = True
                        break

            # ---- Attach results (backward-compatible flags derived from edges) ----
            node_data["makes_external_call"] = makes_external_call
            node_data["external_call_nodes"] = [ev["call_desc"] for ev in external_call_events]
            node_data["external_call_type"] = sorted(list(set(ev["call_type"] for ev in external_call_events)))
            node_data["state_write_after_external_call"] = state_write_after
            node_data["state_write_after_reentrant_call"] = state_write_after_reentrant

    # ================================================================
    # Story 3.4 / Story 1.3 — Deterministic Reentrancy Rule
    # ================================================================
    def _detect_reentrancy_risks(self):
        """
        Combines structural properties to identify reentrancy-vulnerable functions.

        Story 1.3 upgrade — reentrancy requires a reentrant-capable call:
          1. reachable_from_external_entry == True
          2. Has EXTERNAL_CALL edge with call_type in (call, delegatecall) AND forwards_gas != 2300
          3. propagated_state_variables not empty
          4. state_write_after_reentrant_call == True

        transfer()/send()/staticcall no longer trigger reentrancy.
        CEI violations without reentrant calls are flagged separately as cei_violation_only.

        Attaches:
        - reentrancy_risk: bool
        - reentrancy_risk_score: int
        - cei_violation_only: bool
        """
        for node_id, node_data in self.graph.nodes(data=True):
            if node_data.get("type") != "function":
                continue

            is_reachable = node_data.get("reachable_from_external_entry", False)
            has_state_vars = len(node_data.get("propagated_state_variables", [])) > 0
            has_reentrant_violation = node_data.get("state_write_after_reentrant_call", False)

            has_reentrant_call = False
            for _, _, edge_data in self.graph.out_edges(node_id, data=True):
                if edge_data.get("relationship") != "EXTERNAL_CALL":
                    continue
                ct = edge_data.get("call_type", "")
                gas = edge_data.get("forwards_gas", "unknown")
                if ct in ("call", "delegatecall") and gas != "2300":
                    has_reentrant_call = True
                    break

            is_risk = (
                is_reachable
                and has_reentrant_call
                and has_state_vars
                and has_reentrant_violation
            )

            score = 0
            if is_risk:
                score = 10
                score += 2 * len(node_data.get("propagated_state_variables", []))

            has_any_cei = node_data.get("state_write_after_external_call", False)
            is_cei_only = (
                has_any_cei
                and has_state_vars
                and node_data.get("makes_external_call", False)
                and not is_risk
            )

            node_data["reentrancy_risk"] = is_risk
            node_data["reentrancy_risk_score"] = score
            node_data["cei_violation_only"] = is_cei_only

    # ================================================================
    # Story 3.5 — Privilege Propagation
    # ================================================================
    def _enrich_state_variable_reverse_mapping(self):
        """
        Populates state variables with reverse mappings: roles using them
        and functions modifying them.
        """
        for var_id, var_data in self.graph.nodes(data=True):
            if var_data.get("type") != "state_variable":
                continue
            
            # Roles using this variable
            roles_using = []
            for contract_id, contract_data in self.graph.nodes(data=True):
                if contract_data.get("type") == "contract":
                    for role in contract_data.get("privileged_roles", []):
                        if role.get("underlying_variable") == var_id:
                            roles_using.append({
                                "contract": contract_id,
                                "role": role.get("role_name"),
                                "modifier": role.get("modifier_name")
                            })
            
            # Functions modifying this variable (propagated)
            modifying_functions = []
            for node_idx, node_data in self.graph.nodes(data=True):
                if node_data.get("type") == "function":
                    if var_id in node_data.get("propagated_state_variables", []):
                        modifying_functions.append(node_idx)
            
            var_data["roles_using_variable"] = roles_using
            var_data["functions_modifying_variable"] = modifying_functions

    def _detect_privilege_escalation(self):
        """
        Flags variables and functions involved in privilege escalation risks.
        """
        # First, ensure all functions have the flag initialized to False
        for node_id, node_data in self.graph.nodes(data=True):
            if node_data.get("type") == "function":
                node_data["can_escalate_privileges"] = False

        for var_id, var_data in self.graph.nodes(data=True):
            if var_data.get("type") != "state_variable":
                continue
            
            roles_using = var_data.get("roles_using_variable", [])
            modifiers = var_data.get("functions_modifying_variable", [])
            
            # Check if any unprotected mutator can modify this var
            is_at_risk = False
            risky_mutators_for_this_var = []
            
            if roles_using: # Only care if the variable controls a role
                for func_id in modifiers:
                    func_data = self.graph.nodes.get(func_id, {})
                    if func_data.get("is_unprotected_mutator", False):
                        is_at_risk = True
                        risky_mutators_for_this_var.append(func_id)
                        # Flag the function: it can escalate privileges because it modifies THIS var
                        self.graph.nodes[func_id]["can_escalate_privileges"] = True
            
            if is_at_risk:
                var_data["privilege_escalation_risk"] = True
                var_data["risky_mutators"] = risky_mutators_for_this_var
            else:
                var_data["privilege_escalation_risk"] = False
                var_data["risky_mutators"] = []

    # ================================================================
    # Epic 6, Story 6.1 — StateTransition Nodes
    # ================================================================

    def _build_state_transitions(self, slither_obj: Slither):
        """
        Creates StateTransition nodes between Functions and StateVariables.

        Replaces the semantic gap of a bare WRITES edge with a richer model:
            Function --PERFORMS--> StateTransition --AFFECTS--> StateVariable

        Each StateTransition carries the operation type (assign, add, sub, push,
        pop, decrement_length, delete) and metadata about the target variable.
        Existing WRITES edges are kept for backward compatibility.
        """
        slither_func_lookup: Dict[str, Any] = {}
        for contract in slither_obj.contracts:
            for function in contract.functions:
                func_node_id = f"{contract.name}::{function.name}"
                slither_func_lookup[func_node_id] = function

        st_counter = 0

        for node_id, node_data in list(self.graph.nodes(data=True)):
            if node_data.get("type") != "function":
                continue

            slither_func = slither_func_lookup.get(node_id)
            if not slither_func:
                continue

            seen: set = set()

            try:
                cfg_nodes = slither_func.nodes
            except Exception:
                continue

            for cfg_node in cfg_nodes:
                written_vars = getattr(cfg_node, "state_variables_written", [])
                if not written_vars:
                    continue

                for state_var in written_vars:
                    var_contract = getattr(state_var, "contract", None)
                    if not var_contract:
                        continue
                    var_node_id = f"{var_contract.name}::{state_var.name}"
                    if not self.graph.has_node(var_node_id):
                        continue

                    operation = self._classify_write_operation(cfg_node, state_var)

                    dedup_key = (var_node_id, operation)
                    if dedup_key in seen:
                        continue
                    seen.add(dedup_key)

                    var_type_str = str(state_var.type) if hasattr(state_var, "type") else ""
                    is_mapping = "mapping" in var_type_str.lower()
                    is_array = "[]" in var_type_str
                    is_array_length = operation in ("decrement_length", "pop")

                    attacker_controlled = self._check_attacker_controlled_input(
                        cfg_node, slither_func
                    )

                    expression = str(cfg_node.expression) if cfg_node.expression else ""

                    st_id = f"__st::{node_id}::{st_counter}"
                    st_counter += 1

                    self.graph.add_node(st_id, **{
                        "type": "state_transition",
                        "node_type": "StateTransition",
                        "function": node_id,
                        "variable": var_node_id,
                        "operation": operation,
                        "is_array_length": is_array_length,
                        "is_array": is_array,
                        "is_mapping": is_mapping,
                        "is_owner_assignment": False,
                        "attacker_controlled_input": attacker_controlled,
                        "affects_privileged_var": False,
                        "ir_expression": expression,
                    })

                    self.graph.add_edge(node_id, st_id, relationship="PERFORMS")
                    self.graph.add_edge(st_id, var_node_id, relationship="AFFECTS")

    def _classify_write_operation(self, cfg_node, state_var) -> str:
        """
        Determines the operation type for a state variable write within a CFG node.

        Expression-based checks run first for patterns that Slither IR may
        obscure (e.g. .pop() is lowered to Delete IR), then IR-based checks
        handle the remaining cases.
        """
        expression = str(cfg_node.expression) if cfg_node.expression else ""
        var_name = state_var.name

        # Expression-based detection first — handles pop/push/length patterns
        # that Slither may lower to different IR types.
        if ".length--" in expression or ".length --" in expression:
            return "decrement_length"
        if ".pop()" in expression:
            return "pop"
        if ".push(" in expression:
            return "push"
        if "+=" in expression:
            return "add"
        if "-=" in expression:
            return "sub"

        # IR-based detection for clear-cut operations
        for ir in cfg_node.irs:
            ir_type = type(ir).__name__
            if ir_type == "Push":
                return "push"
            if ir_type == "Delete":
                return "delete"

        # IR-based fallback: check Binary operations that feed into the var
        for ir in cfg_node.irs:
            if type(ir).__name__ != "Binary":
                continue
            binary_type_str = str(getattr(ir, "type", "")).upper()
            used = getattr(ir, "used", [])
            involves_var = any(
                str(getattr(v, "name", "")) == var_name for v in used
            )
            if involves_var:
                if "ADD" in binary_type_str:
                    return "add"
                if "SUB" in binary_type_str:
                    return "sub"

        return "assign"

    def _check_attacker_controlled_input(self, cfg_node, slither_func) -> bool:
        """
        Heuristic: returns True when a function parameter (or msg.value) appears
        in the write expression of an external/public function.
        """
        vis = str(getattr(slither_func, "visibility", "internal"))
        if vis not in ("public", "external"):
            return False

        param_names: set = set()
        for p in slither_func.parameters:
            pname = str(getattr(p, "name", ""))
            if pname:
                param_names.add(pname)

        expression = str(cfg_node.expression) if cfg_node.expression else ""

        if "msg.value" in expression:
            return True

        for pname in param_names:
            if pname in expression:
                return True

        return False

    def _enrich_state_transitions(self):
        """
        Second pass over StateTransition nodes: sets is_owner_assignment and
        affects_privileged_var now that access control analysis has completed.
        """
        privileged_var_ids: set = set()
        for _, node_data in self.graph.nodes(data=True):
            if node_data.get("type") == "contract":
                for role in node_data.get("privileged_roles", []):
                    uv = role.get("underlying_variable", "")
                    if uv:
                        privileged_var_ids.add(uv)

        owner_names = {"owner", "_owner", "admin", "_admin", "governance", "authority"}

        for _, node_data in self.graph.nodes(data=True):
            if node_data.get("type") != "state_transition":
                continue

            var_id = node_data.get("variable", "")
            var_data = self.graph.nodes.get(var_id, {})
            var_name_lower = var_data.get("name", "").lower()

            node_data["is_owner_assignment"] = (
                var_name_lower in owner_names or var_id in privileged_var_ids
            )
            node_data["affects_privileged_var"] = var_id in privileged_var_ids

    # ================================================================
    # Epic 6, Story 6.2 — Array Length Mutation Detection
    # ================================================================

    def _detect_array_length_mutations(self):
        """
        Scans StateTransition nodes for array length decrements (pop /
        decrement_length).  Sets has_array_length_mutation on the owning
        function so the risk scorer can pick it up.

        Enables deterministic detection of the AlienCodex primitive:
        underflowing a dynamic array's length gives the attacker access
        to the full storage space.
        """
        for node_id, node_data in self.graph.nodes(data=True):
            if node_data.get("type") != "state_transition":
                continue

            operation = node_data.get("operation", "")
            is_array = node_data.get("is_array", False)

            if operation in ("decrement_length", "pop") and is_array:
                node_data["is_array_length"] = True
                func_id = node_data.get("function", "")
                if func_id and self.graph.has_node(func_id):
                    self.graph.nodes[func_id]["has_array_length_mutation"] = True

    # ================================================================
    # Epic 6, Story 6.3 — Delegatecall Storage Collision Detection
    # ================================================================

    def _detect_delegatecall_storage_risk(self):
        """
        Flags functions where:
          1. A delegatecall is made to an attacker-controlled target, OR
          2. State is written after a delegatecall, OR
          3. The owning contract is marked upgradeable.

        Any of these in the presence of a delegatecall constitutes a
        DELEGATECALL_STORAGE_RISK primitive.
        """
        for node_id, node_data in self.graph.nodes(data=True):
            if node_data.get("type") != "function":
                continue

            contract_name = node_data.get("contract", "")

            contract_state_var_names: set = set()
            for nid, ndata in self.graph.nodes(data=True):
                if (
                    ndata.get("type") == "state_variable"
                    and ndata.get("contract") == contract_name
                ):
                    contract_state_var_names.add(ndata.get("name", ""))

            has_delegatecall = False
            target_attacker_controlled = False

            for _, target, edge_data in self.graph.out_edges(node_id, data=True):
                if edge_data.get("relationship") != "EXTERNAL_CALL":
                    continue
                if edge_data.get("call_type") != "delegatecall":
                    continue

                has_delegatecall = True

                target_expr = edge_data.get("target_expression", "")
                addr_part = target_expr.split(".")[0].strip() if "." in target_expr else target_expr
                if addr_part and addr_part not in contract_state_var_names:
                    target_attacker_controlled = True

            if not has_delegatecall:
                node_data["delegatecall_storage_risk"] = False
                continue

            writes_state_after = node_data.get("state_write_after_external_call", False)
            has_state_writes = (
                node_data.get("writes_state", False)
                or len(node_data.get("propagated_state_variables", [])) > 0
            )

            contract_data = self.graph.nodes.get(contract_name, {})
            is_upgradeable = contract_data.get("is_upgradeable", False)

            is_risk = (
                target_attacker_controlled
                or (writes_state_after and has_state_writes)
                or is_upgradeable
            )

            node_data["delegatecall_storage_risk"] = is_risk

    # ================================================================
    # Epic 7 — Contract Tier Classification
    # ================================================================

    def _classify_contract_tiers(self, slither_obj: Slither):
        """
        Assigns a tier to every Contract node:
            CORE     — has external entries AND makes external calls
                       (primary business logic / attack surface)
            FACTORY  — any function contains a ``new ContractName(...)`` operation
            LIBRARY  — Solidity library, interface, or has zero external entries
            INFRA    — default for contracts that don't match another tier

        The tier is stored as ``contract_node["tier"]`` and consumed by
        ``_compute_global_risk_scores`` for impact weighting.
        """
        contract_creates: Dict[str, bool] = {}
        for contract in slither_obj.contracts:
            creates = False
            for function in contract.functions:
                if creates:
                    break
                try:
                    for cfg_node in function.nodes:
                        if creates:
                            break
                        for ir in cfg_node.irs:
                            if type(ir).__name__ == "NewContract":
                                creates = True
                                break
                except Exception:
                    pass
                if not creates:
                    expression = ""
                    try:
                        if function.source_mapping:
                            sm = function.source_mapping
                            with open(sm.filename.absolute, "r", encoding="utf-8") as fh:
                                content = fh.read()
                                expression = content[sm.start:sm.start + sm.length]
                    except Exception:
                        pass
                    if re.search(r"\bnew\s+[A-Z]\w*\s*\(", expression):
                        creates = True
            contract_creates[contract.name] = creates

        for node_id, node_data in self.graph.nodes(data=True):
            if node_data.get("type") != "contract":
                continue

            name = node_data.get("name", node_id)
            is_library = node_data.get("is_library", False)
            is_interface = node_data.get("is_interface", False)
            creates = contract_creates.get(name, False)

            external_entries = 0
            makes_ext_call = False
            for fid, fdata in self.graph.nodes(data=True):
                if fdata.get("type") != "function":
                    continue
                if fdata.get("contract") != name:
                    continue
                if fdata.get("is_external_entry"):
                    external_entries += 1
                if fdata.get("makes_external_call"):
                    makes_ext_call = True

            if creates:
                tier = "FACTORY"
            elif is_library or is_interface or external_entries == 0:
                tier = "LIBRARY"
            elif external_entries > 0 and makes_ext_call:
                tier = "CORE"
            else:
                tier = "INFRA"

            node_data["tier"] = tier

    # ================================================================
    # Story 4.2 / Epic 3, Story 3.1 — Multi-Dimensional Risk Scoring
    # ================================================================
    def _compute_global_risk_scores(self):
        """
        Computes multi-dimensional risk scores for each function node.

        Dimensions:
          structural_score  — presence of dangerous patterns detected by
                              the deterministic graph analysis (CEI, reentrancy,
                              unprotected mutation, privilege escalation).
          exploitability_score — how attackable the pattern is: requires
                                 external reachability, attacker-controlled
                                 input, reentrant-capable call type, etc.
          impact_score      — magnitude of damage: number of state variables
                              at risk, payability, privilege scope.
          final_score       — weighted combination used for hotspot selection.

        Hotspot gate (applied in get_high_risk_hotspots):
          structural_score >= 40  AND  exploitability_score >= 30

        Backward-compatible: risk_score is kept as an alias for final_score.
        """
        for node_id, node_data in self.graph.nodes(data=True):
            if node_data.get("type") != "function":
                continue

            structural = 0
            exploitability = 0
            impact = 0
            risk_categories = []

            # ── Structural Score ──────────────────────────────
            if node_data.get("reentrancy_risk"):
                structural += 50
                risk_categories.append("reentrancy")

            if node_data.get("can_escalate_privileges"):
                structural += 50
                risk_categories.append("privilege_escalation")

            if node_data.get("is_unprotected_mutator"):
                structural += 40
                risk_categories.append("unprotected_mutator")

            if node_data.get("cei_violation_only"):
                structural += 15
                risk_categories.append("cei_violation")
            elif (node_data.get("state_write_after_external_call")
                  and not node_data.get("reentrancy_risk")):
                structural += 15
                risk_categories.append("cei_violation")

            # Epic 6, Story 6.2
            if node_data.get("has_array_length_mutation"):
                structural += 40
                risk_categories.append("array_length_mutation")

            # Epic 6, Story 6.3
            if node_data.get("delegatecall_storage_risk"):
                structural += 50
                risk_categories.append("delegatecall_storage_risk")

            # ── Exploitability Score ──────────────────────────
            if node_data.get("reachable_from_external_entry"):
                exploitability += 30

            has_reentrant_edge = False
            for _, _, ed in self.graph.out_edges(node_id, data=True):
                if ed.get("relationship") != "EXTERNAL_CALL":
                    continue
                ct = ed.get("call_type", "")
                gas = ed.get("forwards_gas", "unknown")
                if ct in ("call", "delegatecall") and gas != "2300":
                    has_reentrant_edge = True
                    break

            if has_reentrant_edge:
                exploitability += 30

            if node_data.get("is_external_entry"):
                exploitability += 10

            if not node_data.get("is_protected") and not node_data.get("is_view_or_pure"):
                exploitability += 15

            has_attacker_input = False
            for _, st_id, ed in self.graph.out_edges(node_id, data=True):
                if ed.get("relationship") != "PERFORMS":
                    continue
                st_data = self.graph.nodes.get(st_id, {})
                if st_data.get("attacker_controlled_input"):
                    has_attacker_input = True
                    break
            if has_attacker_input:
                exploitability += 15

            # ── Impact Score ──────────────────────────────────
            prop_vars = node_data.get("propagated_state_variables", [])
            if prop_vars:
                impact += min(30, 5 * len(prop_vars))

            if node_data.get("is_payable"):
                impact += 20

            if node_data.get("can_escalate_privileges"):
                impact += 30

            if node_data.get("is_unprotected_mutator"):
                level = node_data.get("unprotected_risk_level", "MEDIUM")
                impact += 20 if level == "HIGH" else 10

            # ── Epic 7, Story 7.2: Tier-weighted impact ──────
            contract_name = node_data.get("contract", "")
            contract_tier = self.graph.nodes.get(contract_name, {}).get("tier", "INFRA")
            if contract_tier == "CORE":
                impact += 20
            elif contract_tier == "FACTORY":
                impact -= 25
            impact = max(0, impact)

            # ── Final Score (weighted combination) ────────────
            final = (
                structural * 0.40
                + exploitability * 0.35
                + impact * 0.25
            )
            final_int = int(round(final))

            node_data["structural_score"] = structural
            node_data["exploitability_score"] = exploitability
            node_data["impact_score"] = impact
            node_data["final_score"] = final_int
            node_data["risk_score"] = final_int   # backward compat
            node_data["risk_categories"] = risk_categories

    # ================================================================
    # Epic 8 — Semantic Vulnerability Detection
    # ================================================================

    def _detect_oracle_patterns(self) -> None:
        """Epic 8.1 — Detect oracle usage and flag manipulation risk."""
        SPOT = [
            "getReserves()", "slot0", ".reserve0", ".reserve1",
            "price0CumulativeLast", "price1CumulativeLast",
            "getPoolTokens", "getNormalizedWeights", "getSpotPrice",
        ]
        SAFE = [
            "latestRoundData", "latestAnswer", "getRoundData",
            "AggregatorV3Interface",
        ]
        TWAP = ["consult(", "observe(", "OracleLibrary.consult", "UniswapV2OracleLibrary"]
        SHORT_WINDOW_THRESHOLD = 1800

        for node_id, data in self.graph.nodes(data=True):
            if data.get("type") != "function":
                continue
            src = data.get("source_code", "")

            uses_spot = any(p in src for p in SPOT)
            uses_safe = any(p in src for p in SAFE)
            uses_twap = any(p in src for p in TWAP)
            is_external = data.get("is_external_entry", False)

            twap_window_short = False
            if uses_twap:
                for pat in TWAP:
                    idx = src.find(pat)
                    if idx == -1:
                        continue
                    window = src[max(0, idx - 200):idx + 200]
                    for m in re.finditer(r"\b(\d+)\b", window):
                        val = int(m.group(1))
                        if 0 < val < SHORT_WINDOW_THRESHOLD:
                            twap_window_short = True
                            break

            sources: list[str] = []
            if any(p in src for p in ["getReserves()", ".reserve0", ".reserve1",
                                       "price0CumulativeLast", "price1CumulativeLast"]):
                sources.append("uniswap_v2_spot")
            if "slot0" in src:
                sources.append("uniswap_v3_spot")
            if any(p in src for p in ["getPoolTokens", "getNormalizedWeights"]):
                sources.append("balancer_spot")
            if uses_safe:
                sources.append("chainlink")
            if uses_twap:
                sources.append("twap")

            manipulation_risk = uses_spot and is_external and not uses_safe

            self.graph.nodes[node_id].update({
                "uses_spot_price_oracle":   uses_spot,
                "uses_safe_oracle":         uses_safe,
                "uses_twap_oracle":         uses_twap,
                "oracle_sources":           sources,
                "oracle_manipulation_risk": manipulation_risk,
                "oracle_risk_score":        120 if manipulation_risk else 0,
                "twap_window_short":        twap_window_short,
            })

            if manipulation_risk:
                current = self.graph.nodes[node_id].get("risk_score", 0)
                cats = list(self.graph.nodes[node_id].get("risk_categories", []))
                self.graph.nodes[node_id]["risk_score"] = current + 120
                self.graph.nodes[node_id]["risk_categories"] = cats + ["oracle_manipulation"]

    def _detect_arithmetic_patterns(self) -> None:
        """Epic 8.2 — Detect arithmetic precision and safety patterns."""
        DIV_MUL_RE = re.compile(
            r"\([^()]*[a-zA-Z_][^()]*\s*/\s*[^()]+\)\s*\*",
        )
        UNSAFE_CAST_RE = re.compile(
            r"(uint256\s*\(\s*int256\s*\(|int256\s*\(\s*uint256\s*\()"
        )

        for node_id, data in self.graph.nodes(data=True):
            if data.get("type") != "function":
                continue
            src = data.get("source_code", "")
            writes = data.get("writes_state", False)

            div_mul = bool(DIV_MUL_RE.search(src))
            unchecked = "unchecked {" in src
            unc_write = unchecked and writes
            unsafe = bool(UNSAFE_CAST_RE.search(src))

            arith_score = 0
            cats = list(self.graph.nodes[node_id].get("risk_categories", []))

            if unc_write:
                arith_score += 50
                cats.append("unchecked_arithmetic")
            if div_mul:
                arith_score += 40
                cats.append("division_before_multiplication")
            if unsafe:
                arith_score += 35
                cats.append("unsafe_type_cast")

            self.graph.nodes[node_id].update({
                "division_before_multiplication": div_mul,
                "has_unchecked_arithmetic":       unchecked,
                "unchecked_with_state_write":     unc_write,
                "unsafe_type_cast":               unsafe,
                "arithmetic_risk_score":          arith_score,
            })

            if arith_score > 0:
                current = self.graph.nodes[node_id].get("risk_score", 0)
                self.graph.nodes[node_id]["risk_score"] = current + arith_score
                self.graph.nodes[node_id]["risk_categories"] = cats

    def _detect_signature_patterns(self) -> None:
        """Epic 8.3 — Detect signature validation and replay risk."""
        SIG_PATTERNS = ["ecrecover(", "ECDSA.", "SignatureChecker."]
        CHAINID_PATTERNS = ["block.chainid", "chain_id", "chainId", "CHAIN_ID"]
        NONCE_PATTERNS = ["nonce", "Nonce"]
        EXPIRY_PATTERNS = ["deadline", "expiry", "validUntil", "expiration",
                           "expiresAt", "validBefore"]
        USED_PATTERNS = ["nonce", "used", "executed", "processed", "spent"]

        for node_id, data in self.graph.nodes(data=True):
            if data.get("type") != "function":
                continue
            src = data.get("source_code", "")

            uses_sig = any(p in src for p in SIG_PATTERNS)

            if not uses_sig:
                self.graph.nodes[node_id].update({
                    "uses_signature_validation": False,
                    "signature_includes_chainid": False,
                    "signature_includes_nonce":   False,
                    "signature_includes_expiry":  False,
                    "signature_marks_used":       False,
                    "signature_replay_risk":      False,
                })
                continue

            window = ""
            for pat in SIG_PATTERNS:
                idx = src.find(pat)
                if idx >= 0:
                    window += src[max(0, idx - 500):idx + 500]

            has_chainid = any(p in window for p in CHAINID_PATTERNS)
            has_nonce = any(p in window for p in NONCE_PATTERNS)
            has_expiry = any(p in window for p in EXPIRY_PATTERNS)

            marks_used = False
            for sv_id in data.get("state_variables_written", []):
                sv_name = sv_id.split("::")[-1].lower()
                if any(p in sv_name for p in USED_PATTERNS):
                    marks_used = True
                    break

            replay_risk = not (has_chainid and has_nonce and marks_used)

            self.graph.nodes[node_id].update({
                "uses_signature_validation":  True,
                "signature_includes_chainid": has_chainid,
                "signature_includes_nonce":   has_nonce,
                "signature_includes_expiry":  has_expiry,
                "signature_marks_used":       marks_used,
                "signature_replay_risk":      replay_risk,
            })

            if replay_risk:
                current = self.graph.nodes[node_id].get("risk_score", 0)
                cats = list(self.graph.nodes[node_id].get("risk_categories", []))
                self.graph.nodes[node_id]["risk_score"] = current + 100
                self.graph.nodes[node_id]["risk_categories"] = cats + ["signature_replay"]

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
