import networkx as nx
import json
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
        
        # Story 3.1: Propagate writes through CALLS edges
        self._propagate_writes()
        
        # Story 3.3: Compute reachability from external entries
        self._compute_reachability()
        
        # Enrich with access control intelligence (Stories 2.2.1-2.2.4)
        self._enrich_access_control(slither_obj)
        
        # Story 3.2: Classify external calls for reentrancy modeling
        self._classify_external_calls(slither_obj)
        
        # Story 3.4: Combine everything for Deterministic Reentrancy Rule
        self._detect_reentrancy_risks()
        
        self._detect_privileged_roles()
        self._detect_unprotected_mutators()
        
        # Story 3.5: Privilege Propagation
        self._enrich_state_variable_reverse_mapping()
        self._detect_privilege_escalation()


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
            from collections import deque
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
        import re
        
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
            import re
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
            import re
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
        """
        calls = []
        has_direct_write = False
        
        # We also need to check for internal calls that write state
        # But we don't have the full graph yet during modifier extraction
        # So we'll store the internal call targets and resolve them later 
        # OR we can just store the node summary.
        
        segment_data = {
            "external_calls": [], # List of (call_desc, call_type, node_idx)
            "direct_writes": [], # List of node_idx
            "internal_calls": [] # List of (target_function_data, node_idx)
        }

        for idx, node in enumerate(nodes):
            # External Calls
            for ir in node.irs:
                ir_type = type(ir).__name__
                call_type = None
                if ir_type == "LowLevelCall":
                    func_name = str(getattr(ir, "function_name", "") or "").lower()
                    call_type = "delegatecall" if "delegatecall" in func_name else ("send" if "send" in func_name else "call")
                elif ir_type == "HighLevelCall":
                    call_type = "interface"
                elif ir_type == "Transfer":
                    call_type = "transfer"
                elif ir_type == "Send":
                    call_type = "send"
                
                if call_type:
                    segment_data["external_calls"].append({
                        "type": call_type,
                        "desc": f"{ir_type}::{str(ir)[:80]}",
                        "idx": idx
                    })
                
                if ir_type == "InternalCall":
                    target_func = getattr(ir, "function", None)
                    if target_func:
                        target_contract = getattr(target_func, "contract_declarer", None) or getattr(target_func, "contract", None)
                        if target_contract:
                            segment_data["internal_calls"].append({
                                "target_id": f"{target_contract.name}::{target_func.name}",
                                "idx": idx
                            })

            # Direct Writes
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
    # Story 3.2 — External Call Classification
    # ================================================================
    def _classify_external_calls(self, slither_obj: Slither):
        """
        Detects external calls in each function using Slither IR and classifies them.
        
        For each function, inspects CFG nodes in order to find:
        - LowLevelCall operations (call, delegatecall, send)
        - HighLevelCall operations (interface/contract calls)
        - Transfer operations
        
        CRITICAL: Detects CEI (Checks-Effects-Interactions) violations by comparing
        node indices of external calls vs state writes.
        
        Robustness improvements:
        1. Tracks ALL external calls and ALL state writes (not just first).
        2. Detects indirect state writes via InternalCall using propagated metadata (Story 3.1).
        3. Flags violation if ANY state write occurs AFTER the FIRST external call.
        4. Handles edge cases like multiple writes/calls, writes in callees, and conditional writes.
        
        Attaches to function nodes:
        - makes_external_call: bool
        - external_call_nodes: List[str] (descriptions of external calls)
        - external_call_type: List[str] (["call", "delegatecall", "transfer", "send", "interface"])
        - state_write_after_external_call: bool
        """
        # Build lookup: node_id -> Slither function object
        slither_func_lookup = {}
        for contract in slither_obj.contracts:
            for function in contract.functions:
                func_node_id = f"{contract.name}::{function.name}"
                slither_func_lookup[func_node_id] = function

        for node_id, node_data in self.graph.nodes(data=True):
            if node_data.get("type") != "function":
                continue

            slither_func = slither_func_lookup.get(node_id)
            
            # --- Phase-based Ranking Model ---
            # Coordinates are (phase, local_idx)
            # Phase 0: Modifiers PRE
            # Phase 1: Function Body
            # Phase 2: Modifiers POST
            
            external_call_events = [] # List of (phase, idx, call_type, call_desc)
            state_write_events = []   # List of (phase, idx)
            
            applied_modifiers = node_data.get("modifiers", [])
            contract_name = node_data.get("contract", "")
            
            # Phase 0: Modifiers PRE
            for m_idx, mod_name in enumerate(applied_modifiers):
                mod_node_id = f"{contract_name}::modifier::{mod_name}"
                mod_data = self.graph.nodes.get(mod_node_id, {})
                if not mod_data: continue
                
                pre_seg = mod_data.get("pre_segment", {})
                for call in pre_seg.get("external_calls", []):
                    external_call_events.append((0, m_idx * 1000 + call["idx"], call["type"], call["desc"]))
                for w_idx in pre_seg.get("direct_writes", []):
                    state_write_events.append((0, m_idx * 1000 + w_idx))
                for icall in pre_seg.get("internal_calls", []):
                    target_data = self.graph.nodes.get(icall["target_id"], {})
                    if target_data.get("writes_state") or len(target_data.get("propagated_state_variables", [])) > 0:
                        state_write_events.append((0, m_idx * 1000 + icall["idx"]))

            # Phase 1: Function Body
            if slither_func:
                for idx, cfg_node in enumerate(slither_func.nodes):
                    # Direct external calls
                    for ir in cfg_node.irs:
                        ir_type = type(ir).__name__
                        call_type = None
                        if ir_type == "LowLevelCall":
                            func_name = str(getattr(ir, "function_name", "") or "").lower()
                            call_type = "delegatecall" if "delegatecall" in func_name else ("send" if "send" in func_name else "call")
                        elif ir_type == "HighLevelCall":
                            call_type = "interface"
                        elif ir_type == "Transfer":
                            call_type = "transfer"
                        elif ir_type == "Send":
                            call_type = "send"
                        
                        if call_type:
                            external_call_events.append((1, idx, call_type, f"{ir_type}::{str(ir)[:80]}"))
                        
                        # Indirect writes via InternalCall
                        if ir_type == "InternalCall":
                            target_func = getattr(ir, "function", None)
                            if target_func:
                                target_contract = getattr(target_func, "contract_declarer", None) or getattr(target_func, "contract", None)
                                if target_contract:
                                    target_id = f"{target_contract.name}::{target_func.name}"
                                    target_data = self.graph.nodes.get(target_id, {})
                                    if target_data.get("writes_state") or len(target_data.get("propagated_state_variables", [])) > 0:
                                        state_write_events.append((1, idx))

                    # Direct writes
                    if hasattr(cfg_node, "state_variables_written") and cfg_node.state_variables_written:
                        state_write_events.append((1, idx))

            # Phase 2: Modifiers POST (Reverse order)
            for m_idx, mod_name in enumerate(reversed(applied_modifiers)):
                mod_node_id = f"{contract_name}::modifier::{mod_name}"
                mod_data = self.graph.nodes.get(mod_node_id, {})
                if not mod_data: continue
                
                post_seg = mod_data.get("post_segment", {})
                for call in post_seg.get("external_calls", []):
                    external_call_events.append((2, m_idx * 1000 + call["idx"], call["type"], call["desc"]))
                for w_idx in post_seg.get("direct_writes", []):
                    state_write_events.append((2, m_idx * 1000 + w_idx))
                for icall in post_seg.get("internal_calls", []):
                    target_data = self.graph.nodes.get(icall["target_id"], {})
                    if target_data.get("writes_state") or len(target_data.get("propagated_state_variables", [])) > 0:
                        state_write_events.append((2, m_idx * 1000 + icall["idx"]))

            # --- CEI Violation Detection ---
            makes_external_call = len(external_call_events) > 0
            state_write_after = False
            
            if makes_external_call and state_write_events:
                # Find the very first external call coordinate
                first_call_coord = min((ev[0], ev[1]) for ev in external_call_events)
                
                # Check if ANY state write coordinate is > first_call_coord
                for write_coord in state_write_events:
                    if write_coord > first_call_coord:
                        state_write_after = True
                        break

            # Attach results
            node_data["makes_external_call"] = makes_external_call
            node_data["external_call_nodes"] = [ev[3] for ev in external_call_events]
            node_data["external_call_type"] = sorted(list(set(ev[2] for ev in external_call_events)))
            node_data["state_write_after_external_call"] = state_write_after

    # ================================================================
    # Story 3.4 — Deterministic Reentrancy Rule
    # ================================================================
    def _detect_reentrancy_risks(self):
        """
        Combines structural properties to identify reentrancy-vulnerable functions.
        
        A function F is reentrancy-risk if:
        1. reachable_from_external_entry == True (Attackable surface)
        2. makes_external_call == True (Interactions)
        3. propagated_state_variables not empty (Effects)
        4. state_write_after_external_call == True (Structural Violation)
        
        Note: The user requested 'external_call_before_state_write', which is 
        equivalent to our 'state_write_after_external_call'.
        
        Attaches:
        - reentrancy_risk: bool
        - reentrancy_risk_score: int
        """
        for node_id, node_data in self.graph.nodes(data=True):
            if node_data.get("type") != "function":
                continue
            
            is_reachable = node_data.get("reachable_from_external_entry", False)
            makes_call = node_data.get("makes_external_call", False)
            has_state_vars = len(node_data.get("propagated_state_variables", [])) > 0
            has_violation = node_data.get("state_write_after_external_call", False)
            
            is_risk = is_reachable and makes_call and has_state_vars and has_violation
            
            score = 0
            if is_risk:
                # Base score for matching the structural vulnerability pattern
                score = 10
                # Increase score based on the number of state variables written (impact)
                score += 2 * len(node_data.get("propagated_state_variables", []))
            
            node_data["reentrancy_risk"] = is_risk
            node_data["reentrancy_risk_score"] = score

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
