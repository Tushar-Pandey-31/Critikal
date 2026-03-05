import networkx as nx
import json
import re
from collections import deque
from slither.slither import Slither
from slither.core.cfg.node import NodeType
from typing import Dict, Any, List
from src.economic_analyzer import EconomicAnalyzer
from src.pattern_scanner import scan_all_sources, get_pattern_summary, PatternHit

ENABLE_CROSS_CONTRACT_EDGES = True

class GraphBuilder:
    def __init__(self):
        self.graph = nx.DiGraph()
        self._file_cache: dict[str, str] = {}
        self._inheritance_modifier_cache: dict[str, dict[str, Any]] = {}

    def _read_file_cached(self, path: str) -> str:
        """Read a file with caching to avoid re-reading the same .sol file for every function."""
        if path not in self._file_cache:
            with open(path, "r", encoding="utf-8") as f:
                self._file_cache[path] = f.read()
        return self._file_cache[path]

    @staticmethod
    def _is_library_contract(contract) -> bool:
        """Return True if a contract lives inside a lib/ or node_modules/ dependency tree."""
        try:
            if contract.source_mapping and contract.source_mapping.filename:
                src = str(contract.source_mapping.filename.absolute).replace("\\", "/")
                if "/lib/" in src or "/node_modules/" in src:
                    return True
        except Exception:
            pass
        return False

    def build_graph(self, slither_obj: Slither):
        """
        Iterates through the Slither object and constructs the Knowledge Graph.
        Library contracts (under lib/ or node_modules/) are added as lightweight
        nodes for reference but excluded from expensive enrichment passes.
        """
        project_contracts = []
        lib_count = 0

        for contract in slither_obj.contracts:
            is_lib = self._is_library_contract(contract)
            self._add_contract_node(contract)
            self._add_inheritance_edges(contract)

            if is_lib:
                lib_count += 1
                continue

            project_contracts.append(contract)

            for function in contract.functions:
                self._add_function_node(contract, function)
                self._add_edge_defines(contract, function)
                self._add_call_edges(contract, function)
                self._add_state_access_edges(contract, function)
                self._add_cross_contract_call_edges(contract, function)

        if lib_count:
            print(f"  [GraphBuilder] Skipped {lib_count} library contracts from enrichment (kept as reference nodes).")
        
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
        # Improvement 2A: Read-only reentrancy risk detection
        self._detect_read_only_reentrancy_risk()
        
        self._detect_privileged_roles()
        # NOTE: _detect_unprotected_mutators runs early for initial flag setting.
        # _recompute_unprotected_mutator_status runs later after all AC enrichments.
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
        
        # Dev Story 1: Inline Guard & Access Pattern Precision Layer
        self._classify_modifier_equivalence()
        self._detect_initializer_guards(slither_obj)
        self._detect_require_access_control(slither_obj)

        # AC Refactor — Parts 3, 4: Additional AC enrichment
        self._detect_internal_guard_calls(slither_obj)
        self._detect_external_role_registry_guards()

        # AC Refactor — Part 7: SSA-aware confidence dampening
        self._apply_ssa_confidence_dampening(slither_obj)

        # AC Refactor — Part 8: Governance classification
        self._classify_governance_contracts()

        # AC Refactor — Part 1: Recompute unprotected mutator status
        # AFTER all AC enrichments (Parts 2-5, 7-8).
        self._recompute_unprotected_mutator_status()

        # Dev Story 2: Inter-Procedural Taint & Dataflow Engine
        self._tag_storage_sensitivity()
        self._compute_taint_propagation(slither_obj)

        # Dev Story 3: Cross-Function State Transition Modeling
        self._build_state_dependency_graph()
        self._detect_dangerous_sequences()
        self._generate_exploit_chains()

        # Dev Story 4: Accounting & Invariant Heuristics Engine
        self._run_accounting_invariant_heuristics()

        # Dev Story 6: External Call Risk Analyzer
        self._analyze_external_call_risks()

        # Dev Story 1: Precision upgrade — negative safety evidence
        self._compute_negative_safety_signals()

        # Titan Pattern Engine: broad-spectrum regex hits validated by graph
        self._integrate_pattern_hits()

        # Story 4.2: Compute final risk scores
        self._compute_global_risk_scores()
        # Dev Story 5: Exploit Target Scoring Engine
        self._compute_exploit_target_scores()

        self._file_cache.clear()


    def _add_contract_node(self, contract):
        node_id = contract.name
        source_file = ""
        try:
            if contract.source_mapping and contract.source_mapping.filename:
                source_file = str(contract.source_mapping.filename.absolute)
        except Exception:
            pass
        metadata = {
            "type": "contract",
            "name": contract.name,
            "is_upgradeable": contract.is_upgradeable,
            "is_library": getattr(contract, "is_library", False),
            "is_interface": getattr(contract, "is_interface", False),
            "source_file": source_file,
        }
        self.graph.add_node(node_id, **metadata)

    def _add_function_node(self, contract, function):
        node_id = f"{contract.name}::{function.name}"
        
        source_code = ""
        source_file = ""
        start_line = 0
        end_line = 0
        if function.source_mapping:
            try:
                src_mapping = function.source_mapping
                abs_path = str(src_mapping.filename.absolute)
                source_file = abs_path
                content = self._read_file_cached(abs_path)
                source_code = content[src_mapping.start:src_mapping.start + src_mapping.length]
                # Calculate line numbers manually
                start_line = content[:src_mapping.start].count('\n') + 1
                end_line = start_line + source_code.count('\n')
            except Exception:
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
            "source_file": source_file,
            "source_start_line": start_line,
            "source_end_line": end_line,
            "modifiers": modifiers,
            "signature": signature or "",
            "access_control_confidence": 0.0,
            "has_internal_guard_call": False,
            "has_external_role_guard": False,
            "governance_design_choice": False,
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

    def _add_cross_contract_call_edges(self, contract, function):
        if not ENABLE_CROSS_CONTRACT_EDGES:
            return
            
        caller_id = f"{contract.name}::{function.name}"
        if not self.graph.has_node(caller_id):
            return
            
        for call in function.high_level_calls:
            if getattr(call, "__class__", None) is tuple or isinstance(call, tuple):
                if len(call) == 2:
                    target_contract, target_func = call
                    if hasattr(target_contract, "name"):
                        t_cname = target_contract.name
                        if self.graph.has_node(t_cname) and hasattr(target_func, "name"):
                            target_id = f"{t_cname}::{target_func.name}"
                            if self.graph.has_node(target_id):
                                self.graph.add_edge(caller_id, target_id, type="CROSS_CONTRACT_CALL")
                                self.graph.nodes[target_id]["reachable_from_cross_contract"] = True

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
            if self._is_library_contract(contract):
                continue
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
        # Build inheritance-aware modifier resolution cache (Part 2)
        self._inheritance_modifier_cache = {}  # contract_name -> {mod_name: pattern}

        # Phase 2a: Populate cache from ALL Slither contracts (including lib/).
        # Bug 1 fix: graph modifier nodes only exist for project contracts —
        # lib contracts (OwnableUpgradeable, ReentrancyGuard, etc.) are skipped
        # by _is_library_contract() in build_graph.  Without this loop,
        # _resolve_modifiers_with_inheritance returns ("none", False) for
        # inherited OZ modifiers, causing false-positive unprotected mutators.
        for contract in slither_obj.contracts:
            for modifier in contract.modifiers:
                if contract.name not in self._inheritance_modifier_cache:
                    self._inheritance_modifier_cache[contract.name] = {}
                if modifier.name not in self._inheritance_modifier_cache[contract.name]:
                    conditions = self._extract_modifier_conditions(modifier)
                    accessed_vars = [
                        f"{sv.contract.name}::{sv.name}"
                        for sv in modifier.state_variables_read
                    ]
                    pattern = self._classify_modifier_pattern(conditions, accessed_vars)
                    self._inheritance_modifier_cache[contract.name][modifier.name] = pattern

        # Phase 2b: Override with graph-derived data (richer for project contracts
        # since graph nodes have full segment analysis).
        for node_id, node_data in self.graph.nodes(data=True):
            if node_data.get("type") == "modifier":
                mod_contract = node_data.get("contract", "")
                mod_name = node_data.get("name", "")
                pattern = node_data.get("access_control_pattern", "none")
                self._inheritance_modifier_cache.setdefault(mod_contract, {})[mod_name] = pattern
        
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
            contract_name = node_data.get("contract", "")
            
            # Resolve modifiers through inheritance chain (Part 2)
            resolved = self._resolve_modifiers_with_inheritance(contract_name, applied_modifiers)
            ac_modifiers = [m for m, (pat, _) in resolved.items() if pat != "none"]
            has_access_control = len(ac_modifiers) > 0
            
            # Compute confidence: 1.0 for local, 0.9 for inherited
            mod_confidence = 0.0
            if has_access_control:
                has_local = any(resolved[m][1] for m in ac_modifiers)
                mod_confidence = 1.0 if has_local else 0.9
            
            # Detect inline require(msg.sender == X) via Slither IR
            slither_func = slither_func_lookup.get(node_id)
            has_inline_check = self._detect_inline_access_check(node_id, node_data, slither_func)
            
            is_protected = has_access_control or has_inline_check
            
            # Compute confidence from best source
            if has_inline_check and not has_access_control:
                ac_confidence = 0.95
            elif has_access_control and has_inline_check:
                ac_confidence = max(mod_confidence, 0.95)
            elif has_access_control:
                ac_confidence = mod_confidence
            else:
                ac_confidence = 0.0
            
            # Attach FunctionAccessProfile
            self._update_access_control(node_id, 
                has_access_control=has_access_control,
                ac_modifiers=ac_modifiers,
                has_inline_check=has_inline_check,
                is_protected=is_protected,
                confidence=ac_confidence)

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
    
    # ================================================================
    # Centralized Access Control Update Helper (Part 6)
    # ================================================================

    def _update_access_control(self, node_id: str, *,
                                has_access_control: bool = None,
                                ac_modifiers: list = None,
                                has_inline_check: bool = None,
                                is_protected: bool = None,
                                confidence: float = None,
                                ac_type: str = None):
        """
        Centralized helper — all access control updates flow through here.
        Only overwrites fields that are explicitly provided (not None).
        Confidence uses max() semantics: new confidence only applies if higher.
        """
        nd = self.graph.nodes[node_id]
        if has_access_control is not None:
            nd["has_access_control"] = has_access_control
        if ac_modifiers is not None:
            nd["access_control_modifiers"] = ac_modifiers
        if has_inline_check is not None:
            nd["has_inline_access_check"] = has_inline_check
        if is_protected is not None:
            nd["is_protected"] = nd.get("is_protected", False) or is_protected
        if confidence is not None:
            nd["access_control_confidence"] = max(
                nd.get("access_control_confidence", 0.0), confidence
            )
        if ac_type is not None:
            existing = nd.get("access_control_type", "none")
            if existing == "none":
                nd["access_control_type"] = ac_type
            elif existing != ac_type and ac_type != "none":
                nd["access_control_type"] = "both"

    # ================================================================
    # Part 2 — Inheritance-Aware Modifier Resolution
    # ================================================================

    def _resolve_modifiers_with_inheritance(self, contract_name: str,
                                            applied_modifiers: List[str]) -> Dict[str, tuple]:
        """
        BFS over INHERITS edges to resolve modifier definitions from parent
        contracts.  Returns {modifier_name: (pattern, is_local)} where
        is_local=True when the modifier is defined directly on contract_name.
        Uses self._inheritance_modifier_cache built during Phase 2 setup.
        """
        if not applied_modifiers:
            return {}

        result = {}
        needed = set(applied_modifiers)

        # Check local contract first
        local_mods = self._inheritance_modifier_cache.get(contract_name, {})
        for m in list(needed):
            if m in local_mods:
                result[m] = (local_mods[m], True)   # is_local = True
                needed.discard(m)

        if not needed:
            return result

        # BFS through INHERITS edges
        visited = {contract_name}
        queue = deque()
        # Collect parents of contract_name
        for _, parent, edata in self.graph.out_edges(contract_name, data=True):
            if edata.get("relationship") == "INHERITS" and parent not in visited:
                queue.append(parent)
                visited.add(parent)

        while queue and needed:
            parent = queue.popleft()
            parent_mods = self._inheritance_modifier_cache.get(parent, {})
            for m in list(needed):
                if m in parent_mods:
                    result[m] = (parent_mods[m], False)  # is_local = False (inherited)
                    needed.discard(m)

            # Continue BFS to grandparents
            for _, gp, edata in self.graph.out_edges(parent, data=True):
                if edata.get("relationship") == "INHERITS" and gp not in visited:
                    queue.append(gp)
                    visited.add(gp)

        # Any remaining unresolved → treat as none
        for m in needed:
            result[m] = ("none", False)

        return result

    # ================================================================
    # Part 3 — Internal Guard Function Detection
    # ================================================================

    _GUARD_NAME_RE = re.compile(
        r'^_?(require|check|only|assert|verify|ensure|validate)'
        r'(Admin|Owner|Role|Auth|Caller|Sender|Gov|Operator|Manager|Guardian|Pauser)',
        re.IGNORECASE
    )

    def _detect_internal_guard_calls(self, slither_obj: Slither):
        """
        Two-phase internal guard detection.
        Phase 1: Identify guard functions (internal/private with AC logic).
        Phase 2: Propagate guard status to callers via CALLS edges.
        """
        guard_functions: set = set()

        # Phase 1 — identify guard functions
        for node_id, data in self.graph.nodes(data=True):
            if data.get("type") != "function":
                continue
            vis = data.get("visibility", "")
            if vis not in ("internal", "private"):
                continue

            is_guard = False
            func_name = data.get("name", "")
            source = data.get("source_code", "")

            # Name-based heuristic
            if self._GUARD_NAME_RE.match(func_name):
                is_guard = True

            # Body analysis: contains require/assert/revert referencing msg.sender
            if not is_guard and source:
                has_sender = "msg.sender" in source
                has_check = ("require(" in source or "revert" in source
                             or "assert(" in source)
                if has_sender and has_check:
                    is_guard = True

            if is_guard:
                guard_functions.add(node_id)
                data["is_guard_function"] = True

        # Phase 2 — propagate to callers via CALLS edges
        for node_id, data in self.graph.nodes(data=True):
            if data.get("type") != "function":
                continue
            for _, callee, edata in self.graph.out_edges(node_id, data=True):
                if edata.get("relationship") == "CALLS" and callee in guard_functions:
                    data["has_internal_guard_call"] = True
                    self._update_access_control(
                        node_id,
                        is_protected=True,
                        confidence=0.85,
                        ac_type="internal-guard",
                    )
                    break  # one guard callee is enough

        # Phase 1b — Bug 3 fix: detect guard calls from Slither IR for
        # functions calling guards in lib contracts that don't have graph
        # nodes. Mirrors _add_call_edges pattern for consistency.
        for contract in slither_obj.contracts:
            for function in contract.functions:
                func_node_id = f"{contract.name}::{function.name}"
                if not self.graph.has_node(func_node_id):
                    continue
                if self.graph.nodes[func_node_id].get("has_internal_guard_call"):
                    continue  # already detected in Phase 2

                for internal_call in function.internal_calls:
                    # Slither 0.10.x: internal_calls returns raw
                    # Function/Modifier objects. Check contract_declarer
                    # or contract to confirm it's a function-like object.
                    target_func = None
                    if hasattr(internal_call, "contract_declarer") or hasattr(internal_call, "contract"):
                        target_func = internal_call
                    else:
                        target_func = getattr(internal_call, "function", None)

                    if not target_func or not hasattr(target_func, "name"):
                        continue

                    callee_name = target_func.name
                    if self._GUARD_NAME_RE.match(callee_name):
                        self.graph.nodes[func_node_id]["has_internal_guard_call"] = True
                        self._update_access_control(
                            func_node_id,
                            is_protected=True,
                            confidence=0.85,
                            ac_type="internal-guard",
                        )
                        break

    # ================================================================
    # Part 4 — External Role Registry Classification
    # ================================================================

    _ROLE_CALL_SIGS = re.compile(
        r'(hasRole|getRoleMember|canCall|isOperator|checkRole|'
        r'_checkRole|onlyRole|hasPermission)\s*\(',
        re.IGNORECASE
    )
    _ROLE_TARGET_KEYWORDS = re.compile(
        r'(role|auth|access|registry|acl|permission)',
        re.IGNORECASE
    )

    def _detect_external_role_registry_guards(self):
        """
        Scans EXTERNAL_CALL edges for role-checking signatures.
        Cross-checks that the call appears inside a require/assert/revert
        context in the function source.
        """
        for node_id, data in self.graph.nodes(data=True):
            if data.get("type") != "function":
                continue

            source = data.get("source_code", "")
            has_require_context = bool(
                source and ("require(" in source or "revert" in source
                            or "assert(" in source)
            )

            for _, target, edata in self.graph.out_edges(node_id, data=True):
                if edata.get("relationship") != "EXTERNAL_CALL":
                    continue

                call_desc = str(edata.get("call_expression", ""))
                target_expr = str(edata.get("target_expression", ""))

                sig_match = self._ROLE_CALL_SIGS.search(call_desc)
                target_match = self._ROLE_TARGET_KEYWORDS.search(target_expr)

                if (sig_match or target_match) and has_require_context:
                    data["has_external_role_guard"] = True
                    self._update_access_control(
                        node_id,
                        is_protected=True,
                        confidence=0.80,
                        ac_type="external-role",
                    )
                    break  # one role-registry call is enough

    # ================================================================
    # Part 7 — SSA-Aware Confidence Dampening
    # ================================================================

    def _apply_ssa_confidence_dampening(self, slither_obj: Slither):
        """
        Detect contracts where Slither SSA conversion failed.
        For all functions in those contracts, dampen access_control_confidence
        by a factor of 0.7.
        """
        ssa_failed_contracts: set = set()

        for contract in slither_obj.contracts:
            c_name = contract.name
            c_node = self.graph.nodes.get(c_name, {})
            if c_node.get("type") != "contract":
                continue

            # Detect SSA failure: check if contract has modifiers but none
            # have parsed conditions (IR was empty).
            # Bug 2 fix: use Slither objects (not graph nodes) to also check
            # lib modifiers. If ANY modifier matches _MODIFIER_EQUIVALENCE_MAP,
            # its empty conditions are expected (OZ 4.x delegation pattern),
            # NOT an SSA failure.
            has_modifier_nodes = False
            all_empty_ir = True
            has_known_semantic_mod = False
            for node_id, data in self.graph.nodes(data=True):
                if data.get("type") == "modifier" and data.get("contract") == c_name:
                    has_modifier_nodes = True
                    if data.get("conditions"):
                        all_empty_ir = False
                        break

            # Check Slither objects for known semantic modifiers (including lib/)
            for slither_contract in slither_obj.contracts:
                if slither_contract.name != c_name:
                    # Also check parent contracts in the inheritance chain
                    if c_name not in [p.name for p in slither_contract.inheritance]:
                        continue
                for modifier in slither_contract.modifiers:
                    mod_name = modifier.name
                    for _cat, _pats in self._MODIFIER_EQUIVALENCE_MAP.items():
                        for _pat in _pats:
                            if _pat.search(mod_name):
                                has_known_semantic_mod = True
                                break
                        if has_known_semantic_mod:
                            break
                    if has_known_semantic_mod:
                        break
                if has_known_semantic_mod:
                    break

            # If modifiers exist but all have empty IR AND none are
            # known semantic modifiers → SSA likely failed
            if has_modifier_nodes and all_empty_ir and not has_known_semantic_mod:
                ssa_failed_contracts.add(c_name)
                c_node["ssa_available"] = False
            else:
                c_node["ssa_available"] = True

        if not ssa_failed_contracts:
            return

        # Dampen confidence for functions in SSA-failed contracts
        for node_id, data in self.graph.nodes(data=True):
            if data.get("type") != "function":
                continue
            if data.get("contract", "") in ssa_failed_contracts:
                current_conf = data.get("access_control_confidence", 0.0)
                data["access_control_confidence"] = current_conf * 0.7

    # ================================================================
    # Part 8 — Governance Classification
    # ================================================================

    _GOVERNANCE_PARENT_CONTRACTS = frozenset([
        "Governor", "GovernorCompatibilityBravo", "TimelockController",
        "GovernorTimelockControl", "GovernorCountingSimple",
        "GovernorVotes", "GovernorVotesQuorumFraction",
        "GovernorSettings", "GovernorTimelockCompound",
    ])
    _GOVERNANCE_KEYWORDS = re.compile(
        r'(quorum|votingPeriod|proposalThreshold|castVote|castVoteBySig'
        r'|proposalDeadline|proposalSnapshot|COUNTING_MODE'
        r'|timelockDelay|queue|execute|cancel)',
        re.IGNORECASE
    )

    def _classify_governance_contracts(self):
        """
        Detects governance contracts via inheritance patterns and keyword heuristics.
        Tags functions that write ACCESS_CRITICAL variables under governance protection
        as governance_design_choice.
        """
        governance_contracts: set = set()

        for node_id, data in self.graph.nodes(data=True):
            if data.get("type") != "contract":
                continue

            c_name = data.get("name", "")
            is_gov = False

            # Check inheritance
            for _, parent, edata in self.graph.out_edges(node_id, data=True):
                if edata.get("relationship") == "INHERITS":
                    if parent in self._GOVERNANCE_PARENT_CONTRACTS:
                        is_gov = True
                        break

            # Check keyword heuristic in contract name + function names
            if not is_gov:
                keyword_count = 0
                if self._GOVERNANCE_KEYWORDS.search(c_name):
                    keyword_count += 1
                for fn_id, fn_data in self.graph.nodes(data=True):
                    if fn_data.get("type") == "function" and fn_data.get("contract") == c_name:
                        fn_source = fn_data.get("source_code", "")
                        fn_name = fn_data.get("name", "")
                        if self._GOVERNANCE_KEYWORDS.search(fn_name):
                            keyword_count += 1
                        if self._GOVERNANCE_KEYWORDS.search(fn_source):
                            keyword_count += 1
                        if keyword_count >= 3:
                            is_gov = True
                            break

            if is_gov:
                governance_contracts.add(c_name)
                data["is_governance_contract"] = True

        if not governance_contracts:
            return

        # Tag functions that write ACCESS_CRITICAL under governance AC
        for node_id, data in self.graph.nodes(data=True):
            if data.get("type") != "function":
                continue

            contract = data.get("contract", "")
            ac_type = data.get("access_control_type", "none")
            ac_conf = data.get("access_control_confidence", 0.0)

            # Function is in or protected by a governance contract
            func_under_gov = (
                contract in governance_contracts
                or ac_type in ("modifier", "require-based", "both")
            )
            if not func_under_gov:
                continue

            # Check if it writes ACCESS_CRITICAL variables
            writes_access_critical = False
            for tw in data.get("tainted_state_writes", []):
                for tag in tw.get("sensitivity", []):
                    if tag == "ACCESS_CRITICAL":
                        writes_access_critical = True
                        break
                if writes_access_critical:
                    break

            # Also check sensitivity tags from storage tagging
            for _, target, edata in self.graph.out_edges(node_id, data=True):
                if edata.get("relationship") != "WRITES":
                    continue
                target_data = self.graph.nodes.get(target, {})
                if target_data.get("sensitivity_tag") == "ACCESS_CRITICAL":
                    writes_access_critical = True
                    break

            if writes_access_critical and ac_conf >= 0.8:
                data["governance_design_choice"] = True

    # ================================================================
    # Part 1 — Recompute Unprotected Mutator Status
    # ================================================================

    def _recompute_unprotected_mutator_status(self):
        """
        Re-evaluate is_unprotected_mutator AFTER all AC enrichments.
        Clears the flag if any form of access control was detected.
        """
        for node_id, data in self.graph.nodes(data=True):
            if data.get("type") != "function":
                continue
            if not data.get("is_unprotected_mutator", False):
                continue

            ac_type = data.get("access_control_type", "none")
            protected_types = ("modifier", "require-based", "both",
                               "internal-guard", "external-role")

            effectively_protected = (
                ac_type in protected_types
                or data.get("has_internal_guard_call", False)
                or data.get("has_external_role_guard", False)
                or data.get("access_control_confidence", 0.0) >= 0.8
            )

            if effectively_protected:
                data["is_unprotected_mutator"] = False
                data["unprotected_risk_level"] = "NONE"

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
    
    # Compiled regex patterns for custom error / revert access control detection (Part 5)
    _REVERT_AC_PATTERNS = [
        re.compile(r'if\s*\(\s*msg\.sender\s*!=', re.IGNORECASE),
        re.compile(r'if\s*\(\s*\w+\s*!=\s*msg\.sender', re.IGNORECASE),
        re.compile(r'if\s*\(\s*!\s*\w+\[msg\.sender\]', re.IGNORECASE),
        re.compile(r'revert\s+(Unauthorized|NotOwner|NotAdmin|AccessDenied|Forbidden|OnlyOwner|OnlyAdmin|NotAuthorized)\s*\(', re.IGNORECASE),
    ]

    def _detect_inline_access_check(self, node_id: str, node_data: Dict, slither_func=None) -> bool:
        """
        Detects inline require(msg.sender == X) patterns in function body.
        Uses Slither IR as primary detection, with source code regex fallback.
        Also detects custom error / revert patterns (Part 5).
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
        
        # Fallback: source code regex (original patterns)
        source = node_data.get("source_code", "")
        if source:
            if re.search(r'require\s*\(\s*msg\.sender\s*==', source):
                return True
            if re.search(r'require\s*\(\s*\w+\s*==\s*msg\.sender', source):
                return True
            # Part 5: Custom error / revert pattern detection
            for pat in self._REVERT_AC_PATTERNS:
                if pat.search(source):
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
    # Improvement 2A — Read-Only Reentrancy Risk Detection
    # ================================================================
    def _detect_read_only_reentrancy_risk(self):
        """
        Detects read-only reentrancy risk: functions that make staticcall/view
        external calls AND write accounting-sensitive state, creating a window
        where external readers can observe stale prices.

        Read-only reentrancy is distinct from classical reentrancy (which
        requires call/delegatecall).  A staticcall cannot modify state, but
        it CAN return stale values mid-transaction.  If the caller writes
        accounting-critical state (totalSupply, totalAssets, share prices)
        *after* the staticcall, an attacker can sandwich-read the stale
        value via a re-entrant path.

        Attaches:
          - read_only_reentrancy_risk: bool
        """
        _ACCOUNTING_SENSITIVE_TAGS = frozenset([
            "ACCOUNTING_CRITICAL", "CAP_CRITICAL",
        ])

        for node_id, node_data in self.graph.nodes(data=True):
            if node_data.get("type") != "function":
                continue

            # Condition 1: has a staticcall / view-interface external call
            has_staticcall = False
            for _, _, edge_data in self.graph.out_edges(node_id, data=True):
                if edge_data.get("relationship") != "EXTERNAL_CALL":
                    continue
                ct = edge_data.get("call_type", "")
                if ct == "staticcall":
                    has_staticcall = True
                    break
                # Interface calls to view/pure targets also count
                if ct == "interface":
                    target_expr = str(edge_data.get("target_expression", ""))
                    call_desc = str(edge_data.get("call_desc", ""))
                    # Heuristic: if call name contains view-like patterns
                    for view_kw in ("getPrice", "getReserve", "totalSupply",
                                    "balanceOf", "getRate", "exchangeRate",
                                    "convertToAssets", "convertToShares",
                                    "previewDeposit", "previewMint",
                                    "previewWithdraw", "previewRedeem"):
                        if view_kw.lower() in call_desc.lower() or view_kw.lower() in target_expr.lower():
                            has_staticcall = True
                            break
                    if has_staticcall:
                        break

            if not has_staticcall:
                node_data["read_only_reentrancy_risk"] = False
                continue

            # Condition 2: writes accounting-sensitive state
            writes_sensitive = False

            # Check direct flags from _detect_arithmetic_patterns
            if (node_data.get("writes_total_supply")
                    or node_data.get("writes_total_assets")
                    or node_data.get("mints_shares_proportionally")
                    or node_data.get("updates_reward_index")):
                writes_sensitive = True

            # Check tainted state writes with sensitive tags
            if not writes_sensitive:
                for tw in node_data.get("tainted_state_writes", []):
                    for tag in tw.get("sensitivity", []):
                        if tag in _ACCOUNTING_SENSITIVE_TAGS:
                            writes_sensitive = True
                            break
                    if writes_sensitive:
                        break

            # Check WRITES edges to variables tagged as accounting-sensitive
            if not writes_sensitive:
                for _, target, edata in self.graph.out_edges(node_id, data=True):
                    if edata.get("relationship") != "WRITES":
                        continue
                    target_data = self.graph.nodes.get(target, {})
                    if target_data.get("sensitivity_tag") in _ACCOUNTING_SENSITIVE_TAGS:
                        writes_sensitive = True
                        break

            node_data["read_only_reentrancy_risk"] = has_staticcall and writes_sensitive

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
            if self._is_library_contract(contract):
                continue
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
                            content = self._read_file_cached(str(sm.filename.absolute))
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
    # Dev Story 1 — Inline Guard & Access Pattern Precision Layer
    # ================================================================

    # Patterns that represent initializer guards in require/if-revert form.
    _INIT_GUARD_PATTERNS = [
        re.compile(r'require\s*\(\s*!\s*initialized\b'),
        re.compile(r'require\s*\(\s*initialized\s*==\s*false\b'),
        re.compile(r'require\s*\(\s*!_initialized\b'),
        re.compile(r'require\s*\(\s*_initialized\s*==\s*false\b'),
        re.compile(r'require\s*\(\s*!_initializing\b'),
        re.compile(r'if\s*\(\s*initialized\s*\)\s*revert\b'),
        re.compile(r'if\s*\(\s*_initialized\b[^)]*\)\s*revert\b'),
        re.compile(r'require\s*\(\s*initializing\s*==\s*0\b'),
        re.compile(r'require\s*\(\s*_initialized\s*==\s*0\b'),
        re.compile(r'require\s*\(\s*_initialized\s*<\s'),
        # Compound / Cream Finance inline accounting guard (Dev Story 1 / Fix)
        re.compile(r'accrualBlockNumber\s*==\s*0'),
        re.compile(r'borrowIndex\s*==\s*0'),
        re.compile(r'market may only be initialized once', re.IGNORECASE),
        re.compile(r'only admin may initialize the market', re.IGNORECASE),
    ]

    # Modifier names that semantically map to known categories.
    _MODIFIER_EQUIVALENCE_MAP = {
        "owner": [
            re.compile(r'only\s*owner', re.IGNORECASE),
            re.compile(r'only_owner', re.IGNORECASE),
            re.compile(r'onlyGovernance', re.IGNORECASE),
            re.compile(r'onlyGuardian', re.IGNORECASE),
            re.compile(r'onlyAuthority', re.IGNORECASE),
        ],
        "admin": [
            re.compile(r'only\s*admin', re.IGNORECASE),
            re.compile(r'onlyRole', re.IGNORECASE),
            re.compile(r'onlyMinter', re.IGNORECASE),
            re.compile(r'onlyOperator', re.IGNORECASE),
            re.compile(r'onlyManager', re.IGNORECASE),
        ],
        "initializer": [
            re.compile(r'^initializer$', re.IGNORECASE),
            re.compile(r'^reinitializer$', re.IGNORECASE),
            re.compile(r'onlyInitializing', re.IGNORECASE),
        ],
        "reentrancy_guard": [
            re.compile(r'^nonReentrant$', re.IGNORECASE),
            re.compile(r'^noReentrancy$', re.IGNORECASE),
            re.compile(r'reentrancyGuard', re.IGNORECASE),
            re.compile(r'^lock$', re.IGNORECASE),
        ],
    }

    def _detect_initializer_guards(self, slither_obj: Slither):
        """
        Dev Story 1.1 — Detects inline initializer guards in function bodies.
        Also checks one level of callees to catch super.initialize() patterns.
        """
        slither_func_lookup: Dict[str, Any] = {}
        for contract in slither_obj.contracts:
            for function in contract.functions:
                fid = f"{contract.name}::{function.name}"
                slither_func_lookup[fid] = function

        for node_id, node_data in self.graph.nodes(data=True):
            if node_data.get("type") != "function":
                continue

            has_guard = False
            
            # 1. Collect sources (self + one level of callees)
            sources = []
            sources.append(node_data.get("source_code", ""))
            
            # Check internal calls (Story 3.1 CALLS edges)
            for _, target, edge_data in self.graph.out_edges(node_id, data=True):
                if edge_data.get("relationship") == "CALLS":
                    callee_data = self.graph.nodes.get(target, {})
                    if callee_data:
                        sources.append(callee_data.get("source_code", ""))
            
            combined_source = "\n".join(sources)

            # 2. IR-based detection within the main function
            slither_func = slither_func_lookup.get(node_id)
            if slither_func:
                try:
                    for cfg_node in slither_func.nodes:
                        if has_guard:
                            break
                        for ir in cfg_node.irs:
                            ir_str = str(ir).lower()
                            if 'require(bool' not in ir_str and 'assert(bool' not in ir_str:
                                continue
                            expr_str = str(cfg_node.expression) if cfg_node.expression else str(ir)
                            expr_lower = expr_str.lower()
                            # Check for both standard and Compound patterns in IR/Expression
                            if any(kw in expr_lower for kw in ("initialized", "_initialized", "initializing", "_initializing", "accrualblocknumber", "borrowindex")):
                                has_guard = True
                                break
                except Exception:
                    pass

            # 3. Source-code fallback: regex patterns on combined source
            if not has_guard and combined_source:
                for pat in self._INIT_GUARD_PATTERNS:
                    if pat.search(combined_source):
                        has_guard = True
                        break

            node_data["has_initializer_guard"] = has_guard

            is_protected_original = node_data.get("is_protected", False)
            has_init_modifier = node_data.get("has_initializer_modifier", False)
            safe_init = has_guard and (is_protected_original or has_init_modifier)
            node_data["safe_init_pattern"] = safe_init
            
            # If a guard is found, update protection status and remove from unprotected mutators
            # (Dev Story 1 / Step 3 Fix)
            if has_guard:
                node_data["is_protected"] = True
                node_data["is_unprotected_mutator"] = False
                node_data["unprotected_risk_level"] = "NONE"

    def _detect_require_access_control(self, slither_obj: Slither):
        """
        Dev Story 1.2 — Detects require-based access control in function bodies.

        Detects patterns like:
            require(msg.sender == owner);
            require(hasRole(X, msg.sender));
            require(_isAdmin(msg.sender));

        Traces the comparison target to a storage variable when possible.

        Sets on function nodes:
            access_control_type: "modifier" | "require-based" | "both" | "none"
            require_access_control_targets: List[str]  (storage variables compared)
        """
        slither_func_lookup: Dict[str, Any] = {}
        for contract in slither_obj.contracts:
            for function in contract.functions:
                fid = f"{contract.name}::{function.name}"
                slither_func_lookup[fid] = function

        for node_id, node_data in self.graph.nodes(data=True):
            if node_data.get("type") != "function":
                continue

            has_modifier_ac = node_data.get("has_access_control", False)
            require_targets: list[str] = []
            has_require_ac = False

            slither_func = slither_func_lookup.get(node_id)
            contract_name = node_data.get("contract", "")

            if slither_func:
                try:
                    for cfg_node in slither_func.nodes:
                        for ir in cfg_node.irs:
                            ir_str = str(ir).lower()
                            if 'require(bool' not in ir_str and 'assert(bool' not in ir_str:
                                continue
                            expr_str = str(cfg_node.expression) if cfg_node.expression else str(ir)
                            if 'msg.sender' not in expr_str:
                                continue

                            has_require_ac = True

                            # Extract the comparison target
                            target = self._extract_compared_variable(expr_str)
                            if target:
                                # Trace to storage variable
                                var_id = f"{contract_name}::{target}"
                                if self.graph.has_node(var_id):
                                    require_targets.append(var_id)
                                else:
                                    for nid, ndata in self.graph.nodes(data=True):
                                        if (ndata.get("type") == "state_variable"
                                                and ndata.get("name") == target):
                                            require_targets.append(nid)
                                            break
                                    else:
                                        require_targets.append(target)

                            # Also detect function-call-style checks
                            if not target:
                                call_patterns = [
                                    r'hasRole\s*\(', r'_isAdmin\s*\(',
                                    r'isOwner\s*\(', r'_checkRole\s*\(',
                                    r'_checkOwner\s*\(', r'onlyRole\s*\(',
                                    r'_requireAuth\s*\(',
                                ]
                                for cp in call_patterns:
                                    if re.search(cp, expr_str):
                                        has_require_ac = True
                                        require_targets.append(f"__role_check::{cp.split('(')[0].strip('\\s*')}")
                                        break
                except Exception:
                    pass

            # Source-code fallback
            if not has_require_ac:
                source = node_data.get("source_code", "")
                if source and 'msg.sender' in source:
                    sender_patterns = [
                        r'require\s*\(\s*msg\.sender\s*==\s*(\w+)',
                        r'require\s*\(\s*(\w+)\s*==\s*msg\.sender',
                        r'if\s*\(\s*msg\.sender\s*!=\s*(\w+)',
                    ]
                    for pat in sender_patterns:
                        m = re.search(pat, source)
                        if m:
                            has_require_ac = True
                            target = m.group(1)
                            if target:
                                var_id = f"{contract_name}::{target}"
                                if self.graph.has_node(var_id):
                                    require_targets.append(var_id)
                                else:
                                    require_targets.append(target)
                            break
                    if not has_require_ac:
                        call_patterns = [
                            r'require\s*\(\s*hasRole\s*\(',
                            r'require\s*\(\s*_isAdmin\s*\(',
                            r'require\s*\(\s*isOwner\s*\(',
                        ]
                        for pat in call_patterns:
                            if re.search(pat, source):
                                has_require_ac = True
                                break

            # Determine composite access_control_type
            if has_modifier_ac and has_require_ac:
                ac_type = "both"
            elif has_modifier_ac:
                ac_type = "modifier"
            elif has_require_ac:
                ac_type = "require-based"
            else:
                ac_type = "none"

            # Update is_protected to include require-based checks
            if has_require_ac and not node_data.get("is_protected"):
                node_data["is_protected"] = True
                node_data["has_inline_access_check"] = True

            node_data["access_control_type"] = ac_type
            node_data["require_access_control_targets"] = sorted(set(require_targets))

    def _classify_modifier_equivalence(self):
        """
        Dev Story 1.3 — Maps modifier names to semantic categories.

        Categories: "owner", "admin", "initializer", "reentrancy_guard"

        Sets on modifier nodes:
            semantic_category: str  (one of the categories, or "custom")

        Sets on function nodes:
            modifier_equivalences: Dict[str, str]  (modifier_name -> category)
            has_reentrancy_guard: bool
            has_initializer_modifier: bool
        """
        # Phase 1: Classify each modifier node
        for node_id, node_data in self.graph.nodes(data=True):
            if node_data.get("type") != "modifier":
                continue

            mod_name = node_data.get("name", "")
            category = "custom"

            for cat, patterns in self._MODIFIER_EQUIVALENCE_MAP.items():
                for pat in patterns:
                    if pat.search(mod_name):
                        category = cat
                        break
                if category != "custom":
                    break

            # Secondary classification from modifier body conditions
            if category == "custom":
                conditions = node_data.get("conditions", [])
                for cond in conditions:
                    if cond.get("checks_msg_sender"):
                        category = "owner"
                        break

            node_data["semantic_category"] = category

        # Phase 2: Build modifier equivalence lookup per contract
        modifier_categories: Dict[str, str] = {}
        for node_id, node_data in self.graph.nodes(data=True):
            if node_data.get("type") == "modifier":
                modifier_categories[node_data.get("name", "")] = node_data.get("semantic_category", "custom")

        # Phase 3: Enrich function nodes
        for node_id, node_data in self.graph.nodes(data=True):
            if node_data.get("type") != "function":
                continue

            applied_mods = node_data.get("modifiers", [])
            equivalences: Dict[str, str] = {}
            has_reentrancy_guard = False
            has_init_modifier = False

            for mod_name in applied_mods:
                cat = modifier_categories.get(mod_name, None)
                # Bug 4 fix: if modifier not in graph (lib contract),
                # fall back to name-based matching against
                # _MODIFIER_EQUIVALENCE_MAP
                if cat is None:
                    cat = "custom"
                    for category, patterns in self._MODIFIER_EQUIVALENCE_MAP.items():
                        for pat in patterns:
                            if pat.search(mod_name):
                                cat = category
                                break
                        if cat != "custom":
                            break
                equivalences[mod_name] = cat
                if cat == "reentrancy_guard":
                    has_reentrancy_guard = True
                if cat == "initializer":
                    has_init_modifier = True

            node_data["modifier_equivalences"] = equivalences
            node_data["has_reentrancy_guard"] = has_reentrancy_guard
            node_data["has_initializer_modifier"] = has_init_modifier

    # ================================================================
    # Dev Story 2 — Inter-Procedural Taint & Dataflow Engine
    # ================================================================

    _SENSITIVITY_PATTERNS: Dict[str, List[str]] = {
        "ACCOUNTING_CRITICAL": [
            "totalSupply", "totalBorrow", "totalBorrows", "totalDebt",
            "balance", "balances", "totalBalance", "reserve", "reserves",
            "exchangeRate", "borrowIndex", "supplyIndex", "accrued",
            "debt", "totalAssets", "totalShares", "totalStaked",
            "totalDeposits", "accountBorrows", "totalCash",
            "interestIndex", "borrowRate", "supplyRate", "totalReserves",
            "shares", "assets",
        ],
        "ACCESS_CRITICAL": [
            "owner", "_owner", "admin", "governance", "authority",
            "operator", "pendingOwner", "roles", "minters", "guardian",
            "comptroller", "paused", "pauseGuardian",
        ],
        "CAP_CRITICAL": [
            "cap", "maxSupply", "supplyCap", "borrowCap", "maxDeposit",
            "maxMint", "ceiling", "limit", "threshold", "maxBorrow",
            "mintCap", "maxWithdraw", "collateralFactor",
        ],
        "REWARD_CRITICAL": [
            "rewardRate", "rewardPerToken", "rewardPerBlock", "rewards",
            "earned", "accRewardPerShare", "bonusMultiplier",
            "emissionRate", "compRate", "compSpeeds", "compAccrued",
            "rewardIndex",
        ],
        "LIQUIDITY_CRITICAL": [
            "totalLiquidity", "poolBalance", "sqrtPrice", "liquidity",
            "tickLower", "tickUpper", "fee", "feeGrowth",
            "protocolFees", "kLast",
        ],
    }

    def _tag_storage_sensitivity(self):
        """
        Dev Story 2.3 — Classifies state variables into sensitivity categories.

        Tags state variable nodes with:
            sensitivity_tags:  List[str]
            sensitivity_tag:   str | None  (primary)
            is_sensitive:      bool
        """
        for node_id, node_data in self.graph.nodes(data=True):
            if node_data.get("type") != "state_variable":
                continue

            var_name = node_data.get("name", "")
            var_lower = var_name.lower()

            tags: list[str] = []
            for category, patterns in self._SENSITIVITY_PATTERNS.items():
                for pattern in patterns:
                    if pattern.lower() == var_lower or pattern.lower() in var_lower:
                        tags.append(category)
                        break

            node_data["sensitivity_tags"] = tags
            node_data["sensitivity_tag"] = tags[0] if tags else None
            node_data["is_sensitive"] = len(tags) > 0
            node_data["tainted"] = False
            node_data["taint_sources"] = []
            node_data["tainted_by_functions"] = []

    def _compute_taint_propagation(self, slither_obj: Slither):
        """
        Dev Story 2.2-2.4 — Full inter-procedural taint tracking engine.

        Phase 1: Intra-procedural taint per function using Slither IR
        Phase 2: Inter-procedural propagation via call graph (fixed-point)
        Phase 3: Tag state variables as tainted
        Phase 4: Vulnerability heuristic detection
        """
        slither_func_lookup: Dict[str, Any] = {}
        for contract in slither_obj.contracts:
            for function in contract.functions:
                fid = f"{contract.name}::{function.name}"
                slither_func_lookup[fid] = function

        # Phase 1: Intra-procedural taint
        func_taint: Dict[str, Dict] = {}
        for node_id, node_data in self.graph.nodes(data=True):
            if node_data.get("type") != "function":
                continue
            slither_func = slither_func_lookup.get(node_id)
            if slither_func:
                result = self._analyze_function_taint(node_id, node_data, slither_func)
            else:
                result = self._taint_from_source_code(node_id, node_data)
            func_taint[node_id] = result

        # Phase 2: Inter-procedural propagation
        self._propagate_taint_interprocedural(func_taint, slither_func_lookup)

        # Phase 3: Mark state variables as tainted
        self._mark_tainted_state_variables(func_taint)

        # Phase 4: Vulnerability heuristics & graph attribute setting
        self._apply_taint_vulnerability_heuristics(func_taint)

    # ── Phase 1: Intra-procedural taint (IR-based) ────────────

    def _analyze_function_taint(
        self, node_id: str, node_data: Dict, slither_func
    ) -> Dict[str, Any]:
        """
        Tracks taint through a single function's Slither IR.

        Taint sources: function parameters (for public/external),
        msg.sender, msg.value, tx.origin, external call return values.
        """
        tainted: set[str] = set()
        source_types: list[str] = []
        tainted_writes: list[Dict] = []
        unchecked_ext_returns: list[str] = []
        param_to_taint: Dict[str, set] = {}
        uses_tainted_math = False

        vis = str(getattr(slither_func, "visibility", "internal"))
        contract_name = node_data.get("contract", "")

        # Seed: function parameters for public/external functions
        if vis in ("public", "external"):
            for param in slither_func.parameters:
                pname = str(getattr(param, "name", ""))
                if pname:
                    tainted.add(pname)
                    tag = f"param:{pname}"
                    source_types.append(tag)
                    param_to_taint[pname] = {tag}

        # Walk CFG nodes and propagate taint
        try:
            cfg_nodes = slither_func.nodes
        except Exception:
            cfg_nodes = []

        for cfg_node in cfg_nodes:
            for ir in cfg_node.irs:
                ir_str = str(ir)
                ir_type = type(ir).__name__

                # External call return values are taint sources
                if ir_type in ("HighLevelCall", "LowLevelCall"):
                    lvalue = getattr(ir, "lvalue", None)
                    if lvalue:
                        lv_name = str(lvalue)
                        tainted.add(lv_name)
                        if "ext_return" not in source_types:
                            source_types.append("ext_return")

                        # Track unchecked return: check if it's later validated
                        rv_checked = self._is_return_value_validated(
                            ir, slither_func, cfg_node
                        )
                        if not rv_checked:
                            unchecked_ext_returns.append(lv_name)

                # Track arithmetic operations with tainted variables
                if ir_type == "Binary":
                    op_type = getattr(ir, "type", None)
                    if op_type:
                        op_name = getattr(op_type, "name", "")
                        if op_name in ("MULTIPLICATION", "DIVISION", "POWER", "ADDITION", "SUBTRACTION"):
                            used = getattr(ir, "used", None) or []
                            if any(str(v) in tainted for v in used if v is not None):
                                uses_tainted_math = True

                # msg.sender / msg.value / tx.origin as taint sources
                for src_name, src_tag in (
                    ("msg.sender", "msg.sender"),
                    ("msg.value", "msg.value"),
                    ("tx.origin", "tx.origin"),
                ):
                    if src_name in ir_str:
                        lvalue = getattr(ir, "lvalue", None)
                        if lvalue:
                            tainted.add(str(lvalue))
                            if src_tag not in source_types:
                                source_types.append(src_tag)

                # Taint propagation: if any used variable is tainted → lvalue tainted
                used = getattr(ir, "used", None) or []
                reads_tainted = any(
                    str(v) in tainted for v in used if v is not None
                )
                if reads_tainted:
                    lvalue = getattr(ir, "lvalue", None)
                    if lvalue:
                        tainted.add(str(lvalue))

            # Check state variable writes from this CFG node
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

                # Does this write use tainted data?
                write_tainted = False
                for ir in cfg_node.irs:
                    used = getattr(ir, "used", None) or []
                    if any(str(v) in tainted for v in used if v is not None):
                        write_tainted = True
                        break

                if write_tainted:
                    var_data = self.graph.nodes.get(var_node_id, {})
                    sensitivity = var_data.get("sensitivity_tags", [])
                    tainted_writes.append({
                        "variable": var_node_id,
                        "source_types": list(source_types),
                        "sensitivity": sensitivity,
                        "paths": [[node_id]],
                    })

        return {
            "taint_sources": source_types,
            "tainted_writes": tainted_writes,
            "tainted_vars": tainted,
            "unchecked_ext_returns": unchecked_ext_returns,
            "param_to_taint": param_to_taint,
            "taint_paths": [[node_id]],
            "uses_tainted_math": uses_tainted_math,
        }

    def _is_return_value_validated(self, call_ir, slither_func, call_node) -> bool:
        """Checks if an external call's return value is validated by require/assert."""
        lvalue = getattr(call_ir, "lvalue", None)
        if not lvalue:
            return True
        track_vars = {str(lvalue).lower()}
        passed_call = False
        try:
            for node in slither_func.nodes:
                for ir_op in node.irs:
                    if ir_op is call_ir:
                        passed_call = True
                        continue
                    if not passed_call:
                        continue
                    op_str = str(ir_op)
                    op_lower = op_str.lower()
                    if type(ir_op).__name__ == "Unpack":
                        tuple_var = getattr(ir_op, "tuple", None)
                        if tuple_var and str(tuple_var).lower() in track_vars:
                            unpacked = getattr(ir_op, "lvalue", None)
                            if unpacked:
                                track_vars.add(str(unpacked).lower())
                    if "require(bool" in op_lower or "assert(bool" in op_lower:
                        for tv in track_vars:
                            if tv in op_lower:
                                return True
        except Exception:
            pass
        return False

    # ── Phase 1 fallback: source-code based taint ─────────────

    def _taint_from_source_code(
        self, node_id: str, node_data: Dict
    ) -> Dict[str, Any]:
        """
        Source-code fallback when Slither IR is unavailable.
        Uses regex heuristics to detect taint sources flowing into state writes.
        """
        source = node_data.get("source_code", "")
        vis = node_data.get("visibility", "internal")
        source_types: list[str] = []
        tainted_writes: list[Dict] = []
        contract_name = node_data.get("contract", "")

        if not source or vis not in ("public", "external"):
            return {
                "taint_sources": [],
                "tainted_writes": [],
                "tainted_vars": set(),
                "unchecked_ext_returns": [],
                "param_to_taint": {},
                "taint_paths": [[node_id]],
                "uses_tainted_math": False,
            }

        if "msg.value" in source:
            source_types.append("msg.value")
        if "msg.sender" in source:
            source_types.append("msg.sender")
        if "tx.origin" in source:
            source_types.append("tx.origin")

        # Extract parameter names from source
        param_match = re.search(
            r'function\s+\w+\s*\(([^)]*)\)', source
        )
        param_names: set[str] = set()
        if param_match:
            param_str = param_match.group(1)
            for chunk in param_str.split(","):
                parts = chunk.strip().split()
                if len(parts) >= 2:
                    pname = parts[-1].strip()
                    param_names.add(pname)
                    source_types.append(f"param:{pname}")

        # Check if taint sources appear in state-modifying expressions
        state_vars_written = node_data.get("state_variables_written", [])
        for var_id in state_vars_written:
            var_data = self.graph.nodes.get(var_id, {})
            var_name = var_data.get("name", var_id.split("::")[-1])
            if var_name in source:
                for pname in param_names:
                    if pname in source:
                        sensitivity = var_data.get("sensitivity_tags", [])
                        tainted_writes.append({
                            "variable": var_id,
                            "source_types": list(source_types),
                            "sensitivity": sensitivity,
                            "paths": [[node_id]],
                        })
                        break
                else:
                    if "msg.value" in source:
                        sensitivity = var_data.get("sensitivity_tags", [])
                        tainted_writes.append({
                            "variable": var_id,
                            "source_types": list(source_types),
                            "sensitivity": sensitivity,
                            "paths": [[node_id]],
                        })

        return {
            "taint_sources": source_types,
            "tainted_writes": tainted_writes,
            "tainted_vars": param_names | {"msg.value", "msg.sender"} if source_types else set(),
            "unchecked_ext_returns": [],
            "param_to_taint": {p: {f"param:{p}"} for p in param_names},
            "taint_paths": [[node_id]],
            "uses_tainted_math": False,
        }

    # ── Phase 2: Inter-procedural propagation ─────────────────

    def _propagate_taint_interprocedural(
        self,
        func_taint: Dict[str, Dict],
        slither_func_lookup: Dict[str, Any],
    ):
        """
        Fixed-point propagation of taint across CALLS edges.

        If function A calls function B with a tainted argument,
        B's corresponding parameter inherits A's taint, and B is
        re-analyzed with the expanded taint set. Return values
        propagate taint backwards.

        Limits to 4 iterations to bound cost on large call graphs.
        """
        MAX_ITERATIONS = 4

        for iteration in range(MAX_ITERATIONS):
            changed = False

            for node_id, node_data in self.graph.nodes(data=True):
                if node_data.get("type") != "function":
                    continue

                caller_result = func_taint.get(node_id)
                if not caller_result:
                    continue
                caller_tainted = caller_result.get("tainted_vars", set())
                if not caller_tainted:
                    continue

                # Find callees via CALLS edges
                for _, target_id, edge_data in self.graph.out_edges(node_id, data=True):
                    if edge_data.get("relationship") != "CALLS":
                        continue
                    target_data = self.graph.nodes.get(target_id, {})
                    if target_data.get("type") != "function":
                        continue

                    callee_result = func_taint.get(target_id)
                    if not callee_result:
                        continue

                    # Try to match tainted args → callee parameters via IR
                    slither_caller = slither_func_lookup.get(node_id)
                    slither_callee = slither_func_lookup.get(target_id)
                    if not slither_caller or not slither_callee:
                        # Heuristic: if caller is tainted and callee writes state,
                        # propagate caller's source types
                        if caller_result["taint_sources"] and callee_result.get("tainted_writes") is not None:
                            new_sources = set(callee_result["taint_sources"])
                            before = len(new_sources)
                            for st in caller_result["taint_sources"]:
                                new_sources.add(st)
                                
                            paths_changed = False
                            for cp in caller_result.get("taint_paths", [[node_id]]):
                                np = cp + [target_id]
                                if np not in callee_result.setdefault("taint_paths", []):
                                    callee_result["taint_paths"].append(np)
                                    paths_changed = True

                            if len(new_sources) > before or paths_changed:
                                callee_result["taint_sources"] = list(new_sources)
                                for tw in callee_result["tainted_writes"]:
                                    for p in callee_result["taint_paths"]:
                                        if p not in tw.setdefault("paths", []):
                                            tw["paths"].append(p)
                                changed = True
                        continue

                    # IR-level argument matching
                    injected = self._inject_caller_taint(
                        slither_caller, slither_callee,
                        caller_result, callee_result, target_id,
                        target_data, node_id
                    )
                    if injected:
                        changed = True

            if not changed:
                break

    def _inject_caller_taint(
        self,
        slither_caller,
        slither_callee,
        caller_result: Dict,
        callee_result: Dict,
        callee_node_id: str,
        callee_node_data: Dict,
        caller_node_id: str,
    ) -> bool:
        """
        Scans caller's IR for InternalCall operations targeting callee.
        If any argument is tainted, marks the corresponding callee
        parameter as tainted and re-derives callee's tainted writes.

        Returns True if callee's taint set expanded.
        """
        callee_name = callee_node_data.get("name", "")
        callee_contract = callee_node_data.get("contract", "")
        callee_tainted = callee_result.get("tainted_vars", set())
        caller_tainted = caller_result.get("tainted_vars", set())
        original_size = len(callee_tainted)
        injected_params: set[str] = set()

        try:
            for cfg_node in slither_caller.nodes:
                for ir in cfg_node.irs:
                    if type(ir).__name__ != "InternalCall":
                        continue
                    target_func = getattr(ir, "function", None)
                    if not target_func:
                        continue
                    if getattr(target_func, "name", "") != callee_name:
                        continue
                    tc = (getattr(target_func, "contract_declarer", None)
                          or getattr(target_func, "contract", None))
                    if tc and tc.name != callee_contract:
                        continue

                    arguments = getattr(ir, "arguments", []) or []
                    params = list(slither_callee.parameters)
                    for i, arg in enumerate(arguments):
                        if str(arg) in caller_tainted and i < len(params):
                            pname = str(getattr(params[i], "name", ""))
                            if pname and pname not in callee_tainted:
                                callee_tainted.add(pname)
                                injected_params.add(pname)
        except Exception:
            pass

        if not injected_params:
            return False

        # Propagate new taint sources
        for pname in injected_params:
            if f"cross:{pname}" not in callee_result["taint_sources"]:
                callee_result["taint_sources"].append(f"cross:{pname}")

        paths_changed = False
        for cp in caller_result.get("taint_paths", [[caller_node_id]]):
            np = cp + [callee_node_id]
            if np not in callee_result.setdefault("taint_paths", []):
                callee_result["taint_paths"].append(np)
                paths_changed = True

        paths_expanded = paths_changed
        if len(callee_tainted) > original_size:
            paths_expanded = True

        # Re-derive tainted writes for the callee with expanded taint
        slither_callee_func = None
        try:
            for cfg_node in slither_callee.nodes:
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
                    for ir in cfg_node.irs:
                        used = getattr(ir, "used", None) or []
                        if any(str(v) in callee_tainted for v in used if v is not None):
                            var_data = self.graph.nodes.get(var_node_id, {})
                            already_idx = -1
                            for idx, tw in enumerate(callee_result["tainted_writes"]):
                                if tw["variable"] == var_node_id:
                                    already_idx = idx
                                    break

                            if already_idx == -1:
                                callee_result["tainted_writes"].append({
                                    "variable": var_node_id,
                                    "source_types": list(callee_result["taint_sources"]),
                                    "sensitivity": var_data.get("sensitivity_tags", []),
                                    "paths": list(callee_result["taint_paths"]),
                                })
                            else:
                                tw = callee_result["tainted_writes"][already_idx]
                                for p in callee_result["taint_paths"]:
                                    if p not in tw.setdefault("paths", []):
                                        tw["paths"].append(p)
                            break
        except Exception:
            pass

        return paths_expanded

    # ── Phase 3: Mark state variables as tainted ──────────────

    def _mark_tainted_state_variables(self, func_taint: Dict[str, Dict]):
        """Marks state variable nodes as tainted based on function analysis."""
        for func_id, result in func_taint.items():
            for tw in result.get("tainted_writes", []):
                var_id = tw["variable"]
                var_data = self.graph.nodes.get(var_id)
                if not var_data:
                    continue
                var_data["tainted"] = True
                existing_sources = set(var_data.get("taint_sources", []))
                existing_sources.update(tw.get("source_types", []))
                var_data["taint_sources"] = sorted(existing_sources)
                funcs = var_data.get("tainted_by_functions", [])
                if func_id not in funcs:
                    funcs.append(func_id)
                var_data["tainted_by_functions"] = funcs

    # ── Phase 4: Vulnerability heuristics ─────────────────────

    _SENSITIVITY_TO_RISK = {
        "ACCOUNTING_CRITICAL": "TAINT_ACCOUNTING_RISK",
        "ACCESS_CRITICAL": "TAINT_ACCESS_RISK",
        "CAP_CRITICAL": "TAINT_CAP_BYPASS",
        "REWARD_CRITICAL": "TAINT_REWARD_RISK",
        "LIQUIDITY_CRITICAL": "TAINT_LIQUIDITY_RISK",
    }

    def _apply_taint_vulnerability_heuristics(self, func_taint: Dict[str, Dict]):
        """
        Detects vulnerability patterns from taint analysis results and
        sets graph attributes on function nodes.

        Produces risk types:
            TAINT_CRITICAL_PATH   — tainted data reaches any sensitive storage
            TAINT_ACCOUNTING_RISK — tainted data influences accounting state
            TAINT_CAP_BYPASS      — tainted data influences cap/limit checks
            TAINT_REWARD_RISK     — tainted data used in reward calculation
            TAINT_ACCESS_RISK     — tainted data modifies access control state
            TAINT_LIQUIDITY_RISK  — tainted data influences liquidity state
            UNCHECKED_EXT_RETURN  — external call return used without validation
            TAINTED_MATH_RISK     — arithmetic operations on tainted data
        """
        # Gather all paths by their entry function to assign cross-function paths correctly
        all_paths_by_entry: Dict[str, list[Dict]] = {fid: [] for fid in func_taint.keys()}

        for sink_id, result in func_taint.items():
            for tw in result.get("tainted_writes", []):
                for path in tw.get("paths", [[sink_id]]):
                    entry_func = path[0]
                    if entry_func in all_paths_by_entry:
                        existing = all_paths_by_entry[entry_func]
                        new_path = {
                            "source_types": tw["source_types"],
                            "sink_variable": tw["variable"],
                            "sensitivity": tw.get("sensitivity", []),
                            "sink_function": sink_id,
                            "path": path,
                        }
                        if new_path not in existing:
                            existing.append(new_path)

        for node_id, node_data in self.graph.nodes(data=True):
            if node_data.get("type") != "function":
                continue

            result = func_taint.get(node_id, {})
            tainted_writes = result.get("tainted_writes", [])
            taint_sources = result.get("taint_sources", [])
            unchecked = result.get("unchecked_ext_returns", [])
            uses_tainted_math = result.get("uses_tainted_math", False)

            risk_types: list[str] = []
            critical_paths: list[Dict] = []
            taint_score = 0

            for tw in tainted_writes:
                var_id = tw["variable"]
                sensitivity_tags = tw.get("sensitivity", [])

                if sensitivity_tags:
                    if "TAINT_CRITICAL_PATH" not in risk_types:
                        risk_types.append("TAINT_CRITICAL_PATH")

                    for stag in sensitivity_tags:
                        risk_type = self._SENSITIVITY_TO_RISK.get(stag)
                        if risk_type and risk_type not in risk_types:
                            risk_types.append(risk_type)

                    for path in tw.get("paths", [[node_id]]):
                        cp = {
                            "source_types": tw["source_types"],
                            "sink_variable": var_id,
                            "sensitivity": sensitivity_tags,
                            "function": node_id,
                            "path": path,
                        }
                        if cp not in critical_paths:
                            critical_paths.append(cp)

            # Add paths where THIS function is the entry point
            cross_paths = all_paths_by_entry.get(node_id, [])
            for cp in cross_paths:
                if len(cp["path"]) > 1:
                    if cp not in critical_paths:
                        critical_paths.append(cp)
                    if "TAINT_CRITICAL_PATH" not in risk_types:
                        risk_types.append("TAINT_CRITICAL_PATH")
                    for stag in cp.get("sensitivity", []):
                        risk_type = self._SENSITIVITY_TO_RISK.get(stag)
                        if risk_type and risk_type not in risk_types:
                            risk_types.append(risk_type)

            # Score taint risk based on what categories are hit
            if "TAINT_ACCOUNTING_RISK" in risk_types:
                taint_score += 45
            if "TAINT_CAP_BYPASS" in risk_types:
                taint_score += 40
            if "TAINT_REWARD_RISK" in risk_types:
                taint_score += 35
            if "TAINT_ACCESS_RISK" in risk_types:
                taint_score += 50
            if "TAINT_LIQUIDITY_RISK" in risk_types:
                taint_score += 35

            if uses_tainted_math:
                risk_types.append("TAINTED_MATH_RISK")
                # Heavy score increase for math + taint
                taint_score += 50
                if "TAINT_ACCOUNTING_RISK" in risk_types or "TAINT_REWARD_RISK" in risk_types:
                    taint_score += 30

            if unchecked:
                risk_types.append("UNCHECKED_EXT_RETURN")
                taint_score += 25

            node_data["taint_sources"] = taint_sources
            node_data["tainted_state_writes"] = tainted_writes
            node_data["taint_risk_types"] = risk_types
            node_data["taint_critical_paths"] = critical_paths
            node_data["has_taint_risk"] = len(risk_types) > 0
            node_data["taint_risk_score"] = taint_score
            node_data["unchecked_external_return"] = len(unchecked) > 0
            node_data["cross_function_taint_paths"] = [p for p in cross_paths if len(p.get("path", [])) > 1]

    # ================================================================
    # Dev Story 3 — Cross-Function State Transition Modeling
    # ================================================================

    def _build_state_dependency_graph(self):
        """
        Dev Story 3.1 — Builds cross-function state dependency edges.

        For each pair of functions (A, B) in the same contract where
        A writes to variable X and B reads from variable X, creates
        a STATE_DEPENDENCY edge:  A --STATE_DEPENDENCY--> B

        Edge properties:
            shared_variables:    List[str]  — variable IDs linking them
            dependency_type:     str        — "write_read" | "write_write"
            sensitivity_overlap: List[str]  — sensitivity tags of shared vars

        Also sets on each function node:
            state_dependencies_out: List[Dict]  — functions this one can influence
            state_dependencies_in:  List[Dict]  — functions that can influence this one
            shared_state_variables: List[str]   — all variables in any dependency
        """
        func_reads: Dict[str, set] = {}
        func_writes: Dict[str, set] = {}
        func_contracts: Dict[str, str] = {}

        for node_id, node_data in self.graph.nodes(data=True):
            if node_data.get("type") != "function":
                continue
            func_contracts[node_id] = node_data.get("contract", "")
            reads: set[str] = set()
            writes: set[str] = set()

            for _, target, edge_data in self.graph.out_edges(node_id, data=True):
                rel = edge_data.get("relationship")
                target_data = self.graph.nodes.get(target, {})
                if target_data.get("type") != "state_variable":
                    continue
                if rel == "READS":
                    reads.add(target)
                elif rel == "WRITES":
                    writes.add(target)

            # Include propagated writes for internal call chains
            for pv in node_data.get("propagated_state_variables", []):
                writes.add(pv)

            func_reads[node_id] = reads
            func_writes[node_id] = writes

        deps_out: Dict[str, list] = {fid: [] for fid in func_reads}
        deps_in: Dict[str, list] = {fid: [] for fid in func_reads}
        shared_vars: Dict[str, set] = {fid: set() for fid in func_reads}

        func_ids = list(func_reads.keys())
        for i, writer_id in enumerate(func_ids):
            writer_contract = func_contracts[writer_id]
            writer_writes = func_writes[writer_id]
            if not writer_writes:
                continue

            for reader_id in func_ids:
                if writer_id == reader_id:
                    continue
                if func_contracts[reader_id] != writer_contract:
                    continue

                # write → read dependencies
                wr_shared = writer_writes & func_reads[reader_id]
                # write → write dependencies (race / ordering)
                ww_shared = writer_writes & func_writes[reader_id]

                all_shared = wr_shared | ww_shared
                if not all_shared:
                    continue

                sensitivity_overlap: list[str] = []
                for var_id in all_shared:
                    for tag in self.graph.nodes.get(var_id, {}).get("sensitivity_tags", []):
                        if tag not in sensitivity_overlap:
                            sensitivity_overlap.append(tag)

                dep_type = "write_read" if wr_shared else "write_write"
                if wr_shared and ww_shared:
                    dep_type = "write_read_write"

                edge_key = f"__sd::{writer_id}::{reader_id}"
                if not self.graph.has_node(edge_key):
                    dep_info = {
                        "target": reader_id,
                        "shared_variables": sorted(all_shared),
                        "dependency_type": dep_type,
                        "sensitivity_overlap": sensitivity_overlap,
                    }
                    deps_out[writer_id].append(dep_info)
                    deps_in[reader_id].append({
                        "source": writer_id,
                        "shared_variables": sorted(all_shared),
                        "dependency_type": dep_type,
                        "sensitivity_overlap": sensitivity_overlap,
                    })
                    shared_vars[writer_id].update(all_shared)
                    shared_vars[reader_id].update(all_shared)

                    self.graph.add_edge(
                        writer_id, reader_id,
                        relationship="STATE_DEPENDENCY",
                        shared_variables=sorted(all_shared),
                        dependency_type=dep_type,
                        sensitivity_overlap=sensitivity_overlap,
                    )

        for fid in func_reads:
            data = self.graph.nodes.get(fid, {})
            data["state_dependencies_out"] = deps_out.get(fid, [])
            data["state_dependencies_in"] = deps_in.get(fid, [])
            data["shared_state_variables"] = sorted(shared_vars.get(fid, set()))

    def _detect_dangerous_sequences(self):
        """
        Dev Story 3.2 — Detects dangerous state manipulation sequences.

        A sequence is dangerous when:
          1. Function A (externally callable) writes to variable X
          2. Function B (externally callable) reads X in a sensitive operation
          3. No invariant guard exists between them (B is not protected, or
             X is sensitive and A is unprotected)

        Flags patterns:
            ACCOUNTING_MANIPULATION — A manipulates accounting state B depends on
            PRIVILEGE_CHAIN        — A modifies access var, B uses it for auth
            REWARD_INFLATION       — A inflates reward state, B claims rewards
            CAP_BYPASS_SEQUENCE    — A modifies cap state, B uses cap for checks
            INVARIANT_BREAK        — A and B write same variable without guard

        Sets on function nodes:
            dangerous_sequences: List[Dict]
            has_dangerous_sequence: bool
            sequence_risk_score: int
        """
        for node_id, node_data in self.graph.nodes(data=True):
            if node_data.get("type") != "function":
                continue

            sequences: list[Dict] = []
            seq_score = 0

            # Check outgoing STATE_DEPENDENCY edges
            for _, target_id, edge_data in self.graph.out_edges(node_id, data=True):
                if edge_data.get("relationship") != "STATE_DEPENDENCY":
                    continue

                writer_data = node_data
                reader_data = self.graph.nodes.get(target_id, {})

                # Both must be externally reachable for attacker exploitation
                writer_reachable = writer_data.get("reachable_from_external_entry", False)
                reader_reachable = reader_data.get("reachable_from_external_entry", False)
                if not (writer_reachable and reader_reachable):
                    continue

                shared = edge_data.get("shared_variables", [])
                sensitivity = edge_data.get("sensitivity_overlap", [])
                dep_type = edge_data.get("dependency_type", "write_read")

                writer_protected = writer_data.get("is_protected", False)
                reader_protected = reader_data.get("is_protected", False)

                # Determine sequence danger level
                danger_types: list[str] = []

                if "ACCOUNTING_CRITICAL" in sensitivity:
                    if not writer_protected:
                        danger_types.append("ACCOUNTING_MANIPULATION")
                    elif dep_type == "write_read" and not reader_protected:
                        danger_types.append("ACCOUNTING_MANIPULATION")

                if "ACCESS_CRITICAL" in sensitivity:
                    danger_types.append("PRIVILEGE_CHAIN")

                if "REWARD_CRITICAL" in sensitivity:
                    danger_types.append("REWARD_INFLATION")

                if "CAP_CRITICAL" in sensitivity:
                    danger_types.append("CAP_BYPASS_SEQUENCE")

                if dep_type in ("write_write", "write_read_write"):
                    both_external = (
                        writer_data.get("is_external_entry", False)
                        and reader_data.get("is_external_entry", False)
                    )
                    if both_external and not (writer_protected and reader_protected):
                        danger_types.append("INVARIANT_BREAK")

                # Non-sensitive shared state: still dangerous if writer unprotected
                if not danger_types and not writer_protected and sensitivity:
                    danger_types.append("UNGUARDED_STATE_INFLUENCE")

                if not danger_types:
                    continue

                score = 0
                for dt in danger_types:
                    score += {
                        "ACCOUNTING_MANIPULATION": 45,
                        "PRIVILEGE_CHAIN": 50,
                        "REWARD_INFLATION": 40,
                        "CAP_BYPASS_SEQUENCE": 40,
                        "INVARIANT_BREAK": 35,
                        "UNGUARDED_STATE_INFLUENCE": 20,
                    }.get(dt, 15)

                sequences.append({
                    "writer": node_id,
                    "reader": target_id,
                    "shared_variables": shared,
                    "sensitivity": sensitivity,
                    "danger_types": danger_types,
                    "writer_protected": writer_protected,
                    "reader_protected": reader_protected,
                    "score": score,
                })
                seq_score = max(seq_score, score)

            node_data["dangerous_sequences"] = sequences
            node_data["has_dangerous_sequence"] = len(sequences) > 0
            node_data["sequence_risk_score"] = seq_score

    def _generate_exploit_chains(self):
        """
        Dev Story 3.3 — Generates ordered exploit call chains for ExploitWriter.

        Walks STATE_DEPENDENCY edges to find multi-step attack flows:
            Step 1: Call A (manipulate state)
            Step 2: Call B (trigger dependent logic)
            Step 3: Call C (extract value / escalate)

        Chains are ordered by attack sequence and scored.

        Sets on function nodes:
            exploit_chains: List[Dict]   — full chain descriptions
            max_chain_length: int        — longest chain involving this function
            is_chain_entry: bool         — this function starts a chain
        """
        external_funcs = set()
        for node_id, node_data in self.graph.nodes(data=True):
            if node_data.get("type") != "function":
                continue
            if node_data.get("reachable_from_external_entry", False):
                external_funcs.add(node_id)

        all_chains: Dict[str, list] = {fid: [] for fid in external_funcs}

        for entry_id in external_funcs:
            entry_data = self.graph.nodes.get(entry_id, {})
            
            # Dev Story 2.2 — Storage Read/Write Temporal Model
            # A temporal taint exploit is: A writes tainted state, B reads it unprotected.
            # We hook into the dangerous sequences array.
            if entry_data.get("dangerous_sequences"):
                for seq in entry_data["dangerous_sequences"]:
                    writer_id = seq["writer"]
                    writer_data = self.graph.nodes.get(writer_id, {})
                    reader_id = seq["reader"]
                    reader_data = self.graph.nodes.get(reader_id, {})

                    # Taint injection: does the writer write tainted data to the shared variables?
                    if writer_data.get("has_taint_risk"):
                        shared = seq["shared_variables"]
                        for tw in writer_data.get("tainted_state_writes", []):
                            if tw["variable"] in shared:
                                # Found temporal taint exploit chain!
                                # If B reads this, it's dangerous.
                                # Check if B makes high-impact actions (writes state, external call)
                                b_writes = reader_data.get("writes_state", False)
                                b_unprotected = not reader_data.get("is_protected", False)
                                if b_writes or b_unprotected:
                                    if "TEMPORAL_TAINT_EXPLOIT" not in seq["danger_types"]:
                                        seq["danger_types"].append("TEMPORAL_TAINT_EXPLOIT")
                                        seq["score"] += 50
                                        entry_data["has_temporal_taint_exploit"] = True
                                        reader_data["has_temporal_taint_exploit"] = True

            if not entry_data.get("dangerous_sequences"):
                continue

            for seq in entry_data["dangerous_sequences"]:
                chain = self._extend_chain(
                    [entry_id, seq["reader"]],
                    seq["shared_variables"],
                    seq["sensitivity"],
                    seq["danger_types"],
                    external_funcs,
                    max_depth=4,
                )

                chain_score = seq["score"]
                # Bonus for longer chains (multi-step = harder to catch)
                if len(chain) >= 3:
                    chain_score += 15
                if len(chain) >= 4:
                    chain_score += 10

                matched_templates = self._match_exploit_templates(chain, seq["shared_variables"])
                adversarial_snapshots = self._generate_adversarial_snapshots(seq["shared_variables"])
                
                # Boost score if it matches a known high-severity bounty template
                if matched_templates:
                    chain_score += 25

                chain_desc = {
                    "steps": chain,
                    "shared_variables": seq["shared_variables"],
                    "sensitivity": seq["sensitivity"],
                    "danger_types": seq["danger_types"],
                    "chain_length": len(chain),
                    "chain_score": chain_score,
                    "matched_templates": matched_templates,
                    "adversarial_state_snapshots": adversarial_snapshots,
                    "exploit_sequence": self._format_exploit_sequence(chain),
                }

                self._evaluate_chain_feasibility(chain_desc)

                all_chains[entry_id].append(chain_desc)

        # Attach to function nodes
        for fid in external_funcs:
            data = self.graph.nodes.get(fid, {})
            chains = all_chains.get(fid, [])
            chains.sort(key=lambda c: c["chain_score"], reverse=True)
            # Keep top 5 chains per function to avoid bloat
            data["exploit_chains"] = chains[:5]
            data["max_chain_length"] = max((c["chain_length"] for c in chains), default=0)
            data["is_chain_entry"] = len(chains) > 0

    def _match_exploit_templates(self, chain: list[str], shared_vars: list[str]) -> list[str]:
        """
        Dev Story 3.1 — Matches discovered sequences against known state manipulation templates.
        Templates:
          - "Inflate -> Claim -> Withdraw"
          - "Deposit -> Manipulate Index -> Redeem"
          - "Set Role -> Upgrade -> Drain"
          - "Deposit small -> Trigger rounding -> Amplify"
        """
        if len(chain) < 2:
            return []
            
        templates = []
        chain_names = [self.graph.nodes.get(fid, {}).get("name", "").lower() for fid in chain]
        roles_assigned = [self.graph.nodes.get(fid, {}).get("modifies_sensitive_storage", False) for fid in chain]
        is_payable = [self.graph.nodes.get(fid, {}).get("is_payable", False) for fid in chain]
        has_math = [self.graph.nodes.get(fid, {}).get("uses_tainted_math", False) for fid in chain]

        # Template 1: Inflate -> Claim -> Withdraw
        # Look for math manipulation followed by a claim/withdraw action
        if any(m for m in has_math[:-1]) and any(n in ("withdraw", "claim") for n in chain_names[-1:]):
            templates.append("Inflate -> Claim -> Withdraw")

        # Template 2: Deposit -> Manipulate Index -> Redeem
        if any("deposit" in n for n in chain_names) and any(m for m in has_math) and any("redeem" in n or "withdraw" in n for n in chain_names):
            templates.append("Deposit -> Manipulate Index -> Redeem")

        # Template 3: Set Role -> Upgrade -> Drain
        # Look for access control var manipulated, followed by a risky call
        if any("grant" in n or "setrole" in n or "transferownership" in n for n in chain_names):
            if any(self.graph.nodes.get(fid, {}).get("can_escalate_privileges", False) for fid in chain):
                templates.append("Set Role -> Upgrade -> Drain")

        # Template 4: Deposit small -> Trigger rounding -> Amplify
        if any("deposit" in n for n in chain_names) and any(m for m in has_math):
            templates.append("Deposit small -> Trigger rounding -> Amplify")
            
        return list(set(templates))

    def _generate_adversarial_snapshots(self, shared_vars: list[str]) -> list[Dict[str, str]]:
        """
        Dev Story 3.2 — Generates adversarial state snapshots for specific variables.
        """
        snapshots = []
        for var_id in shared_vars:
            var_data = self.graph.nodes.get(var_id, {})
            name = var_data.get("name", "").lower()
            
            if "balance" in name or "amount" in name or "supply" in name:
                snapshots.extend([
                    {"variable": var_id, "state": "large (type(uint256).max)"},
                    {"variable": var_id, "state": "small (1 wei)"},
                    {"variable": var_id, "state": "zero (0)"},
                ])
            elif "reward" in name or "index" in name or "rate" in name:
                snapshots.extend([
                    {"variable": var_id, "state": "abnormally high"},
                    {"variable": var_id, "state": "abnormally low"},
                ])
            elif "cap" in name or "limit" in name or "max" in name:
                snapshots.extend([
                    {"variable": var_id, "state": "at or slightly above limit"},
                    {"variable": var_id, "state": "slightly below limit"},
                ])
        return snapshots

    def _extend_chain(
        self,
        current_chain: list[str],
        shared_vars: list[str],
        sensitivity: list[str],
        danger_types: list[str],
        external_funcs: set[str],
        max_depth: int,
    ) -> list[str]:
        """DFS extension of an exploit chain through STATE_DEPENDENCY edges."""
        if len(current_chain) >= max_depth:
            return current_chain

        last_func = current_chain[-1]
        best_extension = current_chain

        for _, next_id, edge_data in self.graph.out_edges(last_func, data=True):
            if edge_data.get("relationship") != "STATE_DEPENDENCY":
                continue
            if next_id in current_chain:
                continue
            if next_id not in external_funcs:
                continue

            next_data = self.graph.nodes.get(next_id, {})
            
            # Dev Story 3.3 - Filter nodes to prevent combinatorial explosion
            # Only extend if node is interesting (taint, sensitive write, high impact)
            is_interesting = (
                next_data.get("has_taint_risk", False) or
                next_data.get("modifies_sensitive_storage", False) or
                next_data.get("impact_score", 0) >= 20 or
                next_data.get("writes_state", False)
            )
            
            if not is_interesting:
                continue

            next_sensitivity = edge_data.get("sensitivity_overlap", [])
            if not next_sensitivity:
                continue

            extended = self._extend_chain(
                current_chain + [next_id],
                shared_vars,
                sensitivity + [s for s in next_sensitivity if s not in sensitivity],
                danger_types,
                external_funcs,
                max_depth,
            )
            if len(extended) > len(best_extension):
                best_extension = extended

        return best_extension

    def _format_exploit_sequence(self, chain: list[str]) -> list[Dict[str, str]]:
        """Formats a chain into step-by-step exploit instructions for ExploitWriter."""
        steps = []
        for i, func_id in enumerate(chain):
            func_data = self.graph.nodes.get(func_id, {})
            contract = func_data.get("contract", "")
            name = func_data.get("name", func_id)
            signature = func_data.get("signature", f"{name}()")
            visibility = func_data.get("visibility", "")
            is_payable = func_data.get("is_payable", False)

            if i == 0:
                role = "MANIPULATE"
                desc = "Manipulate state by calling"
            elif i == len(chain) - 1:
                role = "EXTRACT"
                desc = "Trigger dependent logic / extract value via"
            else:
                role = "INTERMEDIATE"
                desc = "Advance exploit state through"

            step = {
                "step": i + 1,
                "role": role,
                "description": f"{desc} {contract}.{signature}",
                "function_id": func_id,
                "contract": contract,
                "function_name": name,
                "signature": signature,
                "is_payable": is_payable,
            }
            steps.append(step)
        return steps

    def _evaluate_chain_feasibility(self, chain_desc: Dict) -> None:
        """
        Dev Story 7 — Feasibility Scoring Validator.
        Instead of hard dropping, assigns feasibility_score (0-1).
        If 0, chain is deterministically impossible.
        """
        score = 1.0
        steps = chain_desc.get("steps", [])
        if not steps:
            chain_desc["feasibility_score"] = 0.0
            chain_desc["is_deterministically_impossible"] = True
            return

        # 1. External Entry Verification
        has_reachable_attacker_entry = False
        for step in steps:
            node_data = self.graph.nodes.get(step, {})
            is_reachable = node_data.get("reachable_from_external_entry", False) or node_data.get("is_external_entry", False)
            has_attacker_influence = node_data.get("attacker_controlled_input", False) or node_data.get("has_taint_risk", False)
            if is_reachable and has_attacker_influence:
                has_reachable_attacker_entry = True
                break
        
        if not has_reachable_attacker_entry:
            chain_desc["feasibility_score"] = 0.0
            chain_desc["is_deterministically_impossible"] = True
            return
            
        # 2. Attacker-Controlled Origin
        first_step = steps[0]
        first_data = self.graph.nodes.get(first_step, {})
        has_influence = first_data.get("attacker_controlled_input", False) or first_data.get("has_taint_risk", False) or first_data.get("is_external_entry", False) or first_data.get("reachable_from_external_entry", False)
        if not has_influence:
            chain_desc["feasibility_score"] = 0.0
            chain_desc["is_deterministically_impossible"] = True
            return

        # 3. Strict Access Guards
        for i, step in enumerate(steps):
            node_data = self.graph.nodes.get(step, {})
            is_protected = node_data.get("is_protected", False) or node_data.get("strict_role_based_access", False)
            if is_protected:
                prior_mutation = False
                for j in range(i):
                    prev_data = self.graph.nodes.get(steps[j], {})
                    if prev_data.get("can_escalate_privileges", False) or prev_data.get("modifies_sensitive_storage", False):
                        prior_mutation = True
                        break
                
                if not prior_mutation:
                    ac_type = node_data.get("access_control_type", "none")
                    score -= 0.5
                    
                    if ac_type in ("modifier", "require-based", "both"):
                        any_mutation = any(self.graph.nodes.get(s, {}).get("can_escalate_privileges", False) for s in steps)
                        any_sensitive = any(self.graph.nodes.get(s, {}).get("modifies_sensitive_storage", False) for s in steps)
                        if not any_mutation and not any_sensitive:
                            score = 0.0
                            break

        # 4. Deterministic Revert Check
        for i in range(1, len(steps)):
            b_data = self.graph.nodes.get(steps[i], {})
            src = b_data.get("source_code", "").lower()
            if "require(" in src or "revert(" in src or "assert(" in src:
                if re.search(r"require\([^=]+==\s*(true|false|\d+)[^\)]*\)", src):
                    score -= 0.2
        
        # Part 10 — Enhanced step callability: check if prior steps
        # specifically modify the AC target variables of protected steps.
        for i, step in enumerate(steps):
            node_data = self.graph.nodes.get(step, {})
            ac_conf = node_data.get("access_control_confidence", 0.0)
            if ac_conf >= 0.8:
                # Find the AC target variables this step checks
                ac_mods = node_data.get("access_control_modifiers", [])
                ac_targets = set()
                for m in ac_mods:
                    # Look up modifier node for compared_variable
                    for nid, ndata in self.graph.nodes(data=True):
                        if ndata.get("type") == "modifier" and ndata.get("name") == m:
                            for cond in ndata.get("conditions", []):
                                cv = cond.get("compared_variable", "")
                                if cv:
                                    ac_targets.add(cv)

                if ac_targets:
                    prior_modifies_target = False
                    for j in range(i):
                        prev_data = self.graph.nodes.get(steps[j], {})
                        # Check if prev step writes the AC target variable
                        for _, wt, edata in self.graph.out_edges(steps[j], data=True):
                            if edata.get("relationship") == "WRITES":
                                wt_data = self.graph.nodes.get(wt, {})
                                wt_name = wt_data.get("name", "")
                                if wt_name in ac_targets:
                                    prior_modifies_target = True
                                    break
                            if prior_modifies_target:
                                break
                        if prior_modifies_target:
                            break

                    if not prior_modifies_target:
                        score -= 0.3

        # Part 10 — Temporal constraint detection
        requires_multi_block = False
        for step in steps:
            src = self.graph.nodes.get(step, {}).get("source_code", "")
            if src:
                if re.search(r'block\.(timestamp|number)\s*>=', src):
                    requires_multi_block = True
                    break
                if re.search(r'block\.(timestamp|number)\s*>', src):
                    requires_multi_block = True
                    break

        if requires_multi_block:
            chain_desc["requires_multi_block"] = True
            score -= 0.15

        score = max(0.0, score)
        
        chain_desc["feasibility_score"] = score
        chain_desc["is_deterministically_impossible"] = (score == 0.0)

    # ================================================================
    # Dev Story 4 — Accounting & Invariant Heuristics Engine
    # ================================================================

    def _run_accounting_invariant_heuristics(self):
        """Runs all accounting and invariant-focused heuristic detectors."""
        self._infer_state_variable_roles()
        self._detect_supply_consistency_issues()
        self._detect_cap_enforcement_issues()
        self._detect_reward_drift_issues()
        self._detect_monotonic_variable_issues()

    @staticmethod
    def _name_has_any(name: str, patterns: List[str]) -> bool:
        low = (name or "").lower()
        return any(p.lower() in low for p in patterns)

    def _function_state_sets(self, function_id: str) -> tuple[set[str], set[str]]:
        """Returns (reads, writes) state-variable node ID sets for a function."""
        reads: set[str] = set()
        writes: set[str] = set()
        for _, target, edge_data in self.graph.out_edges(function_id, data=True):
            target_data = self.graph.nodes.get(target, {})
            if target_data.get("type") != "state_variable":
                continue
            rel = edge_data.get("relationship")
            if rel == "READS":
                reads.add(target)
            elif rel == "WRITES":
                writes.add(target)

        writes.update(self.graph.nodes.get(function_id, {}).get("propagated_state_variables", []))
        return reads, writes

    def _infer_state_variable_roles(self):
        """
        Dev Story 4.1 — Variable Role Inference.
        Tags variables with abstract roles: SUPPLY, CAP, INDEX, RESERVE, BALANCE.
        """
        for var_id, var_data in self.graph.nodes(data=True):
            if var_data.get("type") != "state_variable":
                continue

            name = str(var_data.get("name", "")).lower()
            role = "UNKNOWN"

            if self._name_has_any(name, ["maxsupply", "cap", "limit", "max"]):
                role = "CAP"
            elif self._name_has_any(name, ["rewardindex", "rate", "accumulator", "index", "interestindex", "accreward"]):
                role = "INDEX"
            elif self._name_has_any(name, ["totalsupply", "totalshares", "supply", "totalassets", "totaldebt", "totalborrows"]):
                role = "SUPPLY"
            elif self._name_has_any(name, ["reserve", "liquidity", "pool"]):
                role = "RESERVE"
            elif self._name_has_any(name, ["balance", "balances", "amount", "shares", "accountborrows"]):
                role = "BALANCE"

            var_data["accounting_role"] = role

    def _detect_supply_consistency_issues(self):
        """
        Story 4.1 — Supply consistency detector.

        Heuristic objective:
          Detect functions likely to violate sum(balances) ~= totalSupply by
          updating supply/accounting state asymmetrically.
        """
        mutator_hints = ["mint", "burn", "deposit", "withdraw", "transfer", "borrow", "repay"]

        for node_id, node_data in self.graph.nodes(data=True):
            if node_data.get("type") != "function":
                continue

            reads, writes = self._function_state_sets(node_id)
            
            writes_balance_like = any(self.graph.nodes.get(v, {}).get("accounting_role") == "BALANCE" for v in writes)
            writes_supply_like = any(self.graph.nodes.get(v, {}).get("accounting_role") == "SUPPLY" for v in writes)
            reads_balance_like = any(self.graph.nodes.get(v, {}).get("accounting_role") == "BALANCE" for v in reads)
            reads_supply_like = any(self.graph.nodes.get(v, {}).get("accounting_role") == "SUPPLY" for v in reads)

            name = node_data.get("name", "")
            looks_like_supply_mutator = self._name_has_any(name, mutator_hints)
            is_external = node_data.get("is_external_entry", False)
            weak_access = not node_data.get("is_protected", False)

            flags: list[str] = []
            score = 0

            # Asymmetric update on a likely supply-mutating path is dangerous.
            if is_external and looks_like_supply_mutator:
                if writes_supply_like and not writes_balance_like:
                    flags.append("SUPPLY_BALANCE_MISMATCH")
                    score += 35
                if writes_balance_like and not writes_supply_like and (reads_supply_like or reads_balance_like):
                    flags.append("BALANCE_SUPPLY_MISMATCH")
                    score += 30

            if weak_access and flags:
                flags.append("UNPROTECTED_ACCOUNTING_MUTATION")
                score += 10

            node_data["supply_consistency_flags"] = flags
            node_data["supply_consistency_issue"] = len(flags) > 0
            node_data["supply_consistency_score"] = score

    def _detect_cap_enforcement_issues(self):
        """
        Story 4.3 — Cap Enforcement Completeness.

        Find all mint/borrow supply paths.
        Ensure every path enforces limit via REQUIRE against a CAP role variable.
        """
        for node_id, node_data in self.graph.nodes(data=True):
            if node_data.get("type") != "function":
                continue

            contract_name = node_data.get("contract", "")
            contract_cap_vars: list[str] = []
            for var_id, var_data in self.graph.nodes(data=True):
                if var_data.get("type") != "state_variable":
                    continue
                if var_data.get("contract") != contract_name:
                    continue
                if var_data.get("accounting_role") == "CAP":
                    contract_cap_vars.append(var_data.get("name", "").lower())

            if not contract_cap_vars:
                node_data["cap_enforcement_flags"] = []
                node_data["cap_enforcement_issue"] = False
                node_data["cap_enforcement_score"] = 0
                continue

            reads, writes = self._function_state_sets(node_id)
            touched_roles = [self.graph.nodes.get(v, {}).get("accounting_role") for v in (reads | writes)]

            fname = (node_data.get("name", "") or "").lower()
            src = node_data.get("source_code", "") or ""
            src_low = src.lower()
            is_external = node_data.get("is_external_entry", False)
            weak_access = not node_data.get("is_protected", False)

            likely_supply_path = any(k in fname for k in ("mint", "deposit", "supply")) or ("SUPPLY" in touched_roles)
            likely_borrow_path = "borrow" in fname or ("BALANCE" in touched_roles and likely_supply_path)

            has_require = ("require(" in src_low) or ("assert(" in src_low) or ("revert(" in src_low)
            reads_any_cap = any(cap in src_low for cap in contract_cap_vars)
            enforces_cap = has_require and reads_any_cap and ("<=" in src_low or "<" in src_low)

            flags: list[str] = []
            score = 0

            if is_external and likely_supply_path:
                if not enforces_cap:
                    flags.append("MISSING_CAP_ENFORCEMENT")
                    score += 50

            if is_external and likely_borrow_path:
                if not enforces_cap and "MISSING_CAP_ENFORCEMENT" not in flags:
                    flags.append("BORROW_CAP_BYPASS")
                    score += 40

            if weak_access and flags:
                flags.append("UNPROTECTED_CAP_MUTATION_PATH")
                score += 15

            node_data["cap_enforcement_flags"] = flags
            node_data["cap_enforcement_issue"] = len(flags) > 0
            node_data["cap_enforcement_score"] = score

    def _detect_reward_drift_issues(self):
        """
        Story 4.3 — Reward drift detector.

        Flags reward-index reset/inflation/manipulation patterns that can cause
        hidden inflation vectors.
        """
        for node_id, node_data in self.graph.nodes(data=True):
            if node_data.get("type") != "function":
                continue

            _, writes = self._function_state_sets(node_id)
            reward_writes = []
            for var_id in writes:
                vdata = self.graph.nodes.get(var_id, {})
                vname = str(vdata.get("name", "")).lower()
                tags = vdata.get("sensitivity_tags", []) or []
                if str(vdata.get("accounting_role", "")) == "INDEX" or "REWARD_CRITICAL" in tags:
                    reward_writes.append(vname)

            src = str(node_data.get("source_code", "") or "").lower()
            weak_access = not node_data.get("is_protected", False)
            flags: list[str] = []
            score = 0

            if reward_writes:
                # Reset-like behavior.
                if any(f"{n} = 0" in src or f"{n}=0" in src for n in reward_writes):
                    flags.append("REWARD_INDEX_RESET")
                    score += 40

                # Inflation-like behavior.
                if any(f"{n} +=" in src or f"{n}*=" in src for n in reward_writes):
                    flags.append("REWARD_INDEX_INFLATION")
                    score += 35

                # Manipulable edge-case path: weak access + arithmetic update.
                if weak_access and any(op in src for op in ("+=", "*=", "/=", "-=")):
                    flags.append("REWARD_EDGECASE_MANIPULATION")
                    score += 25

            node_data["reward_drift_flags"] = flags
            node_data["reward_drift_issue"] = len(flags) > 0
            node_data["reward_drift_score"] = score

    def _detect_monotonic_variable_issues(self):
        """
        Story 4.2 — Monotonic Verification.

        Detects unexpected decreases or unprotected resets in INDEX variables.
        """
        for node_id, node_data in self.graph.nodes(data=True):
            if node_data.get("type") != "function":
                continue

            _, writes = self._function_state_sets(node_id)
            idx_vars = []
            for var_id in writes:
                vdata = self.graph.nodes.get(var_id, {})
                if str(vdata.get("accounting_role", "")) == "INDEX":
                    idx_vars.append(str(vdata.get("name", "")).lower())

            src = str(node_data.get("source_code", "") or "").lower()
            weak_access = not node_data.get("is_protected", False)
            flags: list[str] = []
            score = 0

            if idx_vars:
                for iv in idx_vars:
                    decreases = (
                        f"{iv} -=" in src
                        or f"{iv}-=" in src
                        or re.search(rf"{re.escape(iv)}\s*=\s*{re.escape(iv)}\s*-\s*", src) is not None
                    )
                    resets = f"{iv} = 0" in src or f"{iv}=0" in src
                    
                    if decreases:
                        flags.append(f"NON_MONOTONIC_INDEX:{iv}")
                        score += 50
                    
                    if resets and weak_access:
                        flags.append(f"UNGUARDED_INDEX_MUTATION:{iv}")
                        score += 50

            node_data["monotonicity_flags"] = flags
            node_data["monotonicity_issue"] = len(flags) > 0
            node_data["monotonicity_score"] = score

    # ================================================================
    # Dev Story 6 — External Call Risk Analyzer
    # ================================================================

    def _classify_external_call(self, caller_contract: str, target_id: str, edge_data: dict) -> str:
        """
        Classifies an external call into one of:
        TOKEN_TRANSFER, ORACLE, SELF_CALL, DELEGATECALL, LOW_LEVEL_CALL, UNTRUSTED_CONTRACT
        """
        target_name = ""
        target_contract = ""
        call_type = edge_data.get("call_type", "")
        expr = str(edge_data.get("target_expression", "")).lower()

        if target_id and self.graph.has_node(target_id):
            target_data = self.graph.nodes[target_id]
            target_name = str(target_data.get("name", "")).lower()
            target_contract = target_data.get("contract", "")

        # 1. SELF_CALL
        if caller_contract and target_contract and caller_contract == target_contract:
            return "SELF_CALL"
        if "this." in expr:
            return "SELF_CALL"

        # 2. DELEGATECALL
        if "delegatecall" in call_type.lower() or "delegatecall(" in expr:
            return "DELEGATECALL"

        # 3. LOW_LEVEL_CALL
        if ".call{" in expr or ".call(" in expr or ".staticcall(" in expr:
            return "LOW_LEVEL_CALL"

        # 4. TOKEN_TRANSFER
        transfer_keywords = ["transfer", "transferfrom", "approve", "safetransfer"]
        if any(k in target_name for k in transfer_keywords) or any(k in expr for k in transfer_keywords):
            return "TOKEN_TRANSFER"

        # 5. ORACLE
        oracle_keywords = ["price", "latestrounddata", "oracle", "getexchangerate"]
        if any(k in target_name for k in oracle_keywords) or any(k in expr for k in oracle_keywords):
            return "ORACLE"

        # 6. UNTRUSTED_CONTRACT (Default)
        return "UNTRUSTED_CONTRACT"

    def _analyze_external_call_risks(self):
        """
        Tags external call risk classes:
          - REENTRANCY_RISK
          - UNCHECKED_RETURN
          - EXTERNAL_DEPENDENCY_RISK
        """
        for node_id, node_data in self.graph.nodes(data=True):
            if node_data.get("type") != "function":
                continue

            tags: list[str] = []
            score = 0
            caller_contract = node_data.get("contract", "")

            # Baseline flags from previous passes
            raw_reentrancy = node_data.get("reentrancy_risk", False)
            raw_unchecked = node_data.get("unchecked_external_return", False)

            has_risky_call = False
            has_unchecked_risky_call = False
            has_risky_call_before_write = False

            call_classes = set()

            for _, target, edge_data in self.graph.out_edges(node_id, data=True):
                if edge_data.get("relationship") != "EXTERNAL_CALL":
                    continue
                
                # Dev Story 6: Classify the call
                call_class = self._classify_external_call(caller_contract, target, edge_data)
                call_classes.add(call_class)

                # Determine if this call is inherently "risky" contextually
                is_untrusted = call_class in ("UNTRUSTED_CONTRACT", "LOW_LEVEL_CALL", "DELEGATECALL")
                is_tainted = len(node_data.get("taint_sources", [])) > 0 or node_data.get("has_taint_risk", False)
                is_unchecked = edge_data.get("return_value_checked") is False

                # We consider it a contextually risky external dependency if it's untrusted
                # OR if it uses tainted parameters (implying attacker controls the target/input).
                if is_untrusted or is_tainted:
                    has_risky_call = True
                    if is_unchecked:
                        has_unchecked_risky_call = True

                # Determine if a risky call happens BEFORE a state update
                target_data = self.graph.nodes.get(target, {})
                writes_state = target_data.get("writes_state", False) or len(target_data.get("propagated_state_variables", [])) > 0
                if (is_untrusted or is_tainted) and (writes_state or node_data.get("state_write_after_external_call", False)):
                    has_risky_call_before_write = True

            node_data["external_call_classes"] = list(call_classes)

            # --- Apply Contextual Scoring ---

            # Reentrancy: Only boost if there is actually a risky external call.
            # Standard token transfers (without other risky flags) do not get the massive 45pt reentrancy penalty.
            if raw_reentrancy:
                tags.append("REENTRANCY_RISK")
                if has_risky_call or has_risky_call_before_write:
                    score += 45
                else:
                    # Token/Oracle reentrancy is a known anti-pattern but vastly lower risk.
                    score += 10

            # Unchecked Return: Only penalize if the call itself was risky (or raw is flagged).
            if raw_unchecked or has_unchecked_risky_call:
                if "UNCHECKED_RETURN" not in tags:
                    tags.append("UNCHECKED_RETURN")
                if has_risky_call:
                    score += 25
                else:
                    score += 5

            # External Dependency:
            if has_risky_call or has_risky_call_before_write:
                if "EXTERNAL_DEPENDENCY_RISK" not in tags:
                    tags.append("EXTERNAL_DEPENDENCY_RISK")
                score += 30

            node_data["external_risk_tags"] = tags
            node_data["has_external_call_risk"] = len(tags) > 0
            node_data["external_call_risk_score"] = score

    # ================================================================
    # Story 4.2 / Epic 3, Story 3.1 — Multi-Dimensional Risk Scoring
    # ================================================================
    def _node_has_sensitive_action(self, node_data: Dict[str, Any]) -> bool:
        """
        True when a function performs state mutation or impacts sensitive state.
        Used by exploit path feasibility checks.
        """
        if node_data.get("writes_state") or len(node_data.get("propagated_state_variables", [])) > 0:
            return True
        if node_data.get("can_escalate_privileges") or node_data.get("is_unprotected_mutator"):
            return True
        if node_data.get("has_dangerous_sequence"):
            return True
        for tw in node_data.get("tainted_state_writes", []):
            if tw.get("sensitivity"):
                return True
        for var_id in node_data.get("propagated_state_variables", []):
            var_data = self.graph.nodes.get(var_id, {})
            if var_data.get("type") == "state_variable" and var_data.get("is_sensitive"):
                return True
        return False

    def _has_viable_attacker_path(self, target_node_id: str) -> bool:
        """
        Returns True iff at least one CALLS path from an external entry reaches
        target_node_id and that path contains state mutation or sensitive action.
        """
        target_data = self.graph.nodes.get(target_node_id, {})
        if target_data.get("type") != "function":
            return False

        entry_points = target_data.get("entry_points", [])
        if not entry_points and target_data.get("is_external_entry"):
            entry_points = [target_node_id]
        if not entry_points:
            return False

        for entry in entry_points:
            if not self.graph.has_node(entry):
                continue
            entry_data = self.graph.nodes.get(entry, {})
            if entry_data.get("type") != "function":
                continue

            queue = deque([(entry, self._node_has_sensitive_action(entry_data))])
            visited = {(entry, self._node_has_sensitive_action(entry_data))}

            while queue:
                current, seen_sensitive_action = queue.popleft()
                if current == target_node_id and seen_sensitive_action:
                    return True

                for _, nxt, edge_data in self.graph.out_edges(current, data=True):
                    if edge_data.get("relationship") != "CALLS":
                        continue
                    nxt_data = self.graph.nodes.get(nxt, {})
                    if nxt_data.get("type") != "function":
                        continue
                    next_seen = seen_sensitive_action or self._node_has_sensitive_action(nxt_data)
                    state = (nxt, next_seen)
                    if state in visited:
                        continue
                    visited.add(state)
                    queue.append(state)

        return False

    def _compute_negative_safety_signals(self):
        """
        Dev Story 1 — precision hard-filter.

        Computes function-level negative evidence and assigns:
          - safety_score: higher means stronger structural evidence of safety.
          - modifies_sensitive_storage: direct/indirect writes to sensitive vars.
        """
        for node_id, node_data in self.graph.nodes(data=True):
            if node_data.get("type") != "function":
                continue

            ac_type = node_data.get("access_control_type", "none")
            strict_role_based_access = ac_type in ("modifier", "require-based", "both")

            has_external_edges = any(
                edge_data.get("relationship") == "EXTERNAL_CALL"
                for _, _, edge_data in self.graph.out_edges(node_id, data=True)
            )
            no_external_calls = (
                not node_data.get("makes_external_call", False)
                and not has_external_edges
            )

            no_state_mutation = (
                not node_data.get("writes_state", False)
                and len(node_data.get("propagated_state_variables", [])) == 0
            )

            no_tainted_inputs = (
                not node_data.get("has_taint_risk", False)
                and len(node_data.get("taint_sources", [])) == 0
                and len(node_data.get("cross_function_taint_paths", [])) == 0
            )

            sensitive_writes = set()
            for var_id in node_data.get("propagated_state_variables", []):
                var_data = self.graph.nodes.get(var_id, {})
                if var_data.get("type") != "state_variable":
                    continue
                if var_data.get("is_sensitive"):
                    sensitive_writes.add(var_id)
            for tw in node_data.get("tainted_state_writes", []):
                if tw.get("sensitivity"):
                    sensitive_writes.add(tw.get("state_var", "__unknown_sensitive_write"))

            modifies_sensitive_storage = len(sensitive_writes) > 0
            no_critical_storage_writes = not modifies_sensitive_storage

            safety_score = 0
            if strict_role_based_access:
                safety_score += 12
            if no_external_calls:
                safety_score += 12
            if no_state_mutation:
                safety_score += 14
            if no_tainted_inputs:
                safety_score += 14
            if no_critical_storage_writes:
                safety_score += 18

            safe_profile = (
                strict_role_based_access
                and no_external_calls
                and no_state_mutation
                and no_tainted_inputs
                and no_critical_storage_writes
                and not modifies_sensitive_storage
            )
            if safe_profile:
                safety_score += 30

            node_data["strict_role_based_access"] = strict_role_based_access
            node_data["no_external_calls"] = no_external_calls
            node_data["no_state_mutation"] = no_state_mutation
            node_data["no_tainted_inputs"] = no_tainted_inputs
            node_data["no_critical_storage_writes"] = no_critical_storage_writes
            node_data["modifies_sensitive_storage"] = modifies_sensitive_storage
            node_data["safe_profile"] = safe_profile
            node_data["safety_score"] = max(0, min(100, int(round(safety_score))))

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
        # Ensure negative evidence metadata exists even when tests call this
        # scorer directly without running the full build_graph pipeline.
        self._compute_negative_safety_signals()

        for node_id, node_data in self.graph.nodes(data=True):
            if node_data.get("type") != "function":
                continue

            structural = 0
            exploitability = 0
            impact = 0
            risk_categories = []

            # ── Dev Story 1: Guard-based downgrade flags ─────
            is_safe_init = node_data.get("safe_init_pattern", False)
            has_init_guard = node_data.get("has_initializer_guard", False)
            has_reentrancy_guard = node_data.get("has_reentrancy_guard", False)
            ac_type = node_data.get("access_control_type", "none")

            # ── Structural Score ──────────────────────────────
            if node_data.get("reentrancy_risk"):
                if has_reentrancy_guard:
                    structural += 10
                    risk_categories.append("reentrancy_guarded")
                else:
                    structural += 50
                    risk_categories.append("reentrancy")

            if node_data.get("can_escalate_privileges"):
                if is_safe_init or ac_type in ("modifier", "require-based", "both"):
                    structural += 10
                    risk_categories.append("privilege_escalation_guarded")
                else:
                    structural += 50
                    risk_categories.append("privilege_escalation")

            # Part 6: Confidence-weighted unprotected mutator scoring
            if node_data.get("is_unprotected_mutator"):
                ac_conf = node_data.get("access_control_confidence", 0.0)
                if ac_type in ("require-based", "both") or ac_conf >= 0.8:
                    structural += 10
                    risk_categories.append("unprotected_mutator_guarded")
                else:
                    structural += int(40 * (1.0 - ac_conf))
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

            # Dev Story 2: Taint-based structural risk
            taint_score = node_data.get("taint_risk_score", 0)
            if taint_score > 0:
                structural += min(taint_score, 60)
                for rt in node_data.get("taint_risk_types", []):
                    risk_categories.append(rt.lower())

            # Dev Story 3: Cross-function sequence risk
            seq_score = node_data.get("sequence_risk_score", 0)
            if seq_score > 0:
                structural += min(seq_score, 50)
                for seq in node_data.get("dangerous_sequences", []):
                    for dt in seq.get("danger_types", []):
                        cat = dt.lower()
                        if cat not in risk_categories:
                            risk_categories.append(cat)

            # Dev Story 4: Accounting & invariant heuristics
            accounting_score = (
                node_data.get("supply_consistency_score", 0)
                + node_data.get("cap_enforcement_score", 0)
                + node_data.get("reward_drift_score", 0)
                + node_data.get("monotonicity_score", 0)
            )
            if accounting_score > 0:
                structural += min(accounting_score, 60)

            for key, cat in (
                ("supply_consistency_issue", "supply_consistency"),
                ("cap_enforcement_issue", "cap_bypass"),
                ("reward_drift_issue", "reward_drift"),
                ("monotonicity_issue", "monotonicity_violation"),
            ):
                if node_data.get(key) and cat not in risk_categories:
                    risk_categories.append(cat)

            # Dev Story 6: External call risk analyzer
            ext_score = node_data.get("external_call_risk_score", 0)
            if ext_score > 0:
                structural += min(ext_score, 45)
            for tag in node_data.get("external_risk_tags", []):
                low = tag.lower()
                if low not in risk_categories:
                    risk_categories.append(low)

            # Improvement 2A: Read-only reentrancy risk
            if node_data.get("read_only_reentrancy_risk"):
                structural += 35
                risk_categories.append("read_only_reentrancy")

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

            # Part 6: Confidence-weighted exploitability
            ac_conf = node_data.get("access_control_confidence", 0.0)
            if not node_data.get("is_protected") and not node_data.get("is_view_or_pure"):
                exploitability += int(15 * (1.0 - ac_conf))
            elif ac_type == "require-based" or ac_conf >= 0.8:
                exploitability += 5

            # Dev Story 3: Exploit chain entry boost
            if node_data.get("is_chain_entry") and node_data.get("max_chain_length", 0) >= 3:
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

            # Part 6: Confidence-weighted impact for unprotected mutators
            if node_data.get("is_unprotected_mutator"):
                ac_conf = node_data.get("access_control_confidence", 0.0)
                level = node_data.get("unprotected_risk_level", "MEDIUM")
                base_impact = 20 if level == "HIGH" else 10
                impact += int(base_impact * (1.0 - ac_conf))

            # Dev Story 3: Impact boost for dangerous sequences
            if node_data.get("has_dangerous_sequence"):
                for seq in node_data.get("dangerous_sequences", []):
                    if "PRIVILEGE_CHAIN" in seq.get("danger_types", []):
                        impact += 20
                        break
                    if "ACCOUNTING_MANIPULATION" in seq.get("danger_types", []):
                        impact += 15
                        break

            # Dev Story 2: Impact boost for taint into sensitive storage
            if node_data.get("has_taint_risk"):
                sensitive_categories = set()
                for tw in node_data.get("tainted_state_writes", []):
                    for s in tw.get("sensitivity", []):
                        sensitive_categories.add(s)
                if "ACCOUNTING_CRITICAL" in sensitive_categories:
                    impact += 25
                if "CAP_CRITICAL" in sensitive_categories:
                    impact += 20
                if "ACCESS_CRITICAL" in sensitive_categories:
                    impact += 30

            # ── Epic 7, Story 7.2: Tier-weighted impact ──────
            contract_name = node_data.get("contract", "")
            contract_tier = self.graph.nodes.get(contract_name, {}).get("tier", "INFRA")
            if contract_tier == "CORE":
                impact += 20
            elif contract_tier == "FACTORY":
                impact -= 25
            impact = max(0, impact)

            # Part 8: Governance design choice — reduce structural
            if node_data.get("governance_design_choice", False):
                structural = max(0, structural - 30)
                risk_categories.append("governance_design_choice")

            # Clamp structural to >= 0 after all reductions
            structural = max(0, structural)

            # ── Final Score (weighted combination) ────────────
            final = (
                structural * 0.40
                + exploitability * 0.35
                + impact * 0.25
            )

            has_taint_involvement = (
                node_data.get("has_taint_risk", False)
                or len(node_data.get("taint_sources", [])) > 0
                or len(node_data.get("cross_function_taint_paths", [])) > 0
                or len(node_data.get("tainted_state_writes", [])) > 0
            )
            has_state_mutation = (
                node_data.get("writes_state", False)
                or len(node_data.get("propagated_state_variables", [])) > 0
            )
            has_sensitive_impact = (
                node_data.get("modifies_sensitive_storage", False)
                or any(tw.get("sensitivity") for tw in node_data.get("tainted_state_writes", []))
            )

            if not (has_taint_involvement or has_state_mutation or has_sensitive_impact):
                # Structural-only shape should not clear hotspot thresholds by itself.
                final = min(final, 55.0)

            base_int = int(round(final))
            safety_score = int(node_data.get("safety_score", 0) or 0)
            final_int = max(0, base_int - safety_score)

            node_data["structural_score"] = structural
            node_data["exploitability_score"] = exploitability
            node_data["impact_score"] = impact
            node_data["base_score"] = base_int
            node_data["safety_score"] = safety_score
            node_data["final_score"] = final_int
            node_data["risk_score"] = final_int   # backward compat
            node_data["risk_categories"] = risk_categories

    # ================================================================
    # Dev Story 5 — Exploit Target Scoring Engine
    # ================================================================
    def _compute_exploit_target_scores(self):
        """
        Computes an exploit-target score (0-100) and eligibility flag for
        ExploitWriter prioritization.
        """
        threshold = 75
        economic_analyzer = EconomicAnalyzer(self.graph)
        for node_id, node_data in self.graph.nodes(data=True):
            if node_data.get("type") != "function":
                continue

            score = 0

            has_taint_involvement = (
                node_data.get("has_taint_risk", False)
                or len(node_data.get("taint_sources", [])) > 0
                or len(node_data.get("cross_function_taint_paths", [])) > 0
                or len(node_data.get("tainted_state_writes", [])) > 0
            )
            has_state_mutation = (
                node_data.get("writes_state", False)
                or len(node_data.get("propagated_state_variables", [])) > 0
            )
            has_sensitive_impact = (
                node_data.get("modifies_sensitive_storage", False)
                or any(tw.get("sensitivity") for tw in node_data.get("tainted_state_writes", []))
            )

            # Taint depth proxy
            taint_sources = node_data.get("taint_sources", [])
            cross_taint_paths = node_data.get("cross_function_taint_paths", [])
            taint_depth = min(3, len(taint_sources) // 2 + len(cross_taint_paths))
            score += taint_depth * 10

            # Sensitive state touched
            sensitive_tags = set()
            for tw in node_data.get("tainted_state_writes", []):
                for tag in tw.get("sensitivity", []):
                    sensitive_tags.add(tag)
            score += min(25, len(sensitive_tags) * 8)

            # External call risk
            if node_data.get("makes_external_call"):
                score += 10
            score += min(20, node_data.get("external_call_risk_score", 0) // 2)

            # Access control weakness
            if node_data.get("is_unprotected_mutator"):
                score += 15
            elif not node_data.get("is_protected") and not node_data.get("is_view_or_pure"):
                score += 10

            # Multi-function exploit chain depth
            chain_len = node_data.get("max_chain_length", 0)
            if chain_len >= 2:
                score += chain_len * 10

            # --- Dev Story 5: Target Score Calibration Boosts ---
            if has_taint_involvement:
                score += 20
            if has_sensitive_impact:
                score += 20
            if node_data.get("uses_tainted_math"):
                score += 15
            if "MISSING_CAP_ENFORCEMENT" in node_data.get("cap_enforcement_flags", []):
                score += 15
            if node_data.get("can_escalate_privileges"):
                score += 20

            # --- Dev Story 5: Target Score Calibration Penalties ---
            if node_data.get("is_protected"):
                score -= 20
            if node_data.get("is_view_or_pure"):
                score -= 50
            if not node_data.get("is_external_entry"):
                score -= 30
            if not has_taint_involvement:
                score -= 20

            # Blend with global final score so exploit targeting aligns with
            # core risk model but still emphasizes exploitability signals.
            final_score = node_data.get("final_score", node_data.get("risk_score", 0))
            score = int(round(score * 0.7 + min(100, final_score) * 0.3))

            # Dev Story 7 & 8: Filter out impossible chains and apply feasibility + economic weighting
            best_feasibility = 0.0
            best_economic_impact = 1.0
            has_valid_chains = False
            
            if node_data.get("is_chain_entry") and len(node_data.get("exploit_chains", [])) > 0:
                valid_chains = [c for c in node_data["exploit_chains"] if c.get("feasibility_score", 0.0) > 0.0]
                if valid_chains:
                    has_valid_chains = True
                    for c in valid_chains:
                        economic_analyzer.evaluate_chain_economic_impact(c)
                        
                    best_feasibility = max((c.get("feasibility_score", 0.0) for c in valid_chains), default=0.0)
                    best_economic_impact = max((c.get("economic_impact_score", 1.0) for c in valid_chains), default=1.0)
                else:
                    score = 0
            
            if has_valid_chains:
                feasibility_weight = 0.4 + 0.6 * best_feasibility
                score = int(round(score * feasibility_weight * best_economic_impact))

            if not (has_taint_involvement or has_state_mutation or has_sensitive_impact):
                # Structural-only/shape-only evidence is insufficient for exploit writer handoff.
                score = min(score, threshold - 1)

            score = max(0, min(100, score))

            has_viable_attacker_path = self._has_viable_attacker_path(node_id)
            if node_data.get("is_chain_entry") and len(node_data.get("exploit_chains", [])) > 0 and not has_valid_chains:
                has_viable_attacker_path = False

            node_data["exploit_target_score"] = score
            node_data["exploit_target_threshold"] = threshold
            node_data["has_viable_attacker_path"] = has_viable_attacker_path
            node_data["send_to_exploit_writer"] = score >= threshold and has_viable_attacker_path

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

            # Dev Story 8 Arithmetic Extractions
            uses_division = bool(re.search(r'(?<!/)/(?!/|\*)|\.div\(', src))
            uses_multiplication = bool(re.search(r'\*(?!\*)|\.mul\(', src))
            uses_ratio_math = uses_division and uses_multiplication
            updates_reward_index = bool(re.search(r'(?i)(reward_?index|reward_?per_?token|acc_?reward|reward_?rate)\s*(\+?=|-?=|=)', src))
            mints_shares_proportionally = bool(re.search(r'(?i)(mint|issue).*(shares|liquidity|pool_?tokens?)', src)) and uses_ratio_math
            writes_total_supply = bool(re.search(r'(?i)totalSupply\s*(\+?=|-?=|=)', src)) or bool(re.search(r'(?i)_mint\(', src))
            writes_total_assets = bool(re.search(r'(?i)totalAssets\s*(\+?=|-?=|=)', src)) or bool(re.search(r'(?i)totalBorrows\s*(\+?=|-?=|=)', src))

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
                # Dev Story 8 Metadata
                "uses_division": uses_division,
                "uses_multiplication": uses_multiplication,
                "uses_ratio_math": uses_ratio_math,
                "updates_reward_index": updates_reward_index,
                "mints_shares_proportionally": mints_shares_proportionally,
                "writes_total_supply": writes_total_supply,
                "writes_total_assets": writes_total_assets,
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

    # ════════════════════════════════════════════════════════════
    #  Titan Pattern Engine — Graph-validated pattern integration
    # ════════════════════════════════════════════════════════════

    def _integrate_pattern_hits(self):
        """
        Run the Titan Pattern Engine over cached .sol sources and attach
        validated hits to function nodes.

        For each PatternHit:
          1. Resolve the file + line to a function node in the graph.
          2. Validate against graph context (modifiers, taint, protection).
          3. Attach validated hits as node metadata and boost structural_score.
        """
        if not self._file_cache:
            return

        raw_hits = scan_all_sources(self._file_cache)
        if not raw_hits:
            return

        summary = get_pattern_summary(raw_hits)
        total = sum(summary.values())
        print(f"  [Titan] Raw pattern scan: {total} hits "
              f"(C={summary['CRITICAL']}, H={summary['HIGH']}, "
              f"M={summary['MEDIUM']}, L={summary.get('LOW', 0)})")

        # Build a reverse index: (normalized_file, line_range) -> node_id
        # Each function node has source_start_line / source_end_line / source_file
        func_index: list[tuple[str, int, int, str]] = []
        for node_id, data in self.graph.nodes(data=True):
            if data.get("type") != "function":
                continue
            src_file = data.get("source_file", "")
            start_line = data.get("source_start_line", 0)
            end_line = data.get("source_end_line", 0)
            if src_file and start_line and end_line:
                func_index.append((src_file, start_line, end_line, node_id))

        validated = 0
        discarded = 0

        for hit in raw_hits:
            # 1. Resolve to function node
            matched_node = None
            for src_file, start, end, node_id in func_index:
                # Normalize paths for comparison
                if hit.file.endswith(src_file) or src_file.endswith(hit.file) or \
                   hit.file == src_file:
                    if start <= hit.line <= end:
                        matched_node = node_id
                        break

            if not matched_node:
                # Can't resolve to a function — skip
                discarded += 1
                continue

            node_data = self.graph.nodes[matched_node]

            # 2. Graph-context validation — discard false positives
            skip = False

            # Reentrancy hit but function has nonReentrant guard
            if hit.category == "reentrancy":
                modifiers = node_data.get("ac_modifiers", [])
                if any("reentr" in str(m).lower() for m in modifiers):
                    skip = True
                if node_data.get("has_reentrancy_guard"):
                    skip = True

            # Access control hit but function has protection
            if hit.category == "access-control" and hit.pattern_id in ("ETH-006", "ETH-009"):
                if node_data.get("is_protected") or node_data.get("has_access_control"):
                    skip = True

            if skip:
                discarded += 1
                continue

            # 3. Attach validated hit to node
            existing_hits = node_data.get("pattern_hits", [])
            existing_hits.append(hit.pattern_id)
            node_data["pattern_hits"] = existing_hits

            existing_cats = node_data.get("pattern_categories", [])
            if hit.category not in existing_cats:
                existing_cats.append(hit.category)
            node_data["pattern_categories"] = existing_cats

            # Store full hit details for reporting
            hit_details = node_data.get("pattern_hit_details", [])
            hit_details.append({
                "id": hit.pattern_id,
                "title": hit.title,
                "severity": hit.severity,
                "confidence": hit.confidence,
                "line": hit.line,
                "description": hit.description,
                "recommendation": hit.recommendation,
                "category": hit.category,
                "swc": hit.swc,
            })
            node_data["pattern_hit_details"] = hit_details

            # 4. Boost structural_score for validated hits
            sev_boost = {"CRITICAL": 15, "HIGH": 10, "MEDIUM": 5, "LOW": 2, "INFORMATIONAL": 0}
            current_structural = node_data.get("structural_score", 0)
            boost = sev_boost.get(hit.severity, 0)
            node_data["structural_score"] = min(100, current_structural + boost)

            # Add to risk_categories if not already present
            risk_cats = node_data.get("risk_categories", [])
            cat_tag = f"PATTERN_{hit.category.upper().replace('-', '_')}"
            if cat_tag not in risk_cats:
                risk_cats.append(cat_tag)
                node_data["risk_categories"] = risk_cats

            validated += 1

        print(f"  [Titan] Graph-validated: {validated} hits attached, "
              f"{discarded} discarded (no match or false positive)")

        # Store summary on graph for reporting
        self.graph.graph.setdefault("report_metadata", {})
        self.graph.graph["report_metadata"]["titan_raw_hits"] = total
        self.graph.graph["report_metadata"]["titan_validated_hits"] = validated
        self.graph.graph["report_metadata"]["titan_discarded_hits"] = discarded

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
