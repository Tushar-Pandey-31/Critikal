"""Graph node and edge construction from Slither IR."""



ENABLE_CROSS_CONTRACT_EDGES = True


class NodeEdgeMixin:
    """Creates contract, function, and state variable nodes and their edges."""

    def _read_file_cached(self, path: str) -> str:
        """Read a file with caching to avoid re-reading the same .sol file for every function."""
        if path not in self._file_cache:
            with open(path, encoding="utf-8") as f:
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
                                self.graph.add_edge(caller_id, target_id, relationship="CROSS_CONTRACT_CALL", call_type="cross_contract")
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
