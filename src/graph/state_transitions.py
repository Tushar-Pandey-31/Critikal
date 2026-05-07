"""State transitions, taint propagation, and dataflow analysis."""

import re
from typing import Any

from slither.slither import Slither


class StateTransitionMixin:
    """Builds state transition nodes, computes taint propagation, and models dataflow."""

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
        slither_func_lookup: dict[str, Any] = {}
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
        contract_creates: dict[str, bool] = {}
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
        slither_func_lookup: dict[str, Any] = {}
        for contract in slither_obj.contracts:
            for function in contract.functions:
                fid = f"{contract.name}::{function.name}"
                slither_func_lookup[fid] = function

        # Phase 1: Intra-procedural taint
        func_taint: dict[str, dict] = {}
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
        self, node_id: str, node_data: dict, slither_func
    ) -> dict[str, Any]:
        """
        Tracks taint through a single function's Slither IR.

        Taint sources: function parameters (for public/external),
        msg.sender, msg.value, tx.origin, external call return values.
        """
        tainted: set[str] = set()
        source_types: list[str] = []
        tainted_writes: list[dict] = []
        unchecked_ext_returns: list[str] = []
        param_to_taint: dict[str, set] = {}
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
        self, node_id: str, node_data: dict
    ) -> dict[str, Any]:
        """
        Source-code fallback when Slither IR is unavailable.
        Uses regex heuristics to detect taint sources flowing into state writes.
        """
        source = node_data.get("source_code", "")
        vis = node_data.get("visibility", "internal")
        source_types: list[str] = []
        tainted_writes: list[dict] = []
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
        func_taint: dict[str, dict],
        slither_func_lookup: dict[str, Any],
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
        caller_result: dict,
        callee_result: dict,
        callee_node_id: str,
        callee_node_data: dict,
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

    def _mark_tainted_state_variables(self, func_taint: dict[str, dict]):
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

    def _apply_taint_vulnerability_heuristics(self, func_taint: dict[str, dict]):
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
        all_paths_by_entry: dict[str, list[dict]] = {fid: [] for fid in func_taint}

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
            critical_paths: list[dict] = []
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
