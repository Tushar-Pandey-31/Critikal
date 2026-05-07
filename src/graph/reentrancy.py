"""Reentrancy detection: external call classification, CEI violations, privilege escalation."""


from slither.slither import Slither


class ReentrancyMixin:
    """Classifies external calls and detects reentrancy risk patterns."""

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
