"""Access control analysis: modifiers, guards, privilege detection, governance."""

import re
from collections import deque
from typing import Any

from slither.core.cfg.node import NodeType
from slither.slither import Slither


class AccessControlMixin:
    """Analyzes access control patterns, modifier semantics, and privilege escalation."""

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
                self.graph.add_node(
                    mod_node_id,
                    **{
                        "type": "modifier",
                        "name": modifier.name,
                        "contract": contract.name,
                        "conditions": conditions,
                        "accesses_state_variables": accessed_state_vars,
                        "is_access_control": is_access_control,
                        "access_control_pattern": pattern,
                        "pre_segment": pre_segment,
                        "post_segment": post_segment,
                    },
                )

                # Edge: Contract --HAS_MODIFIER--> Modifier
                self.graph.add_edge(contract.name, mod_node_id, relationship="HAS_MODIFIER")

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
                    accessed_vars = [f"{sv.contract.name}::{sv.name}" for sv in modifier.state_variables_read]
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
            self._update_access_control(
                node_id,
                has_access_control=has_access_control,
                ac_modifiers=ac_modifiers,
                has_inline_check=has_inline_check,
                is_protected=is_protected,
                confidence=ac_confidence,
            )

    def _extract_modifier_conditions(self, modifier) -> list[dict[str, Any]]:
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
                    if "require(bool" in ir_str or "assert(bool" in ir_str:
                        cond_type = "require" if "require" in ir_str else "assert"

                        # Get the full expression from the node
                        expression_str = str(node.expression) if node.expression else str(ir)

                        checks_msg_sender = "msg.sender" in expression_str
                        checks_tx_origin = "tx.origin" in expression_str

                        # Try to find what variable is being compared
                        compared_variable = self._extract_compared_variable(expression_str)

                        conditions.append(
                            {
                                "type": cond_type,
                                "expression": expression_str,
                                "checks_msg_sender": checks_msg_sender,
                                "checks_tx_origin": checks_tx_origin,
                                "compared_variable": compared_variable,
                            }
                        )
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
        match = re.search(r"msg\.sender\s*==\s*(\w+)", expression)
        if match:
            return match.group(1)

        # Pattern: <variable> == msg.sender
        match = re.search(r"(\w+)\s*==\s*msg\.sender", expression)
        if match:
            return match.group(1)

        # Pattern: tx.origin == <variable>
        match = re.search(r"tx\.origin\s*==\s*(\w+)", expression)
        if match:
            return match.group(1)

        # Pattern: <mapping>[msg.sender] (e.g., admins[msg.sender])
        match = re.search(r"(\w+)\[msg\.sender\]", expression)
        if match:
            return match.group(1)

        # Pattern: hasRole(..., msg.sender)
        if "hasRole" in expression or "hasrole" in expression.lower():
            return "roles"

        return ""

    # ================================================================
    # Centralized Access Control Update Helper (Part 6)
    # ================================================================

    def _update_access_control(
        self,
        node_id: str,
        *,
        has_access_control: bool = None,
        ac_modifiers: list = None,
        has_inline_check: bool = None,
        is_protected: bool = None,
        confidence: float = None,
        ac_type: str = None,
    ):
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
            nd["access_control_confidence"] = max(nd.get("access_control_confidence", 0.0), confidence)
        if ac_type is not None:
            existing = nd.get("access_control_type", "none")
            if existing == "none":
                nd["access_control_type"] = ac_type
            elif existing != ac_type and ac_type != "none":
                nd["access_control_type"] = "both"

    # ================================================================
    # Part 2 — Inheritance-Aware Modifier Resolution
    # ================================================================

    def _resolve_modifiers_with_inheritance(self, contract_name: str, applied_modifiers: list[str]) -> dict[str, tuple]:
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
                result[m] = (local_mods[m], True)  # is_local = True
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
        r"^_?(require|check|only|assert|verify|ensure|validate)"
        r"(Admin|Owner|Role|Auth|Caller|Sender|Gov|Operator|Manager|Guardian|Pauser)",
        re.IGNORECASE,
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
                has_check = "require(" in source or "revert" in source or "assert(" in source
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
        r"(hasRole|getRoleMember|canCall|isOperator|checkRole|"
        r"_checkRole|onlyRole|hasPermission)\s*\(",
        re.IGNORECASE,
    )
    _ROLE_TARGET_KEYWORDS = re.compile(r"(role|auth|access|registry|acl|permission)", re.IGNORECASE)

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
            has_require_context = bool(source and ("require(" in source or "revert" in source or "assert(" in source))

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

    _GOVERNANCE_PARENT_CONTRACTS = frozenset(
        [
            "Governor",
            "GovernorCompatibilityBravo",
            "TimelockController",
            "GovernorTimelockControl",
            "GovernorCountingSimple",
            "GovernorVotes",
            "GovernorVotesQuorumFraction",
            "GovernorSettings",
            "GovernorTimelockCompound",
        ]
    )
    _GOVERNANCE_KEYWORDS = re.compile(
        r"(quorum|votingPeriod|proposalThreshold|castVote|castVoteBySig"
        r"|proposalDeadline|proposalSnapshot|COUNTING_MODE"
        r"|timelockDelay|queue|execute|cancel)",
        re.IGNORECASE,
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
            func_under_gov = contract in governance_contracts or ac_type in ("modifier", "require-based", "both")
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
            protected_types = ("modifier", "require-based", "both", "internal-guard", "external-role")

            effectively_protected = (
                ac_type in protected_types
                or data.get("has_internal_guard_call", False)
                or data.get("has_external_role_guard", False)
                or data.get("access_control_confidence", 0.0) >= 0.8
            )

            if effectively_protected:
                data["is_unprotected_mutator"] = False
                data["unprotected_risk_level"] = "NONE"

    def _classify_modifier_pattern(self, conditions: list[dict], state_vars: list[str]) -> str:
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
                if "[msg.sender]" in expr or "hasRole" in expr or "hasrole" in expr.lower():
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
        re.compile(r"if\s*\(\s*msg\.sender\s*!=", re.IGNORECASE),
        re.compile(r"if\s*\(\s*\w+\s*!=\s*msg\.sender", re.IGNORECASE),
        re.compile(r"if\s*\(\s*!\s*\w+\[msg\.sender\]", re.IGNORECASE),
        re.compile(
            r"revert\s+(Unauthorized|NotOwner|NotAdmin|AccessDenied|Forbidden|OnlyOwner|OnlyAdmin|NotAuthorized)\s*\(",
            re.IGNORECASE,
        ),
    ]

    def _detect_inline_access_check(self, node_id: str, node_data: dict, slither_func=None) -> bool:
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
                        if "require(bool" in ir_str or "assert(bool" in ir_str:
                            expr_str = str(node.expression) if node.expression else str(ir)
                            if "msg.sender" in expr_str:
                                return True
            except Exception:
                pass

        # Fallback: source code regex (original patterns)
        source = node_data.get("source_code", "")
        if source:
            if re.search(r"require\s*\(\s*msg\.sender\s*==", source):
                return True
            if re.search(r"require\s*\(\s*\w+\s*==\s*msg\.sender", source):
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
                    if underlying_var:
                        break

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
                "pattern": pattern,
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
            match = re.search(r"require\s*\(\s*msg\.sender\s*==\s*(\w+)", source)
            if match:
                compared_var = match.group(1)
            else:
                match = re.search(r"require\s*\(\s*(\w+)\s*==\s*msg\.sender", source)
                if match:
                    compared_var = match.group(1)

            role_name = compared_var if compared_var else "inline_check"

            role_profile = {
                "role_name": role_name,
                "modifier_name": "",
                "protected_functions": [node_id],
                "underlying_variable": compared_var,
                "how_verified": "inline_require",
                "pattern": "owner_check",
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

    def _derive_role_name(self, modifier_name: str, mod_data: dict) -> str:
        """
        Derives a human-readable role name from a modifier name.
        e.g., 'onlyOwner' -> 'owner', 'onlyAdmin' -> 'admin',
              'whenNotPaused' -> 'paused_flag', 'onlyRole' -> 'role'
        """
        name_lower = modifier_name.lower()

        if "owner" in name_lower:
            return "owner"
        if "admin" in name_lower:
            return "admin"
        if "role" in name_lower:
            return "role"
        if "pause" in name_lower:
            return "paused_flag"
        if "txorigin" in name_lower or "tx_origin" in name_lower:
            return "tx_origin"

        # Fallback: strip 'only' prefix if present
        if name_lower.startswith("only"):
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

    def _analyze_modifier_segment(self, nodes: list) -> dict[str, Any]:
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
                    segment_data["external_calls"].append(
                        {
                            "type": call_type,
                            "desc": f"{ir_type}::{str(ir)[:80]}",
                            "idx": idx,
                            "forwards_gas": forwards_gas,
                            "target_expression": target_expression,
                            "return_value_checked": True,
                            "resolved_target": resolved_target,
                        }
                    )

                if ir_type == "InternalCall":
                    target_func = getattr(ir, "function", None)
                    if target_func:
                        target_contract = getattr(target_func, "contract_declarer", None) or getattr(
                            target_func, "contract", None
                        )
                        if target_contract:
                            segment_data["internal_calls"].append(
                                {
                                    "target_id": f"{target_contract.name}::{target_func.name}",
                                    "idx": idx,
                                }
                            )

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

            if is_externally_callable and writes_state and not is_protected and not is_constructor:
                # Determine risk level
                risk_level = "HIGH" if is_payable else "MEDIUM"

                self.graph.nodes[node_id]["is_unprotected_mutator"] = True
                self.graph.nodes[node_id]["unprotected_risk_level"] = risk_level
            else:
                self.graph.nodes[node_id]["is_unprotected_mutator"] = False
                self.graph.nodes[node_id]["unprotected_risk_level"] = "NONE"

    def _detect_initializer_guards(self, slither_obj: Slither):
        """
        Dev Story 1.1 — Detects inline initializer guards in function bodies.
        Also checks one level of callees to catch super.initialize() patterns.
        """
        slither_func_lookup: dict[str, Any] = {}
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
                            if "require(bool" not in ir_str and "assert(bool" not in ir_str:
                                continue
                            expr_str = str(cfg_node.expression) if cfg_node.expression else str(ir)
                            expr_lower = expr_str.lower()
                            # Check for both standard and Compound patterns in IR/Expression
                            if any(
                                kw in expr_lower
                                for kw in (
                                    "initialized",
                                    "_initialized",
                                    "initializing",
                                    "_initializing",
                                    "accrualblocknumber",
                                    "borrowindex",
                                )
                            ):
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
        slither_func_lookup: dict[str, Any] = {}
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
                            if "require(bool" not in ir_str and "assert(bool" not in ir_str:
                                continue
                            expr_str = str(cfg_node.expression) if cfg_node.expression else str(ir)
                            if "msg.sender" not in expr_str:
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
                                        if ndata.get("type") == "state_variable" and ndata.get("name") == target:
                                            require_targets.append(nid)
                                            break
                                    else:
                                        require_targets.append(target)

                            # Also detect function-call-style checks
                            if not target:
                                call_patterns = [
                                    r"hasRole\s*\(",
                                    r"_isAdmin\s*\(",
                                    r"isOwner\s*\(",
                                    r"_checkRole\s*\(",
                                    r"_checkOwner\s*\(",
                                    r"onlyRole\s*\(",
                                    r"_requireAuth\s*\(",
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
                if source and "msg.sender" in source:
                    sender_patterns = [
                        r"require\s*\(\s*msg\.sender\s*==\s*(\w+)",
                        r"require\s*\(\s*(\w+)\s*==\s*msg\.sender",
                        r"if\s*\(\s*msg\.sender\s*!=\s*(\w+)",
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
                            r"require\s*\(\s*hasRole\s*\(",
                            r"require\s*\(\s*_isAdmin\s*\(",
                            r"require\s*\(\s*isOwner\s*\(",
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
        modifier_categories: dict[str, str] = {}
        for node_id, node_data in self.graph.nodes(data=True):
            if node_data.get("type") == "modifier":
                modifier_categories[node_data.get("name", "")] = node_data.get("semantic_category", "custom")

        # Phase 3: Enrich function nodes
        for node_id, node_data in self.graph.nodes(data=True):
            if node_data.get("type") != "function":
                continue

            applied_mods = node_data.get("modifiers", [])
            equivalences: dict[str, str] = {}
            has_reentrancy_guard = False
            has_init_modifier = False

            for mod_name in applied_mods:
                cat = modifier_categories.get(mod_name)
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

    _SENSITIVITY_PATTERNS: dict[str, list[str]] = {
        "ACCOUNTING_CRITICAL": [
            "totalSupply",
            "totalBorrow",
            "totalBorrows",
            "totalDebt",
            "balance",
            "balances",
            "totalBalance",
            "reserve",
            "reserves",
            "exchangeRate",
            "borrowIndex",
            "supplyIndex",
            "accrued",
            "debt",
            "totalAssets",
            "totalShares",
            "totalStaked",
            "totalDeposits",
            "accountBorrows",
            "totalCash",
            "interestIndex",
            "borrowRate",
            "supplyRate",
            "totalReserves",
            "shares",
            "assets",
        ],
        "ACCESS_CRITICAL": [
            "owner",
            "_owner",
            "admin",
            "governance",
            "authority",
            "operator",
            "pendingOwner",
            "roles",
            "minters",
            "guardian",
            "comptroller",
            "paused",
            "pauseGuardian",
        ],
        "CAP_CRITICAL": [
            "cap",
            "maxSupply",
            "supplyCap",
            "borrowCap",
            "maxDeposit",
            "maxMint",
            "ceiling",
            "limit",
            "threshold",
            "maxBorrow",
            "mintCap",
            "maxWithdraw",
            "collateralFactor",
        ],
        "REWARD_CRITICAL": [
            "rewardRate",
            "rewardPerToken",
            "rewardPerBlock",
            "rewards",
            "earned",
            "accRewardPerShare",
            "bonusMultiplier",
            "emissionRate",
            "compRate",
            "compSpeeds",
            "compAccrued",
            "rewardIndex",
        ],
        "LIQUIDITY_CRITICAL": [
            "totalLiquidity",
            "poolBalance",
            "sqrtPrice",
            "liquidity",
            "tickLower",
            "tickUpper",
            "fee",
            "feeGrowth",
            "protocolFees",
            "kLast",
        ],
    }
