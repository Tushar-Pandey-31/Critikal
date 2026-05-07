"""Risk scoring: global risk scores, exploit target scores, negative safety signals."""

from collections import deque
from typing import Any

from src.economic_analyzer import EconomicAnalyzer


class ScoringMixin:
    """Computes risk scores, exploit target scores, and negative safety evidence."""

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
    def _node_has_sensitive_action(self, node_data: dict[str, Any]) -> bool:
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

            structural = node_data.get("structural_score", 0)
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

            if node_data.get("cei_violation_only") or (node_data.get("state_write_after_external_call")
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
            # Phase 1.2: Invariant violation scoring — combined cap at 100
            invariant_score = node_data.get("invariant_violation_score", 0)
            total_accounting = min(accounting_score, 60) + min(invariant_score, 80)
            structural += min(total_accounting, 100)

            for key, cat in (
                ("supply_consistency_issue", "supply_consistency"),
                ("cap_enforcement_issue", "cap_bypass"),
                ("reward_drift_issue", "reward_drift"),
                ("monotonicity_issue", "monotonicity_violation"),
            ):
                if node_data.get(key) and cat not in risk_categories:
                    risk_categories.append(cat)

            if invariant_score > 0:
                risk_categories.append("invariant_violation")

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

            # Phase 2.1: Flash loan amplification risk
            flash_score = node_data.get("flash_loan_score", 0)
            if flash_score > 0:
                structural += min(flash_score, 70)
                risk_categories.append("flash_loan_amplifiable")

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

            has_titan_hits = bool(node_data.get("pattern_hits", []))

            if not (has_taint_involvement or has_state_mutation or has_sensitive_impact or has_titan_hits):
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

            has_titan_hits = bool(node_data.get("pattern_hits", []))

            if not (has_taint_involvement or has_state_mutation or has_sensitive_impact or has_titan_hits):
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
