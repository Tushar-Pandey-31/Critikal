"""
GraphBuilder — the main entry point for constructing the security knowledge graph.

Composes all analysis mixins into a single class. The build_graph() method
orchestrates the full pipeline: Slither IR → NetworkX DiGraph enriched with
access control, reentrancy, taint, invariant, and risk-scoring metadata.
"""

import json
from typing import Any

import networkx as nx
from slither.slither import Slither

from src.graph.access_control import AccessControlMixin
from src.graph.enrichment import EnrichmentMixin
from src.graph.nodes_edges import NodeEdgeMixin
from src.graph.reentrancy import ReentrancyMixin
from src.graph.scoring import ScoringMixin
from src.graph.state_transitions import StateTransitionMixin
from src.graph.vulnerability_detection import VulnerabilityDetectionMixin


class GraphBuilder(
    NodeEdgeMixin,
    EnrichmentMixin,
    AccessControlMixin,
    ReentrancyMixin,
    StateTransitionMixin,
    VulnerabilityDetectionMixin,
    ScoringMixin,
):
    def __init__(self):
        self.graph = nx.DiGraph()
        self._file_cache: dict[str, str] = {}
        self._inheritance_modifier_cache: dict[str, dict[str, Any]] = {}

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
        self._detect_flash_loan_attack_surface()  # Phase 2.1 — must run after oracle patterns
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

        # Story 4.2: Compute final risk scores
        self._compute_global_risk_scores()
        # Dev Story 5: Exploit Target Scoring Engine
        self._compute_exploit_target_scores()

        self._file_cache.clear()


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
