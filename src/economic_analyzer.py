import networkx as nx

class EconomicAnalyzer:
    def __init__(self, graph: nx.DiGraph):
        self.graph = graph

    def evaluate_chain_economic_impact(self, chain_desc: dict) -> float:
        """
        Evaluates the economic distortion risk of an exploit chain.
        Returns an economic_impact_score multiplier bounded between [1.0, 1.5].
        """
        steps = chain_desc.get("steps", [])
        combined_multiplier = 1.0
        
        flags = []
        
        for node_id in steps:
            node_data = self.graph.nodes.get(node_id, {})
            
            # Check for taint involvement in this node
            has_taint_involvement = (
                node_data.get("has_taint_risk", False)
                or len(node_data.get("taint_sources", [])) > 0
                or len(node_data.get("cross_function_taint_paths", [])) > 0
                or len(node_data.get("tainted_state_writes", [])) > 0
            )

            # We only evaluate economic distortion if the math involves attacker-controlled input (taint)
            if not has_taint_involvement:
                continue

            # 3. Denominator manipulation (ratio math with tainted input)
            if node_data.get("uses_ratio_math"):
                combined_multiplier += 0.2
                flags.append("DENOMINATOR_MANIPULATION_RISK")

            # 4. Precision Loss & Rounding Drift (reward index update with division and taint)
            if node_data.get("updates_reward_index") and node_data.get("uses_division"):
                combined_multiplier += 0.1
                flags.append("PRECISION_DRIFT_RISK")

            # 5. Unbounded Mint Detection (writes supply/shares without cap enforcement)
            # Some versions of graph_builder may not set cap_enforcement_flags if empty, use get with []
            missing_cap = "MISSING_CAP_ENFORCEMENT" in node_data.get("cap_enforcement_flags", [])
            
            # Default missing cap heuristic if flag wasn't available: 
            # If no access control or missing checks, assume missing cap.
            is_unprotected = not node_data.get("is_protected", False)
            
            if (node_data.get("writes_total_supply") or node_data.get("mints_shares_proportionally")):
                if missing_cap or is_unprotected:
                    combined_multiplier += 0.5
                    flags.append("UNBOUNDED_MINT_RISK")
                    node_data["unbounded_inflation_risk"] = True
                
        # Target requirements: explicit capping using min(1.5, combined_multiplier) -> no ranking chaos
        economic_impact_score = min(1.5, combined_multiplier)
        
        # Attach results to the chain desc
        chain_desc["economic_impact_score"] = economic_impact_score
        chain_desc["economic_distortion_flags"] = list(set(flags))
        
        return economic_impact_score
