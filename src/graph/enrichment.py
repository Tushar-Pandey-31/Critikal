"""Graph enrichment: storage mutations, internal calls, write propagation, reachability."""

from collections import deque


class EnrichmentMixin:
    """Enriches function nodes with derived metadata via graph traversal."""

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
