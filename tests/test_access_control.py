import os
import sys
import pytest

# Add src to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

from analysis_engine import AnalysisEngine
from graph_builder import GraphBuilder
from utils.graph_queries import GraphQueries


# ================================================================
# Shared Fixture: Build graph once for all tests
# ================================================================
@pytest.fixture(scope="module")
def access_control_graph():
    """Builds the Knowledge Graph from the test contracts directory."""
    repo_path = os.path.join(os.getcwd(), 'tests', 'contracts')
    
    engine = AnalysisEngine()
    slither_obj = engine.run_analysis(repo_path)
    assert slither_obj is not None, "Slither analysis failed"
    
    builder = GraphBuilder()
    builder.build_graph(slither_obj)
    
    return builder.graph


@pytest.fixture(scope="module")
def queries(access_control_graph):
    """Creates a GraphQueries instance."""
    return GraphQueries(access_control_graph)


# ================================================================
# Story 2.2.1 — Modifier Extraction Engine
# ================================================================
class TestModifierExtraction:
    """Tests for Story 2.2.1: Modifier nodes with condition parsing."""

    def test_modifier_nodes_exist(self, access_control_graph):
        """Modifier definitions should create graph nodes with type='modifier'."""
        graph = access_control_graph
        
        modifier_nodes = [
            (nid, nd) for nid, nd in graph.nodes(data=True)
            if nd.get("type") == "modifier" and nd.get("contract") == "AccessControlTest"
        ]
        
        modifier_names = [nd["name"] for _, nd in modifier_nodes]
        print(f"\nFound {len(modifier_nodes)} modifier nodes: {modifier_names}")
        
        # Should have: onlyOwner, onlyAdmin, whenNotPaused, onlyTxOrigin, onlyRole
        assert len(modifier_nodes) >= 5, \
            f"Expected at least 5 modifier nodes, got {len(modifier_nodes)}: {modifier_names}"
        
        for expected in ["onlyOwner", "onlyAdmin", "whenNotPaused", "onlyTxOrigin", "onlyRole"]:
            assert expected in modifier_names, \
                f"Modifier '{expected}' not found. Found: {modifier_names}"

    def test_onlyOwner_conditions(self, access_control_graph):
        """onlyOwner should have require condition checking msg.sender == owner."""
        graph = access_control_graph
        mod_id = "AccessControlTest::modifier::onlyOwner"
        
        assert graph.has_node(mod_id), f"Node {mod_id} not found"
        mod_data = graph.nodes[mod_id]
        
        conditions = mod_data.get("conditions", [])
        assert len(conditions) >= 1, "onlyOwner should have at least 1 condition"
        
        cond = conditions[0]
        assert cond["type"] == "require", f"Expected 'require', got '{cond['type']}'"
        assert cond["checks_msg_sender"] == True, "onlyOwner should check msg.sender"
        assert cond["checks_tx_origin"] == False, "onlyOwner should NOT check tx.origin"
        
        print(f"✓ onlyOwner condition: {cond['expression']}")
        print(f"  compared_variable: {cond.get('compared_variable')}")

    def test_onlyOwner_pattern(self, access_control_graph):
        """onlyOwner should be classified as 'owner_check' pattern."""
        graph = access_control_graph
        mod_id = "AccessControlTest::modifier::onlyOwner"
        
        mod_data = graph.nodes[mod_id]
        assert mod_data.get("is_access_control") == True
        assert mod_data.get("access_control_pattern") == "owner_check"

    def test_onlyAdmin_pattern(self, access_control_graph):
        """onlyAdmin should be classified as 'role_mapping' pattern."""
        graph = access_control_graph
        mod_id = "AccessControlTest::modifier::onlyAdmin"
        
        assert graph.has_node(mod_id), f"Node {mod_id} not found"
        mod_data = graph.nodes[mod_id]
        
        assert mod_data.get("is_access_control") == True
        assert mod_data.get("access_control_pattern") == "role_mapping", \
            f"Expected 'role_mapping', got '{mod_data.get('access_control_pattern')}'"
        
        # Should check msg.sender
        conditions = mod_data.get("conditions", [])
        assert any(c.get("checks_msg_sender") for c in conditions)

    def test_whenNotPaused_pattern(self, access_control_graph):
        """whenNotPaused should be classified as 'boolean_flag' pattern."""
        graph = access_control_graph
        mod_id = "AccessControlTest::modifier::whenNotPaused"
        
        assert graph.has_node(mod_id), f"Node {mod_id} not found"
        mod_data = graph.nodes[mod_id]
        
        assert mod_data.get("access_control_pattern") == "boolean_flag", \
            f"Expected 'boolean_flag', got '{mod_data.get('access_control_pattern')}'"

    def test_onlyTxOrigin_pattern(self, access_control_graph):
        """onlyTxOrigin should be classified as 'tx_origin' pattern."""
        graph = access_control_graph
        mod_id = "AccessControlTest::modifier::onlyTxOrigin"
        
        assert graph.has_node(mod_id), f"Node {mod_id} not found"
        mod_data = graph.nodes[mod_id]
        
        assert mod_data.get("is_access_control") == True
        assert mod_data.get("access_control_pattern") == "tx_origin", \
            f"Expected 'tx_origin', got '{mod_data.get('access_control_pattern')}'"
        
        # Should check tx.origin
        conditions = mod_data.get("conditions", [])
        assert any(c.get("checks_tx_origin") for c in conditions)

    def test_onlyRole_pattern(self, access_control_graph):
        """onlyRole should be classified as 'role_mapping' pattern (hasRole)."""
        graph = access_control_graph
        mod_id = "AccessControlTest::modifier::onlyRole"
        
        assert graph.has_node(mod_id), f"Node {mod_id} not found"
        mod_data = graph.nodes[mod_id]
        
        assert mod_data.get("is_access_control") == True
        pattern = mod_data.get("access_control_pattern")
        # hasRole pattern should be role_mapping or owner_check
        assert pattern in ("role_mapping", "owner_check"), \
            f"Expected role-based pattern, got '{pattern}'"

    def test_has_modifier_edges(self, access_control_graph):
        """Contract should have HAS_MODIFIER edges to modifier nodes."""
        graph = access_control_graph
        
        has_modifier_edges = [
            (src, tgt) for src, tgt, data in graph.edges(data=True)
            if data.get("relationship") == "HAS_MODIFIER"
            and src == "AccessControlTest"
        ]
        
        assert len(has_modifier_edges) >= 5, \
            f"Expected at least 5 HAS_MODIFIER edges, got {len(has_modifier_edges)}"

    def test_modifier_state_variable_access(self, access_control_graph):
        """Modifiers should track which state variables they read."""
        graph = access_control_graph
        mod_id = "AccessControlTest::modifier::onlyOwner"
        
        mod_data = graph.nodes[mod_id]
        accessed_vars = mod_data.get("accesses_state_variables", [])
        
        # onlyOwner reads 'owner'
        assert any("owner" in v for v in accessed_vars), \
            f"onlyOwner should access 'owner' variable. Got: {accessed_vars}"


# ================================================================
# Story 2.2.2 — Function Access Mapping
# ================================================================
class TestFunctionAccessMapping:
    """Tests for Story 2.2.2: FunctionAccessProfile on function nodes."""

    def test_protected_function_with_modifier(self, access_control_graph):
        """setOwner (with onlyOwner) should have is_protected=True."""
        graph = access_control_graph
        func_id = "AccessControlTest::setOwner"
        
        assert graph.has_node(func_id), f"Node {func_id} not found"
        func_data = graph.nodes[func_id]
        
        assert func_data.get("is_protected") == True
        assert func_data.get("has_access_control") == True
        assert "onlyOwner" in func_data.get("access_control_modifiers", [])

    def test_unprotected_function(self, access_control_graph):
        """unsafeIncrement (no modifiers) should have is_protected=False."""
        graph = access_control_graph
        func_id = "AccessControlTest::unsafeIncrement"
        
        assert graph.has_node(func_id), f"Node {func_id} not found"
        func_data = graph.nodes[func_id]
        
        assert func_data.get("is_protected") == False
        assert func_data.get("has_access_control") == False
        assert len(func_data.get("access_control_modifiers", [])) == 0

    def test_inline_protected_function(self, access_control_graph):
        """inlineProtected (with inline require(msg.sender==owner)) should have is_protected=True."""
        graph = access_control_graph
        func_id = "AccessControlTest::inlineProtected"
        
        assert graph.has_node(func_id), f"Node {func_id} not found"
        func_data = graph.nodes[func_id]
        
        assert func_data.get("is_protected") == True
        assert func_data.get("has_inline_access_check") == True

    def test_multi_modifier_function(self, access_control_graph):
        """protectedPausableAction (onlyOwner + whenNotPaused) should have both modifiers."""
        graph = access_control_graph
        func_id = "AccessControlTest::protectedPausableAction"
        
        assert graph.has_node(func_id), f"Node {func_id} not found"
        func_data = graph.nodes[func_id]
        
        assert func_data.get("is_protected") == True
        ac_mods = func_data.get("access_control_modifiers", [])
        assert len(ac_mods) >= 1, f"Should have at least 1 access control modifier, got {ac_mods}"

    def test_view_function_not_protected(self, access_control_graph):
        """getBalance (view, no modifiers) should have is_protected=False."""
        graph = access_control_graph
        func_id = "AccessControlTest::getBalance"
        
        assert graph.has_node(func_id), f"Node {func_id} not found"
        func_data = graph.nodes[func_id]
        
        assert func_data.get("is_protected") == False
        assert func_data.get("has_access_control") == False

    def test_all_functions_have_access_profile(self, access_control_graph):
        """Every function node in AccessControlTest should have access profile fields."""
        graph = access_control_graph
        
        required_fields = [
            "has_access_control",
            "access_control_modifiers",
            "has_inline_access_check",
            "is_protected"
        ]
        
        for node_id, node_data in graph.nodes(data=True):
            if node_data.get("type") != "function":
                continue
            if node_data.get("contract") != "AccessControlTest":
                continue
            
            for field in required_fields:
                assert field in node_data, \
                    f"Function {node_id} missing field '{field}'"


# ================================================================
# Story 2.2.3 — Privileged Role Detection
# ================================================================
class TestPrivilegedRoleDetection:
    """Tests for Story 2.2.3: RoleProfile structures on contract nodes."""

    def test_privileged_roles_exist(self, access_control_graph):
        """AccessControlTest contract should have privileged_roles metadata."""
        graph = access_control_graph
        
        contract_data = graph.nodes.get("AccessControlTest", {})
        roles = contract_data.get("privileged_roles", [])
        
        assert len(roles) >= 1, f"Expected at least 1 privileged role, got {len(roles)}"
        
        role_names = [r["role_name"] for r in roles]
        print(f"\nDetected roles: {role_names}")

    def test_owner_role_detected(self, access_control_graph):
        """Owner role should be detected with correct protected functions."""
        graph = access_control_graph
        
        contract_data = graph.nodes.get("AccessControlTest", {})
        roles = contract_data.get("privileged_roles", [])
        
        owner_roles = [r for r in roles if r["role_name"] == "owner"]
        assert len(owner_roles) >= 1, f"Owner role not found. Roles: {[r['role_name'] for r in roles]}"
        
        owner_role = owner_roles[0]
        assert len(owner_role["protected_functions"]) >= 1, \
            "Owner role should protect at least 1 function"
        
        # setOwner should be protected by owner
        assert any("setOwner" in f for f in owner_role["protected_functions"]), \
            f"setOwner should be in protected functions. Got: {owner_role['protected_functions']}"
        
        assert owner_role["how_verified"] == "modifier"
        assert owner_role["pattern"] == "owner_check"
        
        print(f"✓ Owner role protects: {owner_role['protected_functions']}")

    def test_admin_role_detected(self, access_control_graph):
        """Admin role should be detected."""
        graph = access_control_graph
        
        contract_data = graph.nodes.get("AccessControlTest", {})
        roles = contract_data.get("privileged_roles", [])
        
        admin_roles = [r for r in roles if r["role_name"] == "admin"]
        assert len(admin_roles) >= 1, f"Admin role not found. Roles: {[r['role_name'] for r in roles]}"
        
        admin_role = admin_roles[0]
        assert any("adminWithdraw" in f for f in admin_role["protected_functions"]), \
            f"adminWithdraw should be protected by admin. Got: {admin_role['protected_functions']}"

    def test_role_profile_structure(self, access_control_graph):
        """Each RoleProfile should have all required fields."""
        graph = access_control_graph
        
        contract_data = graph.nodes.get("AccessControlTest", {})
        roles = contract_data.get("privileged_roles", [])
        
        required_fields = [
            "role_name", "protected_functions", "underlying_variable",
            "how_verified", "pattern"
        ]
        
        for role in roles:
            for field in required_fields:
                assert field in role, \
                    f"Role '{role.get('role_name')}' missing field '{field}'"


# ================================================================
# Story 2.2.4 — Unprotected Mutator Detection
# ================================================================
class TestUnprotectedMutatorDetection:
    """Tests for Story 2.2.4: Flagging unprotected state-changing functions."""

    def test_unsafe_increment_flagged(self, access_control_graph):
        """unsafeIncrement (public, writes state, no modifier) should be flagged."""
        graph = access_control_graph
        func_id = "AccessControlTest::unsafeIncrement"
        
        assert graph.has_node(func_id), f"Node {func_id} not found"
        func_data = graph.nodes[func_id]
        
        assert func_data.get("is_unprotected_mutator") == True, \
            "unsafeIncrement should be flagged as unprotected mutator"
        assert func_data.get("unprotected_risk_level") == "MEDIUM", \
            f"Expected MEDIUM risk, got {func_data.get('unprotected_risk_level')}"

    def test_unsafe_set_value_flagged(self, access_control_graph):
        """unsafeSetValue (external, writes state, no modifier) should be flagged."""
        graph = access_control_graph
        func_id = "AccessControlTest::unsafeSetValue"
        
        assert graph.has_node(func_id), f"Node {func_id} not found"
        func_data = graph.nodes[func_id]
        
        assert func_data.get("is_unprotected_mutator") == True

    def test_unsafe_deposit_high_risk(self, access_control_graph):
        """unsafeDeposit (payable + writes state + no modifier) should be HIGH risk."""
        graph = access_control_graph
        func_id = "AccessControlTest::unsafeDeposit"
        
        assert graph.has_node(func_id), f"Node {func_id} not found"
        func_data = graph.nodes[func_id]
        
        assert func_data.get("is_unprotected_mutator") == True
        assert func_data.get("unprotected_risk_level") == "HIGH", \
            f"Payable unprotected mutator should be HIGH risk, got {func_data.get('unprotected_risk_level')}"

    def test_protected_function_not_flagged(self, access_control_graph):
        """setOwner (has onlyOwner modifier) should NOT be flagged."""
        graph = access_control_graph
        func_id = "AccessControlTest::setOwner"
        
        func_data = graph.nodes[func_id]
        assert func_data.get("is_unprotected_mutator") == False, \
            "Protected function should NOT be flagged as unprotected mutator"

    def test_inline_protected_not_flagged(self, access_control_graph):
        """inlineProtected (inline require) should NOT be flagged."""
        graph = access_control_graph
        func_id = "AccessControlTest::inlineProtected"
        
        func_data = graph.nodes[func_id]
        assert func_data.get("is_unprotected_mutator") == False, \
            "Inline-protected function should NOT be flagged"

    def test_view_function_not_flagged(self, access_control_graph):
        """getBalance (view, no state writes) should NOT be flagged."""
        graph = access_control_graph
        func_id = "AccessControlTest::getBalance"
        
        func_data = graph.nodes[func_id]
        assert func_data.get("is_unprotected_mutator") == False, \
            "View function should NOT be flagged"

    def test_constructor_not_flagged(self, access_control_graph):
        """Constructor should NOT be flagged even though it writes state."""
        graph = access_control_graph
        
        constructor_candidates = [
            "AccessControlTest::constructor",
            "AccessControlTest::slitherConstructorVariables",
            "AccessControlTest::slitherConstructorConstantVariables"
        ]
        
        for candidate in constructor_candidates:
            if graph.has_node(candidate):
                func_data = graph.nodes[candidate]
                if func_data.get("is_constructor"):
                    assert func_data.get("is_unprotected_mutator") == False, \
                        "Constructor should NOT be flagged as unprotected mutator"


# ================================================================
# Query API Tests
# ================================================================
class TestAccessControlQueryAPI:
    """Tests for the 4 new query API methods."""

    def test_get_modifier_details(self, queries):
        """get_modifier_details should return full modifier structure."""
        result = queries.get_modifier_details("onlyOwner", "AccessControlTest")
        
        assert "error" not in result, f"Modifier lookup failed: {result}"
        assert result["name"] == "onlyOwner"
        assert result["is_access_control"] == True
        assert result["access_control_pattern"] == "owner_check"
        assert len(result["conditions"]) >= 1

    def test_get_modifier_details_not_found(self, queries):
        """get_modifier_details should return error for non-existent modifier."""
        result = queries.get_modifier_details("nonExistent")
        assert "error" in result

    def test_get_access_control_summary(self, queries):
        """get_access_control_summary should return profiles for all functions."""
        summary = queries.get_access_control_summary("AccessControlTest")
        
        assert len(summary) >= 5, f"Expected at least 5 functions, got {len(summary)}"
        
        # Verify required fields
        required_fields = [
            "function_id", "name", "contract", "visibility",
            "has_access_control", "is_protected", "writes_state"
        ]
        for entry in summary:
            for field in required_fields:
                assert field in entry, f"Missing field '{field}' in {entry.get('name')}"

    def test_get_access_control_summary_filter(self, queries):
        """get_access_control_summary should filter by contract."""
        summary = queries.get_access_control_summary("AccessControlTest")
        for entry in summary:
            assert entry["contract"] == "AccessControlTest"

    def test_get_privileged_roles(self, queries):
        """get_privileged_roles should return detected roles."""
        roles = queries.get_privileged_roles("AccessControlTest")
        
        assert len(roles) >= 1, f"Expected at least 1 role, got {len(roles)}"
        
        role_names = [r["role_name"] for r in roles]
        assert "owner" in role_names, f"Owner role not found. Got: {role_names}"

    def test_get_privileged_roles_structure(self, queries):
        """Each role from get_privileged_roles should have required fields."""
        roles = queries.get_privileged_roles("AccessControlTest")
        
        required_fields = [
            "contract", "role_name", "protected_functions",
            "underlying_variable", "how_verified", "pattern"
        ]
        for role in roles:
            for field in required_fields:
                assert field in role, \
                    f"Role '{role.get('role_name')}' missing field '{field}'"

    def test_get_unprotected_mutators(self, queries):
        """get_unprotected_mutators should return flagged functions."""
        mutators = queries.get_unprotected_mutators("AccessControlTest")
        
        assert len(mutators) >= 2, \
            f"Expected at least 2 unprotected mutators, got {len(mutators)}"
        
        mutator_names = [m["name"] for m in mutators]
        assert "unsafeIncrement" in mutator_names
        assert "unsafeSetValue" in mutator_names
        
        # Verify HIGH risk for payable
        deposit_mutators = [m for m in mutators if m["name"] == "unsafeDeposit"]
        if deposit_mutators:
            assert deposit_mutators[0]["risk_level"] == "HIGH"

    def test_get_unprotected_mutators_empty(self, queries):
        """get_unprotected_mutators with non-existent contract should return empty."""
        result = queries.get_unprotected_mutators("NonExistentContract")
        assert len(result) == 0

    def test_get_unprotected_mutators_excludes_protected(self, queries):
        """Protected functions should NOT appear in unprotected mutators."""
        mutators = queries.get_unprotected_mutators("AccessControlTest")
        mutator_names = [m["name"] for m in mutators]
        
        # These should NOT be in the list
        assert "setOwner" not in mutator_names, "setOwner is protected by onlyOwner"
        assert "adminWithdraw" not in mutator_names, "adminWithdraw is protected by onlyAdmin"
        assert "inlineProtected" not in mutator_names, "inlineProtected has inline check"
        assert "getBalance" not in mutator_names, "getBalance is view-only"


# ================================================================
# Run directly
# ================================================================
if __name__ == "__main__":
    print("=" * 60)
    print("Testing Access Control Modeling (Stories 2.2.1-2.2.4)")
    print("=" * 60)
    
    # Build graph once
    repo_path = os.path.join(os.getcwd(), 'tests', 'contracts')
    engine = AnalysisEngine()
    slither_obj = engine.run_analysis(repo_path)
    assert slither_obj is not None, "Slither analysis failed"
    
    builder = GraphBuilder()
    builder.build_graph(slither_obj)
    graph = builder.graph
    queries_obj = GraphQueries(graph)
    
    print(f"\nGraph Stats: {builder.get_graph_stats()}")
    
    # Quick summary
    print("\n--- Modifier Nodes ---")
    for nid, nd in graph.nodes(data=True):
        if nd.get("type") == "modifier" and nd.get("contract") == "AccessControlTest":
            print(f"  {nid}: pattern={nd.get('access_control_pattern')}, "
                  f"conditions={len(nd.get('conditions', []))}")
    
    print("\n--- Unprotected Mutators ---")
    for m in queries_obj.get_unprotected_mutators("AccessControlTest"):
        print(f"  {m['function_id']}: risk={m['risk_level']}")
    
    print("\n--- Privileged Roles ---")
    for r in queries_obj.get_privileged_roles("AccessControlTest"):
        print(f"  {r['role_name']}: protects {len(r['protected_functions'])} functions, "
              f"pattern={r['pattern']}")
    
    print("\n" + "=" * 60)
    print("Summary complete. Run 'pytest tests/test_access_control.py -v' for full validation.")
