
import os
import sys
import unittest

import networkx as nx

# Add src to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

from utils.graph_queries import GraphQueries


class TestGraphQueries(unittest.TestCase):
    def setUp(self):
        self.graph = nx.DiGraph()
        self.queries = GraphQueries(self.graph)

    def test_get_function_context(self):
        # Setup graph
        self.graph.add_node("A::func", type="function", source_code="function func() {}", modifiers=["view"])
        self.graph.add_node("B::caller", type="function")
        self.graph.add_node("C::callee", type="function")

        self.graph.add_edge("B::caller", "A::func", relationship="CALLS")
        self.graph.add_edge("A::func", "C::callee", relationship="CALLS")

        context = self.queries.get_function_context("A::func")

        self.assertEqual(context["node_id"], "A::func")
        self.assertEqual(context["source_code"], "function func() {}")
        self.assertEqual(context["code"], "function func() {}")
        self.assertIn("B::caller", context["callers"])
        self.assertIn("C::callee", context["callees"])

    def test_get_function_context_normalizes_dot_notation(self):
        self.graph.add_node("Vault::withdraw", type="function", source_code="function withdraw() {}")
        context = self.queries.get_function_context("Vault.withdraw")
        self.assertEqual(context["node_id"], "Vault::withdraw")
        self.assertEqual(context["source_code"], "function withdraw() {}")

    def test_find_state_mutators(self):
        self.graph.add_node("A::var", type="state_variable")
        self.graph.add_node("A::setter", type="function")
        self.graph.add_node("A::getter", type="function")

        self.graph.add_edge("A::setter", "A::var", relationship="WRITES")
        self.graph.add_edge("A::getter", "A::var", relationship="READS")

        mutators = self.queries.find_state_mutators("A::var")
        self.assertEqual(mutators, ["A::setter"])
        mutators_dot = self.queries.find_state_mutators("A.var")
        self.assertEqual(mutators_dot, ["A::setter"])

    def test_get_modifiers(self):
        self.graph.add_node("A::secure", type="function", modifiers=["onlyOwner", "nonReentrant"])
        self.graph.add_node("A::open", type="function", modifiers=[])

        self.assertEqual(self.queries.get_modifiers("A::secure"), ["onlyOwner", "nonReentrant"])
        self.assertEqual(self.queries.get_modifiers("A::open"), [])
        self.assertEqual(self.queries.get_modifiers("A.secure"), ["onlyOwner", "nonReentrant"])

    def test_verify_existence(self):
        self.graph.add_node("Real::node")
        self.assertTrue(self.queries.verify_existence("Real::node"))
        self.assertFalse(self.queries.verify_existence("Fake::node"))

if __name__ == '__main__':
    unittest.main()
