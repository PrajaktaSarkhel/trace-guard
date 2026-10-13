import unittest
from backend.scenarios import ScenarioManager
from backend.mcp_server import TraceGuardMCPServer
from backend.agent import TraceGuardAgent
from backend.models import ActionStatus, NodeStatus

class TestTraceGuard(unittest.TestCase):
    def setUp(self):
        self.scenario_data = ScenarioManager.load_scenario_1()
        self.mcp = TraceGuardMCPServer(
            graph=self.scenario_data["graph"],
            siem_logs=self.scenario_data["siem_logs"],
            threat_intel=self.scenario_data["threat_intel"]
        )
        self.agent = TraceGuardAgent(mcp_server=self.mcp)

    def test_scenario_initialization(self):
        graph = self.scenario_data["graph"]
        self.assertTrue(graph.has_node("usr-alice"))
        self.assertTrue(graph.has_node("file-customer-ssn-export"))
        self.assertTrue(graph.has_node("ip-c2-exfil"))
        node = graph.get_node("usr-alice")
        self.assertEqual(node.label, "Alice Vance (Senior DevOps)")

    def test_graph_algorithms(self):
        graph = self.scenario_data["graph"]
        # Multi-hop neighbors
        neighbors = graph.get_neighbors("usr-alice")
        self.assertGreater(len(neighbors), 0)

        # Blast radius
        blast = graph.calculate_blast_radius("sess-alice-rogue", max_hops=3)
        self.assertGreater(blast["blast_radius_score"], 50.0)
        self.assertGreater(len(blast["crown_jewels_at_risk"]), 0)

        # Centrality
        centrality = graph.calculate_centrality()
        self.assertIn("top_bridge_nodes", centrality)

        # Attack path
        path = graph.find_attack_path("usr-alice", "ip-c2-exfil")
        self.assertIsNotNone(path)
        self.assertGreater(path["path_length"], 2)

    def test_mcp_tools(self):
        # 1. MCP Graph Query
        res_graph = self.mcp.call_tool("security_graph_query", {"action": "get_node", "node_id": "usr-alice"})
        self.assertTrue(res_graph["success"])
        self.assertEqual(res_graph["node"]["id"], "usr-alice")

        # 2. MCP SIEM log search
        res_siem = self.mcp.call_tool("siem_log_search", {"query": "alice"})
        self.assertTrue(res_siem["success"])
        self.assertGreater(res_siem["count"], 0)

        # 3. Threat intel lookup
        res_intel = self.mcp.call_tool("threat_intel_lookup", {"indicator": "194.26.29.112"})
        self.assertTrue(res_intel["success"])
        self.assertEqual(res_intel["intel"]["reputation"], "MALICIOUS")

        # 4. Risk assessment tool
        res_risk = self.mcp.call_tool("risk_assessment_tool", {"node_id": "sess-alice-rogue"})
        self.assertTrue(res_risk["success"])
        self.assertGreater(res_risk["composite_risk_score"], 70.0)

    def test_autonomous_agent_investigation(self):
        alert = self.scenario_data["alert"]
        events = []
        def on_event(e):
            events.append(e)

        report = self.agent.investigate_incident(alert, progress_callback=on_event)

        # Verify steps and hops
        self.assertGreaterEqual(len(events), 5)
        self.assertEqual(report.alert_id, alert.id)
        self.assertGreater(len(report.chain_of_evidence), 3)
        self.assertGreater(len(report.mitre_attack_mapping), 0)
        self.assertGreater(len(report.actions_taken) + len(report.pending_actions), 0)

        # Verify Human-in-the-Loop action approval
        pending = [a for a in report.pending_actions if a.status == ActionStatus.PENDING_APPROVAL]
        if pending:
            action_to_approve = pending[0]
            approved = self.mcp.approve_action(action_to_approve.action_id, approver="Chief Security Officer")
            self.assertIsNotNone(approved)
            self.assertEqual(approved.status, ActionStatus.EXECUTED)
            self.assertEqual(approved.approved_by, "Chief Security Officer")

if __name__ == "__main__":
    unittest.main()
