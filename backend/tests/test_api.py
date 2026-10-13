import unittest
from fastapi.testclient import TestClient
from backend.main import app

class TestTraceGuardAPI(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)

    def test_scenarios_endpoint(self):
        resp = self.client.get("/api/scenarios")
        self.assertEqual(resp.status_code, 200)
        scenarios = resp.json()
        self.assertGreaterEqual(len(scenarios), 3)

    def test_load_scenario_endpoint(self):
        resp = self.client.post("/api/scenarios/scenario_lateral_exfil/load")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["status"], "loaded")
        self.assertIn("graph_elements", data)

    def test_graph_endpoint(self):
        resp = self.client.get("/api/graph")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("elements", data)
        self.assertIn("centrality", data)

    def test_mcp_tools_endpoint(self):
        resp = self.client.get("/api/mcp/tools")
        self.assertEqual(resp.status_code, 200)
        tools = resp.json().get("tools", [])
        tool_names = [t["name"] for t in tools]
        self.assertIn("security_graph_query", tool_names)
        self.assertIn("execute_mitigation_action", tool_names)

    def test_investigate_endpoint(self):
        resp = self.client.post("/api/investigate")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("report", data)
        report = data["report"]
        self.assertEqual(report["severity"], "CRITICAL")
        self.assertGreater(len(report["chain_of_evidence"]), 2)

    def test_action_approve_endpoint(self):
        # Investigate first to generate pending action
        inv_resp = self.client.post("/api/investigate")
        report = inv_resp.json()["report"]
        pending = report.get("pending_actions", [])
        if pending:
            action_id = pending[0]["action_id"]
            app_resp = self.client.post(f"/api/actions/{action_id}/approve", json={"approver": "Security Lead"})
            self.assertEqual(app_resp.status_code, 200)
            app_data = app_resp.json()
            self.assertEqual(app_data["status"], "approved_and_executed")

    def test_frontend_serving(self):
        resp = self.client.get("/")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("TraceGuard", resp.text)

if __name__ == "__main__":
    unittest.main()
