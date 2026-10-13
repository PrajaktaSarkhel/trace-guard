import os
import asyncio
from typing import Dict, Any, Optional
from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from backend.scenarios import ScenarioManager
from backend.mcp_server import TraceGuardMCPServer
from backend.agent import TraceGuardAgent
from backend.models import SecurityAlert, Severity

app = FastAPI(
    title="TraceGuard API",
    description="Autonomous Security Incident Investigator using Connected Data and MCP",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

active_scenario: Dict[str, Any] = ScenarioManager.load_scenario_1()
mcp_server = TraceGuardMCPServer(
    graph=active_scenario["graph"],
    siem_logs=active_scenario["siem_logs"],
    threat_intel=active_scenario["threat_intel"]
)
agent = TraceGuardAgent(mcp_server=mcp_server)
last_report: Optional[Dict[str, Any]] = None

@app.get("/api/scenarios")
def get_scenarios():
    """List all pre-configured enterprise incident scenarios."""
    return [
        {
            "id": "scenario_lateral_exfil",
            "name": "Scenario 1: Lateral Movement & Cloud S3 Exfiltration",
            "category": "Credential Theft & Exfiltration",
            "description": "Impossible travel login -> Shared bastion host -> IAM Admin escalation -> Sensitive PII accessed -> Exfiltration to Russian C2 IP.",
            "target": "Alice Vance (usr-alice)"
        },
        {
            "id": "scenario_insider_sabotage",
            "name": "Scenario 2: Insider Threat & Supply Chain Code Tampering",
            "category": "Software Supply Chain & Persistence",
            "description": "Departing engineer uses personal BYOD laptop via Tor Exit node at 03:30 AM to bypass branch protection and inject backdoor.",
            "target": "Charlie Ray (usr-charlie)"
        },
        {
            "id": "scenario_ransomware_staging",
            "name": "Scenario 3: Ransomware Precursor & Backup Token Hijacking",
            "category": "Inhibit System Recovery & Ransomware",
            "description": "Compromised Kubelet worker node leaks backup service token used to delete RDS snapshots and share databases externally.",
            "target": "svc-backup-daemon (usr-svc-backup)"
        }
    ]

@app.post("/api/scenarios/{scenario_id}/load")
def load_scenario(scenario_id: str):
    """Loads a scenario into active memory."""
    global active_scenario, mcp_server, agent, last_report
    last_report = None

    if scenario_id == "scenario_lateral_exfil":
        active_scenario = ScenarioManager.load_scenario_1()
    elif scenario_id == "scenario_insider_sabotage":
        active_scenario = ScenarioManager.load_scenario_2()
    elif scenario_id == "scenario_ransomware_staging":
        active_scenario = ScenarioManager.load_scenario_3()
    else:
        raise HTTPException(status_code=404, detail="Scenario not found")

    mcp_server.set_context(
        graph=active_scenario["graph"],
        siem_logs=active_scenario["siem_logs"],
        threat_intel=active_scenario["threat_intel"]
    )
    agent = TraceGuardAgent(mcp_server=mcp_server)

    return {
        "status": "loaded",
        "scenario_id": active_scenario["scenario_id"],
        "name": active_scenario["name"],
        "alert": active_scenario["alert"].model_dump(),
        "graph_elements": active_scenario["graph"].to_cytoscape_elements(),
        "siem_logs_count": len(active_scenario["siem_logs"])
    }

@app.get("/api/graph")
def get_current_graph():
    """Returns the current state of the connected security graph in Cytoscape format."""
    return {
        "elements": mcp_server.graph.to_cytoscape_elements(),
        "centrality": mcp_server.graph.calculate_centrality()
    }

@app.get("/api/mcp/tools")
def get_mcp_tools():
    """Lists available MCP tools adhering to the Model Context Protocol."""
    return {"tools": mcp_server.get_tool_definitions()}

class ToolCallRequest(BaseModel):
    name: str
    arguments: Dict[str, Any]

@app.post("/api/mcp/call")
def call_mcp_tool(req: ToolCallRequest):
    """Directly invokes an MCP tool."""
    res = mcp_server.call_tool(req.name, req.arguments)
    return res

@app.post("/api/investigate")
def investigate_sync():
    """Triggers autonomous investigation synchronously and returns full report."""
    global last_report
    alert = active_scenario["alert"]
    report = agent.investigate_incident(alert)
    last_report = report.model_dump()
    return {
        "report": last_report,
        "graph_elements": mcp_server.graph.to_cytoscape_elements()
    }

@app.websocket("/ws/investigate")
async def investigate_stream(websocket: WebSocket):
    """
    WebSocket endpoint streaming live hop-by-hop agent thoughts,
    MCP tool calls, risk changes, and real-time graph updates.
    """
    await websocket.accept()
    global last_report

    try:
        alert = active_scenario["alert"]
        queue = asyncio.Queue()

        def callback(event: Dict[str, Any]):
            queue.put_nowait(event)

        loop = asyncio.get_event_loop()
        future = loop.run_in_executor(None, agent.investigate_incident, alert, callback)

        while not future.done() or not queue.empty():
            try:
                event = await asyncio.wait_for(queue.get(), timeout=0.1)
                await websocket.send_json(event)
                await asyncio.sleep(0.3)
            except asyncio.TimeoutError:
                continue

        report = future.result()
        last_report = report.model_dump()

        await websocket.send_json({
            "type": "final_update",
            "report": last_report,
            "graph_elements": mcp_server.graph.to_cytoscape_elements()
        })

    except WebSocketDisconnect:
        pass
    except Exception as e:
        await websocket.send_json({"type": "error", "error": str(e)})
    finally:
        await websocket.close()

class ActionApproveRequest(BaseModel):
    approver: str = "Lead Security Analyst"

@app.post("/api/actions/{action_id}/approve")
def approve_mitigation_action(action_id: str, req: ActionApproveRequest):
    """Human-in-the-Loop approval for containment action."""
    action = mcp_server.approve_action(action_id, approver=req.approver)
    if not action:
        raise HTTPException(status_code=404, detail="Pending action not found")
    return {
        "status": "approved_and_executed",
        "action": action.model_dump(),
        "graph_elements": mcp_server.graph.to_cytoscape_elements()
    }

class CustomAlertRequest(BaseModel):
    title: str
    target_node_id: str
    severity: str = "HIGH"
    description: str

@app.post("/api/custom-alert")
def inject_custom_alert(req: CustomAlertRequest):
    """Injects a custom alert into the active scenario."""
    if not mcp_server.graph.has_node(req.target_node_id):
        raise HTTPException(status_code=400, detail=f"Node {req.target_node_id} does not exist in graph")

    custom_alert = SecurityAlert(
        id=f"ALT-USER-{os.urandom(2).hex()}",
        title=req.title,
        severity=Severity(req.severity),
        source="Custom Alert Injector",
        target_node_id=req.target_node_id,
        mitre_tactic="Custom Anomaly",
        mitre_technique="T1078 (Account Use)",
        description=req.description,
        timestamp="2026-10-11T12:00:00Z"
    )
    active_scenario["alert"] = custom_alert
    return {"status": "injected", "alert": custom_alert.model_dump()}

frontend_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "frontend")
if os.path.exists(frontend_dir):
    app.mount("/", StaticFiles(directory=frontend_dir, html=True), name="frontend")
