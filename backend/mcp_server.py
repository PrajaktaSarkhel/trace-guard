import json
import sys
from typing import Dict, List, Any, Optional
from datetime import datetime, timezone
from backend.models import NodeStatus, MitigationAction, ActionStatus
from backend.graph_engine import SecurityGraph

class TraceGuardMCPServer:
    """
    Model Context Protocol (MCP) Server for TraceGuard.
    Exposes graph queries, graph algorithms, SIEM log queries, threat intel,
    and remediation actions as standard MCP tools.
    """

    def __init__(self, graph: Optional[SecurityGraph] = None, siem_logs: Optional[List[Dict[str, Any]]] = None, threat_intel: Optional[Dict[str, Any]] = None):
        self.graph = graph or SecurityGraph()
        self.siem_logs = siem_logs or []
        self.threat_intel = threat_intel or {}
        self.actions_log: List[MitigationAction] = []

    def set_context(self, graph: SecurityGraph, siem_logs: List[Dict[str, Any]], threat_intel: Dict[str, Any]):
        self.graph = graph
        self.siem_logs = siem_logs
        self.threat_intel = threat_intel
        self.actions_log = []

    def get_tool_definitions(self) -> List[Dict[str, Any]]:
        """
        Returns MCP-compliant tool specifications.
        """
        return [
            {
                "name": "security_graph_query",
                "description": "Query the connected security graph. Perform multi-hop neighbor expansion, path finding, blast radius analysis, or centrality calculation across Users, Devices, Sessions, Permissions, Files, and IPs.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "action": {
                            "type": "string",
                            "enum": ["get_node", "get_neighbors", "expand_subgraph", "find_path", "blast_radius", "centrality"],
                            "description": "Graph query or algorithm to execute."
                        },
                        "node_id": {
                            "type": "string",
                            "description": "Primary node ID to inspect or start traversal from."
                        },
                        "target_node_id": {
                            "type": "string",
                            "description": "Target node ID (used when action is 'find_path')."
                        },
                        "direction": {
                            "type": "string",
                            "enum": ["both", "outgoing", "incoming"],
                            "description": "Direction of graph edges to follow (default: both)."
                        },
                        "max_hops": {
                            "type": "integer",
                            "description": "Maximum hop depth for expansion or blast radius (default: 2 or 3)."
                        }
                    },
                    "required": ["action"]
                }
            },
            {
                "name": "siem_log_search",
                "description": "Search raw SIEM, Okta, CloudTrail, and VPC flow logs to correlate graph nodes with raw security telemetry.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "query": {
                            "type": "string",
                            "description": "Keyword search term (e.g., username, IP, ARN, or filename)."
                        },
                        "node_id": {
                            "type": "string",
                            "description": "Optional node ID to filter relevant logs for."
                        }
                    }
                }
            },
            {
                "name": "threat_intel_lookup",
                "description": "Query threat intelligence database for IP reputation, known APT associations, bulletproof hosting, and abuse confidence score.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "indicator": {
                            "type": "string",
                            "description": "IP address or domain to look up."
                        }
                    },
                    "required": ["indicator"]
                }
            },
            {
                "name": "risk_assessment_tool",
                "description": "Calculate composite risk score for a node or sub-chain based on graph topology, crown-jewel proximity, and anomaly indicators.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "node_id": {
                            "type": "string",
                            "description": "Node ID to evaluate."
                        }
                    },
                    "required": ["node_id"]
                }
            },
            {
                "name": "execute_mitigation_action",
                "description": "Take action based on what the graph revealed. Execute containment actions (e.g. isolate device, revoke privilege, suspend user, terminate session) or request Human-in-the-Loop approval for high-impact actions.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "action_type": {
                            "type": "string",
                            "enum": ["ISOLATE_DEVICE", "SUSPEND_USER", "REVOKE_PERMISSION", "TERMINATE_SESSION", "CREATE_INCIDENT_TICKET"],
                            "description": "Type of remediation action to perform."
                        },
                        "target_node_id": {
                            "type": "string",
                            "description": "ID of the target node to remediate."
                        },
                        "reasoning": {
                            "type": "string",
                            "description": "Evidence-backed justification derived from graph traversal."
                        },
                        "force_immediate": {
                            "type": "boolean",
                            "description": "True to bypass approval if policy permits; otherwise generates approval request."
                        }
                    },
                    "required": ["action_type", "target_node_id", "reasoning"]
                }
            },
            {
                "name": "falkordb_cypher_query",
                "description": "Execute openCypher queries directly on FalkorDB for custom graph pattern matching, multi-hop traversals, or algorithmic analytics.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "cypher": {
                            "type": "string",
                            "description": "Cypher query to execute (e.g. MATCH (u:User)-[r]->(d) RETURN u, r, d LIMIT 25)."
                        },
                        "params": {
                            "type": "object",
                            "description": "Optional key-value parameters for query binding."
                        }
                    },
                    "required": ["cypher"]
                }
            }
        ]

    def call_tool(self, tool_name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """
        Executes an MCP tool and returns structured result.
        """
        if tool_name == "falkordb_cypher_query":
            cypher = arguments.get("cypher", "")
            params = arguments.get("params", {})
            return self.graph.query_cypher(cypher, params)

        elif tool_name == "security_graph_query":
            action = arguments.get("action")
            node_id = arguments.get("node_id")

            if action == "get_node":
                node = self.graph.get_node(node_id)
                return {"success": True, "node": node.model_dump() if node else None}

            elif action == "get_neighbors":
                direction = arguments.get("direction", "both")
                neighbors = self.graph.get_neighbors(node_id, direction=direction)
                return {"success": True, "node_id": node_id, "neighbors": neighbors, "count": len(neighbors)}

            elif action == "expand_subgraph":
                max_hops = arguments.get("max_hops", 2)
                subgraph = self.graph.expand_subgraph(node_id, max_hops=max_hops)
                return {"success": True, "subgraph": subgraph}

            elif action == "find_path":
                target_node_id = arguments.get("target_node_id")
                path = self.graph.find_attack_path(node_id, target_node_id)
                return {"success": True, "attack_path": path}

            elif action == "blast_radius":
                max_hops = arguments.get("max_hops", 3)
                blast = self.graph.calculate_blast_radius(node_id, max_hops=max_hops)
                return {"success": True, "blast_radius": blast}

            elif action == "centrality":
                centrality = self.graph.calculate_centrality()
                return {"success": True, "centrality": centrality}

            else:
                return {"success": False, "error": f"Unknown graph action: {action}"}

        elif tool_name == "siem_log_search":
            query = arguments.get("query", "").lower()
            node_id = arguments.get("node_id", "")
            matches = []

            for log in self.siem_logs:
                log_str = json.dumps(log).lower()
                if query and query in log_str:
                    matches.append(log)
                elif node_id and (node_id.lower() in log_str or (node_id.replace("usr-", "").lower() in log_str)):
                    matches.append(log)

            if not matches and not query and not node_id:
                matches = self.siem_logs[:5]

            return {"success": True, "matched_logs": matches, "count": len(matches)}

        elif tool_name == "threat_intel_lookup":
            indicator = arguments.get("indicator", "")
            intel = self.threat_intel.get(indicator)
            if intel:
                return {"success": True, "indicator": indicator, "intel": intel}
            else:
                return {
                    "success": True,
                    "indicator": indicator,
                    "intel": {
                        "reputation": "UNKNOWN",
                        "abuse_score": 0,
                        "note": "No active threat intelligence reports found."
                    }
                }

        elif tool_name == "risk_assessment_tool":
            node_id = arguments.get("node_id")
            node = self.graph.get_node(node_id)
            if not node:
                return {"success": False, "error": f"Node {node_id} not found."}

            blast = self.graph.calculate_blast_radius(node_id, max_hops=2)
            has_crown_jewels = len(blast.get("crown_jewels_at_risk", [])) > 0

            composite_risk = (node.risk_score * 0.5) + (blast.get("blast_radius_score", 0) * 0.5)
            if has_crown_jewels:
                composite_risk = min(100.0, composite_risk + 15.0)

            return {
                "success": True,
                "node_id": node_id,
                "base_risk": node.risk_score,
                "blast_radius_score": blast.get("blast_radius_score", 0),
                "composite_risk_score": round(composite_risk, 1),
                "crown_jewel_exposure": has_crown_jewels,
                "verdict": "CRITICAL" if composite_risk >= 85 else "HIGH" if composite_risk >= 65 else "MEDIUM"
            }

        elif tool_name == "execute_mitigation_action":
            action_type = arguments.get("action_type")
            target_node_id = arguments.get("target_node_id")
            reasoning = arguments.get("reasoning", "")
            force = arguments.get("force_immediate", False)

            target_node = self.graph.get_node(target_node_id)
            label = target_node.label if target_node else target_node_id

            requires_approval = True
            if action_type == "CREATE_INCIDENT_TICKET":
                requires_approval = False
            elif force:
                requires_approval = False

            action_id = f"ACT-{len(self.actions_log) + 1:03d}"
            status = ActionStatus.EXECUTED if not requires_approval else ActionStatus.PENDING_APPROVAL

            desc_map = {
                "ISOLATE_DEVICE": f"Quarantine device '{label}' from corporate network VPC",
                "SUSPEND_USER": f"Suspend user account '{label}' and invalidate active Okta/SSO tokens",
                "REVOKE_PERMISSION": f"Detach IAM policy and revoke elevated access '{label}'",
                "TERMINATE_SESSION": f"Kill active session token for '{label}'",
                "CREATE_INCIDENT_TICKET": f"File SOC P1 Incident ticket for compromised asset '{label}'"
            }

            action = MitigationAction(
                action_id=action_id,
                action_type=action_type,
                target_node_id=target_node_id,
                target_label=label,
                description=desc_map.get(action_type, f"Execute {action_type} on {label}"),
                requires_approval=requires_approval,
                status=status,
                reasoning=reasoning,
                approved_by="TraceGuard Autonomous Policy" if not requires_approval else None,
                executed_at=datetime.now(timezone.utc).isoformat() if not requires_approval else None
            )

            if status == ActionStatus.EXECUTED:
                self.graph.update_node_status(target_node_id, NodeStatus.CONTAINED)

            self.actions_log.append(action)

            return {
                "success": True,
                "action": action.model_dump(),
                "requires_human_approval": requires_approval,
                "status": status.value
            }

        return {"success": False, "error": f"Unknown tool: {tool_name}"}

    def approve_action(self, action_id: str, approver: str = "SOC Lead Analyst") -> Optional[MitigationAction]:
        """
        Human-in-the-Loop approval for pending mitigation actions.
        """
        for act in self.actions_log:
            if act.action_id == action_id and act.status == ActionStatus.PENDING_APPROVAL:
                act.status = ActionStatus.EXECUTED
                act.approved_by = approver
                act.executed_at = datetime.now(timezone.utc).isoformat()
                self.graph.update_node_status(act.target_node_id, NodeStatus.CONTAINED)
                return act
        return None

    def run_stdio_server(self):
        """
        MCP Standard JSON-RPC stdio server interface for external clients.
        """
        for line in sys.stdin:
            if not line.strip():
                continue
            try:
                request = json.loads(line)
                req_id = request.get("id")
                method = request.get("method")
                params = request.get("params", {})

                if method == "tools/list":
                    response = {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "result": {"tools": self.get_tool_definitions()}
                    }
                elif method == "tools/call":
                    name = params.get("name")
                    args = params.get("arguments", {})
                    tool_output = self.call_tool(name, args)
                    response = {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "result": {
                            "content": [
                                {
                                    "type": "text",
                                    "text": json.dumps(tool_output, indent=2)
                                }
                            ]
                        }
                    }
                else:
                    response = {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "error": {"code": -32601, "message": f"Method {method} not found"}
                    }
                sys.stdout.write(json.dumps(response) + "\n")
                sys.stdout.flush()
            except Exception as e:
                err_resp = {
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {"code": -32603, "message": str(e)}
                }
                sys.stdout.write(json.dumps(err_resp) + "\n")
                sys.stdout.flush()

if __name__ == "__main__":
    server = TraceGuardMCPServer()
    server.run_stdio_server()
