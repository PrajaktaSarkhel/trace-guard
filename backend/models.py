from enum import Enum
from typing import Dict, List, Any, Optional
from pydantic import BaseModel, Field
from datetime import datetime, timezone

class NodeType(str, Enum):
    USER = "USER"
    DEVICE = "DEVICE"
    SESSION = "SESSION"
    PERMISSION = "PERMISSION"
    FILE = "FILE"
    IP = "IP"
    ALERT = "ALERT"

class NodeStatus(str, Enum):
    BENIGN = "benign"
    SUSPICIOUS = "suspicious"
    COMPROMISED = "compromised"
    CONTAINED = "contained"

class EdgeType(str, Enum):
    AUTHENTICATED_ON = "AUTHENTICATED_ON"
    SPAWNED_SESSION = "SPAWNED_SESSION"
    ORIGINATED_FROM = "ORIGINATED_FROM"
    GRANTED_PRIVILEGE = "GRANTED_PRIVILEGE"
    ACCESSED_FILE = "ACCESSED_FILE"
    DOWNLOADED = "DOWNLOADED"
    EXFILTRATED_TO = "EXFILTRATED_TO"
    TRIGGERED_BY = "TRIGGERED_BY"
    CONNECTED_TO = "CONNECTED_TO"

class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class Node(BaseModel):
    id: str
    label: str
    type: NodeType
    status: NodeStatus = NodeStatus.BENIGN
    risk_score: float = Field(default=0.0, ge=0.0, le=100.0)
    crown_jewel: bool = False
    properties: Dict[str, Any] = Field(default_factory=dict)

class Edge(BaseModel):
    source: str
    target: str
    type: EdgeType
    weight: float = 1.0
    timestamp: Optional[str] = None
    properties: Dict[str, Any] = Field(default_factory=dict)

class SecurityAlert(BaseModel):
    id: str
    title: str
    severity: Severity
    source: str
    target_node_id: str
    mitre_tactic: str
    mitre_technique: str
    description: str
    timestamp: str

class InvestigationStep(BaseModel):
    step_id: int
    hop_number: int
    thought: str
    tool_called: str
    tool_args: Dict[str, Any] = Field(default_factory=dict)
    tool_result: Dict[str, Any] = Field(default_factory=dict)
    discovered_nodes: List[str] = Field(default_factory=list)
    risk_delta: float = 0.0
    mitre_tactic: Optional[str] = None
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

class ActionStatus(str, Enum):
    PENDING_APPROVAL = "PENDING_APPROVAL"
    APPROVED = "APPROVED"
    EXECUTED = "EXECUTED"
    REJECTED = "REJECTED"

class MitigationAction(BaseModel):
    action_id: str
    action_type: str
    target_node_id: str
    target_label: str
    description: str
    requires_approval: bool = True
    status: ActionStatus = ActionStatus.PENDING_APPROVAL
    reasoning: str
    approved_by: Optional[str] = None
    executed_at: Optional[str] = None

class IncidentReport(BaseModel):
    incident_id: str
    alert_id: str
    severity: Severity
    summary: str
    attack_narrative: str
    chain_of_evidence: List[Dict[str, Any]]
    mitre_attack_mapping: List[Dict[str, str]]
    blast_radius: Dict[str, Any]
    timeline: List[Dict[str, Any]]
    actions_taken: List[MitigationAction]
    pending_actions: List[MitigationAction]
    investigation_duration_sec: float
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
