from typing import Dict, List, Any
from backend.models import Node, Edge, NodeType, EdgeType, NodeStatus, SecurityAlert, Severity
from backend.graph_engine import SecurityGraph

class ScenarioManager:
    """
    Manages realistic enterprise scenarios for TraceGuard.
    Each scenario contains:
    - Initial alert
    - Connected security graph (Users, Devices, Sessions, Permissions, Files, IPs)
    - Correlated raw SIEM/Audit logs
    - Threat Intelligence feeds
    """

    @staticmethod
    def load_scenario_1() -> Dict[str, Any]:
        """
        Scenario 1: Lateral Movement & S3 Data Exfiltration
        Chain: Impossible Travel Login -> Shared Bastion Host -> Rogue IAM Admin Escalation ->
               Sensitive Customer PII Accessed -> Exfiltration to Foreign C2 IP.
        """
        graph = SecurityGraph()

        # Nodes
        nodes = [
            Node(
                id="usr-alice",
                label="Alice Vance (Senior DevOps)",
                type=NodeType.USER,
                status=NodeStatus.SUSPICIOUS,
                risk_score=75.0,
                crown_jewel=False,
                properties={
                    "email": "alice.vance@acmecorp.com",
                    "department": "Platform Engineering",
                    "mfa_method": "SMS (Vulnerable to SIM swap)",
                    "clearance": "Confidential"
                }
            ),
            Node(
                id="dev-mac-alice",
                label="Alice's Corporate MacBook",
                type=NodeType.DEVICE,
                status=NodeStatus.BENIGN,
                risk_score=15.0,
                crown_jewel=False,
                properties={
                    "hostname": "mac-alice-09.corp.acmecorp.com",
                    "os": "macOS Sonoma 14.5",
                    "ip_address": "10.0.14.88",
                    "is_managed": True,
                    "compliance": "Compliant"
                }
            ),
            Node(
                id="dev-bastion-01",
                label="Shared Bastion Jump Host (srv-bastion-prod)",
                type=NodeType.DEVICE,
                status=NodeStatus.COMPROMISED,
                risk_score=90.0,
                crown_jewel=True,
                properties={
                    "hostname": "srv-bastion-01.infra.acmecorp.com",
                    "os": "Ubuntu 22.04 LTS",
                    "ip_address": "10.100.1.5",
                    "is_managed": True,
                    "open_ports": [22, 443, 8080],
                    "role": "Production Ingress Gateway"
                }
            ),
            Node(
                id="sess-alice-legit",
                label="Alice Corporate Work Session",
                type=NodeType.SESSION,
                status=NodeStatus.BENIGN,
                risk_score=10.0,
                crown_jewel=False,
                properties={
                    "start_time": "2026-10-11T09:12:00Z",
                    "geo_location": "San Francisco, CA, US",
                    "auth_method": "Okta SSO + FIDO2",
                    "ip_address": "198.51.100.22"
                }
            ),
            Node(
                id="sess-alice-rogue",
                label="Anomalous Remote SSH Session",
                type=NodeType.SESSION,
                status=NodeStatus.COMPROMISED,
                risk_score=95.0,
                crown_jewel=False,
                properties={
                    "start_time": "2026-10-11T02:14:18Z",
                    "geo_location": "St. Petersburg, Russia",
                    "auth_method": "SSH Key (compromised id_ed25519)",
                    "ip_address": "194.26.29.112",
                    "is_anomaly": True
                }
            ),
            Node(
                id="perm-devops-base",
                label="DevOps-Base-Read Role",
                type=NodeType.PERMISSION,
                status=NodeStatus.BENIGN,
                risk_score=20.0,
                crown_jewel=False,
                properties={
                    "system": "AWS IAM / Kubernetes",
                    "privilege_level": "Read/List",
                    "assigned_at": "2025-01-15T00:00:00Z"
                }
            ),
            Node(
                id="perm-iam-root-admin",
                label="AWS-AdministratorAccess (Privilege Escalation)",
                type=NodeType.PERMISSION,
                status=NodeStatus.COMPROMISED,
                risk_score=98.0,
                crown_jewel=True,
                properties={
                    "system": "AWS IAM",
                    "privilege_level": "Full Administrative Control (*:*)",
                    "policy_arn": "arn:aws:iam::aws:policy/AdministratorAccess",
                    "modified_time": "2026-10-11T02:18:04Z",
                    "anomaly_note": "Attached without change ticket or peer approval"
                }
            ),
            Node(
                id="file-customer-ssn-export",
                label="customers_ssn_vault_2026.parquet",
                type=NodeType.FILE,
                status=NodeStatus.COMPROMISED,
                risk_score=99.0,
                crown_jewel=True,
                properties={
                    "s3_path": "s3://acme-finance-vault/restricted/customers_ssn_vault_2026.parquet",
                    "classification": "RESTRICTED PII",
                    "records_count": 450000,
                    "file_size": "3.8 GB",
                    "encryption": "AWS KMS"
                }
            ),
            Node(
                id="file-kubeconfig-prod",
                label="/etc/kubernetes/admin.conf (Cluster Root Key)",
                type=NodeType.FILE,
                status=NodeStatus.SUSPICIOUS,
                risk_score=85.0,
                crown_jewel=True,
                properties={
                    "path": "/etc/kubernetes/admin.conf",
                    "classification": "HIGH_SECRET_CREDENTIAL",
                    "target": "EKS Production Cluster"
                }
            ),
            Node(
                id="ip-c2-exfil",
                label="194.26.29.112 (Known Adversary C2 / Bulletproof IP)",
                type=NodeType.IP,
                status=NodeStatus.COMPROMISED,
                risk_score=100.0,
                crown_jewel=False,
                properties={
                    "ip_address": "194.26.29.112",
                    "country": "Russia",
                    "asn": "AS49981 WorldStream B.V.",
                    "abuse_confidence_score": 98,
                    "threat_type": "Data Exfiltration Endpoint / Cobalt Strike C2"
                }
            ),
            Node(
                id="usr-bob-contractor",
                label="Bob Martinez (Contractor)",
                type=NodeType.USER,
                status=NodeStatus.BENIGN,
                risk_score=25.0,
                crown_jewel=False,
                properties={
                    "email": "bob.contractor@external-vendor.com",
                    "department": "External SRE Support"
                }
            )
        ]

        for n in nodes:
            graph.add_node(n)

        # Edges
        edges = [
            Edge(source="usr-alice", target="dev-mac-alice", type=EdgeType.AUTHENTICATED_ON, properties={"frequency": "Daily"}),
            Edge(source="usr-alice", target="sess-alice-legit", type=EdgeType.SPAWNED_SESSION, properties={"time": "09:12:00Z"}),
            Edge(source="usr-alice", target="sess-alice-rogue", type=EdgeType.SPAWNED_SESSION, properties={"time": "02:14:18Z", "flag": "Off-hours anomaly"}),
            Edge(source="sess-alice-rogue", target="ip-c2-exfil", type=EdgeType.ORIGINATED_FROM, properties={"remote_port": 49123}),
            Edge(source="sess-alice-rogue", target="dev-bastion-01", type=EdgeType.AUTHENTICATED_ON, properties={"protocol": "SSH", "key": "alice_shared"}),
            Edge(source="usr-bob-contractor", target="dev-bastion-01", type=EdgeType.AUTHENTICATED_ON, properties={"note": "Shared jump host"}),
            Edge(source="usr-alice", target="perm-devops-base", type=EdgeType.GRANTED_PRIVILEGE, properties={"default": True}),
            Edge(source="sess-alice-rogue", target="perm-iam-root-admin", type=EdgeType.GRANTED_PRIVILEGE, properties={"action": "AttachUserPolicy", "time": "02:18:04Z"}),
            Edge(source="sess-alice-rogue", target="file-customer-ssn-export", type=EdgeType.ACCESSED_FILE, properties={"action": "s3:GetObject", "bytes_transferred": 3879731200, "time": "02:22:15Z"}),
            Edge(source="sess-alice-rogue", target="file-kubeconfig-prod", type=EdgeType.ACCESSED_FILE, properties={"action": "read", "time": "02:20:00Z"}),
            Edge(source="file-customer-ssn-export", target="ip-c2-exfil", type=EdgeType.EXFILTRATED_TO, properties={"egress_bytes": "3.8 GB", "dest_port": 443, "time": "02:24:30Z"})
        ]

        for e in edges:
            graph.add_edge(e)

        # Alert
        alert = SecurityAlert(
            id="ALT-2026-1011",
            title="Critical: Impossible Travel & Anomalous Egress Detected",
            severity=Severity.CRITICAL,
            source="AWS GuardDuty & Okta Identity Engine",
            target_node_id="usr-alice",
            mitre_tactic="Initial Access & Exfiltration",
            mitre_technique="T1078.004 (Valid Accounts: Cloud Accounts) + T1567 (Exfiltration Over Web Service)",
            description=(
                "User 'alice.vance@acmecorp.com' authenticated from St. Petersburg, Russia (194.26.29.112) "
                "only 5 hours after active session in San Francisco, CA. Session logged into shared infrastructure "
                "jump host 'srv-bastion-prod' followed by high-volume S3 data transfer."
            ),
            timestamp="2026-10-11T02:25:00Z"
        )

        # SIEM / Audit Logs
        siem_logs = [
            {
                "timestamp": "2026-10-11T02:14:18Z",
                "source": "Okta / SSH Audit",
                "event": "SSH_LOGIN_SUCCESS",
                "user": "alice.vance",
                "device": "srv-bastion-01",
                "src_ip": "194.26.29.112",
                "geo": "St. Petersburg, Russia",
                "anomaly": "Impossible travel speed: 5,400 mph"
            },
            {
                "timestamp": "2026-10-11T02:18:04Z",
                "source": "AWS CloudTrail",
                "event": "AttachUserPolicy",
                "actor": "alice.vance",
                "policy": "arn:aws:iam::aws:policy/AdministratorAccess",
                "status": "Success",
                "user_agent": "aws-cli/2.15.15 Python/3.11.8 Linux/Ubuntu",
                "src_ip": "194.26.29.112"
            },
            {
                "timestamp": "2026-10-11T02:22:15Z",
                "source": "AWS S3 Access Log",
                "event": "REST.GET.OBJECT",
                "bucket": "acme-finance-vault",
                "key": "restricted/customers_ssn_vault_2026.parquet",
                "bytes_sent": 3879731200,
                "status": "200 OK",
                "src_ip": "194.26.29.112"
            },
            {
                "timestamp": "2026-10-11T02:24:30Z",
                "source": "VPC Flow Logs",
                "event": "OUTBOUND_TRANSFER",
                "src": "10.100.1.5:49123",
                "dst": "194.26.29.112:443",
                "packets": 2841000,
                "bytes": 3880100000,
                "flag": "HIGH_VOLUME_EGRESS"
            }
        ]

        # Threat Intel
        threat_intel = {
            "194.26.29.112": {
                "reputation": "MALICIOUS",
                "threat_actor": "APT-29 / Midnight Blizzard affiliate proxy",
                "abuse_score": 98,
                "country": "Russia",
                "isp": "WorldStream B.V. Bulletproof Hosting",
                "tor_exit": False,
                "botnet_c2": True
            }
        }

        return {
            "scenario_id": "scenario_lateral_exfil",
            "name": "Lateral Movement & Cloud S3 Exfiltration",
            "category": "Credential Theft & Data Exfiltration",
            "alert": alert,
            "graph": graph,
            "siem_logs": siem_logs,
            "threat_intel": threat_intel
        }

    @staticmethod
    def load_scenario_2() -> Dict[str, Any]:
        """
        Scenario 2: Insider Threat & Supply Chain Code Tampering
        """
        graph = SecurityGraph()

        nodes = [
            Node(
                id="usr-charlie",
                label="Charlie Ray (Staff Developer)",
                type=NodeType.USER,
                status=NodeStatus.SUSPICIOUS,
                risk_score=80.0,
                properties={"email": "charlie.ray@acmecorp.com", "role": "Senior Core Dev", "status_hr": "Notice Period / Resignation Active"}
            ),
            Node(
                id="dev-byod-laptop",
                label="Charlie's Personal Laptop (BYOD)",
                type=NodeType.DEVICE,
                status=NodeStatus.COMPROMISED,
                risk_score=75.0,
                properties={"hostname": "charlie-thinkpad.home", "is_managed": False, "compliance": "Non-compliant"}
            ),
            Node(
                id="sess-late-night-token",
                label="03:30 AM GitHub Personal Access Token",
                type=NodeType.SESSION,
                status=NodeStatus.COMPROMISED,
                risk_score=90.0,
                properties={"start_time": "2026-10-11T03:30:12Z", "token_name": "ghp_emergency_deploy", "ip": "185.220.101.5"}
            ),
            Node(
                id="perm-repo-release-write",
                label="Repo-Prod-Release: ForcePush & BypassReviews",
                type=NodeType.PERMISSION,
                status=NodeStatus.COMPROMISED,
                risk_score=95.0,
                crown_jewel=True,
                properties={"system": "GitHub Enterprise", "privilege": "Branch Protection Bypass"}
            ),
            Node(
                id="file-auth-service-core",
                label="auth-service-core.go (SSO Gateway)",
                type=NodeType.FILE,
                status=NodeStatus.COMPROMISED,
                risk_score=96.0,
                crown_jewel=True,
                properties={"repo": "acme/auth-gateway", "branch": "main", "diff": "Hardcoded backdoor token added to jwt_validator.go"}
            ),
            Node(
                id="ip-tor-exit",
                label="185.220.101.5 (Tor Exit Node)",
                type=NodeType.IP,
                status=NodeStatus.COMPROMISED,
                risk_score=100.0,
                properties={"ip_address": "185.220.101.5", "country": "Germany", "tor_exit": True}
            )
        ]

        for n in nodes:
            graph.add_node(n)

        edges = [
            Edge(source="usr-charlie", target="dev-byod-laptop", type=EdgeType.AUTHENTICATED_ON),
            Edge(source="usr-charlie", target="sess-late-night-token", type=EdgeType.SPAWNED_SESSION),
            Edge(source="sess-late-night-token", target="ip-tor-exit", type=EdgeType.ORIGINATED_FROM),
            Edge(source="sess-late-night-token", target="perm-repo-release-write", type=EdgeType.GRANTED_PRIVILEGE),
            Edge(source="sess-late-night-token", target="file-auth-service-core", type=EdgeType.ACCESSED_FILE, properties={"action": "git push --force"}),
        ]

        for e in edges:
            graph.add_edge(e)

        alert = SecurityAlert(
            id="ALT-2026-1022",
            title="High: Branch Protection Bypass & Code Tampering Detected",
            severity=Severity.HIGH,
            source="GitHub Enterprise Security & Branch Auditor",
            target_node_id="usr-charlie",
            mitre_tactic="Persistence & Defense Evasion",
            mitre_technique="T1195.001 (Supply Chain Compromise) + T1556 (Modify Authentication Process)",
            description=(
                "Engineer in notice period bypassed PR reviews at 03:30 AM via Tor Exit Node (185.220.101.5) "
                "to commit code modifications to critical authentication service repository."
            ),
            timestamp="2026-10-11T03:32:00Z"
        )

        siem_logs = [
            {
                "timestamp": "2026-10-11T03:30:12Z",
                "source": "GitHub Audit Log",
                "event": "PAT_AUTHENTICATE",
                "user": "charlie.ray",
                "token_id": "ghp_emergency_deploy",
                "src_ip": "185.220.101.5"
            },
            {
                "timestamp": "2026-10-11T03:31:05Z",
                "source": "GitHub Audit Log",
                "event": "BRANCH_PROTECTION_OVERRIDE",
                "repo": "acme/auth-gateway",
                "branch": "main",
                "actor": "charlie.ray"
            },
            {
                "timestamp": "2026-10-11T03:31:45Z",
                "source": "Git Hook Auditing",
                "event": "COMMIT_PUSH_FORCE",
                "commit": "9b1f4a2",
                "modified_files": ["jwt_validator.go"],
                "status": "Pushed directly without approval"
            }
        ]

        threat_intel = {
            "185.220.101.5": {
                "reputation": "ANONYMOUS_PROXY",
                "threat_actor": "Tor Project Anonymity Network",
                "abuse_score": 92,
                "country": "Germany",
                "tor_exit": True
            }
        }

        return {
            "scenario_id": "scenario_insider_sabotage",
            "name": "Insider Threat & Supply Chain Code Tampering",
            "category": "Insider Threat & Software Supply Chain",
            "alert": alert,
            "graph": graph,
            "siem_logs": siem_logs,
            "threat_intel": threat_intel
        }

    @staticmethod
    def load_scenario_3() -> Dict[str, Any]:
        """
        Scenario 3: Ransomware Precursor & Backup Token Hijacking
        """
        graph = SecurityGraph()

        nodes = [
            Node(
                id="usr-svc-backup",
                label="svc-backup-daemon (Service Account)",
                type=NodeType.USER,
                status=NodeStatus.COMPROMISED,
                risk_score=92.0,
                properties={"role": "Infrastructure Automated Backup", "account_type": "Non-Human Identity"}
            ),
            Node(
                id="dev-worker-node-4",
                label="k8s-worker-node-04 (Compromised Cluster Node)",
                type=NodeType.DEVICE,
                status=NodeStatus.COMPROMISED,
                risk_score=88.0,
                properties={"cluster": "production-us-east", "container_runtime": "containerd", "is_managed": True}
            ),
            Node(
                id="sess-token-replay",
                label="Kubelet Token Replay Session",
                type=NodeType.SESSION,
                status=NodeStatus.COMPROMISED,
                risk_score=95.0,
                properties={"start_time": "2026-10-11T04:10:00Z", "auth": "Bearer ServiceAccountToken"}
            ),
            Node(
                id="perm-db-snapshot-delete",
                label="RDS:DeleteDBSnapshot & EncryptWithCustomKMS",
                type=NodeType.PERMISSION,
                status=NodeStatus.COMPROMISED,
                risk_score=99.0,
                crown_jewel=True,
                properties={"system": "AWS RDS", "privilege": "Destructive Backup Erasure"}
            ),
            Node(
                id="file-db-dump-production",
                label="rds-prod-master-snapshot-20261010",
                type=NodeType.FILE,
                status=NodeStatus.COMPROMISED,
                risk_score=98.0,
                crown_jewel=True,
                properties={"target": "PostgreSQL Core Database", "size": "420 GB"}
            ),
            Node(
                id="ip-ransom-c2",
                label="45.154.255.89 (Ransomware Command & Control)",
                type=NodeType.IP,
                status=NodeStatus.COMPROMISED,
                risk_score=100.0,
                properties={"ip_address": "45.154.255.89", "country": "Seychelles", "threat_type": "BlackCat / ALPHV C2"}
            )
        ]

        for n in nodes:
            graph.add_node(n)

        edges = [
            Edge(source="usr-svc-backup", target="dev-worker-node-4", type=EdgeType.AUTHENTICATED_ON),
            Edge(source="usr-svc-backup", target="sess-token-replay", type=EdgeType.SPAWNED_SESSION),
            Edge(source="sess-token-replay", target="ip-ransom-c2", type=EdgeType.ORIGINATED_FROM),
            Edge(source="sess-token-replay", target="perm-db-snapshot-delete", type=EdgeType.GRANTED_PRIVILEGE),
            Edge(source="sess-token-replay", target="file-db-dump-production", type=EdgeType.ACCESSED_FILE, properties={"action": "ModifyDBClusterSnapshotAttribute"}),
            Edge(source="file-db-dump-production", target="ip-ransom-c2", type=EdgeType.EXFILTRATED_TO, properties={"action": "Snapshot shared with external AWS Account"})
        ]

        for e in edges:
            graph.add_edge(e)

        alert = SecurityAlert(
            id="ALT-2026-1033",
            title="Critical: Ransomware Precursor - Destructive Backup Manipulation",
            severity=Severity.CRITICAL,
            source="CloudTrail Anomaly Guard & Datadog Security",
            target_node_id="usr-svc-backup",
            mitre_tactic="Impact & Inhibit System Recovery",
            mitre_technique="T1490 (Inhibit System Recovery) + T1537 (Transfer Data to Cloud Account)",
            description=(
                "Automated backup service account hijacked from compromised Kubelet node. "
                "Adversary initiated deletion of production database snapshots and shared snapshots with external tenant."
            ),
            timestamp="2026-10-11T04:15:00Z"
        )

        siem_logs = [
            {
                "timestamp": "2026-10-11T04:10:00Z",
                "source": "Kubernetes API",
                "event": "TOKEN_EXTRACT_SECRET",
                "pod": "compromised-ingress-nginx",
                "secret": "backup-controller-token"
            },
            {
                "timestamp": "2026-10-11T04:12:30Z",
                "source": "AWS CloudTrail",
                "event": "ModifyDBClusterSnapshotAttribute",
                "attribute": "restore",
                "valuesToAdd": ["987654321098"],
                "note": "Snapshot made public/shared with adversary AWS account"
            }
        ]

        threat_intel = {
            "45.154.255.89": {
                "reputation": "MALICIOUS",
                "threat_actor": "BlackCat Ransomware Infrastructure",
                "abuse_score": 100,
                "country": "Seychelles"
            }
        }

        return {
            "scenario_id": "scenario_ransomware_staging",
            "name": "Ransomware Precursor & Backup Token Hijacking",
            "category": "Ransomware & Inhibit System Recovery",
            "alert": alert,
            "graph": graph,
            "siem_logs": siem_logs,
            "threat_intel": threat_intel
        }
