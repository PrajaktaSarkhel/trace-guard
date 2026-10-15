# 🛡️ TraceGuard : Autonomous Security Incident Investigator

> **Track:** *Agents That Act on Connected Data*  
> **Primary Graph Database:** *FalkorDB (Low-Latency GraphBLAS Engine & openCypher)*  
>
> *An autonomous AI security agent that investigates suspicious enterprise activity through multi-hop graph reasoning, executes Cypher queries and graph algorithms via Model Context Protocol (MCP) tools, and orchestrates targeted containment with explainable forensic evidence.*

[![Track](https://img.shields.io/badge/Track-Agents%20That%20Act%20on%20Connected%20Data-blueviolet?style=for-the-badge)](https://github.com/PrajaktaSarkhel/trace-guard)
[![FalkorDB](https://img.shields.io/badge/Graph%20Database-FalkorDB%20(Cypher)-ff0055?style=for-the-badge)](https://falkordb.com)
[![Protocol](https://img.shields.io/badge/Protocol-Model%20Context%20Protocol%20(MCP)-00f2fe?style=for-the-badge)](https://modelcontextprotocol.io)
[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-white?style=for-the-badge)](LICENSE)

---

## 📌 The Problem & Motivation

Traditional Security Information and Event Management (SIEM) and Security Orchestration (SOAR) platforms generate thousands of alerts in isolation. Security Analysts are forced to manually correlate disjointed tables: *Who logged in? From what laptop? Which IAM role did they assume? What files did they read? Where was the data transferred?*

**TraceGuard transforms security investigations from disconnected log searches into autonomous graph traversals powered by FalkorDB.**

### 🎯 Core Engineering Innovations

| Engineering Capability | How TraceGuard Solves It |
| :--- | :--- |
| **Multi-Hop Connected Reasoning** | Traverses `Alert ➔ User ➔ Device ➔ Session ➔ Permission ➔ File ➔ C2 IP` across 3 to 6 hops to reconstruct the full attack chain using FalkorDB pattern matching. |
| **FalkorDB as Primary Graph Database** | Ingests enterprise entities into FalkorDB and executes native **openCypher** queries and graph algorithms (**Dijkstra Shortest Attack Path via `shortestPath`**, **Blast Radius Reachability**, **Betweenness Centrality**) directly on the graph engine. |
| **MCP Tool Protocol** | Implements the official **Model Context Protocol (MCP)** specification. Graph capabilities, SIEM correlation, threat intel, and remediation actions are standard MCP tools dynamically invoked by the agent. |
| **Graph-Informed Containment** | Distinguishes between automated safe containment (terminating compromised session tokens, filing P1 tickets) and **Human-in-the-Loop (HITL) gated actions** (requiring analyst approval before revoking admin IAM roles or isolating production hosts). |
| **Explainable Forensic Proof** | Outputs a **Mathematical Chain of Evidence**, an interactive Cytoscape graph replay, an executive narrative, and a full **MITRE ATT&CK** matrix mapping. |

---

## 🏗️ Architecture Overview

```
                      ┌──────────────────────────────────────────────┐
                      │    TraceGuard SOC Command Center (Web UI)    │
                      │   - Live Cytoscape Force-Directed Canvas     │
                      │   - Real-Time WebSocket Thought Stream       │
                      │   - Human-in-the-Loop Action Approval        │
                      └──────────────────────▲───────────────────────┘
                                             │ WebSocket / REST
                                             ▼
                      ┌──────────────────────────────────────────────┐
                      │             FastAPI Backend Hub              │
                      │       (Scenario Manager & Event Bus)         │
                      └──────────────────────▲───────────────────────┘
                                             │
                      ┌──────────────────────┴───────────────────────┐
                      │            TraceGuard Agent Loop             │
                      │        (Autonomous Multi-Hop ReAct)          │
                      └──────────────────────▲───────────────────────┘
                                             │ MCP JSON-RPC
                      ┌──────────────────────▼───────────────────────┐
                      │         TraceGuard MCP Server                │
                      │   - falkordb_cypher_query                    │
                      │   - security_graph_query                     │
                      │   - siem_log_search                          │
                      │   - threat_intel_lookup                      │
                      │   - risk_assessment_tool                     │
                      │   - execute_mitigation_action                │
                      └──────────────────────▲───────────────────────┘
                                             │ Cypher Queries / GraphBLAS
                      ┌──────────────────────▼───────────────────────┐
                      │       FalkorDB Graph Database Engine         │
                      │  Users ↔ Devices ↔ Sessions ↔ Roles ↔ Files  │
                      │  Cypher: shortestPath, Pattern Match, Blast  │
                      └──────────────────────────────────────────────┘
```

---

## 🌐 FalkorDB Graph Data Model

TraceGuard models the enterprise IT and security ecosystem as a typed property directed graph in FalkorDB:

### Node Labels
- `:User` — Corporate identity (`id`, `label`, `department`, `mfa_status`, `risk_score`)
- `:Device` — Endpoints & jump hosts (`id`, `label`, `hostname`, `os`, `is_managed`, `risk_score`)
- `:Session` — Active authentication tokens (`id`, `label`, `ip_address`, `is_anomaly`, `auth_time`)
- `:Permission` — IAM roles & privileges (`id`, `label`, `cloud_provider`, `crown_jewel`, `risk_score`)
- `:File` — Sensitive assets & vaults (`id`, `label`, `path`, `classification`, `crown_jewel`)
- `:IP` — External endpoints & C2 addresses (`id`, `label`, `geo_country`, `threat_reputation`)
- `:Alert` — Triggered detection events (`id`, `title`, `severity`, `mitre_tactic`, `mitre_technique`)

### Relationship Types
- `(:User)-[:AUTHENTICATED_ON]->(:Device)`
- `(:User)-[:SPAWNED_SESSION]->(:Session)`
- `(:Session)-[:ORIGINATED_FROM]->(:IP)`
- `(:Session)-[:GRANTED_PRIVILEGE]->(:Permission)`
- `(:Session)-[:ACCESSED_FILE]->(:File)`
- `(:File)-[:EXFILTRATED_TO]->(:IP)`

---

## ⚡ Core Cypher Queries & Graph Algorithms in FalkorDB

TraceGuard's reasoning engine depends on real Cypher queries executed against FalkorDB:

### 1. Multi-Hop Neighborhood Expansion (Hop 2 Traversal)
```cypher
MATCH (start {id: $node_id})-[r]-(neighbor)
RETURN neighbor.id AS id, 
       labels(neighbor) AS labels, 
       type(r) AS edge_type, 
       properties(neighbor) AS props;
```

### 2. Dijkstra Shortest Attack Path (`shortestPath`)
Reconstructs the shortest lateral movement path from patient-zero to the crown-jewel exfiltration destination:
```cypher
MATCH (origin {id: $source_id}), (exfil {id: $target_id})
MATCH p = shortestPath((origin)-[*..10]-(exfil))
RETURN [n IN nodes(p) | n.id] AS path_nodes,
       [r IN relationships(p) | type(r)] AS attack_hops,
       length(p) AS total_hops;
```

### 3. Blast Radius & Crown-Jewel Exposure Analysis
Quantifies all reachable enterprise assets within `N` hops and flags high-value crown-jewel data:
```cypher
MATCH p = (origin {id: $node_id})-[*1..3]-(reachable)
RETURN DISTINCT reachable.id AS asset_id,
       labels(reachable) AS entity_type,
       reachable.crown_jewel AS is_crown_jewel,
       reachable.risk_score AS risk,
       length(p) AS hop_distance;
```

### 4. Bridge / Choke Point Detection (Centrality Analysis)
Identifies shared bastion hosts and high-privilege jump nodes using graph algorithms:
```cypher
CALL algo.betweenness('Device', 'AUTHENTICATED_ON')
YIELD node, score
RETURN node.id, node.label, score
ORDER BY score DESC
LIMIT 5;
```

---

## 🧰 MCP Tool Specifications

TraceGuard implements the Model Context Protocol (MCP) with 6 production-grade tools:

1. `falkordb_cypher_query`: Executes openCypher queries directly on FalkorDB.
2. `security_graph_query`:
   - `get_node`: Inspect node properties and risk level.
   - `get_neighbors`: Multi-hop neighborhood expansion.
   - `expand_subgraph`: Breadth-first extraction up to `N` hops.
   - `find_path`: Cypher Dijkstra shortest attack path between origin and exfiltrated asset.
   - `blast_radius`: Computes reachable asset exposure, crown jewels at risk, and blast radius metric (0-100).
   - `centrality`: Betweenness & degree centrality identifying bridge choke points.
3. `siem_log_search`: Full-text and entity-correlated query over raw CloudTrail, SSH, and VPC Flow logs.
4. `threat_intel_lookup`: Enriches IP indicators with APT actor attribution, abuse score, and Tor exit flags.
5. `risk_assessment_tool`: Dynamic composite risk scoring factoring graph topology and crown jewel proximity.
6. `execute_mitigation_action`: Executes containment (`ISOLATE_DEVICE`, `SUSPEND_USER`, `REVOKE_PERMISSION`, `TERMINATE_SESSION`, `CREATE_INCIDENT_TICKET`) with Human-in-the-Loop approval workflows.

---

## 🎬 Enterprise Threat Scenarios

1. **Scenario 1: Lateral Movement & S3 Data Exfiltration**
   - *Alert:* Impossible Travel Login for Alice Vance (`usr-alice`) from St. Petersburg, Russia.
   - *Attack Chain:* Traced to shared bastion jump host `srv-bastion-prod` ➔ Rogue IAM AdministratorAccess elevation at 02:18 AM ➔ Access to `customers_ssn_vault_2026.parquet` (450k records, Restricted PII) ➔ 3.8 GB exfiltrated to Russian C2 IP (`194.26.29.112`).
   - *MITRE ATT&CK:* T1078 (Valid Accounts), T1021 (Remote Services), T1098 (Account Manipulation), T1567 (Exfiltration Over Web Service).

2. **Scenario 2: Insider Threat & Supply Chain Code Tampering**
   - *Alert:* Off-hours branch protection bypass by departing engineer Charlie Ray (`usr-charlie`).
   - *Attack Chain:* Unmanaged personal laptop ➔ 03:30 AM GitHub PAT session ➔ Tor exit node (`185.220.101.5`) ➔ Bypass PR reviews on `acme/auth-gateway` ➔ Injected backdoor into JWT validator core.
   - *MITRE ATT&CK:* T1195.001 (Supply Chain Compromise), T1556 (Modify Authentication Process).

3. **Scenario 3: Ransomware Precursor & Backup Token Hijacking**
   - *Alert:* Anomalous destructive snapshot manipulation on AWS RDS.
   - *Attack Chain:* Compromised Kubelet worker node ➔ Hijacked automated backup service account token ➔ RDS database snapshot deletion ➔ Snapshot shared with external adversary AWS tenant.
   - *MITRE ATT&CK:* T1490 (Inhibit System Recovery), T1537 (Transfer Data to Cloud Account).

---

## 🚀 Quick Start Guide

### 1. Prerequisites
- Python 3.10+ (Tested on Python 3.13)
- [Docker](https://www.docker.com/) (for running FalkorDB locally) or a [FalkorDB Cloud](https://app.falkordb.cloud/) instance
- Modern web browser (Chrome, Edge, Firefox, Brave)

### 2. Start FalkorDB (Primary Graph Database)

Using Docker:
```bash
docker run -p 6379:6379 -it --rm falkordb/falkordb:latest
```
*(Alternatively, you can provide FalkorDB Cloud credentials in `.env`)*.

### 3. Setup Python Environment

```bash
# Clone the repository
git clone https://github.com/PrajaktaSarkhel/trace-guard.git
cd trace-guard

# Create and activate virtual environment
python -m venv .venv

# On Windows:
.venv\Scripts\activate

# On macOS/Linux:
source .venv/bin/activate

# Install dependencies (including falkordb)
pip install -r requirements.txt
```

### 4. Launch the SOC Command Center

```bash
python run.py
```

The application will start at **`http://127.0.0.1:8000`** and automatically open your default browser.

*(Optional)* If you wish to enable live LLM generation with your Gemini or OpenAI API key, copy `.env.example` to `.env` and insert your key. If no external key is provided, TraceGuard runs out of the box using its built-in deterministic reasoning engine with zero setup required.

---

## 🧪 Running Automated Tests

TraceGuard includes a comprehensive test suite verifying FalkorDB Cypher execution, graph algorithms, MCP tool schemas, autonomous investigation loops, and REST endpoints:

```bash
python -m unittest discover -s backend/tests
```

---

## 💡 Interactive SOC Walkthrough (Live Demonstration)

1. **Select a Scenario**: In the top navigation bar, choose `1. Lateral Movement & S3 Exfiltration`. Notice the alert details and connected topology graph loaded on screen.
2. **Start Investigation**: Click **⚡ Start Autonomous Investigation**.
3. **Watch Multi-Hop Traversal**: Observe the live agent stream on the right. Watch the agent traverse from User Alice ➔ Rogue Session ➔ Shared Bastion Host ➔ IAM Admin Role ➔ Customer SSN Parquet Vault ➔ Adversary C2 IP.
4. **Inspect Graph Highlights**: See nodes glow and change risk colors in real time. Click on any node (e.g. `srv-bastion-prod` or `customers_ssn_vault_2026.parquet`) to view its deep forensic metadata.
5. **Human-in-the-Loop Mitigation**: Switch to the **Mitigation (HITL)** tab. Review the pending action: `Detach IAM policy and revoke elevated access`. Click **✅ Approve & Execute Containment**. Watch the node immediately turn neon green (`CONTAINED`) across the entire SOC graph!
6. **Export Report**: Switch to the **Report** tab to view the generated forensic summary or click **📋 Copy Markdown** / **📥 Export JSON**.

---

## 🤖 AI Assistant Disclosure (Rule 11 Compliance)

In compliance with Rule 11 of Graph Hacks, AI coding assistants (Gemini / Antigravity) were utilized during the development of this project for initial code scaffolding, rapid prototyping, and test suite generation. The graph data model, Cypher queries, multi-hop investigation logic, and architectural design were directed, verified, and integrated by the author.

---

## 👤 Author

**Prajakta Sarkhel**  
- GitHub: [PrajaktaSarkhel](https://github.com/PrajaktaSarkhel)
- Project: [TraceGuard](https://github.com/PrajaktaSarkhel/trace-guard)

---

## 📄 License

Distributed under the MIT License. See `LICENSE` for more information.
