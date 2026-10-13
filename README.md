# 🛡️ TraceGuard — Autonomous Security Incident Investigator

> *An autonomous AI-powered security incident investigator that inspects suspicious enterprise activity through multi-hop graph reasoning, executes graph algorithms via Model Context Protocol (MCP) tools, and takes targeted containment actions with explainable forensic evidence.*

[![Architecture](https://img.shields.io/badge/Architecture-Graph--Native%20SOC-7928ca?style=for-the-badge)](https://github.com/PrajaktaSarkhel/trace-guard)
[![Protocol](https://img.shields.io/badge/Protocol-Model%20Context%20Protocol%20(MCP)-00f2fe?style=for-the-badge)](https://modelcontextprotocol.io)
[![Engine](https://img.shields.io/badge/Graph%20Engine-NetworkX%20DiGraph-38ef7d?style=for-the-badge)](https://networkx.org)
[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-white?style=for-the-badge)](LICENSE)

---

## 📌 The Problem & Motivation

Traditional Security Information and Event Management (SIEM) and Security Orchestration (SOAR) platforms generate thousands of alerts in isolation. Security Analysts are forced to manually correlate disjointed tables: *Who logged in? From what laptop? Which IAM role did they assume? What files did they read? Where was the data transferred?*

**TraceGuard transforms security investigations from disconnected log searches into autonomous graph traversals.**

### 🎯 Core Engineering Innovations

| Engineering Capability | How TraceGuard Solves It |
| :--- | :--- |
| **Multi-Hop Reasoning** | Instead of stopping at a single user risk score, TraceGuard traverses `Alert ➔ User ➔ Device ➔ Session ➔ Permission ➔ File ➔ C2 IP` across 3 to 6 hops to reconstruct the full attack chain. |
| **Graph Queries & Algorithms as Agent Tools** | The agent wields real graph algorithms as tools: **Dijkstra Shortest Attack Path**, **Blast Radius Calculation**, **Betweenness & Degree Centrality** (identifying shared choke points like bastion hosts), and **Neighborhood Expansion**. |
| **Tool Selection through MCP** | Implements the official **Model Context Protocol (MCP)** specification. All graph capabilities, SIEM correlation, threat intel, and remediation actions are standard MCP tools dynamically selected by the agent. |
| **Actions Based on What the Graph Shows** | Distinguishes between automated safe containment (terminating compromised session tokens, filing P1 incident tickets) and **Human-in-the-Loop (HITL) gated actions** (requesting analyst approval before isolating production jump hosts or revoking admin keys). |
| **Explainable Results** | Rather than an opaque risk score, TraceGuard outputs a **Mathematical Chain of Evidence**, an interactive Cytoscape graph replay, an executive narrative, and a full **MITRE ATT&CK** matrix mapping. |

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
                      │   - security_graph_query                     │
                      │   - siem_log_search                          │
                      │   - threat_intel_lookup                      │
                      │   - risk_assessment_tool                     │
                      │   - execute_mitigation_action                │
                      └──────────────────────▲───────────────────────┘
                                             │
                      ┌──────────────────────┴───────────────────────┐
                      │      Connected Security Graph Engine         │
                      │  Users ↔ Devices ↔ Sessions ↔ Roles ↔ Files  │
                      │  Algorithms: Dijkstra, Blast Radius, PageRank│
                      └──────────────────────────────────────────────┘
```

---

## 🌐 Connected Security Graph Schema

TraceGuard operates over a rich typed directed graph:

- **Nodes:**
  - `User`: Corporate identity, department, MFA status, risk score
  - `Device`: Managed/unmanaged laptops, shared bastion hosts, Kubelet nodes
  - `Session`: Active tokens, authentication method, source IP, anomaly flag
  - `Permission`: IAM roles, GitHub release rights, database policies
  - `File`: Sensitive assets, customer PII parquet tables, cluster kubeconfigs
  - `IP`: External endpoints, Tor exit nodes, bulletproof hosting C2s
  - `Alert`: Triggered detection events

- **Edges:**
  - `AUTHENTICATED_ON` (`User` ➔ `Device`)
  - `SPAWNED_SESSION` (`User` ➔ `Session`)
  - `ORIGINATED_FROM` (`Session` ➔ `IP`)
  - `GRANTED_PRIVILEGE` (`Session` ➔ `Permission`)
  - `ACCESSED_FILE` (`Session` ➔ `File`)
  - `EXFILTRATED_TO` (`File` / `Session` ➔ `IP`)

---

## 🧰 MCP Tool Specifications

TraceGuard implements the Model Context Protocol (MCP) with 5 production-grade tools:

1. `security_graph_query`:
   - `get_node`: Inspect node properties and risk level.
   - `get_neighbors`: Multi-hop neighborhood expansion in incoming, outgoing, or both directions.
   - `expand_subgraph`: Breadth-first extraction up to `N` hops.
   - `find_path`: Dijkstra shortest attack path between origin and exfiltrated asset.
   - `blast_radius`: Computes reachable asset exposure, crown jewels at risk, and composite blast radius metric (0-100).
   - `centrality`: Betweenness & degree centrality identifying lateral movement bridge nodes.
2. `siem_log_search`: Full-text and entity-correlated query over raw CloudTrail, SSH, and VPC Flow logs.
3. `threat_intel_lookup`: Enriches IP indicators with APT actor attribution, abuse score, and Tor exit flags.
4. `risk_assessment_tool`: Dynamic composite risk scoring factoring graph topology and crown jewel proximity.
5. `execute_mitigation_action`: Executes containment (`ISOLATE_DEVICE`, `SUSPEND_USER`, `REVOKE_PERMISSION`, `TERMINATE_SESSION`, `CREATE_INCIDENT_TICKET`) with Human-in-the-Loop approval workflows.

---

## 🎬 Enterprise Threat Scenarios

1. **Scenario 1: Lateral Movement & S3 Data Exfiltration**
   - *Alert:* Impossible Travel Login for Alice Vance (`usr-alice`) from St. Petersburg, Russia.
   - *Chain:* Traced to shared bastion jump host `srv-bastion-prod` ➔ Rogue IAM AdministratorAccess elevation at 02:18 AM ➔ Access to `customers_ssn_vault_2026.parquet` (450k records, Restricted PII) ➔ 3.8 GB exfiltrated to Russian C2 IP (`194.26.29.112`).
   - *MITRE:* T1078 (Valid Accounts), T1021 (Remote Services), T1098 (Account Manipulation), T1567 (Exfiltration Over Web Service).

2. **Scenario 2: Insider Threat & Supply Chain Code Tampering**
   - *Alert:* Off-hours branch protection bypass by departing engineer Charlie Ray (`usr-charlie`).
   - *Chain:* Unmanaged personal laptop ➔ 03:30 AM GitHub PAT session ➔ Tor exit node (`185.220.101.5`) ➔ Bypass PR reviews on `acme/auth-gateway` ➔ Injected backdoor into JWT validator core.
   - *MITRE:* T1195.001 (Supply Chain Compromise), T1556 (Modify Authentication Process).

3. **Scenario 3: Ransomware Precursor & Backup Token Hijacking**
   - *Alert:* Anomalous destructive snapshot manipulation on AWS RDS.
   - *Chain:* Compromised Kubelet worker node ➔ Hijacked automated backup service account token ➔ RDS database snapshot deletion ➔ Snapshot shared with external adversary AWS tenant.
   - *MITRE:* T1490 (Inhibit System Recovery), T1537 (Transfer Data to Cloud Account).

---

## 🚀 Quick Start Guide

### 1. Prerequisites
- Python 3.10+ (Tested on Python 3.13)
- Modern web browser (Chrome, Edge, Firefox, Brave)

### 2. Clone & Setup

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

# Install dependencies
pip install -r requirements.txt
```

### 3. Launch the SOC Command Center

```bash
python run.py
```

The application will start at **`http://127.0.0.1:8000`** and automatically open your default browser.

*(Optional)* If you wish to enable live LLM generation with your Gemini or OpenAI API key, copy `.env.example` to `.env` and insert your key. If no external key is provided, TraceGuard runs out of the box using its built-in deterministic reasoning engine with zero setup required.

---

## 🧪 Running Automated Tests

TraceGuard includes a comprehensive test suite verifying graph algorithms, MCP tool schemas, autonomous investigation loops, and REST endpoints:

```bash
# Run all unit and integration tests
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

## 👤 Author

**Prajakta Sarkhel**  
- GitHub: [@PrajaktaSarkhel](https://github.com/PrajaktaSarkhel)
- Project: [TraceGuard](https://github.com/PrajaktaSarkhel/trace-guard)

---

## 📄 License

Distributed under the MIT License. See `LICENSE` for more information.
