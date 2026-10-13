// =========================================================================
// TraceGuard SOC Command Center Application Controller
// Graph Visualizer, Real-Time WebSocket Streaming, MCP Tool Replay, & HITL
// =========================================================================

let cy = null;
let currentScenarioId = "scenario_lateral_exfil";
let currentAlert = null;
let currentReport = null;
let isInvestigating = false;
let investigationTimer = null;
let investigationStartTime = 0;

// Initialize when DOM is ready
document.addEventListener("DOMContentLoaded", () => {
  initCytoscape();
  setupEventListeners();
  loadScenario(currentScenarioId);
});

// =========================================================================
// 1. Cytoscape Graph Visualizer Initialization
// =========================================================================
function initCytoscape() {
  const container = document.getElementById("cy");
  if (!container) return;

  cy = cytoscape({
    container: container,
    elements: [],
    style: [
      // Core Node Styling
      {
        selector: 'node',
        style: {
          'label': 'data(label)',
          'color': '#f0f4f8',
          'font-family': 'Outfit, sans-serif',
          'font-size': '11px',
          'font-weight': 600,
          'text-valign': 'bottom',
          'text-margin-y': 6,
          'text-background-color': '#0d121d',
          'text-background-opacity': 0.8,
          'text-background-padding': 3,
          'text-background-shape': 'roundrectangle',
          'border-width': 2,
          'border-color': 'rgba(255, 255, 255, 0.2)',
          'transition-property': 'background-color, border-color, width, height, border-width',
          'transition-duration': '0.3s'
        }
      },
      // Type-based Node Shapes & Colors
      {
        selector: 'node[type = "USER"]',
        style: {
          'shape': 'ellipse',
          'background-color': '#00f2fe',
          'width': 42,
          'height': 42
        }
      },
      {
        selector: 'node[type = "DEVICE"]',
        style: {
          'shape': 'roundrectangle',
          'background-color': '#4facfe',
          'width': 44,
          'height': 44
        }
      },
      {
        selector: 'node[type = "SESSION"]',
        style: {
          'shape': 'diamond',
          'background-color': '#ffaa00',
          'width': 40,
          'height': 40
        }
      },
      {
        selector: 'node[type = "PERMISSION"]',
        style: {
          'shape': 'hexagon',
          'background-color': '#ffea00',
          'width': 44,
          'height': 44
        }
      },
      {
        selector: 'node[type = "FILE"]',
        style: {
          'shape': 'barrel',
          'background-color': '#ff007f',
          'width': 42,
          'height': 42
        }
      },
      {
        selector: 'node[type = "IP"]',
        style: {
          'shape': 'triangle',
          'background-color': '#ff334b',
          'width': 46,
          'height': 46
        }
      },
      // Status Styles
      {
        selector: 'node[status = "compromised"]',
        style: {
          'border-color': '#ff334b',
          'border-width': 4,
          'border-opacity': 1
        }
      },
      {
        selector: 'node[status = "suspicious"]',
        style: {
          'border-color': '#ffaa00',
          'border-width': 3
        }
      },
      {
        selector: 'node[status = "contained"]',
        style: {
          'background-color': '#00e676 !important',
          'border-color': '#ffffff',
          'border-width': 4
        }
      },
      // Crown Jewel Highlight
      {
        selector: 'node[?crown_jewel]',
        style: {
          'border-color': '#ffd700',
          'border-width': 4
        }
      },
      // Dynamic Hop Discovery Highlight
      {
        selector: 'node.active-hop',
        style: {
          'border-color': '#00f2fe',
          'border-width': 6,
          'width': 54,
          'height': 54
        }
      },
      // Edge Styles
      {
        selector: 'edge',
        style: {
          'width': 2,
          'line-color': 'rgba(255, 255, 255, 0.2)',
          'target-arrow-color': 'rgba(255, 255, 255, 0.4)',
          'target-arrow-shape': 'triangle',
          'curve-style': 'bezier',
          'arrow-scale': 1.1,
          'label': 'data(type)',
          'font-family': 'JetBrains Mono, monospace',
          'font-size': '8px',
          'color': '#8899ac',
          'text-background-color': '#070a10',
          'text-background-opacity': 0.8,
          'text-background-padding': 2,
          'text-rotation': 'autorotate'
        }
      },
      // Attack Path Edge Highlight
      {
        selector: 'edge.attack-path-edge',
        style: {
          'width': 4,
          'line-color': '#ff334b',
          'target-arrow-color': '#ff334b',
          'line-style': 'dashed'
        }
      }
    ],
    layout: {
      name: 'cose',
      animate: true,
      animationDuration: 800,
      nodeRepulsion: 6000,
      idealEdgeLength: 100,
      padding: 40
    }
  });

  // Node Click Inspector
  cy.on('tap', 'node', (evt) => {
    const node = evt.target;
    showNodeInspector(node.data());
  });

  // Tap Background Closes Inspector
  cy.on('tap', (evt) => {
    if (evt.target === cy) {
      document.getElementById('nodeInspector').style.display = 'none';
    }
  });
}

// =========================================================================
// 2. Scenario Loading & UI Synchronization
// =========================================================================
async function loadScenario(scenarioId) {
  try {
    showToast(`Loading ${scenarioId}...`);
    const resp = await fetch(`/api/scenarios/${scenarioId}/load`, { method: "POST" });
    if (!resp.ok) throw new Error("Failed to load scenario");
    const data = await resp.json();

    currentAlert = data.alert;
    updateAlertBanner(data.alert);

    // Refresh Cytoscape Graph
    if (cy && data.graph_elements) {
      cy.elements().remove();
      cy.add(data.graph_elements);
      runGraphLayout();
      updateGraphHUD();
      populateCustomAlertNodes(data.graph_elements);
    }

    // Reset Investigation UI
    resetInvestigationState();

    // Fetch and display SIEM logs
    fetchAndRenderSIEMLogs();

    showToast(`Loaded ${data.name}`);
  } catch (err) {
    console.error("Error loading scenario:", err);
    showToast("Error loading scenario", true);
  }
}

function runGraphLayout(layoutName = 'cose') {
  if (!cy) return;
  cy.layout({
    name: layoutName,
    animate: true,
    animationDuration: 700,
    nodeRepulsion: 7000,
    idealEdgeLength: 110,
    padding: 50
  }).run();
}

function updateAlertBanner(alert) {
  if (!alert) return;
  document.getElementById("alertTitle").textContent = alert.title;
  document.getElementById("alertDesc").textContent = alert.description;
  document.getElementById("alertSeverity").textContent = alert.severity;
  document.getElementById("alertSource").textContent = `Source: ${alert.source}`;
  document.getElementById("alertMitre").textContent = `MITRE: ${alert.mitre_technique || alert.mitre_tactic}`;
}

function updateGraphHUD() {
  if (!cy) return;
  const nodes = cy.nodes();
  const crownJewels = nodes.filter(n => n.data('crown_jewel') === true);

  document.getElementById("hudTotalNodes").textContent = `${nodes.length} Nodes / ${cy.edges().length} Edges`;
  document.getElementById("hudCrownJewels").textContent = `${crownJewels.length} Assets`;

  // Fetch Centrality from API
  fetch('/api/graph')
    .then(r => r.json())
    .then(res => {
      const topBridge = res.centrality?.top_bridge_nodes?.[0];
      if (topBridge) {
        document.getElementById("hudChokePoint").textContent = `${topBridge.label.split(' ')[0]} (${topBridge.betweenness_score})`;
      }
    })
    .catch(() => {});
}

// =========================================================================
// 3. Autonomous Multi-Hop Investigation (WebSocket / REST Stream)
// =========================================================================
function startInvestigation() {
  if (isInvestigating) return;

  isInvestigating = true;
  investigationStartTime = Date.now();
  setAgentStatus("INVESTIGATING...", true);

  // Clear previous stream
  const streamContainer = document.getElementById("reasoningStream");
  streamContainer.innerHTML = '';

  // Start UI Timer
  investigationTimer = setInterval(() => {
    const elapsed = ((Date.now() - investigationStartTime) / 1000).toFixed(1);
    document.getElementById("agentTimer").textContent = `${elapsed}s`;
  }, 100);

  // Attempt WebSocket stream; fallback to REST POST if WS fails
  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  const wsUrl = `${protocol}//${window.location.host}/ws/investigate`;
  let socket = null;

  try {
    socket = new WebSocket(wsUrl);

    socket.onopen = () => {
      console.log("TraceGuard Agent WebSocket connected.");
    };

    socket.onmessage = (event) => {
      const data = JSON.parse(event.data);

      if (data.type === "step") {
        handleInvestigationStep(data.step);
      } else if (data.type === "final_update") {
        handleInvestigationComplete(data.report, data.graph_elements);
      } else if (data.type === "error") {
        showToast(`Investigation error: ${data.error}`, true);
        finishInvestigation();
      }
    };

    socket.onerror = (err) => {
      console.warn("WebSocket error, falling back to REST endpoint...", err);
      fallbackToRestInvestigation();
    };

    socket.onclose = () => {
      finishInvestigation();
    };
  } catch (e) {
    fallbackToRestInvestigation();
  }
}

async function fallbackToRestInvestigation() {
  try {
    const resp = await fetch('/api/investigate', { method: 'POST' });
    const data = await resp.json();
    if (data.report) {
      // Replay steps
      if (data.report.timeline) {
        data.report.timeline.forEach((item, idx) => {
          handleInvestigationStep({
            step_id: idx + 1,
            hop_number: item.hop || idx + 1,
            thought: `Hop ${item.hop}: Evaluated connected node and called ${item.action}`,
            tool_called: item.action,
            mitre_tactic: item.tactic,
            tool_result: {}
          });
        });
      }
      handleInvestigationComplete(data.report, data.graph_elements);
    }
  } catch (err) {
    console.error("Rest investigation failed:", err);
    showToast("Investigation failed", true);
  } finally {
    finishInvestigation();
  }
}

function handleInvestigationStep(step) {
  const streamContainer = document.getElementById("reasoningStream");

  // Create Step Card
  const card = document.createElement("div");
  card.className = "step-card";
  card.innerHTML = `
    <div class="step-header">
      <span class="step-hop-pill">HOP ${step.hop_number}</span>
      <span class="step-tactic-tag">${step.mitre_tactic || 'Reasoning'}</span>
    </div>
    <div class="step-thought">${escapeHtml(step.thought)}</div>
    <div class="step-tool-call">
      <span class="tool-name-badge">MCP Tool:</span> ${escapeHtml(step.tool_called)}
      <div class="step-tool-output">Discovered Nodes: ${step.discovered_nodes ? step.discovered_nodes.join(', ') : 'None'}</div>
    </div>
  `;
  streamContainer.appendChild(card);
  streamContainer.scrollTop = streamContainer.scrollHeight;

  // Pulse & Highlight Discovered Nodes in Cytoscape Graph
  if (cy && step.discovered_nodes && step.discovered_nodes.length > 0) {
    step.discovered_nodes.forEach(nodeId => {
      const cyNode = cy.$id(nodeId);
      if (cyNode.length > 0) {
        cyNode.addClass('active-hop');
        cy.animate({
          center: { eles: cyNode },
          zoom: 1.3
        }, { duration: 400 });
      }
    });
  }
}

function handleInvestigationComplete(report, updatedElements) {
  currentReport = report;
  finishInvestigation();

  // Update Cytoscape Graph with updated elements
  if (cy && updatedElements) {
    cy.elements().remove();
    cy.add(updatedElements);
    runGraphLayout();
    highlightAttackChain(report.chain_of_evidence);
  }

  // Update HUD
  if (report.blast_radius) {
    document.getElementById("hudBlastRadius").textContent = `${report.blast_radius.blast_radius_score || 85}/100`;
  }

  // Render Tabs
  renderEvidenceChain(report.chain_of_evidence);
  renderMitreMatrix(report.mitre_attack_mapping);
  renderMitigationActions(report.actions_taken, report.pending_actions);
  renderIncidentReportPaper(report);

  // Switch to Evidence or Actions tab to WOW the user
  showToast("Multi-Hop Investigation Complete! Review Evidence & Actions.");
}

function finishInvestigation() {
  isInvestigating = false;
  if (investigationTimer) {
    clearInterval(investigationTimer);
    investigationTimer = null;
  }
  setAgentStatus("AGENT READY", false);
}

function setAgentStatus(text, isBusy) {
  const pulse = document.getElementById("agentStatusPulse");
  const label = document.getElementById("agentStatusText");
  label.textContent = text;
  if (isBusy) {
    pulse.classList.add("investigating");
  } else {
    pulse.classList.remove("investigating");
  }
}

// =========================================================================
// 4. Evidence Chain & Attack Path Visualization
// =========================================================================
function highlightAttackChain(chain) {
  if (!cy || !chain) return;

  // Highlight all nodes in chain
  const nodeIds = chain.map(c => c.node_id);
  cy.nodes().removeClass('active-hop');
  
  nodeIds.forEach(id => {
    cy.$id(id).addClass('active-hop');
  });

  // Highlight connecting edges
  for (let i = 0; i < nodeIds.length - 1; i++) {
    const u = nodeIds[i];
    const v = nodeIds[i + 1];
    const edge = cy.edges(`[source = "${u}"][target = "${v}"], [source = "${v}"][target = "${u}"]`);
    if (edge.length > 0) {
      edge.addClass('attack-path-edge');
    }
  }
}

function renderEvidenceChain(chain) {
  const container = document.getElementById("chainTimeline");
  document.getElementById("evidenceBadgeCount").textContent = chain ? chain.length : 0;
  if (!chain || chain.length === 0) {
    container.innerHTML = '<div class="empty-state-sm">No evidence chain found.</div>';
    return;
  }

  container.innerHTML = '';
  chain.forEach(item => {
    const card = document.createElement("div");
    card.className = "chain-node-card";
    card.innerHTML = `
      <div class="chain-node-title">
        <span>${escapeHtml(item.label)}</span>
        <span class="chain-node-role">${escapeHtml(item.role)}</span>
      </div>
      <div class="chain-node-desc">${escapeHtml(item.findings)}</div>
    `;
    card.addEventListener('click', () => {
      const cyNode = cy.$id(item.node_id);
      if (cyNode.length > 0) {
        cy.center(cyNode);
        showNodeInspector(cyNode.data());
      }
    });
    container.appendChild(card);
  });
}

function renderMitreMatrix(mitreList) {
  const tbody = document.getElementById("mitreBody");
  if (!mitreList || mitreList.length === 0) return;

  tbody.innerHTML = '';
  mitreList.forEach(m => {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td><span class="meta-tag mitre">${escapeHtml(m.tactic)}</span></td>
      <td><strong>${escapeHtml(m.technique)}</strong></td>
      <td><code>${escapeHtml(m.evidence)}</code></td>
    `;
    tbody.appendChild(tr);
  });
}

// =========================================================================
// 5. Mitigation & Human-in-the-Loop Actions
// =========================================================================
function renderMitigationActions(executedActions, pendingActions) {
  const autoList = document.getElementById("autoActionsList");
  const pendingList = document.getElementById("pendingActionsList");

  const totalPending = pendingActions ? pendingActions.length : 0;
  document.getElementById("actionBadgeCount").textContent = totalPending;

  // Render Automated Actions
  if (!executedActions || executedActions.length === 0) {
    autoList.innerHTML = '<div class="empty-state-sm">No automated actions taken yet.</div>';
  } else {
    autoList.innerHTML = '';
    executedActions.forEach(act => {
      const card = document.createElement("div");
      card.className = "action-card executed";
      card.innerHTML = `
        <div class="action-header">
          <span class="action-title">${escapeHtml(act.description)}</span>
          <span class="action-status-badge executed">EXECUTED</span>
        </div>
        <div class="action-reasoning">${escapeHtml(act.reasoning)}</div>
      `;
      autoList.appendChild(card);
    });
  }

  // Render Pending Human-in-the-Loop Actions
  if (!pendingActions || pendingActions.length === 0) {
    pendingList.innerHTML = '<div class="empty-state-sm">No actions pending approval. All containment executed.</div>';
  } else {
    pendingList.innerHTML = '';
    pendingActions.forEach(act => {
      const card = document.createElement("div");
      card.className = "action-card pending";
      card.innerHTML = `
        <div class="action-header">
          <span class="action-title">${escapeHtml(act.description)}</span>
          <span class="action-status-badge pending">PENDING APPROVAL</span>
        </div>
        <div class="action-reasoning">${escapeHtml(act.reasoning)}</div>
        <button class="btn-approve-action" data-action-id="${act.action_id}">
          ✅ Approve & Execute Containment
        </button>
      `;
      const btn = card.querySelector(".btn-approve-action");
      btn.addEventListener("click", () => approveAction(act.action_id));
      pendingList.appendChild(card);
    });
  }
}

async function approveAction(actionId) {
  try {
    showToast(`Approving action ${actionId}...`);
    const resp = await fetch(`/api/actions/${actionId}/approve`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ approver: "Lead SOC Analyst" })
    });
    if (!resp.ok) throw new Error("Approval failed");
    const data = await resp.json();

    showToast(`Action ${actionId} approved and executed! Target contained.`);

    // Update Graph live (target node becomes CONTAINED / neon green)
    if (cy && data.graph_elements) {
      cy.elements().remove();
      cy.add(data.graph_elements);
      runGraphLayout();
    }

    // Refresh Investigation State
    const respSync = await fetch('/api/investigate', { method: 'POST' });
    const syncData = await respSync.json();
    if (syncData.report) {
      currentReport = syncData.report;
      renderMitigationActions(currentReport.actions_taken, currentReport.pending_actions);
    }
  } catch (err) {
    console.error("Action approval error:", err);
    showToast("Error approving action", true);
  }
}

// =========================================================================
// 6. Incident Report Formatter
// =========================================================================
function renderIncidentReportPaper(report) {
  const paper = document.getElementById("reportPaper");
  if (!report) return;

  paper.innerHTML = `
    <h2>Security Incident Forensic Report: ${escapeHtml(report.incident_id)}</h2>
    <p><strong>Severity:</strong> <span class="alert-badge critical">${escapeHtml(report.severity)}</span> &bull; 
       <strong>Investigated in:</strong> ${report.investigation_duration_sec}s</p>
    
    <h3>Executive Summary</h3>
    <p>${escapeHtml(report.summary)}</p>

    <h3>Attack Narrative & Findings</h3>
    <p>${escapeHtml(report.attack_narrative)}</p>

    <h3>Blast Radius Analysis</h3>
    <p>Score: <strong>${report.blast_radius?.blast_radius_score || 85}/100</strong> &bull; Total Assets at Risk: <strong>${report.blast_radius?.total_reachable_assets || 0}</strong></p>

    <h3>Actions & Containment</h3>
    <p>Executed: <strong>${report.actions_taken?.length || 0}</strong> &bull; Pending Analyst Approval: <strong>${report.pending_actions?.length || 0}</strong></p>
  `;
}

// =========================================================================
// 7. Node Inspector Drawer
// =========================================================================
function showNodeInspector(nodeData) {
  const drawer = document.getElementById("nodeInspector");
  document.getElementById("inspectType").textContent = nodeData.type;
  document.getElementById("inspectLabel").textContent = nodeData.label;
  document.getElementById("inspectRisk").textContent = `${nodeData.risk_score || 0}/100`;

  const propsDiv = document.getElementById("inspectProps");
  propsDiv.innerHTML = '';

  const skipKeys = ['id', 'label', 'type', 'status', 'risk_score', 'crown_jewel'];
  for (const [k, v] of Object.entries(nodeData)) {
    if (skipKeys.includes(k)) continue;
    const row = document.createElement("div");
    row.className = "prop-row";
    row.innerHTML = `
      <span class="prop-key">${escapeHtml(k)}:</span>
      <span class="prop-val">${escapeHtml(typeof v === 'object' ? JSON.stringify(v) : String(v))}</span>
    `;
    propsDiv.appendChild(row);
  }

  // Remediation button
  const actBtn = document.getElementById("btnInspectAction");
  actBtn.textContent = nodeData.status === 'contained' ? 'Entity Contained' : `Quarantine ${nodeData.type}`;
  actBtn.onclick = () => {
    if (nodeData.status !== 'contained') {
      approveActionDirect(nodeData.id);
    }
  };

  drawer.style.display = 'block';
}

async function approveActionDirect(nodeId) {
  try {
    const resp = await fetch('/api/mcp/call', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        name: 'execute_mitigation_action',
        arguments: {
          action_type: 'ISOLATE_DEVICE',
          target_node_id: nodeId,
          reasoning: 'Manual analyst quarantine from graph inspector',
          force_immediate: true
        }
      })
    });
    const res = await resp.json();
    if (res.success) {
      showToast(`Isolated node ${nodeId}`);
      cy.$id(nodeId).data('status', 'contained');
      showNodeInspector(cy.$id(nodeId).data());
    }
  } catch (e) {
    showToast("Error isolating node", true);
  }
}

// =========================================================================
// 8. SIEM Telemetry Logs Viewer
// =========================================================================
async function fetchAndRenderSIEMLogs() {
  try {
    const res = await fetch('/api/mcp/call', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        name: 'siem_log_search',
        arguments: { query: '' }
      })
    });
    const data = await res.json();
    const logs = data.matched_logs || [];

    document.getElementById("logCountBadge").textContent = `${logs.length} Events`;
    const tbody = document.getElementById("telemetryBody");
    tbody.innerHTML = '';

    logs.forEach(l => {
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td>${escapeHtml(l.timestamp || '--')}</td>
        <td><span class="meta-tag">${escapeHtml(l.source || '--')}</span></td>
        <td><strong>${escapeHtml(l.event || '--')}</strong></td>
        <td>${escapeHtml(l.user || l.actor || '--')}</td>
        <td><code>${escapeHtml(l.src_ip || l.src || '--')}</code></td>
        <td>${escapeHtml(l.anomaly || l.note || JSON.stringify(l))}</td>
      `;
      tbody.appendChild(tr);
    });
  } catch (err) {
    console.error("Failed to load SIEM logs:", err);
  }
}

// =========================================================================
// 9. Custom Alert Modal
// =========================================================================
function populateCustomAlertNodes(elements) {
  const sel = document.getElementById("customTargetNode");
  sel.innerHTML = '';
  if (!elements) return;

  elements.forEach(el => {
    if (el.data && !el.data.source) { // Is a node
      const opt = document.createElement("option");
      opt.value = el.data.id;
      opt.textContent = `${el.data.label} (${el.data.type})`;
      sel.appendChild(opt);
    }
  });
}

async function submitCustomAlert() {
  const title = document.getElementById("customAlertTitle").value;
  const targetId = document.getElementById("customTargetNode").value;
  const severity = document.getElementById("customSeverity").value;
  const desc = document.getElementById("customDesc").value;

  try {
    const resp = await fetch('/api/custom-alert', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        title,
        target_node_id: targetId,
        severity,
        description: desc
      })
    });
    const res = await resp.json();
    if (res.status === 'injected') {
      currentAlert = res.alert;
      updateAlertBanner(res.alert);
      document.getElementById("customAlertModal").style.display = 'none';
      showToast("Custom alert injected! Click Start Autonomous Investigation.");
    }
  } catch (e) {
    showToast("Failed to inject alert", true);
  }
}

// =========================================================================
// 10. Event Listeners & Tab Controls
// =========================================================================
function setupEventListeners() {
  // Scenario Selector
  document.getElementById("scenarioSelect").addEventListener("change", (e) => {
    currentScenarioId = e.target.value;
    loadScenario(currentScenarioId);
  });

  // Start Investigation Button
  document.getElementById("btnInvestigate").addEventListener("click", () => {
    startInvestigation();
  });

  // Fit Graph Button
  document.getElementById("btnFitGraph").addEventListener("click", () => {
    if (cy) cy.fit(null, 40);
  });

  // Toggle Layout
  document.getElementById("btnToggleLayout").addEventListener("click", () => {
    runGraphLayout('concentric');
  });

  // Attack Path Highlight
  document.getElementById("btnHighlightPath").addEventListener("click", () => {
    if (currentReport && currentReport.chain_of_evidence) {
      highlightAttackChain(currentReport.chain_of_evidence);
    } else {
      showToast("Run investigation first to discover attack path.");
    }
  });

  // Close Node Inspector
  document.getElementById("btnCloseInspector").addEventListener("click", () => {
    document.getElementById("nodeInspector").style.display = 'none';
  });

  // Tabs
  document.querySelectorAll(".tab-btn").forEach(btn => {
    btn.addEventListener("click", () => {
      document.querySelectorAll(".tab-btn").forEach(b => b.classList.remove("active"));
      document.querySelectorAll(".tab-content").forEach(c => c.classList.remove("active"));
      btn.classList.add("active");
      const targetId = btn.getAttribute("data-tab");
      document.getElementById(targetId).classList.add("active");
    });
  });

  // Bottom Telemetry Drawer Toggle
  document.getElementById("drawerToggle").addEventListener("click", () => {
    const drawer = document.getElementById("telemetryDrawer");
    const arrow = document.getElementById("drawerArrow");
    drawer.classList.toggle("expanded");
    arrow.textContent = drawer.classList.contains("expanded") ? "▼ Collapse" : "▲ Expand";
  });

  // Custom Alert Modal
  document.getElementById("btnCustomAlert").addEventListener("click", () => {
    document.getElementById("customAlertModal").style.display = 'flex';
  });
  document.getElementById("btnCloseModal").addEventListener("click", () => {
    document.getElementById("customAlertModal").style.display = 'none';
  });
  document.getElementById("btnCancelModal").addEventListener("click", () => {
    document.getElementById("customAlertModal").style.display = 'none';
  });
  document.getElementById("btnSubmitCustomAlert").addEventListener("click", submitCustomAlert);

  // Copy Markdown Report
  document.getElementById("btnCopyReport").addEventListener("click", () => {
    if (!currentReport) return showToast("No report to copy.");
    const md = `# Incident Report: ${currentReport.incident_id}\n\n**Severity**: ${currentReport.severity}\n\n## Summary\n${currentReport.summary}\n\n## Attack Narrative\n${currentReport.attack_narrative}\n\n## MITRE ATT&CK Mapping\n${JSON.stringify(currentReport.mitre_attack_mapping, null, 2)}`;
    navigator.clipboard.writeText(md).then(() => showToast("Report copied to clipboard!"));
  });

  // Download JSON
  document.getElementById("btnDownloadJson").addEventListener("click", () => {
    if (!currentReport) return showToast("No report to export.");
    const blob = new Blob([JSON.stringify(currentReport, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${currentReport.incident_id}.json`;
    a.click();
    URL.revokeObjectURL(url);
    showToast("Exported JSON report.");
  });
}

function resetInvestigationState() {
  document.getElementById("reasoningStream").innerHTML = `
    <div class="empty-state" id="streamPlaceholder">
      <div class="empty-icon">🛡️</div>
      <h3>Autonomous Agent Standby</h3>
      <p>Click <strong>Start Autonomous Investigation</strong> to watch TraceGuard traverse connected nodes, call MCP graph tools, and uncover the full attack narrative.</p>
    </div>
  `;
  document.getElementById("chainTimeline").innerHTML = '<div class="empty-state-sm">No active evidence chain yet. Run an investigation.</div>';
  document.getElementById("autoActionsList").innerHTML = '<div class="empty-state-sm">No automated actions taken yet.</div>';
  document.getElementById("pendingActionsList").innerHTML = '<div class="empty-state-sm">No actions currently pending approval.</div>';
  document.getElementById("reportPaper").innerHTML = '<div class="empty-state-sm">Incident report will be automatically generated upon investigation completion.</div>';
  document.getElementById("hudBlastRadius").textContent = '--';
  document.getElementById("agentTimer").textContent = '0.0s';
  document.getElementById("evidenceBadgeCount").textContent = '0';
  document.getElementById("actionBadgeCount").textContent = '0';
}

function showToast(msg, isError = false) {
  const toast = document.getElementById("toastNotification");
  toast.textContent = msg;
  toast.style.borderColor = isError ? "var(--color-critical)" : "var(--accent-cyan)";
  toast.style.display = "block";
  setTimeout(() => {
    toast.style.display = "none";
  }, 2800);
}

function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}
