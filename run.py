#!/usr/bin/env python3
"""
TraceGuard — Autonomous Security Incident Investigator
Hackathon Track 01: Agents That Act on Connected Data

Run this script to start the TraceGuard SOC Command Center:
    python run.py
"""

import sys
import os
import webbrowser
import time
import uvicorn

BANNER = r"""
================================================================================
  _______                   _____                     _ 
 |__   __|                 / ____|                   | |
    | |_ __ __ _  ___ ___ | |  __ _   _  __ _ _ __ __| |
    | | '__/ _` |/ __/ _ \| | |_ | | | |/ _` | '__/ _` |
    | | | | (_| | (_|  __/| |__| | |_| | (_| | | | (_| |
    |_|_|  \__,_|\___\___| \_____|\__,_|\__,_|_|  \__,_|
                                                        
 Autonomous Security Incident Investigator & Connected Data Agent
 Track 01: Agents That Act on Connected Data
================================================================================
 [✓] Multi-Hop Graph Reasoning Engine: NetworkX DiGraph
 [✓] Model Context Protocol (MCP) Server: Active on JSON-RPC / REST / WS
 [✓] Autonomous Investigation Agent: ReAct & Evidence Chain Generator
 [✓] Human-in-the-Loop (HITL) Containment: Interactive Approval Gate
 [✓] SOC Command Center UI: Live Cytoscape Force-Directed Visualizer
================================================================================
"""

def main():
    print(BANNER)
    port = int(os.environ.get("PORT", 8000))
    host = os.environ.get("HOST", "127.0.0.1")
    url = f"http://{host}:{port}"

    print(f"[*] Starting TraceGuard Server on {url} ...")
    print(f"[*] Open {url} in your browser to view the SOC Command Center.")
    print("[*] Press Ctrl+C to terminate the server.\n")

    # Open browser automatically after a short delay
    def open_browser():
        time.sleep(1.2)
        try:
            webbrowser.open(url)
        except Exception:
            pass

    import threading
    threading.Thread(target=open_browser, daemon=True).start()

    uvicorn.run("backend.main:app", host=host, port=port, log_level="info", reload=False)

if __name__ == "__main__":
    main()
