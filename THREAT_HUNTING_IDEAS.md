# Threat Hunting Feature Ideas

Based on your current stack (Splunk, Velociraptor, VirusTotal, LangGraph Agent), here are several advanced threat hunting features you can implement:

## 1. Automated IOC Enrichment & Sweeping (The "Hunter's Loop")
**Concept:** Automatically correlate indicators across your stack.
- **Workflow:**
    1.  **Trigger:** User asks to check an IP/Hash or a Splunk alert fires.
    2.  **Enrich:** Agent queries **VirusTotal** for reputation.
    3.  **Sweep (If Malicious):** If VT returns > 0 detections, the Agent automatically:
        -   Queries **Splunk** for historical access (`index=* "1.2.3.4"`).
        -   Queries **Velociraptor** to check *all* online endpoints for active connections or file presence (`SELECT * FROM netstat() WHERE RemoteAddress = '1.2.3.4'`).
    4.  **Report:** Aggregates findings: "IP is malicious (VT). Found in 5 Splunk logs (past 24h). Currently active on Host-A."

## 2. "One-Click" Live Forensics Playbook
**Concept:** Automate the "first 15 minutes" of incident response.
- **Workflow:**
    -   User says: *"Investigate Host Workstation-01"*
    -   Agent runs a standard **Velociraptor Artifact Chain**:
        1.  `Windows.Sys.Info` (Basic info)
        2.  `Windows.Network.Netstat` (Active connections)
        3.  `Windows.System.Pslist` (Running processes)
        4.  `Windows.System.Services` (Installed services)
        5.  `Windows.Persistence.Autoruns` (Persistence mechanisms)
    -   **LLM Analysis:** The Agent feeds the JSON results to the LLM to identify anomalies (e.g., "Process `svchost.exe` running from `C:\Temp` is suspicious").

## 3. CVE Vulnerability Scoping
**Concept:** Go from "News" to "Fleet Status" in minutes.
- **Workflow:**
    -   User says: *"Am I vulnerable to CVE-2024-XXXX?"*
    -   **Research:** Agent uses **Web Search** to find the affected software and version (e.g., "Chrome < 120.0.0").
    -   **Hunt:** Agent generates a **Velociraptor VQL** query to check installed applications on all hosts:
        `SELECT Name, Version FROM apps() WHERE Name =~ 'Chrome' AND Version < '120.0.0'`
    -   **Result:** Returns a list of vulnerable hosts.

## 4. Behavioral Anomaly Detection (LLM-Driven)
**Concept:** Use the LLM to spot "weird" things that signature-based tools miss.
- **Workflow:**
    -   User says: *"Analyze process trees on Server-DB"*
    -   Agent retrieves process list via Velociraptor.
    -   Agent sends the process tree to the LLM with a prompt: *"Analyze this process list for suspicious parent-child relationships (e.g., Word spawning PowerShell, cmd.exe spawning unknown binaries). Return a list of suspicious PIDs and reasons."*

## 5. Persistence Hunting
**Concept:** Proactively look for hidden backdoors.
- **Workflow:**
    -   User says: *"Check for persistence on the CEO's laptop"*
    -   Agent runs Velociraptor's `Windows.Persistence.*` artifacts (Scheduled Tasks, Registry Run Keys, Services).
    -   Agent cross-references binaries found in persistence locations with **VirusTotal** (using the hash).
    -   **Alert:** "Found unknown binary `update.exe` in Startup folder with 0/70 VT score (Unknown) but unsigned."

## 6. "Ask the Fleet" (Natural Language VQL)
**Concept:** Turn any question into a fleet-wide query.
- **Workflow:**
    -   User says: *"Who has the file 'passwords.txt' on their desktop?"*
    -   Agent translates this to VQL: `SELECT * FROM glob(globs='C:/Users/*/Desktop/passwords.txt')`
    -   Agent executes across the fleet and reports hits.

## Implementation Roadmap
1.  **Enhance `multitool_agent.py`**: Add a "Playbook" mode that chains multiple tool calls (e.g., VT -> Velociraptor).
2.  **VQL Library**: Create a library of "Golden VQL" queries for common tasks (Persistence, Software Inventory) so the LLM doesn't have to write them from scratch every time.
3.  **Response Parsing**: Improve the `_summarize_results` function to handle large JSON blobs from Velociraptor better, perhaps filtering for "interesting" fields before sending to the LLM.
