# Velociraptor — Integration Hand‑Off

## Runtime Topology (What’s Running, Where)
- **Windows service:** `Velociraptor` (**server** role) — **Running**
- **Effective server config (used by the service):**  
  `C:\\Program Files\\Velociraptor\\Velociraptor.config.yaml`
- **API client principal:** `ThreatHunterAgent` with roles `administrator, api`  
  **API creds file:** `C:\\Program Files\\Velociraptor\\api.config.yaml`  
  **Sanity test:** `SELECT version() FROM info()` returned JSON ✅
- **At least one client online:** e.g., `C.c9be2aef833126a9` (Windows 11 Pro 24H2)

## Agent-Server Connection (WSL ↔ Windows)
The Python agent running in WSL connects to the Velociraptor server running on Windows.

### Mechanism
1.  **Config Access**: The agent reads the API configuration file directly from the Windows filesystem via the WSL mount point:
    -   Path: `/mnt/c/Program Files/Velociraptor/api.config.yaml`
    -   Configured in `.env`: `VELOCIRAPTOR_CONFIG="/mnt/c/Program Files/Velociraptor/api.config.yaml"`
2.  **Network**: The agent connects to the API port `127.0.0.1:8001`.
    -   This works because WSL 2 (especially in mirrored networking mode) can access services listening on the Windows localhost.

### Verifying Connectivity
To confirm the agent can talk to the Velociraptor server, run this Python one-liner from the `agentic-hunter` directory (ensure `hunter_env` is active or use the full path):

```bash
./hunter_env/bin/python3 -c "from dotenv import load_dotenv; load_dotenv(); from tools.velociraptor_tool import run_velociraptor_query; print(run_velociraptor_query('SELECT version() FROM info()'))"
```

**Success Output:**
```json
[{"version()": 0}]
```
If you see a JSON list with the version, the connection is established and authenticated.

## Network Bindings & URLs (from server.config.yaml)
- **API (gRPC):** `tcp://127.0.0.1:8001`  
  - Local-only (loopback). The agent must run **on the server host** (or tunnel it).
- **Frontend (client ingress):** `https://0.0.0.0:8002/` (certificate configured)  
  - Clients in this config use `server_urls: ["https://localhost:8002/"]` → only valid for **same-host** clients. For remote clients, update to a reachable host (e.g., `https://<server-ip-or-fqdn>:8002/`) before packaging their client config.
- **GUI (web app):** `https://0.0.0.0:8889`  
  - `public_url: https://localhost:8889/app/index.html` (how the UI links itself).  
  - Exposed on all interfaces; restrict with firewall/VPN if not meant for LAN access.
- **Monitoring endpoint:** `127.0.0.1:8003` (local metrics).

## Crypto / Auth (Summary)
- CA, Frontend, and GUI certificates are defined in the config. Treat all **private keys** as **secrets**.
- GUI authenticator: **Basic** (username/password). Initial users exist; automation uses the API principal **ThreatHunterAgent**.

## Datastore & Logs (Operational Paths)
- **Datastore:** `C:\\Program Files\\Velociraptor\\datastore`
- **Filestore:** `C:\\ Program Files\\Velociraptor\\filestore`
- **Logs (rotated, per component):** `C:\\ Program Files\\Velociraptor\\logs\\Velociraptor*`
- **Resource tuning:** `expected_clients: 30000`
- **Max upload size:** client 5 MB; server 10 MB

## Defaults / Misc
- **Default client monitoring artifact:** `Generic.Client.Stats`
- **Hunt expiry:** 168 hours (7 days)
- **Notebook cell timeout:** 10 minutes
- **Certificate validity:** 365 days

---

## Service Recovery / Restart (Windows)

If the Velociraptor service is not running or needs to be restarted on the Windows host, follow these steps in an **Administrator PowerShell**:

### 1. Clean Up and Delete the Faulty Service
Ensure the faulty service is entirely removed.
```powershell
Stop-Service Velociraptor -Force
sc.exe delete Velociraptor
```

### 2. Define the Command String
Define the command string as a variable to handle spaces in paths correctly.
```powershell
$cmd_path = '"C:\PROGRA~1\VELOCI~1\velociraptor.exe" --config "C:\PROGRA~1\VELOCI~1\server.config.yaml" frontend'
```

### 3. Create the Service
Pass the variable to `sc.exe`.
```powershell
sc.exe create Velociraptor binPath= $cmd_path start= auto displayname= "Velociraptor Server"
```
Expected Output: `CreateService SUCCESS`

### 4. Start the Service and Verify
```powershell
Start-Service Velociraptor
```
**Verification:**
- Wait about 15 seconds.
- Open your web browser and navigate to: `https://localhost:8889`

---

## Canonical Commands (for the Agent)

### Health & Inventory
```powershell
# API connectivity
.\velociraptor.exe --api_config "C:\Program Files\Velociraptor\api.config.yaml" `
  query "SELECT version() FROM info()"

# Client list with friendly columns (nested fields)
.\velociraptor.exe --api_config "C:\Program Files\Velociraptor\api.config.yaml" `
  query "SELECT client_id,
                os_info.system   AS os,
                os_info.release  AS os_release,
                os_info.hostname AS hostname,
                os_info.fqdn     AS fqdn,
                timestamp(epoch=last_seen_at/1000000).String AS last_seen
         FROM clients()"
```

### Per‑Client Collection → Status → Results
```powershell
# Start a collection (replace client_id)
.\velociraptor.exe --api_config "C:\Program Files\Velociraptor\api.config.yaml" `
  query "SELECT flow_id FROM collect_client(
           client_id='C.c9be2aef833126a9',
           artifacts=['Windows.Sys.Info'])"

# Watch flows for that client
.\velociraptor.exe --api_config "C:\Program Files\Velociraptor\api.config.yaml" `
  query "SELECT flow_id, state, started, completed
         FROM flows(client_id='C.c9be2aef833126a9')
         ORDER BY started DESC LIMIT 5"

# Read results (use returned flow_id)
.\velociraptor.exe --api_config "C:\Program Files\Velociraptor\api.config.yaml" `
  query "SELECT * FROM read_results(
           client_id='C.c9be2aef833126a9',
           flow_id='F.XXXX',
           artifact='Windows.Sys.Info')"
```

### Fleet‑Wide Hunts
```powershell
# Create a hunt across Windows clients
.\velociraptor.exe --api_config "C:\Program Files\Velociraptor\api.config.yaml" `
  query "SELECT hunt_id FROM create_hunt(
           artifacts=['Windows.Sys.Info'],
           description='SysInfo sweep')"

# Inspect recent hunts
.\velociraptor.exe --api_config "C:\Program Files\Velociraptor\api.config.yaml" `
  query "SELECT hunt_id, state, created, expires
         FROM hunts()
         ORDER BY created DESC LIMIT 5"
```

---

## Integration Notes (Important for Reliability & Security)
1. **Run the agent on the server host** (or provide a tunnel) because the API is bound to `127.0.0.1:8001`.
2. **Remote clients**: before generating or distributing client configs/installer bundles, change
   `Client.server_urls` to a reachable URL (e.g., `https://<server-fqdn>:8002/`), not `https://localhost:8002/`.
3. **Secrets hygiene**: never commit `api.config.yaml` or private keys from the server config to source control.
4. **Least privilege (optional later)**: once workflows are stable, reduce the API user to a minimal policy (e.g., `any_query`, `collect_client`, `read_results`). After CLI user/ACL changes, **restart** the service.
5. **Timestamps**: many fields (e.g., `last_seen_at`) are **microseconds**. Use `timestamp(epoch=field/1000000)` in VQL to render human‑readable times.
6. **Backups**: snapshot both **datastore** and **filestore** paths for restore.

## Pitfalls Already Solved
- **“User not found” on API calls** → service previously ran as a **client**; now fixed by installing as a **server** and creating the API user against the same datastore.
- **NULL client fields** → use nested fields (`os_info.*`) and convert `last_seen_at` from microseconds.
- **CLI changes not reflected** → always **restart** the `Velociraptor` service after `user add`, `acl grant`, or `config api_client`.
