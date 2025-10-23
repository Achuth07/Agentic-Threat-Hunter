# Agentic-Threat-Hunter

![Status](https://img.shields.io/badge/status-in%20development-green)

An autonomous AI agent for proactive cybersecurity threat hunting. This agent leverages local LLMs via Ollama and the LangGraph framework to intelligently query security platforms like Splunk, automating the process of learning about and hunting for threats with minimal human intervention.

## Table of Contents

- [Project Goal](#project-goal)
- [Architectural Plan](#architectural-plan)
- [Current Progress](#current-progress)
- [Getting Started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Installation](#installation)
  - [Usage](#usage)
  - [Run the Web UI](#run-the-web-ui)
  - [Health Endpoints](#health-endpoints)
- [Roadmap](#roadmap)
- [Contributing](#contributing)
- [License](#license)

## Project Goal

The primary goal of this project is to build an autonomous AI agent that can perform cybersecurity threat hunting with minimal human input. The agent will be capable of:

- **Learning**: Receiving a high-level query, such as an APT group name (e.g., "APT29") or a TTP (e.g., "PowerShell execution").
- **Planning**: Researching the threat to understand its behaviors, tools, and indicators of compromise (IoCs).
- **Acting**: Translating its understanding into concrete search queries for various security platforms.
- **Executing**: Running these queries against target systems, starting with Splunk.
- **Adapting**: Analyzing the results, handling errors, and refining its approach in a continuous loop, much like a human analyst.

This project aims to create a powerful, low-cost, and private threat hunting assistant by leveraging open-source technologies.

## Architectural Plan

The agent is built on a modular and resilient architecture:

- **Orchestration Engine**: LangGraph is used to define the agent's workflow as a stateful graph. This allows for complex, cyclical logic, enabling the agent to loop, branch, and self-correct when queries fail or return no results.
- **Reasoning Engine**: A locally-hosted Large Language Model (LLM) served via Ollama. The initial model is `llama3:8b`, which provides a strong balance of performance and resource usage on consumer hardware. This approach ensures privacy and eliminates API inference costs.
- **The Hunting Grounds**:
  - Splunk Enterprise (Free License) as the SIEM, integrated via the Splunk Python SDK.
  - Velociraptor for live endpoint forensics, integrated via `pyvelociraptor`.
- **Tools**: Custom tools include a Splunk search executor and a Velociraptor VQL executor. More tools (threat intel, EDR) can be added.
- **Multi-agent Graph (LangGraph)**: The agent is modeled as nodes:
  - `tool_router` → decides the best tool (Splunk vs Velociraptor).
  - `generate_query` → produces SPL or VQL based on the chosen tool.
  - `execute_tool` → runs the query and returns normalized results.
  - Strong, explicit router rules ensure correct selection.
- **Dedicated Models**:
  - `splunk_hunter`: SPL specialization for clean, single-line Splunk queries.
  - `velociraptor_hunter`: VQL specialization for robust Velociraptor queries (no host filters, correct functions).
- **Web UI**: React + Vite + Tailwind frontend with a FastAPI backend and WebSocket streaming. Activity feed shows each step; raw results are labeled with their source (Splunk or Velociraptor).

## Current Progress

Key capabilities currently working:

- ✅ **Splunk Integration**: Execute SPL via Splunk SDK with guardrails (default index policy, time window normalization, backtick stripping, query normalization).
- ✅ **Velociraptor Integration**: Execute VQL via `pyvelociraptor` using `LoadConfigFile` and `velo_pandas.DataFrameQuery`, returning normalized JSON row lists.
- ✅ **Dedicated Models**: Custom `splunk_hunter` (SPL) and `velociraptor_hunter` (VQL) models built with Modelfiles; the backend selects them via env vars.
- ✅ **Router Node + Heuristics**: Strong decision matrix to route endpoint/system state requests to Velociraptor and log/SIEM analytics to Splunk.
- ✅ **Web UI Enhancements**: Activity feed correlates steps; shows generated SPL/VQL inline; raw results labeled by source; integrations panel shows live health.
- ✅ **Health Endpoints**: `/health/splunk` and `/health/velociraptor` for quick connectivity checks; surfaced in the UI.

## Getting Started

Follow these steps to set up the project on your own machine.

### Prerequisites

- **Hardware**: A machine with a dedicated NVIDIA GPU is highly recommended for acceptable performance.
- **Operating System**: Windows 10/11 with WSL 2 enabled, or a native Linux distribution.
- **Software**:
  - [Splunk Enterprise](https://www.splunk.com/en_us/download/splunk-enterprise.html) installed and running.
  - Ollama installed, with a model pulled (e.g., `ollama pull llama3:8b`).
  - Python 3.9+.
  - Node.js 18+ and npm (for the React frontend).
  - Git.

### Installation

1. **Clone the Repository:**
```bash
git clone https://github.com/your-username/Agentic-Threat-Hunter.git
cd Agentic-Threat-Hunter
```

2. **Set Up Python Environment:**

```bash
python3 -m venv hunter_env
source hunter_env/bin/activate
```

3. **Install Dependencies:**

```bash
pip install -r requirements.txt
```

4. **Configure Credentials:**

Create a `.env` file for your Splunk password:

```
SPLUNK_PASSWORD=your_splunk_password
```

Create a `.splunkrc` file in your home directory (`~/.splunkrc`) for the SDK:

```ini
host=localhost
port=8089
username=admin
password=your_splunk_password
scheme=https
```

### Usage

Run simple checks for the core components.

```bash
# This will run the tests defined at the bottom of the script
python main.py
```

### Run the Web UI

The project includes a modern React-based web interface built with **React**, **Tailwind CSS**, and **lucide-react**. The UI is **fully responsive** and optimized for desktop, tablet, and mobile devices. Features include:

- **AI Threat Hunting Chat**: Interactive chat interface to query the AI agent
- **Real-time Activity Feed**: See step-by-step agent operations as they happen
- **Search Result Summary**: LLM-generated summaries of findings
- **Raw Search Results**: View raw JSON responses from security platforms
- **Dashboard View**: Security metrics and threat detection timeline
- **Integrations View**: Manage connected security platforms
- **Responsive Design**: Seamless experience across all screen sizes with mobile menu

#### Development Mode

For frontend development with hot reload:

```bash
# Terminal 1: Start the backend
PORT=8005 python server.py

# Terminal 2: Start the React dev server
cd web
npm install  # First time only
npm run dev
```

The frontend will be available at http://localhost:3000 and will proxy API/WebSocket requests to the backend on port 8005.

#### Production Mode

Build and serve the React app from the FastAPI backend:

```bash
# Build the React app
cd web
npm run build
cd ..

# Start the server (serves the built React app)
PORT=8005 python server.py
```

Open http://localhost:8005 to access the full application.

**Features:**

- Chat with the LLM at the top; messages are sent via WebSocket to the backend.
- Watch step-by-step agent activity as it generates SPL or VQL and executes queries.
- See LLM-generated summaries of search results and raw JSON data.
- Raw results include `source` badges (splunk or velociraptor). VQL and SPL strings are displayed in the activity feed.
- Multiple views: Chat, Dashboard, Integrations, and Settings.

### Configuration

Environment variables and guardrails:

- `DEFAULT_INDEX` (default: `main`)
  - Used when the query starts with `search` and no `index=` is present.
  - If the SPL contains `index=_internal` but the user did not ask for internal logs, the server rewrites it to `index=DEFAULT_INDEX`.

- `TIME_POLICY_MODE` (default: `normalize`)
  - Controls how time windows are handled.
  - `off`: Do nothing. The LLM’s SPL is used as-is (no fixes, no inference).
  - `normalize`: Convert invalid tokens to valid SPL (e.g., `timeframe:end-1d` → `earliest=-1d`). Do not infer windows.
  - `infer`: If the user asks for a range (e.g., “last 24 hours”) and the SPL lacks `earliest=`, insert an appropriate `earliest`.

- `OLLAMA_MODEL` (default: `splunk_hunter`)
  - Model used for SPL generation.
- `VQL_MODEL` (default: `velociraptor_hunter`)
  - Model used for VQL generation.
- `SUMMARY_MODEL` (default: `llama3:8b`)
  - Model used to summarize results for humans.
- `VELOCIRAPTOR_CONFIG` (optional)
  - Path to the Velociraptor `api.config.yaml`. If not set, the server looks for `api.config.yaml` in the project root.

Examples:

```bash
# Default behavior (normalize time tokens only)
python server.py

# Pure LLM output, no policy changes
TIME_POLICY_MODE=off python server.py

# Infer missing time windows from the question
TIME_POLICY_MODE=infer python server.py

# Change default index if desired
DEFAULT_INDEX=my_index python server.py
```

In the activity feed you’ll see entries when a policy is applied (e.g., “Index policy applied”, “Time window applied (mode=normalize/infer)”).

### Dedicated VQL Model (Velociraptor)

This project includes a specialized Ollama model for generating Velociraptor VQL only. It improves correctness for functions like pslist(), info(), users(), netstat(), prefetch(), stat(), and glob().

- The Modelfile lives at `VelociraptorModelfile`.
- Create the model locally (name: `velociraptor_hunter`).
- The backend will use it automatically for VQL generation via the `VQL_MODEL` env var (defaults to `velociraptor_hunter`).

Example:

```bash
# Build the model
ollama create velociraptor_hunter -f VelociraptorModelfile

# Optional: run a quick smoke test
echo 'show me all the local user accounts' | ollama run velociraptor_hunter
echo 'what is the basic information about this computer?' | ollama run velociraptor_hunter

# Backend will pick this up by default; to override:
VQL_MODEL=velociraptor_hunter python server.py
```

Notes:
- The model outputs a single VQL statement with no code fences or extra text.
- Quotes in strings are unescaped (e.g., `WHERE Name =~ "notepad.exe"` will appear as `WHERE Name =~ "notepad.exe"`).

Guardrails in generation and runtime:
- pslist() takes no parameters. The model prompt forbids `pslist(hostname=...)`.
- Hostname filters are not allowed. Mentions of hostnames are treated as context only.
- The backend sanitizes generated VQL to remove accidental `Hostname=` or `ComputerName=` filters and strips parameters from `pslist(...)` to `pslist()`.

### Dedicated SPL Model (Splunk)

This project also includes a Modelfile tailored for SPL generation.

- The Splunk Modelfile lives at `SplunkModelfile` (renamed from `Modelfile` to avoid confusion).
- Create the model locally (name suggestion: `splunk_hunter`).
- The backend uses `OLLAMA_MODEL` for SPL generation and defaults to `splunk_hunter`.

Example:

```bash
# Build the Splunk model
ollama create splunk_hunter -f SplunkModelfile

# Optional: run a quick smoke test
echo 'failed logons in last day' | ollama run splunk_hunter

# Backend will pick this up by default; to override:
OLLAMA_MODEL=splunk_hunter python server.py
```

### Health Endpoints

Backend exposes simple health checks that the UI surfaces in the Integrations panel:

- `GET /health/splunk` → checks Splunk connectivity by running a trivial search.
- `GET /health/velociraptor` → runs a minimal VQL (`SELECT * FROM pslist() LIMIT 1`) using the configured Velociraptor API config.

### Tool Router Decision Matrix

Routing is determined by a heuristic plus an LLM fallback with explicit rules:

- Use Velociraptor for live endpoint/system state:
  - Processes (pslist), services, listening ports (netstat), basic system info (info()), local users (users()), prefetch, registry, filesystem metadata (stat, glob), autoruns, memory artifacts.
- Use Splunk for SIEM/log analytics:
  - EventID/EventCode, `sourcetype`, `index=`, `tstats`/`mstats`, dashboards, authentication/logon events, trends over time, historical searches across many hosts.
- If a hostname is mentioned for endpoint state, still choose Velociraptor (hostnames are context; no host filters are added to VQL).

## Roadmap

This project is in active development. The next steps are:

- [ ] **LangGraph Enhancements**: Expand the agentic workflow with planning, self-correction loops, and analysis nodes.
- [ ] **Threat Intelligence Tools**: Add tools for MITRE ATT&CK, OTX, etc.
- [ ] **Prompt Refinements**: Continue improving SPL and VQL prompts and examples.
- [ ] **EDR Expansion**: Integrate with additional endpoint platforms.
- [ ] **Automated Tests**: Add unit and integration tests for router decisions and query generation.

## Contributing

Contributions are welcome! If you have ideas for new features, improvements, or bug fixes, please feel free to open an issue or submit a pull request.

1. Fork the repository.
2. Create a new branch (`git checkout -b feature/YourFeature`).
3. Commit your changes (`git commit -m 'Add some feature'`).
4. Push to the branch (`git push origin feature/YourFeature`).
5. Open a Pull Request.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.