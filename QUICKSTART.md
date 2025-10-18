# Quick Start Guide

## Prerequisites Check
- [ ] Splunk Enterprise installed and running
- [ ] Ollama installed with llama3:8b model
- [ ] Python 3.9+ with virtual environment
- [ ] Node.js 18+ and npm

## Step 1: Backend Setup (5 minutes)

```bash
# Clone and navigate
git clone https://github.com/Achuth07/Agentic-Threat-Hunter.git
cd Agentic-Threat-Hunter

# Set up Python environment
python3 -m venv hunter_env
source hunter_env/bin/activate
pip install -r requirements.txt

# Configure Splunk credentials
echo "SPLUNK_PASSWORD=your_splunk_password" > .env
echo "DEFAULT_INDEX=main" >> .env
echo "TIME_POLICY_MODE=normalize" >> .env
echo "OLLAMA_MODEL=llama3:8b" >> .env
```

Also create `~/.splunkrc`:
```ini
host=localhost
port=8089
username=admin
password=your_splunk_password
scheme=https
```

## Step 2: Frontend Setup (3 minutes)

```bash
cd web
npm install
npm run build
cd ..
```

## Step 3: Run the Application

### Production Mode (Recommended for First Run)
```bash
source hunter_env/bin/activate
PORT=8002 python server.py
```
Open http://localhost:8002 in your browser.

### Development Mode (For Frontend Development)
```bash
# Terminal 1: Backend
source hunter_env/bin/activate
PORT=8002 python server.py

# Terminal 2: Frontend with hot reload
cd web
npm run dev
```
Open http://localhost:3000 in your browser.

## Step 4: Test the Agent

1. Open the web interface
2. Navigate to the **Agentic Chat** view
3. Type a query like: "Find failed authentication attempts in the last 24 hours"
4. Watch the agent:
   - Generate an SPL query
   - Execute it against Splunk
   - Summarize the results

## Troubleshooting

### Backend Issues
- **"ModuleNotFoundError"**: Make sure virtual environment is activated
  ```bash
  source hunter_env/bin/activate
  ```
- **"Connection refused" to Splunk**: Check Splunk is running and credentials are correct
- **"Connection refused" to Ollama**: Ensure Ollama is running
  ```bash
  ollama serve
  ```

### Frontend Issues
- **"npm: command not found"**: Install Node.js and npm
  ```bash
  sudo apt update && sudo apt install nodejs npm
  ```
- **"Failed to fetch"**: Check backend is running on port 8002
- **WebSocket connection failed**: Ensure no firewall is blocking port 8002

## Configuration Options

Edit `.env` to customize behavior:

```bash
# Default Splunk index to search
DEFAULT_INDEX=main

# Time window policy: off | normalize | infer
TIME_POLICY_MODE=normalize

# Ollama model to use
OLLAMA_MODEL=llama3:8b

# Splunk connection
SPLUNK_HOST=localhost
SPLUNK_PORT=8089
SPLUNK_USERNAME=admin
```

## Features Overview

- **Chat Interface**: Natural language threat hunting
- **Real-time Activity**: See agent operations as they happen
- **Search Results**: LLM-generated summaries + raw JSON
- **Dashboard**: Security metrics and timelines
- **Integrations**: Manage security platforms
- **Settings**: Configure agent behavior

## Next Steps

1. Try different queries to test the agent
2. Review the activity feed to understand the workflow
3. Check the search results and summaries
4. Explore the dashboard and integrations views
5. Configure settings for autonomous hunting

## Need Help?

- Check `README.md` for detailed documentation
- Review `MIGRATION_SUMMARY.md` for technical details
- See `.github/copilot-instructions.md` for developer guidance
