# Copilot Instructions for Agentic-Threat-Hunter

## Overview
Agentic-Threat-Hunter is an autonomous AI agent designed for proactive cybersecurity threat hunting. It leverages local LLMs via Ollama and the LangGraph framework to intelligently query security platforms like Splunk. The agent automates the process of learning about and hunting for threats with minimal human intervention.

## Architecture
- **Orchestration Engine**: LangGraph defines the agent's workflow as a stateful graph, enabling complex logic like loops, branching, and self-correction.
- **Reasoning Engine**: A locally-hosted LLM (e.g., `llama3:8b`) served via Ollama ensures privacy and eliminates API costs.
- **Hunting Ground**: Splunk Enterprise (Free License) serves as the initial SIEM platform, with programmatic interaction via the Splunk Python SDK.
- **Custom Tools**: Tools are modular and include Splunk search execution. Future tools will expand capabilities to threat intelligence gathering and EDR interaction.

## Developer Workflows
### Setting Up the Environment
1. Clone the repository:
   ```bash
   git clone https://github.com/your-username/Agentic-Threat-Hunter.git
   cd Agentic-Threat-Hunter
   ```
2. Set up the Python environment:
   ```bash
   python3 -m venv hunter_env
   source hunter_env/bin/activate
   ```
3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
4. Configure Splunk credentials:
   - Add `SPLUNK_PASSWORD` to a `.env` file.
   - Create a `~/.splunkrc` file with Splunk connection details.

### Running the Agent
- Execute the main script to test core components:
  ```bash
  python main.py
  ```

### Testing and Debugging
- Use the `main.py` script to verify the integration of LangGraph, Ollama, and Splunk.
- Logs and print statements in `main.py` provide insights into the agent's workflow.

## Project-Specific Conventions
- **Stateful Graphs**: LangGraph nodes represent distinct stages like planning, query generation, and execution.
- **Self-Correction**: The agent analyzes and retries failed Splunk queries.
- **Local LLMs**: All reasoning is performed locally to ensure privacy.

## Key Files and Directories
- `main.py`: Entry point for the agent. Contains the workflow and integration logic.
- `requirements.txt`: Lists Python dependencies.
- `hunter_env/`: Virtual environment directory.
- `.env`: Stores sensitive environment variables like `SPLUNK_PASSWORD`.
- `~/.splunkrc`: Configuration file for Splunk SDK.

## External Dependencies
- **LangGraph**: For workflow orchestration.
- **Ollama**: Hosts the local LLM.
- **Splunk Python SDK**: Interfaces with Splunk.

## Examples
### Splunk Query Execution
The agent uses a custom tool to execute Splunk searches. Example:
```python
agent_chain = prompt | llm | StrOutputParser() | execute_splunk_search
final_result = agent_chain.invoke({"question": user_question})
```

### Self-Correction Loop
The agent retries failed queries with modified parameters based on analysis of the failure.

---

This document will evolve as the project progresses. Please update it to reflect new patterns, tools, or workflows.