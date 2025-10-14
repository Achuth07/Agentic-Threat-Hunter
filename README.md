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
- **The Hunting Ground**: Splunk Enterprise (Free License) serves as the initial SIEM platform. The agent interacts with Splunk programmatically via the Splunk Python SDK.
- **Tools**: The agent's capabilities are defined by a collection of custom tools. The first tool is for executing Splunk searches. Future tools will expand its capabilities to threat intelligence gathering and EDR interaction.

## Current Progress

As of now, the foundational setup of the project is complete.

- ✅ **Environment Setup**: The development environment has been fully configured on a dedicated laptop running Windows 11.
- ✅ **WSL 2 Integration**: Windows Subsystem for Linux (WSL 2) with an Ubuntu distribution is installed and configured to serve as the primary development environment.
- ✅ **GPU Acceleration**: NVIDIA drivers and the CUDA Toolkit for WSL have been installed, enabling GPU-accelerated LLM inference.
- ✅ **AI Engine Deployed**: Ollama is installed within WSL, and the `llama3:8b` model has been successfully pulled and tested.
- ✅ **SIEM Deployed**: A Splunk Enterprise instance is installed on the Windows host and has been switched to the perpetual Free License.
- ✅ **Project Initialized**: The Python project has been set up with a `hunter_env` virtual environment, and all necessary libraries (`langgraph`, `langchain`, `ollama`, `splunk-sdk`) have been installed.
- ✅ **Version Control**: The project is managed with Git and has been pushed to this GitHub repository.
- ✅ **Core Components Tested**:
  - Successfully connected to the Ollama LLM from a Python script.
  - Developed and tested a custom LangChain tool to execute searches on the Splunk instance.

## Getting Started

Follow these steps to set up the project on your own machine.

### Prerequisites

- **Hardware**: A machine with a dedicated NVIDIA GPU is highly recommended for acceptable performance.
- **Operating System**: Windows 10/11 with WSL 2 enabled, or a native Linux distribution.
- **Software**:
  - [Splunk Enterprise](https://www.splunk.com/en_us/download/splunk-enterprise.html) installed and running.
  - Ollama installed, with a model pulled (e.g., `ollama pull llama3:8b`).
  - Python 3.9+.
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

Currently, the project contains test scripts for the core components. You can run them to verify your setup.

```bash
# This will run the tests defined at the bottom of the script
python main.py
```

## Roadmap

This project is in active development. The next steps are:

- [ ] **Implement the LangGraph State Machine**: Build the full agentic workflow with nodes for planning, query generation, execution, and analysis.
- [ ] **Develop Intelligence Tools**: Create tools to fetch data from threat intelligence feeds like MITRE ATT&CK and AlienVault OTX.
- [ ] **Refine Prompt Engineering**: Develop and test a robust "Hunter" persona prompt to improve the accuracy of SPL query generation.
- [ ] **Build the Self-Correction Loop**: Implement the conditional logic that allows the agent to analyze and fix failed Splunk queries.
- [ ] **Expand to EDR**: Create new tools to integrate with Endpoint Detection and Response (EDR) platforms.
- [ ] **Create a User Interface**: Develop a simple command-line interface (CLI) to interact with the agent.

## Contributing

Contributions are welcome! If you have ideas for new features, improvements, or bug fixes, please feel free to open an issue or submit a pull request.

1. Fork the repository.
2. Create a new branch (`git checkout -b feature/YourFeature`).
3. Commit your changes (`git commit -m 'Add some feature'`).
4. Push to the branch (`git push origin feature/YourFeature`).
5. Open a Pull Request.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.