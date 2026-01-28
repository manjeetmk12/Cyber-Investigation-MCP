# 🛡️ Cyber Investigator MCP Server

A cybersecurity investigation orchestration platform that combines AI planning with OpenSearch/Wazuh querying capabilities. This system enables natural language investigations that are automatically converted to structured queries, executed, and reported in SOC-friendly formats.

## 🏗️ Architecture Overview

The system consists of three main components working together:

### 1. **MCP Server** (`mcp_server.py`)
- Exposes an MCP endpoint for integration with OpenWebUI
- Provides an HTTP REST API endpoint
- Bridges OpenWebUI's MCP protocol with the cybersecurity orchestrator pipeline

### 2. **Cybersecurity Orchestrator** (`orchestrator.py`)
- Coordinates the end-to-end investigation workflow
- Integrates Planner → Executor → Report Generator pipeline
- Compatible with both HTTP REST calls and MCP Server integrations

### 3. **AI Agents**
#### Planner Agent (`planner_agent.py`)
- Decomposes investigation goals into precise, executable tasks
- Maintains full awareness of available tools and their capabilities
- Generates structured multi-step investigation plans

#### Executor Agent (`executor_agent.py`)
- Executes each step from the generated investigation plan
- Resolves dependencies and invokes OpenSearch tools safely
- Handles sequential and parallel task execution

## 🚀 Getting Started

### Prerequisites

- Python 3.8+
- OpenSearch/Wazuh cluster
- LLM API endpoint (configured in `planner_agent.py`)

### Installation

1. Clone the repository:
```bash
git clone https://github.com/manjeetmk12/Cyber-Investigation-MCP.git
cd cyber-investigator-mcp
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Configure environment variables:
```bash
cp .env.example .env
# Edit .env with your OpenSearch credentials
```

### Configuration

Create a `.env` file with your OpenSearch configuration:
```env
OPENSEARCH_HOST=your-opensearch-host
OPENSEARCH_PORT=9200
OPENSEARCH_USER=your-username
OPENSEARCH_PASSWORD="your-password"
```

Update the LLM API endpoint in `planner_agent.py`:
```python
API_ENDPOINT = "your-llm-api-endpoint"
API_KEY = "your-api-key"
```

### Running the Services

The system requires running three services:

1. **Planner Agent** (Port 8000):
```bash
python planner_agent.py
```

2. **Orchestrator** (Port 8002):
```bash
python orchestrator.py
```

3. **MCP Server** (Port 8080):
```bash
python mcp_server.py
```

## 📡 API Endpoints

### HTTP REST API
- `POST /run_investigation` - Run a cybersecurity investigation
- Example payload:
```json
{
  "user_input": "Investigate failed SSH logins on Linux systems"
}
```

### Orchestrator API
- `POST /run_full_analysis` - Execute the full investigative workflow

### Planner API
- `POST /create_plan` - Generate a structured investigation plan

## 🧰 Available Tools

The system comes with several pre-built tools for cybersecurity investigations:

- `build_query` - Creates structured queries for OpenSearch/Wazuh
- `search_raw_logs` - Searches raw logs in OpenSearch
- `search_alerts` - Searches Wazuh alerts with severity filtering
- `get_agent_data` - Retrieves Wazuh agent information
- `search_vulnerabilities` - Searches for vulnerabilities in Wazuh alerts

## 📊 Workflow

1. **Planning**: User submits a natural language investigation request
2. **Plan Generation**: AI planner decomposes the request into structured tasks
3. **Execution**: Executor agent runs each task using appropriate tools
4. **Reporting**: Results are compiled into a SOC-readable report

## 🛠️ Development

### Project Structure
```
├── .env                           # Environment configuration
├── audit_logger.py               # Audit trail logging
├── executor_agent.py             # Task execution agent
├── mcp_server.py                 # MCP + HTTP server
├── orchestrator.py               # Investigation workflow coordinator
├── planner_agent.py              # AI planning agent
├── requirements.txt              # Python dependencies
└── tools/                        # Tools directory
    └── main_opensearch.py        # OpenSearch/Wazuh tool implementations
```

### Adding New Tools

1. Add tool metadata to `TOOLS` dictionary in `tools/main_opensearch.py`
2. Implement the tool function in the same file
3. Register the tool in `TOOL_MAPPING` in `executor_agent.py`

## 📦 Dependencies

Key dependencies include:
- `fastapi` - Web framework for APIs
- `opensearch-py` - OpenSearch client
- `mcp` - Model Context Protocol integration
- `langchain` - LLM integration utilities
- `loguru` - Enhanced logging

See `requirements.txt` for a complete list.

## 📝 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 🆘 Support

For support, please open an issue on GitHub or contact the maintainers.
