import os
import logging
from datetime import datetime, timedelta
from opensearchpy import OpenSearch
from dotenv import load_dotenv

# =====================================================
# Load environment variables
# =====================================================
load_dotenv()
OPENSEARCH_HOST = os.getenv("OPENSEARCH_HOST", "localhost")
OPENSEARCH_PORT = int(os.getenv("OPENSEARCH_PORT", 9200))
OPENSEARCH_USER = os.getenv("OPENSEARCH_USER")
OPENSEARCH_PASSWORD = os.getenv("OPENSEARCH_PASSWORD")

# =====================================================
# Configure OpenSearch client
# =====================================================
logger = logging.getLogger(__name__)
try:
    opensearch_client = OpenSearch(
        hosts=[{"host": OPENSEARCH_HOST, "port": OPENSEARCH_PORT}],
        http_auth=(OPENSEARCH_USER, OPENSEARCH_PASSWORD),
        use_ssl=True,
        verify_certs=False,  # Set True in production
        ssl_assert_hostname=False
    )
    opensearch_client.info()
    logger.info("✅ Connected to OpenSearch.")
except Exception as e:
    logger.error(f"Failed to connect to OpenSearch: {e}")
    opensearch_client = None

# =====================================================
# Tool Metadata (Planner uses this)
# =====================================================
TOOLS = {
    "build_query": {
        "description": "Build a Wazuh/OpenSearch query for logs based on a search string and time range.",
        "inputs": ["query_string", "time_range"],
        "outputs": ["query_dict"]
    },
    "search_raw_logs": {
        "description": "Search raw logs in OpenSearch.",
        "inputs": ["query", "time_range"],
        "outputs": ["log_entries"]
    },
    "search_alerts": {
        "description": "Search Wazuh alerts with optional severity filtering.",
        "inputs": ["query", "time_range", "min_level"],
        "outputs": ["alert_entries"]
    },
    "get_agent_data": {
        "description": "Retrieve Wazuh agent info by agent_id or agent_name.",
        "inputs": ["agent_id", "agent_name"],
        "outputs": ["agent_info"]
    },
    "search_vulnerabilities": {
        "description": "Search for vulnerabilities in Wazuh alerts with optional filtering.",
        "inputs": ["query", "time_range", "min_level"],
        "outputs": ["vulnerability_entries"]
    }
}

# =====================================================
# Tool Implementations (Executor uses these)
# =====================================================
def build_query(query_string, time_range="2d"):
    """
    Returns a structured query dict for OpenSearch/Wazuh.
    """
    time_filter = {}
    if time_range.lower() != "anytime":
        end_time = datetime.utcnow()
        if "d" in time_range:
            days = int(time_range.replace("d", ""))
            start_time = end_time - timedelta(days=days)
        else:
            start_time = end_time
        time_filter = {"range": {"@timestamp": {"gte": start_time.isoformat(), "lte": end_time.isoformat()}}}

    query = {
        "query": {
            "bool": {
                "filter": []
            }
        }
    }
    if time_filter:
        query["query"]["bool"]["filter"].append(time_filter)
    query["query"]["bool"]["filter"].append({"query_string": {"query": query_string}})
    return query

def search_raw_logs(query, time_range="1h"):
    if not opensearch_client:
        return {"error": "OpenSearch client not initialized"}
    search_body = {
        "query": {
            "bool": {
                "must": [{"query_string": {"query": query}}],
                "filter": [{"range": {"@timestamp": {"gte": f"now-{time_range}"}}}]
            }
        },
        "size": 20
    }
    try:
        resp = opensearch_client.search(body=search_body, index="wazuh-archives-*")
        return [hit["_source"] for hit in resp.get("hits", {}).get("hits", [])]
    except Exception as e:
        logger.error(f"search_raw_logs failed: {e}")
        return []

def search_alerts(query, time_range="1h", min_level=0):
    if not opensearch_client:
        return {"error": "OpenSearch client not initialized"}
    search_body = {
        "query": {
            "bool": {
                "must": [{"query_string": {"query": query}}],
                "filter": [
                    {"range": {"@timestamp": {"gte": f"now-{time_range}"}}},
                    {"range": {"rule.level": {"gte": min_level}}}
                ]
            }
        },
        "size": 20
    }
    try:
        resp = opensearch_client.search(body=search_body, index="wazuh-alerts-*")
        return [hit["_source"] for hit in resp.get("hits", {}).get("hits", [])]
    except Exception as e:
        logger.error(f"search_alerts failed: {e}")
        return []

def get_agent_data(agent_id=None, agent_name=None):
    if not opensearch_client:
        return {"error": "OpenSearch client not initialized"}
    if not agent_id and not agent_name:
        return {"error": "agent_id or agent_name required"}
    query_str = f'agent.id:"{agent_id}"' if agent_id else f'agent.name:"{agent_name}"'
    search_body = {"query": {"query_string": {"query": query_str}}, "size": 1}
    try:
        resp = opensearch_client.search(body=search_body, index="wazuh-agent-*")
        return [hit["_source"] for hit in resp.get("hits", {}).get("hits", [])]
    except Exception as e:
        logger.error(f"get_agent_data failed: {e}")
        return []

def search_vulnerabilities(query="*", time_range="1h", min_level=5):
    if not opensearch_client:
        return {"error": "OpenSearch client not initialized"}
    vuln_query = "rule.groups:vulnerability-detector"
    if query != "*":
        vuln_query = f"{vuln_query} AND ({query})"
    search_body = {
        "query": {
            "bool": {
                "must": [{"query_string": {"query": vuln_query}}],
                "filter": [
                    {"range": {"@timestamp": {"gte": f"now-{time_range}"}}}, 
                    {"range": {"rule.level": {"gte": min_level}}}
                ]
            }
        },
        "size": 20
    }
    try:
        resp = opensearch_client.search(body=search_body, index="wazuh-alerts-*")
        return [hit["_source"] for hit in resp.get("hits", {}).get("hits", [])]
    except Exception as e:
        logger.error(f"search_vulnerabilities failed: {e}")
        return []

# =====================================================
# Dynamic executor for any tool
# =====================================================
def execute_tool(tool_name, **kwargs):
    """
    Dynamically executes a tool by name.
    """
    if tool_name == "build_query":
        return build_query(**kwargs)
    elif tool_name == "search_raw_logs":
        return search_raw_logs(**kwargs)
    elif tool_name == "search_alerts":
        return search_alerts(**kwargs)
    elif tool_name == "get_agent_data":
        return get_agent_data(**kwargs)
    elif tool_name == "search_vulnerabilities":
        return search_vulnerabilities(**kwargs)
    else:
        raise ValueError(f"Unknown tool: {tool_name}")
