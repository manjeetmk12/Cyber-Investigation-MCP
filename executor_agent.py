"""
Executor Agent — Cyber Investigation Task Runner
------------------------------------------------
Executes each step from the generated investigation plan,
resolving dependencies and invoking OpenSearch tools safely.
"""

import asyncio
import json
import logging
from datetime import datetime
from copy import deepcopy

# Import tooling functions
from tools.main_opensearch import (
    build_query,
    search_raw_logs,
    search_alerts,
    get_agent_data,
    search_vulnerabilities
)

# =====================================================
# Logging Configuration
# =====================================================
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("executor_agent")

# =====================================================
# TOOL MAPPING
# =====================================================
TOOL_MAPPING = {
    "build_query": build_query,
    "search_raw_logs": search_raw_logs,
    "search_alerts": search_alerts,
    "get_agent_data": get_agent_data,
    "search_vulnerabilities": search_vulnerabilities
}

# =====================================================
# 🔹 Utility Helpers
# =====================================================
def safe_json(obj):
    """Ensure result is JSON-serializable."""
    try:
        json.dumps(obj)
        return obj
    except TypeError:
        return str(obj)

def refine_query_for_tool(base_query: dict, tool_name: str):
    """Adjust or extend the query structure for each tool."""
    if not isinstance(base_query, dict):
        return base_query

    refined_query = deepcopy(base_query)
    refined_query.setdefault("bool", {}).setdefault("must", [])

    if tool_name == "search_alerts":
        refined_query["bool"]["must"] += [
            {"match_phrase": {"rule.description": "ssh"}},
            {"range": {"rule.level": {"gte": 5}}}
        ]
    elif tool_name == "search_raw_logs":
        refined_query["bool"]["must"] += [
            {"match_phrase": {"event.action": "failure"}},
            {"match_phrase": {"process.name": "sshd"}}
        ]
    elif tool_name == "search_vulnerabilities":
        refined_query["bool"]["must"].append({"wildcard": {"vulnerability.id": "CVE-*"}})

    return refined_query


# =====================================================
# 🔹 Core Task Execution
# =====================================================
async def execute_task(task, results_cache):
    """Executes a single task safely using mapped tools."""
    tool_name = task.get("tool_name")
    sub_task = task.get("sub_task", "")
    func = TOOL_MAPPING.get(tool_name)

    if not func:
        error_msg = f"❌ Tool '{tool_name}' not found or undefined."
        logger.error(error_msg)
        return {"task_id": task.get("task_id"), "error": error_msg}

    kwargs = {}
    base_query = None
    result = None

    try:
        # =====================================================
        # 🧩 Build Query
        # =====================================================
        if tool_name == "build_query":
            result = func(sub_task, time_range="2d")

        # =====================================================
        # 🔍 Search Tools
        # =====================================================
        elif tool_name in ["search_raw_logs", "search_alerts", "search_vulnerabilities"]:
            # safely read dependencies (handles None or empty lists)
            deps = task.get("dependent_on_tasks") or []
            prev_task_id = deps[0] if len(deps) > 0 else None

            # try to extract a usable base_query from dependency result (if any)
            if prev_task_id:
                prev_result = results_cache.get(prev_task_id)
                if isinstance(prev_result, dict):
                    # prev_result could be {'query': {...}} or directly the query dict
                    if "query" in prev_result and isinstance(prev_result["query"], dict):
                        base_query = prev_result["query"]
                    else:
                        base_query = prev_result
                else:
                    base_query = prev_result

            # if no base_query available, ask the build_query tool and normalize its shape
            if not base_query:
                logger.warning(f"No base query found for {tool_name}, building fresh.")
                built = build_query(sub_task, time_range="2d")
                # build_query might return {'query': {...}} or the query dict itself
                if isinstance(built, dict) and "query" in built and isinstance(built["query"], dict):
                    base_query = built["query"]
                else:
                    base_query = built

            # refine and normalize before sending to underlying tool
            refined = refine_query_for_tool(base_query, tool_name)
            # unwrap if the refine returned a top-level {"query": {...}} wrapper
            if isinstance(refined, dict) and "query" in refined and len(refined) == 1:
                refined = refined["query"]

            kwargs["query"] = refined
            kwargs["time_range"] = "2d"

            result = (
                await func(**kwargs)
                if asyncio.iscoroutinefunction(func)
                else func(**kwargs)
            )

        # =====================================================
        # 🧠 Agent Data Lookup
        # =====================================================
        elif tool_name == "get_agent_data":
            deps = task.get("dependent_on_tasks") or []
            prev_results = [results_cache.get(tid) for tid in deps]
            agent_name = None
            if prev_results:
                try:
                    first = prev_results[0]
                    if isinstance(first, list) and len(first) > 0:
                        agent_name = first[0].get("agent", {}).get("name")
                except Exception:
                    logger.warning("Could not extract agent name from dependency.")
            # Note: get_agent_data expects agent_id or agent_name
            result = func(agent_name=agent_name)

        # =====================================================
        # 🧩 Default / Fallback
        # =====================================================
        else:
            result = func()

        # =====================================================
        # ✅ Finalize and Store
        # =====================================================
        result = safe_json(result)
        results_cache[task["task_id"]] = result

        logger.info(f"✅ Task {task['task_id']} executed with tool '{tool_name}'.")
        return {"task_id": task["task_id"], "result": result}

    except Exception as e:
        logger.exception(f"Error executing {tool_name}: {e}")
        return {"task_id": task.get("task_id"), "error": str(e)}


# =====================================================
# 🔹 Plan Orchestration
# =====================================================
async def run_execution_plan(plan: dict):
    """
    Executes a complete investigation plan sequentially,
    resolving dependencies dynamically.
    """
    if not plan or "plans" not in plan:
        return {"status": False, "error": "Invalid plan format"}

    logger.info("🚀 Starting plan execution...")
    results_cache = {}
    task_results = []

    for task in plan["plans"]:
        task_id = task.get("task_id")
        deps = task.get("dependent_on_tasks", []) or []

        # 🔄 Resolve Dependencies
        for dep_id in deps:
            if dep_id not in results_cache:
                dep_task = next((t for t in plan["plans"] if t["task_id"] == dep_id), None)
                if dep_task:
                    dep_result = await execute_task(dep_task, results_cache)
                    task_results.append(dep_result)

        # ⚙️ Execute Current Task
        result = await execute_task(task, results_cache)
        task_results.append(result)

    aggregated_results = {
        r["task_id"]: r.get("result")
        for r in task_results
        if "result" in r
    }

    logger.info("🏁 Plan execution completed successfully.")
    return {
        "status": True,
        "executed_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "task_results": task_results,
        "aggregated_results": aggregated_results,
    }


# =====================================================
# 🧪 Standalone Testing
# =====================================================
if __name__ == "__main__":
    import json
    import asyncio

    dummy_plan = {
        "plans": [
            {
                "task_id": "1",
                "sub_task": "Find SSH brute-force attempts",
                "dependent_on_tasks": [],
                "tool_name": "build_query",
            },
            {
                "task_id": "2",
                "sub_task": "Search for failed SSH login logs",
                "dependent_on_tasks": ["1"],
                "tool_name": "search_raw_logs",
            },
        ]
    }

    print("Running dummy plan for testing...\n")
    result = asyncio.run(run_execution_plan(dummy_plan))
    print(json.dumps(result, indent=2))
