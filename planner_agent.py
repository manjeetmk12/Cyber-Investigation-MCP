"""
Planner Agent — Cyber Investigation Plan Generator
--------------------------------------------------
Creates structured multi-step investigation plans
based on user input, with full tool awareness.
"""

import json
import re
import requests
from datetime import datetime
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from tools.main_opensearch import TOOLS
from audit_logger import log_step

API_ENDPOINT = "http://10.10.111.11:8000/v1/chat/completions"
API_KEY = "Td4nbrkzNBx2d1kqBRNyOtYn5e"

app = FastAPI(title="Cybersecurity Planning Agent (Tool-Aware)")

# =====================================================
# Utility Helpers
# =====================================================

def extract_json_from_text(text: str):
    """Extract valid JSON safely from LLM output."""
    codeblock = re.search(r'```json(.*?)```', text, re.DOTALL)
    if codeblock:
        text = codeblock.group(1)
    match = re.search(r'\{.*\}', text, re.DOTALL)
    if not match:
        raise ValueError("No JSON found in model output.")
    return json.loads(match.group(0))


def build_tool_context():
    """Describe available tools for the LLM."""
    lines = []
    for name, meta in TOOLS.items():
        inputs = ", ".join(meta.get("inputs", []))
        outputs = ", ".join(meta.get("outputs", []))
        lines.append(f"- {name}: {meta['description']} (inputs: {inputs}, outputs: {outputs})")
    return "\n".join(lines)

# =====================================================
# API Routes
# =====================================================

@app.get("/")
async def index():
    return {"message": "Cybersecurity Planning Agent is online and tool-aware."}


@app.post("/create_plan")
async def create_plan(request: Request):
    """Generate structured investigation plan."""
    body = await request.json()
    user_input = body.get("user_input")
    if not user_input:
        return JSONResponse({"status": False, "error": "No input provided"}, status_code=400)

    tool_context = build_tool_context()
    prompt = f"""
You are **XYZ**, a senior cybersecurity analyst and task planner in a SOC team.
Your job is to decompose an investigation goal into precise, executable tasks.

Available tools:
{tool_context}

Guidelines:
1. Use the available tools logically to achieve the user's goal.
2. Use 3–6 meaningful steps.
3. Respect dependencies between steps.
4. Output *only valid JSON* (no markdown or explanations).

Expected JSON Schema:
{{
  "plans": [
    {{
      "task_id": "1",
      "sub_task": "Describe the specific step",
      "dependent_on_tasks": [],
      "tool_name": "build_query",
      "show_results_now": false
    }}
  ]
}}

User Goal: "{user_input}"
"""

    payload = {
        "model": "Qwen3-Coder-480B-A35B-Instruct-GPTQ-Int4-Int8Mix",
        "messages": [
            {"role": "system", "content": "You are a senior SOC planner that returns structured JSON only."},
            {"role": "user", "content": prompt}
        ],
        "temperature": 0.5,
    }

    headers = {"Content-Type": "application/json", "Authorization": f"Bearer {API_KEY}"}
    log_step("plan_generation", "started", {"goal": user_input})

    try:
        response = requests.post(API_ENDPOINT, headers=headers, json=payload, timeout=90)
        response.raise_for_status()
        result = response.json()

        content = result["choices"][0]["message"]["content"]
        plan_data = extract_json_from_text(content)

        log_step("plan_generation", "success", {"task_count": len(plan_data.get("plans", []))})
        return JSONResponse({
            "status": True,
            "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "goal": user_input,
            "plan": plan_data,
            "tools": list(TOOLS.keys())
        })

    except Exception as e:
        log_step("plan_generation", "failed", {"error": str(e)})
        return JSONResponse({"status": False, "error": str(e)}, status_code=500)

# =====================================================
# Direct Call (for Orchestrator)
# =====================================================
def generate_plan(user_input: str):
    from fastapi.testclient import TestClient
    client = TestClient(app)
    return client.post("/create_plan", json={"user_input": user_input}).json()

# =====================================================
# SOC Report Generator
# =====================================================
def generate_report_from_results(goal: str, exec_results: dict):
    """Generate a human-readable SOC report from execution results."""
    prompt = f"""
You are XYZ, a senior SOC analyst creating an incident report.

Investigation Goal:
"{goal}"

Raw Execution Results (JSON):
{json.dumps(exec_results, indent=2)}

Write a structured SOC report that includes:
- Executive Summary
- Key Findings
- Detected Threats / Anomalies
- Recommendations
"""

    payload = {
        "model": "Qwen3-Coder-480B-A35B-Instruct-GPTQ-Int4-Int8Mix",
        "messages": [
            {"role": "system", "content": "You are a cybersecurity analyst writing a structured SOC report."},
            {"role": "user", "content": prompt}
        ],
        "temperature": 0.4,
    }

    headers = {"Content-Type": "application/json", "Authorization": f"Bearer {API_KEY}"}

    try:
        response = requests.post(API_ENDPOINT, headers=headers, json=payload, timeout=120)
        response.raise_for_status()
        report_text = response.json()["choices"][0]["message"]["content"]
        log_step("report_generation", "success", {"summary": "Report generated successfully"})
        return {"status": True, "report": report_text}
    except Exception as e:
        log_step("report_generation", "failed", {"error": str(e)})
        return {"status": False, "error": str(e)}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
