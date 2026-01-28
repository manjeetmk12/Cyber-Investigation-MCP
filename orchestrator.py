"""
Cybersecurity Orchestrator (Planner → Executor → Report Generator)
------------------------------------------------------------------
This service coordinates:
  1. Planning via LLM-based planner_agent
  2. Execution of investigation steps via executor_agent
  3. Report generation for SOC-level readability

Compatible with:
  - HTTP REST calls (POST /run_full_analysis)
  - MCP Server integrations via OpenWebUI
"""

import json
import asyncio
from datetime import datetime
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

# Import core agents
from planner_agent import generate_plan, generate_report_from_results
from executor_agent import run_execution_plan
from audit_logger import log_step


# =====================================================
# FastAPI App
# =====================================================
app = FastAPI(title="Cybersecurity Orchestrator (MCP Compatible)")


@app.get("/")
async def index():
    return {
        "message": "Cybersecurity Orchestrator online.",
        "workflow": ["Planner", "Executor", "Report Generator"],
        "endpoint": "POST /run_full_analysis",
        "expected_payload": {"user_input": "Find failed SSH login attempts"}
    }


# =====================================================
# 🧠 Main Workflow Endpoint
# =====================================================
@app.post("/run_full_analysis")
async def run_full_analysis(request: Request):
    """
    Executes the full investigative workflow:
      Step 1. Generate a plan from the LLM planner
      Step 2. Execute plan using integrated tools
      Step 3. Generate a SOC-readable report
    """
    try:
        body = await request.json()
    except Exception:
        body = {}

    # --- Normalize Input for MCP/OpenWebUI ---
    user_input = (
        body.get("user_input")
        or body.get("input")
        or (body if isinstance(body, str) else None)
    )

    if not user_input:
        log_step("orchestration", "failed", {"error": "Missing user_input or input"})
        return JSONResponse(
            {
                "status": False,
                "error": "Missing 'user_input' or 'input' in request payload",
                "received": body,
            },
            status_code=400,
        )

    # =====================================================
    # Step 1: PLAN GENERATION
    # =====================================================
    log_step("plan_generation", "in_progress", {"goal": user_input})
    print(f"\n🔹 [Orchestrator] Generating plan for: {user_input}")

    try:
        plan_data = (
            await generate_plan(user_input)
            if asyncio.iscoroutinefunction(generate_plan)
            else generate_plan(user_input)
        )
    except Exception as e:
        log_step("plan_generation", "failed", {"error": str(e)})
        return JSONResponse({"status": False, "error": f"Planner error: {e}"}, status_code=500)

    if not plan_data.get("status"):
        log_step("plan_generation", "failed", data=plan_data)
        return JSONResponse(
            {"status": False, "error": "Planner failed", "details": plan_data},
            status_code=500,
        )

    log_step("plan_generation", "success", data={"plan_tasks": len(plan_data.get("plan", {}).get("plans", []))})
    print("✅ Plan generated successfully.")

    # =====================================================
    # Step 2: EXECUTION
    # =====================================================
    log_step("plan_execution", "in_progress", {"tasks": len(plan_data.get('plan', {}).get('plans', []))})
    print("🔹 [Orchestrator] Executing generated plan...")

    try:
        exec_data = (
            await run_execution_plan(plan_data["plan"])
            if asyncio.iscoroutinefunction(run_execution_plan)
            else run_execution_plan(plan_data["plan"])
        )
    except Exception as e:
        log_step("plan_execution", "failed", {"error": str(e)})
        return JSONResponse({"status": False, "error": f"Executor error: {e}"}, status_code=500)

    if not exec_data.get("status"):
        log_step("plan_execution", "failed", data=exec_data)
        return JSONResponse(
            {"status": False, "error": "Executor failed", "details": exec_data},
            status_code=500,
        )

    log_step("plan_execution", "success", data=exec_data)
    print("✅ Plan executed successfully.")

    # =====================================================
    # Step 3: RESULT AGGREGATION
    # =====================================================
    combined_result = {
        "status": True,
        "executed_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "goal": plan_data.get("goal"),
        "plan": plan_data.get("plan"),
        "task_results": exec_data.get("task_results"),
        "aggregated_results": exec_data.get("aggregated_results"),
    }

    # =====================================================
    # Step 4: REPORT GENERATION
    # =====================================================
    log_step("report_generation", "in_progress", {"goal": user_input})
    print("🔹 [Orchestrator] Generating SOC report...")

    try:
        report_result = generate_report_from_results(
            goal=plan_data.get("goal"),
            exec_results=combined_result,
        )
    except Exception as e:
        log_step("report_generation", "failed", {"error": str(e)})
        combined_result["report_generation_error"] = str(e)
        report_result = {"status": False, "error": str(e)}

    if report_result.get("status"):
        combined_result["formatted_report"] = report_result["report"]
        log_step("report_generation", "success", {"summary": "Report generated"})
        print("✅ SOC report generated successfully.")
    else:
        combined_result["report_generation_error"] = report_result.get("error", "Unknown error")
        log_step("report_generation", "failed", report_result)

    # =====================================================
    # Step 5: FINALIZE
    # =====================================================
    log_step("orchestration_complete", "success", data={"goal": user_input})
    print("🏁 [Orchestrator] Workflow completed successfully.\n")

    return JSONResponse(combined_result)


# =====================================================
# Run Standalone
# =====================================================
if __name__ == "__main__":
    import uvicorn

    print("🚀 Starting Orchestrator server on 0.0.0.0:8002")
    uvicorn.run(app, host="0.0.0.0", port=8002)
