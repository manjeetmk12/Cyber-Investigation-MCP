"""
Cyber Investigator MCP + HTTP Wrapper
-------------------------------------
Exposes:
  1. An MCP tooling endpoint for OpenWebUI (`run_cyber_investigation`)
  2. An HTTP API endpoint (`http://0.0.0.0:8080/run_investigation`)

Example Request:
  POST /run_investigation
  {
      "user_input": "Investigate failed SSH logins on Linux systems"
  }

This bridges OpenWebUI's MCP protocol with the cybersecurity orchestrator pipeline.
"""

import asyncio
import json
import traceback
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from mcp.server.fastmcp import FastMCP
from pydantic import BaseModel
import uvicorn

# Internal imports
from orchestrator import run_full_analysis
from audit_logger import log_step


# =====================================================
# 🔹 MCP Server Definition
# =====================================================
mcp = FastMCP(name="cyber_investigator_mcp")
"""
Handles MCP requests from OpenWebUI and triggers the
end-to-end cybersecurity investigation workflow.
"""


@mcp.tool()
async def run_cyber_investigation(user_input: str) -> dict:
    """
    🔍 MCP Tool: Executes a full cybersecurity investigation
    through the orchestrator (plan → execute → report).

    Args:
        user_input (str): Investigation request or natural language query.

    Returns:
        dict: Full orchestrator output (plan, results, and report)
    """
    log_step("mcp_invocation", "started", {"goal": user_input})
    print(f"\n🧠 [MCP] Received investigation request: {user_input}")

    try:
        # Dummy FastAPI-style request to reuse orchestrator directly
        class DummyRequest:
            async def json(self):
                return {"user_input": user_input}

        dummy_request = DummyRequest()
        response = await run_full_analysis(dummy_request)

        # Decode orchestrator's JSONResponse
        try:
            data = json.loads(response.body.decode())
        except Exception:
            data = response if isinstance(response, dict) else {"raw_response": str(response)}

        log_step("mcp_invocation", "success", {"summary": "Investigation completed"})
        print("✅ [MCP] Investigation completed successfully.\n")

        return {"status": True, "result": data}

    except Exception as e:
        err_trace = traceback.format_exc()
        log_step("mcp_invocation", "failed", {"error": str(e), "trace": err_trace})
        print(f"❌ [MCP] Error during investigation:\n{err_trace}")
        return {"status": False, "error": str(e)}


# =====================================================
# 🌐 FastAPI HTTP Server Definition
# =====================================================
app = FastAPI(title="Cyber Investigator MCP Server", version="1.1.0")

class InvestigationRequest(BaseModel):
    user_input: str | None = None
    input: str | None = None
    query: str | None = None


@app.get("/")
async def index():
    """Root endpoint for diagnostics and usage guidance."""
    return {
        "message": "🛡️ Cyber Investigator MCP Server online",
        "modes": ["HTTP", "MCP"],
        "example_request": {"user_input": "Find failed SSH login attempts"},
        "mcp_tool": "run_cyber_investigation",
        "orchestrator": "http://127.0.0.1:8002/run_full_analysis",
    }


@app.post("/run_investigation")
async def run_investigation(req: InvestigationRequest, request: Request):
    """
    HTTP wrapper for investigation trigger.
    Accepts multiple key formats for user input.
    """
    try:
        # Extract user input from various potential payload formats
        user_input = req.user_input or req.input or req.query
        if not user_input:
            raw = await request.json()
            return JSONResponse(
                {
                    "status": False,
                    "error": "Missing 'user_input' or 'input' in request payload",
                    "received": raw,
                },
                status_code=400,
            )

        # Run investigation through MCP tool
        result = await run_cyber_investigation(user_input)
        return JSONResponse(result)

    except Exception as e:
        err_trace = traceback.format_exc()
        log_step("http_invocation", "failed", {"error": str(e), "trace": err_trace})
        print(f"❌ [HTTP] Exception during /run_investigation:\n{err_trace}")
        return JSONResponse({"status": False, "error": str(e)}, status_code=500)


# =====================================================
# 🚀 Dual Runtime (MCP + HTTP)
# =====================================================
async def start_http():
    """Starts FastAPI HTTP server asynchronously."""
    config = uvicorn.Config(app, host="0.0.0.0", port=8080, log_level="info")
    server = uvicorn.Server(config)
    await server.serve()


async def main():
    print("🚀 Launching Cyber Investigator MCP + HTTP server...")
    print("🔹 Starting MCP (for OpenWebUI)...")
    print("🔹 Starting HTTP REST API (on port 8080)...\n")

    await asyncio.gather(
        mcp.run_sse_async(),  # MCP endpoint (used by OpenWebUI)
        start_http(),         # REST endpoint for external integrations
    )


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n🛑 Server shutdown requested. Goodbye.")
