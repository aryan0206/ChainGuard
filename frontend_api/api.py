"""Loopback-only demo adapter. Run one Uvicorn worker; state is in memory."""

import asyncio
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from functools import lru_cache
import json
import os
from pathlib import Path
import signal
import subprocess
from tempfile import TemporaryDirectory
from typing import Literal
from uuid import uuid4

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict
from starlette.middleware.trustedhost import TrustedHostMiddleware

from frontend_api.runtime_context import checkout_revision, runtime_environment
from frontend_api.scenario_guides import GUIDES


ROOT = Path(__file__).resolve().parent.parent
RUNTIME = ROOT / ".venv" / "bin" / "python"
SCENARIOS = [
    {"id": "live-authorization", "title": "Live authorization & acceptance", "milestone": "M6.4",
     "description": "Synthetic read, denied release, one-use grant, revocation and new-grant restoration; signed evidence and complete-run acceptance.",
     "capabilities": ["tool_outputs", "audit", "detectors", "evidence", "authorization", "acceptance"],
     "custom_inputs": False,
     "steps": ["Read synthetic source", "Deny ungranted send", "Grant one use", "Send once", "Deny reuse",
               "Grant then revoke", "Deny revoked send", "New grant restores send", "Controlled tool error"],
     "input_note": "Fixed synthetic payload and host controls. Grants cannot be supplied by the browser.",
     "detector_note": "Four shadow evaluators share one synthetic release history. The host permission gate controls actual dispatch; shadow findings do not. Results are bounded engineering demonstrations."},
    {"id": "signed-evidence", "title": "Signed evidence", "milestone": "M4",
     "description": "Audited success / controlled error / success, signed closure and separate-process offline inspection.",
     "capabilities": ["tool_outputs", "audit", "detectors", "evidence"], "custom_inputs": False,
     "steps": ["echo", "controlled_failure", "echo"],
     "input_note": "The original demo supplies synthetic tokens. Custom tool arguments are not exposed.",
     "detector_note": "Four shadow evaluators share the same public, non-release history. Findings do not control dispatch in this demonstration."},
    {"id": "mediation", "title": "MCP mediation", "milestone": "M1",
     "description": "SDK client → stdio proxy → controlled server. Transport demonstration; no security-policy evaluation or signed audit.",
     "capabilities": ["tool_outputs"], "custom_inputs": False,
     "steps": ["echo", "controlled_failure", "echo"],
     "input_note": "The original demo supplies synthetic tokens. Custom tool arguments are not exposed.",
     "detector_note": "M1 demonstrates transport only. It produces no detector findings or signed evidence."},
]
SCENARIOS = [{**scenario, **GUIDES[scenario["id"]]} for scenario in SCENARIOS]
ORIGINS = {f"http://{host}:{port}" for host in ("localhost", "127.0.0.1") for port in (5174, 8001)}


def now():
    return datetime.now(timezone.utc).isoformat()


@lru_cache(maxsize=1)
def runtime_ready():
    try:
        check = subprocess.run([str(RUNTIME), "-B", "-c",
            "from mcp import Client; from chainguard.m6_live_runtime import M6Host; "
            "from chainguard.m6_live_verifier import inspect_live_run; "
            "from chainguard.acceptance import AcceptanceRegistry; "
            "from chainguard.m6_live_profile import live_configuration; live_configuration(); "
            "from cryptography.hazmat.primitives.asymmetric import ec"],
            cwd=ROOT, env=runtime_environment(), capture_output=True, timeout=10)
        return check.returncode == 0
    except (OSError, subprocess.SubprocessError, RuntimeError):
        return False


class RunRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    scenario_id: Literal["mediation", "signed-evidence", "live-authorization"]


class RunManager:
    def __init__(self, timeout=150):
        self.runs = {}
        self.task = None
        self.timeout = timeout

    def event(self, run, event, status):
        run["events"].append({"sequence": len(run["events"]) + 1, "timestamp": now(),
            "event": event, "status": status, "source": "adapter"})

    def create(self, scenario):
        if scenario not in {item["id"] for item in SCENARIOS}:
            raise HTTPException(422, "Unsupported scenario.")
        if self.task is not None and not self.task.done():
            raise HTTPException(409, "Another demo is running. Wait for it to finish.")
        # Bounded memory; old runs are removed only when admitting another run.
        while len(self.runs) >= 20:
            self.runs.pop(next(iter(self.runs)))
        run = {"run_id": str(uuid4()), "scenario_id": scenario, "status": "queued",
               "created_at": now(), "finished_at": None, "exit_code": None,
               "events": [], "result": None, "error": None}
        self.event(run, "run_accepted", "queued")
        self.runs[run["run_id"]] = run
        self.task = asyncio.create_task(self.execute(run))
        return run

    def command(self, scenario, directory):
        return [str(RUNTIME), "-B", "-m", "frontend_api.worker", scenario, directory]

    async def execute(self, run):
        process = None
        try:
            with TemporaryDirectory(prefix="chainguard-web-", dir="/private/tmp" if os.path.isdir("/private/tmp") else None) as directory:
                try:
                    run["status"] = "running"
                    process = await asyncio.create_subprocess_exec(*self.command(run["scenario_id"], directory),
                        cwd=ROOT, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
                        env=runtime_environment(), start_new_session=True)
                    self.event(run, "demo_process_started", "running")
                    stdout, _stderr = await asyncio.wait_for(process.communicate(), timeout=self.timeout)
                    run["exit_code"] = process.returncode
                    if process.returncode != 0:
                        raise RuntimeError("DEMO_FAILED")
                    result = json.loads(stdout)
                    if not isinstance(result, dict) or set(result) != {"report", "evidence"}:
                        raise ValueError("Invalid worker response")
                    run["result"] = result
                    run["status"] = "completed"
                    self.event(run, "demo_result_received", "completed")
                finally:
                    # Kill the whole subprocess group, including proxy/server descendants,
                    # before removing temporary evidence and keys, even on timeout/shutdown.
                    if process is not None:
                        try:
                            os.killpg(process.pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                        await process.wait()
        except asyncio.TimeoutError:
            run["status"] = "timed_out"
            run["error"] = {"code": "TIMEOUT", "message": "Demo exceeded the execution limit; its process group was stopped."}
        except asyncio.CancelledError:
            run["status"] = "failed"
            run["error"] = {"code": "INTERRUPTED", "message": "Adapter shutdown interrupted the demo."}
            raise
        except Exception:
            run["status"] = "failed"
            run["error"] = {"code": "DEMO_FAILED", "message": "The demo failed. Check the runtime installation or run its documented CLI for diagnostics."}
        finally:
            if process is not None and run["exit_code"] is None:
                run["exit_code"] = process.returncode
            run["finished_at"] = now()
            self.event(run, "run_finalized", run["status"])

    async def close(self):
        if self.task is not None and not self.task.done():
            self.task.cancel()
            try:
                await self.task
            except asyncio.CancelledError:
                pass


def create_app(manager=None, readiness=runtime_ready):
    manager = manager or RunManager()

    @asynccontextmanager
    async def lifespan(app):
        yield
        await manager.close()

    app = FastAPI(title="ChainGuard local adapter", lifespan=lifespan)
    app.state.manager = manager
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=["localhost", "127.0.0.1", "testserver"])

    @app.middleware("http")
    async def local_browser_boundary(request: Request, call_next):
        origin = request.headers.get("origin")
        if origin and origin not in ORIGINS:
            return JSONResponse({"detail": "Origin is not allowed."}, status_code=403)
        if request.method == "POST":
            if request.headers.get("x-chainguard-client") != "local-dashboard":
                return JSONResponse({"detail": "Dashboard request header is required."}, status_code=403)
            if request.headers.get("content-type", "").split(";")[0] != "application/json":
                return JSONResponse({"detail": "Expected application/json."}, status_code=415)
            body = await request.body()
            if len(body) > 4096:
                return JSONResponse({"detail": "Request is too large."}, status_code=413)
        response = await call_next(request)
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.get("/api/health")
    def health():
        try:
            revision = checkout_revision()
        except (OSError, subprocess.SubprocessError, RuntimeError):
            revision = None
        return {"status": "ok", "runtime_ready": readiness(), "mode": "local", "revision": revision,
                "busy": manager.task is not None and not manager.task.done()}

    @app.get("/api/scenarios")
    def scenarios():
        return {"scenarios": SCENARIOS, "tools": ["echo", "controlled_failure", "read_secret_a", "send_sink"],
                "input_mode": "fixed_demo", "custom_inputs": False}

    @app.post("/api/runs", status_code=202)
    async def start(body: RunRequest):
        if not readiness():
            raise HTTPException(503, "Pinned MCP runtime is unavailable. Complete the README setup and restart the adapter.")
        return manager.create(body.scenario_id)

    def find(run_id):
        if run_id not in manager.runs:
            raise HTTPException(404, "Run is unknown or has expired.")
        return manager.runs[run_id]

    @app.get("/api/runs/{run_id}")
    def get_run(run_id: str):
        return find(run_id)

    @app.get("/api/runs/{run_id}/events")
    def events(run_id: str):
        run = find(run_id)
        records = ((run["result"] or {}).get("evidence") or {}).get("package", {}).get("records", [])
        return {"adapter_events": run["events"], "audit_records": records,
                "mode": "polling", "audit_availability": "after_demo_completion"}

    @app.get("/api/runs/{run_id}/evidence")
    def evidence(run_id: str):
        run = find(run_id)
        return {"status": run["status"], "evidence": (run["result"] or {}).get("evidence")}

    return app


app = create_app()
