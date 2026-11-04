"""ASGI contract tests without adding a second HTTP client dependency."""

import asyncio
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

from frontend_api.api import ROOT, RUNTIME, RunManager, create_app, runtime_ready
from frontend_api.runtime_context import REVISION_ENV, checkout_revision, runtime_environment
from frontend_api.scenario_guides import GUIDES


async def call(app, method, path, data=None, headers=None):
    encoded = json.dumps(data).encode() if data is not None else b""
    request_headers = {"host": "testserver", "content-type": "application/json",
                       "x-chainguard-client": "local-dashboard", **(headers or {})}
    messages = []
    delivered = False
    complete = asyncio.Event()

    async def receive():
        nonlocal delivered
        if not delivered:
            delivered = True
            return {"type": "http.request", "body": encoded, "more_body": False}
        await complete.wait()
        return {"type": "http.disconnect"}

    async def send(message):
        messages.append(message)
        if message["type"] == "http.response.body" and not message.get("more_body", False):
            complete.set()

    scope = {"type": "http", "asgi": {"version": "3.0", "spec_version": "2.4"},
             "http_version": "1.1", "method": method, "scheme": "http", "path": path,
             "raw_path": path.encode(), "root_path": "", "query_string": b"",
             "server": ("testserver", 80), "client": ("127.0.0.1", 12345),
             "headers": [(k.encode(), v.encode()) for k, v in request_headers.items()]}
    await asyncio.wait_for(app(scope, receive, send), 15)
    status = next(m["status"] for m in messages if m["type"] == "http.response.start")
    body = b"".join(m.get("body", b"") for m in messages if m["type"] == "http.response.body")
    return status, json.loads(body) if body.startswith((b"{", b"[")) else body.decode()


class ApiTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.manager = RunManager()
        self.app = create_app(self.manager, readiness=lambda: True)

    async def asyncTearDown(self):
        await self.manager.close()

    async def test_health_and_confirmed_scenarios(self):
        status, data = await call(self.app, "GET", "/api/health")
        self.assertEqual((status, data["runtime_ready"]), (200, True))
        status, data = await call(self.app, "GET", "/api/scenarios")
        self.assertEqual({s["id"] for s in data["scenarios"]}, {"mediation", "signed-evidence", "live-authorization"})
        self.assertFalse(data["custom_inputs"])
        live = next(s for s in data["scenarios"] if s["id"] == "live-authorization")
        self.assertIn("acceptance", live["capabilities"])
        self.assertGreater(len(live["steps"]), 3)
        for scenario in data["scenarios"]:
            for step in scenario["workflow"]:
                self.assertNotIn("expected", step)
                self.assertNotIn("expected_status", step)

    async def test_unsupported_operation_and_extra_inputs_rejected(self):
        for body in ({"scenario_id": "shell"}, {"scenario_id": "mediation", "command": "pwd"},
                     {"scenario_id": "signed-evidence", "arguments": {"token": "anything"}}, {}):
            status, _ = await call(self.app, "POST", "/api/runs", body)
            self.assertEqual(status, 422)
        self.assertEqual(len(self.manager.runs), 0)

    async def test_client_cannot_supply_live_host_controls(self):
        for extra in ({"grants": ["anything"]}, {"synthetic_local_sink_override": True},
                      {"arguments": {"payload": "anything"}}, {"destination": "external"},
                      {"revision": "f" * 40}):
            status, _ = await call(self.app, "POST", "/api/runs", {"scenario_id": "live-authorization", **extra})
            self.assertEqual(status, 422)
        self.assertEqual(self.manager.runs, {})

    async def test_origin_and_browser_header_boundary(self):
        for headers in ({"origin": "https://untrusted.example"}, {"x-chainguard-client": ""}):
            status, _ = await call(self.app, "POST", "/api/runs", {"scenario_id": "mediation"}, headers)
            self.assertEqual(status, 403)

    async def test_disallowed_host(self):
        status, _ = await call(self.app, "GET", "/api/health", headers={"host": "untrusted.example"})
        self.assertEqual(status, 400)

    async def test_non_json_and_large_requests_rejected(self):
        status, _ = await call(self.app, "POST", "/api/runs", {}, {"content-type": "text/plain"})
        self.assertEqual(status, 415)
        status, _ = await call(self.app, "POST", "/api/runs", {"scenario_id": "x" * 5000})
        self.assertEqual(status, 413)

    async def test_missing_runtime_and_unknown_run(self):
        app = create_app(readiness=lambda: False)
        status, _ = await call(app, "POST", "/api/runs", {"scenario_id": "mediation"})
        self.assertEqual(status, 503)
        for suffix in ("", "/events", "/evidence"):
            status, _ = await call(self.app, "GET", "/api/runs/missing" + suffix)
            self.assertEqual(status, 404)

    async def test_mediation_matches_original_cli_and_no_evidence_claim(self):
        self.assertTrue(runtime_ready(), "Install the pinned runtime first")
        status, run = await call(self.app, "POST", "/api/runs", {"scenario_id": "mediation"})
        self.assertEqual(status, 202)
        await self.manager.task
        _, run = await call(self.app, "GET", "/api/runs/" + run["run_id"])
        self.assertEqual(run["status"], "completed", run)
        cli = await asyncio.create_subprocess_exec(str(RUNTIME), "-B", "-m", "chainguard.client",
            cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, _ = await cli.communicate()
        self.assertEqual(cli.returncode, 0)
        self.assertEqual(run["result"]["report"], json.loads(stdout))
        self.assertIsNone(run["result"]["evidence"])
        self.assertTrue(run["result"]["report"]["controlled_error"]["isError"])

    async def test_real_m4_audit_findings_and_verification(self):
        _, run = await call(self.app, "POST", "/api/runs", {"scenario_id": "signed-evidence"})
        await self.manager.task
        _, run = await call(self.app, "GET", "/api/runs/" + run["run_id"])
        self.assertEqual(run["status"], "completed", run)
        self.assertEqual(run["exit_code"], 0)
        evidence = run["result"]["evidence"]
        self.assertTrue(evidence["verification"]["inspection_passed"])
        self.assertEqual(evidence["acceptance"]["status"], "NOT_CHECKED")
        records = evidence["package"]["records"]
        self.assertEqual([r["event"]["seq"] for r in records], list(range(1, 27)))
        self.assertEqual(len([r for r in records if r["event"]["event_type"] == "DETECTOR_FINDING"]), 12)
        self.assertEqual(evidence["package"]["commitment"]["final_head"], run["result"]["report"]["final_head"])
        self.assertNotIn("PRIVATE KEY", json.dumps(run))
        _, events = await call(self.app, "GET", f'/api/runs/{run["run_id"]}/events')
        self.assertEqual(events["audit_records"], records)
        self.assertEqual([e["sequence"] for e in events["adapter_events"]], [1, 2, 3, 4])
        _, result = await call(self.app, "GET", f'/api/runs/{run["run_id"]}/evidence')
        self.assertEqual(result["evidence"], evidence)

    async def test_concurrent_runs_rejected(self):
        _, first = await call(self.app, "POST", "/api/runs", {"scenario_id": "mediation"})
        status, _ = await call(self.app, "POST", "/api/runs", {"scenario_id": "mediation"})
        self.assertEqual(status, 409)
        self.assertEqual(len(self.manager.runs), 1)
        await self.manager.task
        self.assertEqual(self.manager.runs[first["run_id"]]["status"], "completed")

    async def test_real_live_permissions_evidence_and_acceptance(self):
        status, run = await call(self.app, "POST", "/api/runs", {"scenario_id": "live-authorization"})
        self.assertEqual(status, 202)
        await self.manager.task
        _, run = await call(self.app, "GET", "/api/runs/" + run["run_id"])
        self.assertEqual((run["status"], run["exit_code"]), ("completed", 0), run)
        report, evidence = run["result"]["report"], run["result"]["evidence"]
        self.assertEqual(report["milestone"], "M6.4")
        self.assertEqual(report["registration"], {"status": "COMMITTED", "read_back_before_task_open": True})
        responses = {r["id"]: r for r in report["assessor_journal"]["responses"]}
        for request_id in ("denied-before-grant", "denied-consumed", "denied-revoked"):
            self.assertEqual(responses[request_id]["error"]["code"], -32003)
        for request_id in ("read", "allowed-once", "allowed-new-grant"):
            self.assertFalse(responses[request_id]["result"]["isError"])
        self.assertTrue(responses["tool-error"]["result"]["isError"])
        arrivals = [r for r in report["assessor_journal"]["runtime_observations"] if r["phase"] == "sink_arrival"]
        self.assertEqual([r["request_id"] for r in arrivals], ["allowed-once", "allowed-new-grant"])
        records = evidence["package"]["records"]
        self.assertEqual([r["event"]["seq"] for r in records], list(range(1, len(records) + 1)))
        self.assertEqual(len(records), 59)
        self.assertEqual(len([r for r in records if r["event"]["event_type"] == "DETECTOR_FINDING"]), 28)
        self.assertEqual(len(evidence["verification"]["dimensions"]), 7)
        self.assertTrue(all(d["status"] == "PASS" for d in evidence["verification"]["dimensions"].values()))
        self.assertEqual(evidence["verification"]["fresh_submission"], "NOT_CHECKED")
        self.assertEqual((evidence["acceptance"]["status"], evidence["acceptance"]["registry_durability"]), ("ACCEPTED", "COMMITTED"))
        self.assertEqual((report["duplicate_submission"]["status"], report["duplicate_submission"]["reason"]), ("REJECTED", "ALREADY_ACCEPTED"))
        self.assertNotIn("PRIVATE KEY", json.dumps(run))
        guide_calls = [step for step in GUIDES["live-authorization"]["workflow"] if step["kind"] == "tool"]
        actual_calls = [item for item in report["assessor_journal"]["issued_requests"] if item["method"] == "tools/call"]
        self.assertEqual([(s["id"], s["tool"], s["arguments"]) for s in guide_calls],
                         [(r["id"], r["params"]["name"], r["params"]["arguments"]) for r in actual_calls])
        self.assertEqual(evidence["package"]["manifest"]["configuration"]["code_revision"], checkout_revision())
        observations = report["observations"]
        self.assertFalse(observations["external_sink_capture"])
        observed_dispatch = [item["request_id"] for item in observations["host"] if item["phase"] == "dispatch_attempt"]
        self.assertNotIn("denied-before-grant", observed_dispatch)
        self.assertNotIn("denied-consumed", observed_dispatch)
        self.assertNotIn("denied-revoked", observed_dispatch)
        self.assertIn("allowed-once", observed_dispatch)
        self.assertIn("allowed-new-grant", observed_dispatch)
        self.assertTrue(any(item["phase"] == "commit_confirmed" for item in observations["host"]))
        self.assertNotIn('"raw_base64"', json.dumps(observations))
        self.assertNotIn('"payload_base64"', json.dumps(observations))
        _, events = await call(self.app, "GET", f'/api/runs/{run["run_id"]}/events')
        self.assertEqual(events["audit_records"], records)

    async def test_failed_live_registration_readback_cannot_open_task(self):
        # Execute with the runtime interpreter; the web environment intentionally
        # does not import the incompatible MCP dependency stack.
        code = '''
from tempfile import TemporaryDirectory
from unittest.mock import patch
from frontend_api.live_demo import execute
with TemporaryDirectory(prefix="chainguard-registration-check-") as directory:
    with patch("chainguard.acceptance.AcceptanceRegistry.expected", return_value=None):
        with patch("chainguard.m6_live_runtime.M6Host.open_task") as opened:
            try:
                execute(directory)
            except RuntimeError as exc:
                assert str(exc) == "Expected-run registration readback failed"
            else:
                raise AssertionError("Invalid registration was accepted")
            opened.assert_not_called()
'''
        process = await asyncio.create_subprocess_exec(str(RUNTIME), "-B", "-c", code,
            cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        _, stderr = await process.communicate()
        self.assertEqual(process.returncode, 0, stderr.decode())


class ControlledWorker(RunManager):
    """Test-only process fixture; never selected from HTTP inputs."""
    def __init__(self, code, timeout=5):
        super().__init__(timeout)
        self.code = code
        self.directories = []

    def command(self, scenario, directory):
        self.directories.append(directory)
        return [sys.executable, "-c", self.code]


class FailureTests(unittest.IsolatedAsyncioTestCase):
    async def test_failure_exit_code_preserved_diagnostics_sanitized(self):
        manager = ControlledWorker("import sys; print('/secret/private.pem', file=sys.stderr); sys.exit(7)")
        run = manager.create("mediation")
        await manager.task
        self.assertEqual((run["status"], run["exit_code"]), ("failed", 7))
        self.assertNotIn("/secret", json.dumps(run))
        self.assertFalse(Path(manager.directories[0]).exists())

    async def test_timeout_stops_process_and_cleans_workspace(self):
        manager = ControlledWorker("import time; time.sleep(30)", timeout=0.1)
        run = manager.create("mediation")
        await asyncio.wait_for(manager.task, 5)
        self.assertEqual(run["status"], "timed_out")
        self.assertLess(run["exit_code"], 0)
        self.assertFalse(Path(manager.directories[0]).exists())

    async def test_malformed_worker_result_not_reported_as_success(self):
        manager = ControlledWorker("print('{}')")
        run = manager.create("mediation")
        await manager.task
        self.assertEqual(run["status"], "failed")
        self.assertIsNone(run["result"])

    async def test_multiple_runs_are_isolated(self):
        manager = ControlledWorker("print('{\"report\":{},\"evidence\":null}')")
        first = manager.create("mediation")
        await manager.task
        second = manager.create("mediation")
        await manager.task
        self.assertNotEqual(first["run_id"], second["run_id"])
        self.assertEqual(len(set(manager.directories)), 2)
        self.assertTrue(all(not Path(d).exists() for d in manager.directories))

    async def test_shutdown_interrupts_active_run(self):
        manager = ControlledWorker("import time; time.sleep(30)")
        run = manager.create("mediation")
        await asyncio.sleep(0.1)
        await manager.close()
        self.assertEqual(run["error"]["code"], "INTERRUPTED")
        self.assertFalse(Path(manager.directories[0]).exists())


class RuntimeContextTests(unittest.TestCase):
    def test_checkout_identity_and_witness_paths_are_host_owned(self):
        revision = checkout_revision()
        with patch.dict(os.environ, {REVISION_ENV: "f" * 40,
                "CHAINGUARD_ASSESSOR_CHILD_WITNESS": "/untrusted/capture",
                "CHAINGUARD_ASSESSOR_SINK_ENDPOINT": "external.example:443"}):
            environment = runtime_environment()
        self.assertEqual(environment[REVISION_ENV], revision)
        self.assertNotIn("CHAINGUARD_ASSESSOR_CHILD_WITNESS", environment)
        self.assertNotIn("CHAINGUARD_ASSESSOR_SINK_ENDPOINT", environment)



if __name__ == "__main__":
    unittest.main()
