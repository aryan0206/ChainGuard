"""M1 contracts: real SDK subprocess path plus bounded relay fault checks."""

from contextlib import redirect_stderr
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

from chainguard.proxy import run


ROOT = Path(__file__).resolve().parent.parent
VERSION = "2026-07-28"
META = {
    "io.modelcontextprotocol/protocolVersion": VERSION,
    "io.modelcontextprotocol/clientCapabilities": {},
    "io.modelcontextprotocol/clientInfo": {"name": "m1-contract-test", "version": "1"},
}


def request(request_id, method="tools/list", **params):
    return {"jsonrpc": "2.0", "id": request_id, "method": method, "params": {"_meta": META, **params}}


def diagnostics(stderr):
    records = []
    for line in stderr.splitlines():
        try:
            record = json.loads(line)
        except ValueError:
            continue
        if isinstance(record, dict) and record.get("component") in {"proxy", "controlled_server"}:
            records.append(record)
    return records


def launch(module, input_bytes=None):
    return subprocess.run(
        [sys.executable, "-u", "-m", module],
        cwd=ROOT,
        env={**os.environ, "PYTHONUTF8": "1"},
        input=input_bytes,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=90,
    )


class M1IntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sdk_flow = launch("chainguard.client")
        if cls.sdk_flow.returncode != 0:
            raise RuntimeError(cls.sdk_flow.stderr.decode("utf-8"))
        cls.report = json.loads(cls.sdk_flow.stdout)
        cls.trace = diagnostics(cls.sdk_flow.stderr.decode("utf-8"))

    def raw_flow(self, requests):
        frames = b"".join(json.dumps(r, ensure_ascii=False).encode("utf-8") + b"\n" for r in requests)
        result = launch("chainguard.proxy", frames)
        self.assertEqual(result.returncode, 0, result.stderr.decode("utf-8"))
        responses = [json.loads(line) for line in result.stdout.splitlines()]
        self.assertEqual(len(responses), len(requests))
        return responses, diagnostics(result.stderr.decode("utf-8"))

    def test_m1_t1_discovery(self):
        self.assertEqual(self.report["protocol_version"], VERSION)
        self.assertEqual(self.report["server"], "chainguard-controlled-m1")
        self.assertEqual(self.report["tools"], ["controlled_failure", "echo"])
        methods = [r["method"] for r in self.trace if r.get("phase") == "forwarded"]
        self.assertEqual(methods, ["server/discover", "tools/list", "tools/call", "tools/call", "tools/call"])

    def test_m1_t2_successful_call(self):
        self.assertEqual(self.report["success"], {"isError": False, "text": "m1-success-A"})
        self.assertEqual(self.report["success_after_error"], {"isError": False, "text": "m1-success-C"})

    def test_m1_t3_controlled_tool_error(self):
        self.assertEqual(
            self.report["controlled_error"],
            {"isError": True, "text": "controlled failure: m1-failure-B"},
        )

    def test_m1_t4_request_result_correlation(self):
        calls = [
            request(7, "tools/call", name="echo", arguments={"token": "first"}),
            request("7", "tools/call", name="controlled_failure", arguments={"token": "second"}),
            request("unicode-\u03bb", "tools/call", name="echo", arguments={"token": "third: \u03bb\nnext"}),
        ]
        responses, trace = self.raw_flow(calls)
        for call, response in zip(calls, responses, strict=True):
            self.assertEqual(type(call["id"]), type(response["id"]))
            self.assertEqual(call["id"], response["id"])
        self.assertEqual(responses[0]["result"]["content"][0]["text"], "first")
        self.assertTrue(responses[1]["result"]["isError"])
        self.assertEqual(responses[1]["result"]["content"][0]["text"], "controlled failure: second")
        self.assertEqual(responses[2]["result"]["content"][0]["text"], "third: \u03bb\nnext")
        self.assertEqual([r["request_id"] for r in trace if r["phase"] == "tool_received"], [7, "7", "unicode-\u03bb"])

    def test_m1_t5_actual_proxy_mediation(self):
        started = [r for r in self.trace if r["phase"] == "started"]
        self.assertEqual(len(started), 1)
        proxy_pid, tool_pid = started[0]["pid"], started[0]["downstream_pid"]
        self.assertNotEqual(proxy_pid, tool_pid)
        forwarded = [r for r in self.trace if r["phase"] == "forwarded"]
        self.assertEqual(len(forwarded), 5)
        self.assertEqual(len([r for r in self.trace if r["phase"] == "returned"]), 5)
        for r in forwarded:
            self.assertEqual(r["pid"], proxy_pid)
            self.assertEqual(r["downstream_pid"], tool_pid)
            phases = [
                item["phase"] for item in self.trace
                if item.get("component") == "proxy" and item.get("request_id") == r["request_id"]
            ]
            self.assertEqual(phases, ["received", "forwarded", "response_received", "returned"])
        arrivals = [r for r in self.trace if r["phase"] == "tool_received"]
        tool_calls = [r for r in forwarded if r["method"] == "tools/call"]
        self.assertEqual(len(arrivals), 3)
        self.assertEqual([r["request_id"] for r in arrivals], [r["request_id"] for r in tool_calls])
        handler_pid = arrivals[0]["pid"]
        for receipt in arrivals:
            self.assertEqual(receipt["pid"], handler_pid)
            self.assertNotEqual(handler_pid, proxy_pid)
            if handler_pid == tool_pid:
                self.assertEqual(receipt["parent_pid"], proxy_pid)
            else:
                # Windows venv's python.exe is a redirector that launches the
                # interpreter worker with the inherited stdio pipes.
                self.assertEqual(sys.platform, "win32")
                self.assertEqual(receipt["parent_pid"], tool_pid)
        stopped = [r for r in self.trace if r["phase"] == "stopped"]
        self.assertEqual(len(stopped), 1)
        self.assertEqual(stopped[0]["downstream_exit_code"], 0)

    def test_modern_metadata_on_every_sdk_request(self):
        received = [r for r in self.trace if r["phase"] == "received"]
        self.assertEqual(len(received), 5)
        for item in received:
            self.assertEqual(item["protocol_version"], VERSION)
            self.assertIs(item["required_metadata"], True)
        self.assertNotIn(b"initialize", self.sdk_flow.stderr)

    def test_missing_metadata_and_wrong_version_are_not_forwarded(self):
        calls = [
            request("no-meta", _meta={}),
            request("no-version", _meta={"io.modelcontextprotocol/clientCapabilities": {}}),
            request("no-capabilities", _meta={"io.modelcontextprotocol/protocolVersion": VERSION}),
            request("old-version", _meta={**META, "io.modelcontextprotocol/protocolVersion": "2025-11-25"}),
            request("valid"),
        ]
        responses, trace = self.raw_flow(calls)
        self.assertEqual([r["id"] for r in responses], [r["id"] for r in calls])
        self.assertEqual([r["error"]["code"] for r in responses[:4]], [-32602, -32602, -32602, -32022])
        self.assertEqual(responses[3]["error"]["data"], {"supportedVersions": [VERSION]})
        self.assertIn("result", responses[4])
        self.assertEqual([r["request_id"] for r in trace if r["phase"] == "forwarded"], ["valid"])

    def test_legacy_and_future_surface_are_unsupported(self):
        calls = [request("legacy", "initialize"), request("resources", "resources/list"), request("modern")]
        responses, trace = self.raw_flow(calls)
        self.assertEqual([r["error"]["code"] for r in responses[:2]], [-32601, -32601])
        self.assertEqual([r["request_id"] for r in trace if r["phase"] == "forwarded"], ["modern"])
        capabilities, _ = self.raw_flow([request("discovery", "server/discover")])
        self.assertEqual(capabilities[0]["result"]["supportedVersions"], [VERSION])
        self.assertEqual(set(capabilities[0]["result"]["capabilities"]), {"tools"})
        self.assertFalse(capabilities[0]["result"]["capabilities"]["tools"]["listChanged"])

    def test_protocol_errors_remain_distinct_from_tool_failure(self):
        calls = [
            request("unknown", "tools/call", name="missing", arguments={"token": "test"}),
            request("invalid", "tools/call", name="echo", arguments={"token": 3}),
            request("recovered", "tools/call", name="echo", arguments={"token": "still works"}),
        ]
        responses, _ = self.raw_flow(calls)
        self.assertEqual([r["error"]["code"] for r in responses[:2]], [-32602, -32602])
        self.assertNotIn("result", responses[0])
        self.assertEqual(responses[2]["result"]["content"][0]["text"], "still works")


class M1RelayTests(unittest.TestCase):
    def injected_downstream(self, frames, child_code):
        # An actual local child exercises the pipes; only the child command is
        # substituted to induce wire faults without adding another server file.
        output, stderr = io.BytesIO(), io.StringIO()
        actual_popen = subprocess.Popen

        def substitute(command, **kwargs):
            self.assertEqual(command, [sys.executable, "-u", "-m", "chainguard.controlled_server"])
            return actual_popen([sys.executable, "-u", "-c", child_code], **kwargs)

        with patch("chainguard.proxy.subprocess.Popen", side_effect=substitute), redirect_stderr(stderr):
            status = run(io.BytesIO(frames), output)
        return status, output.getvalue(), diagnostics(stderr.getvalue())

    def test_supported_frames_are_preserved_byte_for_byte(self):
        sent = (json.dumps(request("wire-id", "tools/call", name="echo", arguments={"token": "wire"}), indent=None)
                + "  \n").encode("utf-8")
        reply = b'{ "jsonrpc": "2.0", "id": "wire-id", "result": {"content": [], "isError": false, "_meta": {"com.example/test": "preserved"}} }\n'
        child = (
            "import sys; frame=sys.stdin.buffer.readline(); "
            f"assert frame == bytes.fromhex('{sent.hex()}'); "
            f"sys.stdout.buffer.write(bytes.fromhex('{reply.hex()}')); "
            "sys.stdout.buffer.flush(); sys.stdin.buffer.read()"
        )
        status, received, _ = self.injected_downstream(sent, child)
        self.assertEqual(status, 0)
        self.assertEqual(received, reply)

    def test_mismatched_response_halts_without_returning_it_or_retrying(self):
        sent = json.dumps(request(7)).encode("utf-8") + b"\n"
        reply = b'{"jsonrpc":"2.0","id":"7","result":{}}\n'
        child = (
            "import sys; sys.stdin.buffer.readline(); "
            f"sys.stdout.buffer.write(bytes.fromhex('{reply.hex()}')); "
            "sys.stdout.buffer.flush(); sys.stdin.buffer.read()"
        )
        status, received, trace = self.injected_downstream(sent + sent, child)
        self.assertEqual(status, 2)
        response = json.loads(received)
        self.assertEqual(response["id"], 7)
        self.assertEqual(response["error"]["code"], -32603)
        self.assertIn("unknown", response["error"]["message"])
        self.assertEqual(len([r for r in trace if r["phase"] == "forwarded"]), 1)
        self.assertFalse(any(r["phase"] == "returned" for r in trace))

    def test_downstream_eof_reports_unknown_outcome_without_retry(self):
        sent = json.dumps(request("eof")).encode("utf-8") + b"\n"
        status, received, trace = self.injected_downstream(sent, "import sys; sys.stdin.buffer.readline()")
        self.assertEqual(status, 2)
        response = json.loads(received)
        self.assertEqual(response["id"], "eof")
        self.assertEqual(response["error"]["code"], -32603)
        self.assertEqual(len([r for r in trace if r["phase"] == "forwarded"]), 1)


if __name__ == "__main__":
    unittest.main()
