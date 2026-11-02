"""Bounded assessor capture for frozen M6Q-01..08; no Git invocation."""

import base64
from datetime import datetime
import hashlib
from io import BytesIO
import json
import os
from pathlib import Path
import sqlite3
import socketserver
import tempfile
from threading import Lock, Thread
from unittest.mock import patch
from uuid import uuid4

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from chainguard import PROTOCOL_VERSION
from chainguard.evidence import SUITE
from chainguard.m6_live_profile import POLICY, PROFILE_VERSIONS, REVISION_ENV, live_configuration
from chainguard.m6_live_runtime import M6Host
from chainguard.m6_live_verifier import inspect_live_package
from chainguard.semantics import Scope


OUTPUT_NAME = os.environ.get("CHAINGUARD_M6Q_OUTPUT", "live_m6")
if OUTPUT_NAME not in {"live_m6", "live_m6_final", "live_m6_sink_final",
                       "live_m6_release"}:
    raise RuntimeError("Unrecognized M6Q output directory")
OUT = Path(__file__).resolve().parent / OUTPUT_NAME
PLAN = Path(__file__).resolve().parent.parent / "H2-H6" / "qualification_plan.json"
PIN = "8b27b5a980a87887be66c409c5a6a31d415a3326"


def now():
    return datetime.now().astimezone().isoformat()


def save(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def lines(path):
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


class AssessorSink:
    """Separate loopback receiver that retains the bytes it actually receives."""

    def __init__(self, path):
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("xb"):
            pass
        self.lock = Lock()
        self.sequence = 0
        owner = self

        class Handler(socketserver.StreamRequestHandler):
            def handle(self):
                header_bytes = self.rfile.readline(1024)
                header = json.loads(header_bytes)
                length = header["length"]
                if (type(length) is not int or not 1 <= length <= POLICY.max_payload_bytes or
                    header.get("destination") not in POLICY.destinations or
                    type(header.get("request_id")) not in (str, int)):
                    return
                payload = self.rfile.read(length)
                if len(payload) != length:
                    return
                owner.record({"phase": "sink_received", "request_id": header["request_id"],
                    "tool": header["tool"], "destination": header["destination"],
                    "payload_byte_count": length,
                    "payload_base64": base64.b64encode(payload).decode("ascii"),
                    "payload_sha256": hashlib.sha256(payload).hexdigest(),
                    "header_sha256": hashlib.sha256(header_bytes).hexdigest(),
                    "observed_local": now()})
                self.wfile.write(b"OK\n")
                self.wfile.flush()

        class Server(socketserver.TCPServer):
            allow_reuse_address = False

        self.server = Server(("127.0.0.1", 0), Handler)
        self.thread = Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.endpoint = f"127.0.0.1:{self.server.server_address[1]}"
        self.record({"phase": "sink_collector_started", "endpoint": self.endpoint,
                     "observed_local": now()})

    def record(self, event):
        with self.lock:
            self.sequence += 1
            raw = (json.dumps({"sequence": self.sequence, **event},
                sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
            with self.path.open("ab") as output:
                output.write(raw)
                output.flush()
                os.fsync(output.fileno())

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)
        self.record({"phase": "sink_collector_closed", "observed_local": now()})


def context(label):
    suffix = uuid4().hex
    identity = {"task_id": label + "-task-" + suffix,
                "session_id": label + "-session-" + suffix,
                "monitor_instance_id": label + "-monitor-" + suffix}
    inventory = {"schema_version": "m4-expected-inventory-v1",
                 "run_id": label + "-run-" + suffix,
                 "run_challenge": os.urandom(32).hex(), "sessions": [identity]}
    return identity, inventory


def raw_call(task, case_id, request_id, name, arguments):
    request = {"jsonrpc": "2.0", "id": request_id, "method": "tools/call",
        "params": {"_meta": {"io.modelcontextprotocol/protocolVersion": PROTOCOL_VERSION,
                             "io.modelcontextprotocol/clientCapabilities": {}},
                   "name": name, "arguments": arguments}}
    raw = json.dumps(request, ensure_ascii=False, separators=(",", ":")).encode("utf-8") + b"\n"
    path = OUT / case_id
    path.mkdir(parents=True, exist_ok=True)
    (path / "request.bin").write_bytes(raw)
    output = BytesIO()
    started = now()
    try:
        task._submit_client_frame(raw, output).result(timeout=15)
        status, exception = "RETURNED", None
    except Exception as exc:
        status, exception = "EXCEPTION", {"type": type(exc).__name__, "message": str(exc)}
    response = output.getvalue()
    (path / "response.bin").write_bytes(response)
    save(path / "call.json", {"case_id": case_id, "request_id": request_id,
        "started_local": started, "ended_local": now(), "status": status,
        "exception": exception, "request_sha256": hashlib.sha256(raw).hexdigest(),
        "response_sha256": hashlib.sha256(response).hexdigest()})
    return json.loads(response) if response else None, exception


def records_for(stream, phase, request_id):
    return [r for r in stream if r.get("phase") == phase and r.get("request_id") == request_id]


def check(condition, reason, checks):
    checks.append({"check": reason, "passed": bool(condition)})


def main():
    if os.environ.get(REVISION_ENV) != PIN:
        raise RuntimeError("Assessor revision pin absent or different")
    if OUT.exists():
        raise RuntimeError("Live qualification output already exists")
    OUT.mkdir()
    plan = json.loads(PLAN.read_text(encoding="utf-8"))
    save(OUT / "frozen_plan.json", plan)
    config = live_configuration()
    save(OUT / "assessor_context.json", {"revision_pin": PIN,
        "configuration": config, "started_local": now(),
        "case_ids": [row["id"] for row in plan["cases"]],
        "scope": "synthetic local stdio; trusted host and controlled child"})
    key = ec.generate_private_key(ec.SECP256R1())
    key_id = "h22-h25-ephemeral-assessor"
    (OUT / "assessor_public_key.pem").write_bytes(key.public_key().public_bytes(
        Encoding.PEM, PublicFormat.SubjectPublicKeyInfo))
    results = {}
    with tempfile.TemporaryDirectory(prefix="m6q-audit-") as temp:
        identity, inventory = context("M6Q-01-07")
        save(OUT / "assessor_inventory.json", inventory)
        sink = AssessorSink(OUT / "witness_primary" / "sink.jsonl")
        task = M6Host().open_task(db_path=Path(temp) / "audit.sqlite",
            trusted_inventory=inventory, **identity, witness_dir=OUT / "witness_primary",
            assessor_sink_endpoint=sink.endpoint)
        scope = Scope(identity["task_id"], "secret-a", "sink")
        controls = []
        try:
            responses = {}
            responses["M6Q-01"] = raw_call(task, "M6Q-01", "q1-read", "read_secret_a", {})
            responses["M6Q-02"] = raw_call(task, "M6Q-02", "q2-deny", "send_sink",
                                           {"payload": "SYNTHETIC_CANARY_A"})
            controls.append({"case_id": "M6Q-03", "kind": "GRANT", "grant_id": "g1",
                             "scope": scope.__dict__, "issued_local": now()})
            task.grant("g1", scope).result(timeout=15)
            controls[-1]["completed_local"] = now()
            responses["M6Q-03"] = raw_call(task, "M6Q-03", "q3-send", "send_sink",
                                           {"payload": "SYNTHETIC_CANARY_A"})
            responses["M6Q-04"] = raw_call(task, "M6Q-04", "q4-reuse", "send_sink",
                                           {"payload": "SYNTHETIC_CANARY_A"})
            controls.append({"case_id": "M6Q-05", "kind": "GRANT", "grant_id": "g2",
                             "scope": scope.__dict__, "issued_local": now()})
            task.grant("g2", scope).result(timeout=15)
            controls[-1]["completed_local"] = now()
            controls.append({"case_id": "M6Q-05", "kind": "REVOKE_SCOPE",
                             "scope": scope.__dict__, "issued_local": now()})
            task.revoke(scope).result(timeout=15)
            controls[-1]["completed_local"] = now()
            responses["M6Q-05"] = raw_call(task, "M6Q-05", "q5-revoked", "send_sink",
                                           {"payload": "SYNTHETIC_CANARY_A"})
            controls.append({"case_id": "M6Q-06", "kind": "GRANT", "grant_id": "g3",
                             "scope": scope.__dict__, "issued_local": now()})
            task.grant("g3", scope).result(timeout=15)
            controls[-1]["completed_local"] = now()
            responses["M6Q-06"] = raw_call(task, "M6Q-06", "q6-send", "send_sink",
                                           {"payload": "SYNTHETIC_CANARY_A"})
            responses["M6Q-07"] = raw_call(task, "M6Q-07", "q1-read", "send_sink",
                                           {"payload": "SYNTHETIC_CANARY_A"})
            task.shutdown().result(timeout=15)
        finally:
            if task._state == "ACTIVE":
                task.shutdown().result(timeout=15)
            task._thread.join(timeout=15)
            sink.close()
        save(OUT / "controls.json", controls)
        child = lines(OUT / "witness_primary" / "child.jsonl")
        host = lines(OUT / "witness_primary" / "host.jsonl")
        sink_records = lines(OUT / "witness_primary" / "sink.jsonl")
        package = task.export_live_evidence(expected_inventory=inventory,
            expected_configuration=config, private_key=key, signer_key_id=key_id,
            pinned_public_keys={key_id: key.public_key()},
            output_path=OUT / "signed_package.json")
        verification = inspect_live_package(package, expected_inventory=inventory,
            expected_configuration=config, trusted_signer_key_id=key_id,
            pinned_public_key=key.public_key(), accepted_versions=PROFILE_VERSIONS,
            accepted_suite=SUITE)
        save(OUT / "offline_verification.json", verification)
        complete = (any(r.get("phase") == "child_exiting" for r in child) and
                    any(r.get("phase") == "child_process_closed" and r.get("clean") for r in host) and
                    sink_records[-1].get("phase") == "sink_collector_closed")
        commits = [r for r in host if r.get("phase") == "commit_confirmed"]
        controls_committed = [e["event_type"] for r in commits
            for e in r.get("control_or_intent", [])]
        for case_id, request_id in (("M6Q-01", "q1-read"), ("M6Q-02", "q2-deny"),
            ("M6Q-03", "q3-send"), ("M6Q-04", "q4-reuse"),
            ("M6Q-05", "q5-revoked"), ("M6Q-06", "q6-send"),
            ("M6Q-07", "q1-read")):
            response, exception = responses[case_id]
            checks = []
            check(complete, "complete child stream and clean process closure", checks)
            check(verification["inspection_passed"], "signed offline inspection", checks)
            handlers = records_for(child, "tool_received", request_id)
            arrivals = records_for(sink_records, "sink_received", request_id)
            if case_id == "M6Q-01":
                check(len(handlers) == 1 and not arrivals, "source handler arrival", checks)
                check(response and response.get("result", {}).get("content", [{}])[0].get("text") ==
                      dict(POLICY.resources)["secret-a"], "independent client source result", checks)
            elif case_id in {"M6Q-03", "M6Q-06"}:
                grant = "g1" if case_id == "M6Q-03" else "g3"
                check("GRANT" in controls_committed and any(
                    e["event_type"] == "DISPATCH_INTENT" and any(
                        g["grant_id"] == grant for g in e["body"]["selected_grants"])
                    for r in commits for e in r.get("control_or_intent", [])),
                    "grant and selected reservation committed", checks)
                check(len(handlers) == len(arrivals) == 1,
                      "handler and sink arrival", checks)
                check(bool(arrivals) and base64.b64decode(arrivals[0]["payload_base64"]) ==
                      b"SYNTHETIC_CANARY_A" and arrivals[0]["payload_sha256"] ==
                      hashlib.sha256(b"SYNTHETIC_CANARY_A").hexdigest(),
                      "exact sink bytes and digest", checks)
                check(response and response.get("result", {}).get("content", [{}])[0].get("text") ==
                      "captured by local sink", "client task acknowledgement", checks)
            else:
                if case_id == "M6Q-05":
                    check("REVOKE_SCOPE" in controls_committed,
                          "revoke committed before attempted send", checks)
                check(response and response.get("error", {}).get("code") == -32003
                      if case_id != "M6Q-07" else exception and
                      exception.get("message") == "Duplicate request ID",
                      "refusal observed", checks)
                check(not arrivals and (not handlers or case_id == "M6Q-07"),
                      "no matching sink arrival by clean closure", checks)
            results[case_id] = {"status": "PASSED" if all(c["passed"] for c in checks)
                                else "FAILED", "checks": checks,
                                "handler_count": len(handlers), "sink_count": len(arrivals)}

        fault_identity, fault_inventory = context("M6Q-08")
        save(OUT / "fault_inventory.json", fault_inventory)
        fault_sink = AssessorSink(OUT / "witness_fault" / "sink.jsonl")
        fault_task = M6Host().open_task(db_path=Path(temp) / "fault_audit.sqlite",
            trusted_inventory=fault_inventory, **fault_identity,
            witness_dir=OUT / "witness_fault",
            assessor_sink_endpoint=fault_sink.endpoint)
        try:
            with patch.object(fault_task._audit, "_commit",
                              side_effect=sqlite3.OperationalError("declared commit refusal")):
                fault_response, fault_exception = raw_call(fault_task, "M6Q-08",
                    "q8-fault", "read_public", {})
            fault_task._thread.join(timeout=15)
        finally:
            if fault_task._state == "ACTIVE":
                fault_task.shutdown().result(timeout=15)
            fault_task._thread.join(timeout=15)
            fault_sink.close()
        fault_child = lines(OUT / "witness_fault" / "child.jsonl")
        fault_host = lines(OUT / "witness_fault" / "host.jsonl")
        fault_sink_records = lines(OUT / "witness_fault" / "sink.jsonl")
        checks = []
        check(fault_exception is not None and fault_task._state == "HALTED",
              "declared pre-dispatch persistence fault halted task", checks)
        check(not records_for(fault_child, "tool_received", "q8-fault") and
              not records_for(fault_sink_records, "sink_received", "q8-fault") and
              fault_sink_records[-1].get("phase") == "sink_collector_closed",
              "no handler or sink arrival", checks)
        check(any(r.get("phase") == "child_process_closed" for r in fault_host),
              "child process closure observed", checks)
        check(not (OUT / "fault_signed_package.json").exists(),
              "no signed export from halted task", checks)
        results["M6Q-08"] = {"status": "PASSED" if all(c["passed"] for c in checks)
                               else "FAILED", "checks": checks,
                               "handler_count": 0, "sink_count": 0}
    save(OUT / "case_results.json", {"ended_local": now(), "cases": results,
        "qualification_claim": "bounded trusted-host synthetic M6 only",
        "warning": "Witnesses are independent of SQLite, not cryptographic proof of host truth."})
    return 0 if all(r["status"] == "PASSED" for r in results.values()) else 1


if __name__ == "__main__":
    raise SystemExit(main())
