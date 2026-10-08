"""M4 controlled non-release live flow and separate-process offline inspection."""

import argparse
from dataclasses import asdict
import json
import os
from pathlib import Path
import queue
import secrets
import sqlite3
import subprocess
import sys
from tempfile import TemporaryDirectory
import threading
from uuid import uuid4

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from chainguard import PROTOCOL_VERSION
from chainguard.audit import AuditError, LiveAudit, _require
from chainguard.canonical import decode, encode
from chainguard.evidence import (INVENTORY_SCHEMA, ROOT, ChainedAuditSession, configuration,
                                load_private, load_public, make_manifest)
from chainguard.m3 import shadows
from chainguard.proxy import diagnostic, run


KEY_ID = "chainguard-m4-fixture-key"


def provision_key(private_path, public_path):
    """Explicit provisioning; fixture keys are generated before evidence exists."""
    private_path, public_path = Path(private_path).resolve(), Path(public_path).resolve()
    _require(not private_path.is_relative_to(ROOT), "Private key must be outside repository")
    _require(private_path != public_path and not private_path.exists() and not public_path.exists(),
             "Key provisioning requires distinct new files")
    key = ec.generate_private_key(ec.SECP256R1())
    private_bytes = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                     serialization.NoEncryption())
    public_bytes = key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    # Synthetic fixture key only: user-selected external storage, no implicit repo secret.
    with private_path.open("xb") as stream:
        stream.write(private_bytes)
    with public_path.open("xb") as stream:
        stream.write(public_bytes)


def proxy(database, output, private_path, public_path, key_id):
    """Host bootstrap precedes MCP input; MCP metadata cannot establish context."""
    session = None
    monitor = str(uuid4())
    diagnostic("m4_monitor_ready", monitor_instance_id=monitor)
    try:
        bootstrap_bytes = sys.stdin.buffer.readline(65537)
        _require(bootstrap_bytes.endswith(b"\n") and len(bootstrap_bytes) <= 65536, "Invalid host bootstrap frame")
        bootstrap = decode(bootstrap_bytes[:-1])
        _require(type(bootstrap) is dict and set(bootstrap) == {"manifest", "inventory"}, "Invalid trusted host bootstrap")
        manifest, inventory = bootstrap["manifest"], bootstrap["inventory"]
        _require(manifest["monitor_instance_id"] == monitor, "Launch monitor association mismatch")
        private_key, public_key = load_private(private_path), load_public(public_path)
        session = ChainedAuditSession(database, manifest, inventory,
            observer=lambda receipt: diagnostic("audit_committed", **asdict(receipt)))
        status = run(sys.stdin.buffer, sys.stdout.buffer, LiveAudit(session, shadows))
        if status == 0:
            session.seal(private_key, key_id, {key_id: public_key}, output=output)
            diagnostic("m4_exported", record_count=session.state.count,
                       cryptographic_head=session.state.cryptographic_head, progress=session.progress)
        return status
    except (AuditError, ValueError, KeyError, TypeError, sqlite3.Error, OSError):
        diagnostic("m4_failure", failure=session.state.failure if session else "M4_START_FAILED",
                   progress=session.progress if session else {"sealing": "INCOMPLETE"})
        return 2
    finally:
        if session is not None:
            session.close()


def execute_demo(directory, register_expected=None):
    """Prewritten real success/error/success; expected context precedes execution."""
    directory = Path(directory).resolve()
    _require(not directory.is_relative_to(ROOT), "Fixture artifacts/private key must be outside repository")
    directory.mkdir(parents=True, exist_ok=True)
    database, output = directory / "audit.sqlite", directory / "evidence.json"
    private_path, public_path = directory / "fixture-private.pem", directory / "fixture-public.pem"
    expected_path, config_path = directory / "expected.json", directory / "configuration.json"
    _require(not any(p.exists() for p in (database, output, expected_path, config_path)), "Demo requires fresh artifact paths")
    provision_key(private_path, public_path)
    run_id, task_id, session_id = (str(uuid4()) for _ in range(3))
    challenge = secrets.token_hex(32)
    config = configuration()
    meta = {"io.modelcontextprotocol/protocolVersion": PROTOCOL_VERSION,
            "io.modelcontextprotocol/clientCapabilities": {}}
    calls = [("echo", "m4-success-A"), ("controlled_failure", "m4-failure-B"), ("echo", "m4-success-C")]
    requests = [{"jsonrpc": "2.0", "id": 1, "method": "server/discover", "params": {"_meta": meta}},
                {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {"_meta": meta}}]
    requests.extend({"jsonrpc": "2.0", "id": i, "method": "tools/call",
                     "params": {"_meta": meta, "name": name, "arguments": {"token": token}}}
                    for i, (name, token) in enumerate(calls, 3))
    command = [sys.executable, "-B", "-u", "-m", "chainguard.m4", "proxy", "--db", str(database),
               "--output", str(output), "--private-key", str(private_path), "--public-key", str(public_path),
               "--key-id", KEY_ID]
    journal, stderr_lines, stdout_chunks = [], [], []
    ready = queue.Queue(maxsize=1)
    with subprocess.Popen(command, cwd=ROOT, env={**os.environ, "PYTHONUTF8": "1"},
                          stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE) as process:
        def collect_stderr():
            for line in process.stderr:
                stderr_lines.append(line)
                if line.startswith(b"{"):
                    observation = json.loads(line)
                    journal.append(observation)
                    if observation.get("phase") == "m4_monitor_ready":
                        ready.put(observation)

        def collect_stdout():
            stdout_chunks.append(process.stdout.read())

        stderr_thread = threading.Thread(target=collect_stderr, daemon=True)
        stdout_thread = threading.Thread(target=collect_stdout, daemon=True)
        stderr_thread.start()
        stdout_thread.start()
        try:
            launch = ready.get(timeout=30)
            inventory = {"schema_version": INVENTORY_SCHEMA, "run_id": run_id, "run_challenge": challenge,
                         "sessions": [{"task_id": task_id, "session_id": session_id,
                                       "monitor_instance_id": launch["monitor_instance_id"]}]}
            # Independently register the launched monitor and immutable expectations BEFORE input.
            expected_path.write_bytes(encode(inventory))
            config_path.write_bytes(encode(config))
            if register_expected is not None:
                # Trusted assessor hook; confirmed registration precedes bootstrap/tool input.
                register_expected(inventory, config, {KEY_ID: load_public(public_path)})
            manifest = make_manifest(inventory, config, task_id, session_id, launch["monitor_instance_id"])
            process.stdin.write(encode({"manifest": manifest, "inventory": inventory}) + b"\n")
            process.stdin.write(b"".join(json.dumps(r).encode("utf-8") + b"\n" for r in requests))
            process.stdin.flush()
            process.stdin.close()
            process.wait(timeout=60)
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
            stderr_thread.join(timeout=5)
            stdout_thread.join(timeout=5)
        _require(process.returncode == 0, "M4 proxy failed: " + b"".join(stderr_lines).decode("utf-8"))
        monitor_pid = process.pid
    responses = [json.loads(line) for line in b"".join(stdout_chunks).splitlines()]
    _require([r["id"] for r in responses] == [1, 2, 3, 4, 5], "M4 response correlation failed")
    _require(responses[0]["result"]["supportedVersions"] == [PROTOCOL_VERSION], "M4 discovery failed")
    _require(sorted(t["name"] for t in responses[1]["result"]["tools"]) == ["controlled_failure", "echo"], "M4 tools mismatch")
    results = []
    for response, (tool, token) in zip(responses[2:], calls, strict=True):
        failed = tool == "controlled_failure"
        expected_text = f"controlled failure: {token}" if failed else token
        _require(response["result"].get("isError", False) is failed
                 and response["result"]["content"][0]["text"] == expected_text, "M4 terminal result mismatch")
        results.append({"request_id": response["id"], "isError": failed, "text": expected_text})
    witnesses = [r for r in journal if r.get("phase") == "audit_committed"]
    arrivals = [r for r in journal if r.get("phase") == "tool_received"]
    _require(len(witnesses) == 8 and [r["request_id"] for r in arrivals] == [3, 4, 5], "M4 independent runtime witnesses mismatch")
    # Monitor has exited. The next process only has package, external config/expectation and public key.
    verified = subprocess.run([sys.executable, "-B", "-m", "chainguard.verifier", "--package", str(output),
        "--expected", str(expected_path), "--config", str(config_path), "--public-key", str(public_path), "--key-id", KEY_ID],
        cwd=ROOT, capture_output=True, timeout=60)
    verification = json.loads(verified.stdout)
    _require(verified.returncode == 0 and verification["inspection_passed"], "Separate-process offline inspection failed")
    package = decode(output.read_bytes())
    _require(len(package["records"]) == 26 and witnesses[-1]["last_seq"] == 26, "Unexpected M4 committed count")
    return {"milestone": "M4", "protocol_version": PROTOCOL_VERSION, "live_results": results,
            "record_count": len(package["records"]), "final_head": package["commitment"]["final_head"],
            "confirmed_transactions": len(witnesses), "handler_request_ids": [r["request_id"] for r in arrivals],
            "monitor_exited_before_verification": True, "monitor_launch_pid": monitor_pid,
            "progress": next(r["progress"] for r in journal if r.get("phase") == "m4_exported"),
            "offline_verifier_exit_code": verified.returncode, "offline_verification": verification,
            "assessor_journal": {"issued_requests": requests, "runtime_observations": journal, "responses": responses},
            "M5_fresh_submission_implemented": False, "M6_permission_lifecycle_implemented": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command")
    demo_parser = sub.add_parser("demo")
    demo_parser.add_argument("--directory", type=Path)
    keys = sub.add_parser("keygen")
    keys.add_argument("--private-key", type=Path, required=True)
    keys.add_argument("--public-key", type=Path, required=True)
    proxy_parser = sub.add_parser("proxy")
    for name in ("db", "output", "private-key", "public-key"):
        proxy_parser.add_argument("--" + name, type=Path, required=True)
    proxy_parser.add_argument("--key-id", required=True)
    args = parser.parse_args()
    if args.command == "proxy":
        return proxy(args.db, args.output, args.private_key, args.public_key, args.key_id)
    if args.command == "keygen":
        provision_key(args.private_key, args.public_key)
        print(json.dumps({"provisioned": True, "public_key": str(args.public_key)}))
        return 0
    if args.command == "demo" and args.directory is not None:
        report = execute_demo(args.directory)
    else:
        with TemporaryDirectory(prefix="chainguard-m4-") as directory:
            report = execute_demo(directory)
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
