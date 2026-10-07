"""M3 live non-release staging harness; M2's oracle stays replay-only."""

import argparse
from dataclasses import asdict
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
from tempfile import TemporaryDirectory
from uuid import uuid4

from chainguard import PROTOCOL_VERSION
from chainguard.audit import AuditError, AuditSession, LiveAudit, RECORD_CLASS, read_records, reconstruct_history
from chainguard.proxy import diagnostic, run


ROOT = Path(__file__).resolve().parent.parent


def shadows(current, history, proposal_id, task_id):
    """Only return finding bodies; caller owns facts and actual dispatch."""
    from dataclasses import replace
    from chainguard.detectors import B2Reference, B2Streaming, b0, b1, equivalent
    from chainguard.semantics import Policy, attach_references, project_b1

    policy = Policy(())  # This live surface has no sensitive sources/releases.
    stream = B2Streaming(task_id, policy)
    for fact in history:
        stream.observe(fact)
    reference = B2Reference(task_id, policy).evaluate(current, history, proposal_id)
    incremental = stream.evaluate(current, proposal_id)
    if not equivalent(reference, incremental):
        raise ValueError("Live M3 non-release B2 prefix mismatch")
    results = (replace(b0(current, policy), supporting_event_ids=(proposal_id,)),
               attach_references(b1(current, project_b1(history, task_id), policy), proposal_id, current, history),
               reference, incremental)
    return tuple({"evaluated_event_id": proposal_id, "detector_id": f.detector_id,
        "detector_version": f.detector_version, "detector_digest": f.artifact_digest,
        "policy_digest": f.policy_digest, "extraction_version": f.extraction_version,
        "behavioral_verdict": f.behavior, "authorization_assessment": f.authorization,
        "hypothetical_recommendation": f.hypothetical_recommendation, "rule_id": f.rule_id,
        "supporting_event_ids": list(f.supporting_event_ids), "explanation": f.explanation} for f in results)


def proxy(path, run_id, task_id, session_id, challenge):
    session = None
    try:
        # Observed at successful transaction completion and continuity advance;
        # parent retains stderr separately from attacker-writable audit rows.
        session = AuditSession(path, run_id, task_id, session_id, challenge,
                               observer=lambda receipt: diagnostic("audit_committed", **asdict(receipt)))
        status = run(sys.stdin.buffer, sys.stdout.buffer, LiveAudit(session, shadows))
        if status == 0:
            session.finish()
        return status
    except (AuditError, ValueError, sqlite3.Error, OSError):
        diagnostic("audit_failure", failure=session.state.failure if session else "AUDIT_START_FAILED")
        return 2
    finally:
        if session is not None:
            session.close()


def execute_demo(path):
    """Prewritten real success/error/success; no grant or release capability."""
    identities = {k: str(uuid4()) for k in ("run_id", "task_id", "session_id", "challenge")}
    meta = {"io.modelcontextprotocol/protocolVersion": PROTOCOL_VERSION,
            "io.modelcontextprotocol/clientCapabilities": {}}
    calls = [("echo", "m3-success-A"), ("controlled_failure", "m3-failure-B"), ("echo", "m3-success-C")]
    requests = [
        {"jsonrpc": "2.0", "id": 1, "method": "server/discover", "params": {"_meta": meta}},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {"_meta": meta}},
    ]
    requests.extend({"jsonrpc": "2.0", "id": i, "method": "tools/call",
                     "params": {"_meta": meta, "name": name, "arguments": {"token": token}}}
                    for i, (name, token) in enumerate(calls, 3))
    command = [sys.executable, "-B", "-u", "-m", "chainguard.m3", "proxy", "--db", str(path)]
    for key, value in identities.items():
        command.extend(["--" + key.replace("_", "-"), value])
    result = subprocess.run(command, cwd=ROOT, env={**os.environ, "PYTHONUTF8": "1"},
        input=b"".join(json.dumps(r).encode("utf-8") + b"\n" for r in requests),
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
    if result.returncode != 0:
        raise RuntimeError("Audited live flow failed: " + result.stderr.decode("utf-8"))
    responses = [json.loads(frame) for frame in result.stdout.splitlines()]
    if [r["id"] for r in responses] != [1, 2, 3, 4, 5]:
        raise RuntimeError("Audited flow correlation failed")
    if responses[0]["result"]["supportedVersions"] != [PROTOCOL_VERSION]:
        raise RuntimeError("Unexpected discovery")
    if sorted(t["name"] for t in responses[1]["result"]["tools"]) != ["controlled_failure", "echo"]:
        raise RuntimeError("Unexpected tool surface")
    for response, (name, token) in zip(responses[2:], calls, strict=True):
        failed = name == "controlled_failure"
        if (response["result"].get("isError", False) is not failed
                or response["result"]["content"][0]["text"] != (f"controlled failure: {token}" if failed else token)):
            raise RuntimeError("Unexpected tool result")
    journal = [json.loads(line) for line in result.stderr.decode("utf-8").splitlines() if line.startswith("{")]
    witnesses = [r for r in journal if r.get("phase") == "audit_committed"]
    arrivals = [r for r in journal if r.get("phase") == "tool_received"]
    records = read_records(path, identities["session_id"])
    history = reconstruct_history(records)
    if len(arrivals) != 3 or [f.outcome for f in history] != ["succeeded", "failed", "succeeded"]:
        raise RuntimeError("Independent handler observations/committed outcomes failed")
    if len(witnesses) != 8 or witnesses[-1]["last_seq"] != len(records):
        raise RuntimeError("Transaction witness count mismatch")
    return {"record_class": RECORD_CLASS, "protocol_version": PROTOCOL_VERSION,
        "expected_context": identities, "monitor_instance_id": records[0]["monitor_instance_id"],
        "record_count": len(records), "continuity_head": [records[-1]["seq"], records[-1]["event_id"]],
        "closure": records[-1]["body"]["closure_status"], "tool_outcomes": [f.outcome for f in history],
        "handler_request_ids": [r["request_id"] for r in arrivals], "confirmed_transactions": len(witnesses),
        "commit_witnesses": witnesses, "assessor_journal": {"issued_requests": requests,
            "runtime_observations": journal, "responses": responses}, "crypto_evidence_implemented": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command")
    demo_parser = sub.add_parser("demo")
    demo_parser.add_argument("--db", type=Path)
    proxy_parser = sub.add_parser("proxy")
    proxy_parser.add_argument("--db", type=Path, required=True)
    for name in ("run-id", "task-id", "session-id", "challenge"):
        proxy_parser.add_argument("--" + name, required=True)
    args = parser.parse_args()
    if args.command == "proxy":
        return proxy(args.db, args.run_id, args.task_id, args.session_id, args.challenge)
    if args.command == "demo" and args.db is not None:
        report = execute_demo(args.db)
    else:
        with TemporaryDirectory(prefix="chainguard-m3-") as directory:
            report = execute_demo(Path(directory) / "audit.sqlite")
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
