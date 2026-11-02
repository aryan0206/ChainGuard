"""Read-only ordering audit of the final assessor-held M6Q streams."""

import json
from datetime import datetime
from pathlib import Path


ROOT = Path(__file__).resolve().parent / "live_m6_sink_final"
STARTED = datetime.now().astimezone().isoformat()


def read(path):
    return [json.loads(line) for line in (ROOT / path).read_text(
        encoding="utf-8").splitlines()]


host = read("witness_primary/host.jsonl")
child = read("witness_primary/child.jsonl")
sink = read("witness_primary/sink.jsonl")
fault_host = read("witness_fault/host.jsonl")
fault_child = read("witness_fault/child.jsonl")
fault_sink = read("witness_fault/sink.jsonl")


def one(rows, predicate):
    matches = [row for row in rows if predicate(row)]
    if len(matches) != 1:
        raise ValueError(f"Expected one witness, found {len(matches)}")
    return matches[0]


def control(kind, grant_id=None):
    return one(host, lambda row: row.get("phase") == "commit_confirmed" and any(
        event["event_type"] == kind and
        (grant_id is None or event["body"].get("grant_id") == grant_id)
        for event in row.get("control_or_intent", [])))["sequence"]


def proposal(request_id):
    return one(host, lambda row: row.get("phase") == "proposal_admitted" and
               row.get("request_id") == request_id)["sequence"]


def intent(grant_id):
    return one(host, lambda row: row.get("phase") == "commit_confirmed" and any(
        event["event_type"] == "DISPATCH_INTENT" and any(
            grant["grant_id"] == grant_id for grant in event["body"]["selected_grants"])
        for event in row.get("control_or_intent", [])))["sequence"]


checks = {
    "g1_before_first_send_intent": control("GRANT", "g1") < proposal("q3-send") < intent("g1"),
    "g2_revoke_before_denied_send": control("GRANT", "g2") < control("REVOKE_SCOPE") < proposal("q5-revoked"),
    "g3_before_regrant_send_intent": control("GRANT", "g3") < proposal("q6-send") < intent("g3"),
    "duplicate_id_not_readmitted": sum(r.get("phase") == "proposal_admitted" and
        r.get("request_id") == "q1-read" for r in host) == 1,
    "only_expected_sink_receipts": [r["request_id"] for r in sink if
        r.get("phase") == "sink_received"] == ["q3-send", "q6-send"],
    "primary_child_and_sink_closed": any(r.get("phase") == "child_exiting" for r in child) and
        any(r.get("phase") == "child_process_closed" and r.get("clean") for r in host) and
        sink[-1].get("phase") == "sink_collector_closed",
    "fault_no_handler_or_sink": not any(r.get("phase") == "tool_received" and
        r.get("request_id") == "q8-fault" for r in fault_child) and
        not any(r.get("phase") == "sink_received" for r in fault_sink) and
        fault_sink[-1].get("phase") == "sink_collector_closed" and
        any(r.get("phase") == "child_process_closed" for r in fault_host),
}
output = {"checks": checks, "passed": all(checks.values()),
          "scope": "final assessor-held M6Q streams only",
          "started_local": STARTED,
          "ended_local": datetime.now().astimezone().isoformat(),
          "command": ".\\.venv\\Scripts\\python.exe -B results/completion_sprint_2026-11-02/H22-H25/verify_witness_order.py",
          "exit_code": 0 if all(checks.values()) else 1}
(ROOT / "postrun_witness_order.json").write_text(json.dumps(output, indent=2) + "\n",
                                                  encoding="utf-8")
raise SystemExit(0 if output["passed"] else 1)
