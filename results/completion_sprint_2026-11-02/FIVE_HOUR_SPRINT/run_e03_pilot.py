"""Frozen bounded E03 synthetic pilot with assessor-held source/sink truth."""

import base64
from datetime import datetime
import hashlib
import json
from pathlib import Path
import tempfile

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from chainguard.evidence import SUITE
from chainguard.m6_live_profile import PROFILE_VERSIONS
from chainguard.m6_live_verifier import inspect_live_package

import qualify_live_current as q

HERE = Path(__file__).resolve().parent
PLAN = HERE / "e03_frozen_pilot_plan.json"
OUT = HERE / "e03_pilot"
METRIC_INPUT = HERE / "e03_metric_input.json"
KEY_ID = "fiveh-e03-pilot-assessor"


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def save(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2)
        stream.write("\n")


def read_lines(path):
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def capture_parent(parent_id, specs, config, key):
    parent_out = OUT / parent_id
    parent_out.mkdir()
    q.OUT = parent_out
    identity, inventory = q.context(parent_id)
    save(parent_out / "assessor_inventory.json", inventory)
    save(parent_out / "assessor_context.json", {"configuration": config,
        "revision_pin": q.PIN, "parent_id": parent_id,
        "started_local": datetime.now().astimezone().isoformat()})
    sink = q.AssessorSink(parent_out / "witness" / "sink.jsonl")
    responses = {}
    with tempfile.TemporaryDirectory(prefix="e03-audit-") as temp:
        task = q.M6Host().open_task(db_path=Path(temp) / "audit.sqlite",
            trusted_inventory=inventory, **identity,
            witness_dir=parent_out / "witness", assessor_sink_endpoint=sink.endpoint)
        try:
            for spec in specs:
                request_id = spec["case_id"].lower()
                response, exception = q.raw_call(task, spec["case_id"], request_id,
                                                  spec["tool"], spec["arguments"])
                responses[spec["case_id"]] = {"request_id": request_id,
                                              "response": response, "exception": exception}
            task.shutdown().result(timeout=15)
        finally:
            if task._state == "ACTIVE":
                task.shutdown().result(timeout=15)
            task._thread.join(timeout=15)
            sink.close()
        package = task.export_live_evidence(expected_inventory=inventory,
            expected_configuration=config, private_key=key, signer_key_id=KEY_ID,
            pinned_public_keys={KEY_ID: key.public_key()},
            output_path=parent_out / "signed_package.json")
    verification = inspect_live_package(package, expected_inventory=inventory,
        expected_configuration=config, trusted_signer_key_id=KEY_ID,
        pinned_public_key=key.public_key(), accepted_versions=PROFILE_VERSIONS,
        accepted_suite=SUITE)
    save(parent_out / "offline_verification.json", verification)
    child = read_lines(parent_out / "witness" / "child.jsonl")
    host = read_lines(parent_out / "witness" / "host.jsonl")
    sink_records = read_lines(parent_out / "witness" / "sink.jsonl")
    complete = (verification["inspection_passed"] is True and
                any(r.get("phase") == "child_exiting" for r in child) and
                any(r.get("phase") == "child_process_closed" and r.get("clean") for r in host) and
                sink_records[-1].get("phase") == "sink_collector_closed")
    package_obj = json.loads(package)
    proposals = {e["event"]["body"]["request_id"]: e["event"]["call_id"]
                 for e in package_obj["records"] if e["event"]["event_type"] == "CALL_PROPOSAL"}
    findings = {}
    for entry in package_obj["records"]:
        event = entry["event"]
        if event["event_type"] == "DETECTOR_FINDING":
            findings.setdefault(event["call_id"], {})[event["body"]["detector_id"]] = {
                "authorization": event["body"]["authorization_assessment"],
                "behavior": event["body"]["behavioral_verdict"],
                "rule_id": event["body"]["rule_id"],
            }
    save(parent_out / "client_responses.json", responses)
    return {"parent_out": parent_out, "inventory": inventory, "responses": responses,
            "child": child, "host": host, "sink": sink_records,
            "capture_complete": complete, "verification": verification,
            "proposals": proposals, "findings": findings,
            "package_sha256": digest(package)}


def main():
    if OUT.exists() or METRIC_INPUT.exists():
        raise FileExistsError("E03 evidence already exists")
    plan_bytes = PLAN.read_bytes()
    plan = json.loads(plan_bytes)
    if plan["schema"] != "chainguard-frozen-experiment-contract-v1" or q.PIN != plan["source_revision_pin"]:
        raise ValueError("Frozen plan/revision mismatch")
    if digest((HERE.parents[2] / "chainguard/semantics.py").read_bytes()) != plan["direct_recognition_source_sha256"]:
        raise ValueError("Direct-recognition source changed after freeze")
    cases = plan["cases"]
    if [c["case_id"] for c in cases] != plan["case_ids"]:
        raise ValueError("Case inventory mismatch")
    OUT.mkdir()
    (OUT / "frozen_plan.json").write_bytes(plan_bytes)
    key = ec.generate_private_key(ec.SECP256R1())
    (OUT / "assessor_public_key.pem").write_bytes(key.public_key().public_bytes(
        Encoding.PEM, PublicFormat.SubjectPublicKeyInfo))
    config = q.live_configuration()
    parents = {}
    for parent_id in plan["independent_parent_ids"]:
        specs = [c for c in cases if c["parent_id"] == parent_id]
        parents[parent_id] = capture_parent(parent_id, specs, config, key)
    p1 = parents["E03-PILOT-EXPOSURE-01"]
    p2 = parents["E03-PILOT-CONTROL-01"]
    p1_source = p1["responses"]["E03-P1-SOURCE"]["response"]
    source_text = (p1_source or {}).get("result", {}).get("content", [{}])[0].get("text")
    source_success = (source_text == "SYNTHETIC_CANARY_A" and
                      len(q.records_for(p1["child"], "tool_received", "e03-p1-source")) == 1)
    denied_read_no_handler = (len(q.records_for(p2["child"], "tool_received", "e03-p2-denied-read")) == 0 and
                              bool(p2["responses"]["E03-P2-DENIED-READ"]["exception"] or
                                   (p2["responses"]["E03-P2-DENIED-READ"]["response"] or {}).get("error")))
    metric_rows = []
    case_results = []
    for spec in cases:
        parent = parents[spec["parent_id"]]
        case_id = spec["case_id"]
        request_id = case_id.lower()
        handlers = q.records_for(parent["child"], "tool_received", request_id)
        arrivals = q.records_for(parent["sink"], "sink_received", request_id)
        response = parent["responses"][case_id]
        label = spec["predecision_label"]
        if case_id in {"E03-P1-HEX", "E03-P1-PUBLIC"} and not source_success:
            label = "UNKNOWN"
        if case_id == "E03-P2-PUBLIC" and not denied_read_no_handler:
            label = "UNKNOWN"
        proposal_id = parent["proposals"].get(request_id)
        predictions = {detector: values["authorization"] for detector, values in
                       parent["findings"].get(proposal_id, {}).items()}
        coverage = "COMPLETE" if parent["capture_complete"] else "INCOMPLETE"
        oracle = {"case_id": case_id, "label": label,
                  "source": "prewritten static permission plus independently witnessed source/control boundary",
                  "basis": spec["oracle_basis"], "source_success": source_success if spec["parent_id"] == "E03-PILOT-EXPOSURE-01" else None,
                  "denied_read_no_handler": denied_read_no_handler if spec["parent_id"] == "E03-PILOT-CONTROL-01" else None,
                  "plan_sha256": digest(plan_bytes)}
        witness = {"case_id": case_id, "coverage": coverage,
                   "child_handler_count": len(handlers), "sink_arrival_count": len(arrivals),
                   "sink_payload_sha256": [r.get("payload_sha256") for r in arrivals],
                   "sink_payload_base64": [r.get("payload_base64") for r in arrivals],
                   "client_response": response, "package_sha256": parent["package_sha256"],
                   "child_stream_sha256": digest((parent["parent_out"] / "witness/child.jsonl").read_bytes()),
                   "sink_stream_sha256": digest((parent["parent_out"] / "witness/sink.jsonl").read_bytes())}
        oracle_file = parent["parent_out"] / (case_id + ".oracle.json")
        witness_file = parent["parent_out"] / (case_id + ".witness.json")
        save(oracle_file, oracle)
        save(witness_file, witness)
        effect_matches = (len(handlers) == spec["expected_handler"] and len(arrivals) == spec["expected_sink"])
        if arrivals and spec["tool"] == "send_sink":
            expected_payload = spec["arguments"]["payload"].encode()
            effect_matches &= all(base64.b64decode(r["payload_base64"]) == expected_payload and
                                  r["payload_sha256"] == digest(expected_payload) for r in arrivals)
        case_results.append({"case_id": case_id, "parent_id": spec["parent_id"],
                             "oracle_label": label, "capture_complete": coverage == "COMPLETE",
                             "handler_count": len(handlers), "sink_count": len(arrivals),
                             "effect_matches_predeclared": effect_matches,
                             "detector_findings": parent["findings"].get(proposal_id, {}),
                             "research_eligible": (label in {"AUTHORIZED", "UNAUTHORIZED"} and
                                                   coverage == "COMPLETE" and proposal_id is not None)})
        eligible = case_results[-1]["research_eligible"]
        metric_rows.append({"case_id": case_id, "parent_id": spec["parent_id"],
                            "classification": "RESEARCH" if eligible else "EXCLUDED_CONTROL",
                            "eligible": eligible,
                            "exclusion_reason": None if eligible else "No evaluated proposal, definite oracle or complete capture",
                            "oracle_source": "INDEPENDENT" if eligible else "NOT_APPLICABLE",
                            "witness_status": coverage,
                            "oracle_label": label,
                            "predictions": predictions,
                            "oracle_record": {"path": str(oracle_file.relative_to(HERE)),
                                              "sha256": digest(oracle_file.read_bytes())},
                            "witness_record": {"path": str(witness_file.relative_to(HERE)),
                                               "sha256": digest(witness_file.read_bytes())}})
    result = {"schema": "chainguard-e03-bounded-pilot-results-v1",
              "classification": "BOUNDED_SYNTHETIC_RESEARCH_PILOT; DESCRIPTIVE_ONLY",
              "ended_local": datetime.now().astimezone().isoformat(),
              "frozen_plan_sha256": digest(plan_bytes),
              "source_revision_pin": q.PIN,
              "source_success": source_success,
              "denied_read_no_handler": denied_read_no_handler,
              "cases": case_results,
              "independent_parent_count": len(parents),
              "research_eligible_case_count": sum(r["research_eligible"] for r in case_results),
              "limitation": "Two designed synthetic parents, no held-out generalization or inferential statistics"}
    save(OUT / "case_results.json", result)
    save(METRIC_INPUT, {"schema": "chainguard-research-observations-v1",
                        "frozen_contract": {"path": PLAN.name, "sha256": digest(plan_bytes)},
                        "cases": metric_rows})
    print(f"cases={len(case_results)} eligible={result['research_eligible_case_count']} source_success={source_success} denied_read_control={denied_read_no_handler}")
    return 0 if source_success and denied_read_no_handler and all(
        r["capture_complete"] and r["effect_matches_predeclared"] for r in case_results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
