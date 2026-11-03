"""Current-source signed wrong-fact engineering cases with separate M6Q truth."""

import base64
from copy import deepcopy
from datetime import datetime
import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from chainguard.canonical import decode, encode
from chainguard.evidence import SUITE, event_hash, genesis
from chainguard.m6_live_profile import PROFILE_VERSIONS
from chainguard.m6_live_seal import make_live_commitment, sign_live_commitment
from chainguard.m6_live_verifier import inspect_live_package

HERE = Path(__file__).resolve().parent
SOURCE = HERE / "live_m6_current"
PLAN = HERE / "e10_development_plan.json"
OUT = HERE / "e10_signed_wrong_development"
KEY_ID = "fiveh-e10-test-signer"


def sha(data):
    return hashlib.sha256(data).hexdigest()


def write(path, data):
    with path.open("xb") as stream:
        stream.write(data)
    return {"path": str(path.relative_to(HERE)), "bytes": len(data), "sha256": sha(data)}


def sign_mutant(source, private, kind):
    package = deepcopy(source)
    if kind == "wrong_observation":
        event = next(e["event"] for e in package["records"]
                     if e["event"]["event_type"] == "TOOL_OUTCOME" and
                     e["event"]["body"].get("tool") == "read_secret_a" and
                     e["event"]["body"].get("status") == "succeeded")
        event["body"]["status"] = "failed"
    elif kind == "wrong_finding":
        event = next(e["event"] for e in package["records"]
                     if e["event"]["event_type"] == "DETECTOR_FINDING")
        event["body"]["explanation"] += " WRONG_TEST_FINDING"
    elif kind == "witnessed_omission":
        index = next(i for i, e in enumerate(package["records"])
                     if e["event"]["event_type"] == "TOOL_OUTCOME" and
                     e["event"]["body"].get("tool") == "send_sink" and
                     e["event"]["body"].get("status") == "succeeded")
        del package["records"][index]
    elif kind != "control":
        raise ValueError(kind)
    head = genesis(package["manifest"])
    for seq, entry in enumerate(package["records"], 1):
        event = entry["event"]
        event["seq"] = seq
        event["prev_hash"] = head
        head = entry["event_hash"] = event_hash(event)
    package["commitment"] = make_live_commitment(
        package["manifest"], len(package["records"]), head, KEY_ID)
    package["signature"] = sign_live_commitment(private, package["commitment"])
    return encode(package)


def main():
    if OUT.exists():
        raise FileExistsError(OUT)
    OUT.mkdir()
    plan_bytes = PLAN.read_bytes()
    plan = json.loads(plan_bytes)
    context = json.loads((SOURCE / "assessor_context.json").read_text(encoding="utf-8"))
    inventory = json.loads((SOURCE / "assessor_inventory.json").read_text(encoding="utf-8"))
    original_bytes = (SOURCE / "signed_package.json").read_bytes()
    original = decode(original_bytes)
    child_path = SOURCE / "witness_primary" / "child.jsonl"
    sink_path = SOURCE / "witness_primary" / "sink.jsonl"
    child_raw, sink_raw = child_path.read_bytes(), sink_path.read_bytes()
    child = [json.loads(line) for line in child_raw.splitlines()]
    sink = [json.loads(line) for line in sink_raw.splitlines()]
    source_response = (SOURCE / "M6Q-01" / "response.bin").read_bytes()
    source_handler = [r for r in child if r.get("phase") == "tool_received" and r.get("request_id") == "q1-read"]
    sink_arrival = [r for r in sink if r.get("phase") == "sink_received" and r.get("request_id") == "q3-send"]
    if len(source_handler) != 1 or len(sink_arrival) != 1:
        raise RuntimeError("Independent child/sink witness coverage missing")
    truth = {"classification": "ASSESSOR_HELD_SYNTHETIC_M6Q_TRUTH",
             "source_response_sha256": sha(source_response),
             "child_witness_sha256": sha(child_raw),
             "sink_witness_sha256": sha(sink_raw),
             "source_handler_count": len(source_handler),
             "sink_arrival_count": len(sink_arrival),
             "sink_payload_sha256": sha(base64.b64decode(sink_arrival[0]["payload_base64"])),
             "sink_recorded_payload_sha256": sink_arrival[0]["payload_sha256"],
             "source_and_sink_records_are_external_to_signed_audit": True}
    if truth["sink_payload_sha256"] != truth["sink_recorded_payload_sha256"]:
        raise RuntimeError("Sink witness payload digest mismatch")
    write(OUT / "assessor_truth.json", (json.dumps(truth, indent=2) + "\n").encode())
    private = ec.generate_private_key(ec.SECP256R1())
    public = private.public_key()
    write(OUT / "test_signer_public_key.pem", public.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo))
    results = []
    for spec in plan["cases"]:
        raw = sign_mutant(original, private, spec["kind"])
        raw_ref = write(OUT / (spec["case_id"] + ".signed_package.bin"), raw)
        report = inspect_live_package(raw, expected_inventory=inventory,
            expected_configuration=context["configuration"],
            trusted_signer_key_id=KEY_ID, pinned_public_key=public,
            accepted_versions=PROFILE_VERSIONS, accepted_suite=SUITE)
        write(OUT / (spec["case_id"] + ".verifier.json"), (json.dumps(report, indent=2) + "\n").encode())
        dims = {k: v["status"] for k, v in report["dimensions"].items()}
        results.append({"case_id": spec["case_id"], "kind": spec["kind"],
                        "signed_package": raw_ref, "dimensions": dims,
                        "inspection_passed": report["inspection_passed"],
                        "expected_signature_met": dims["trusted_signature"] == spec["expected_signature"],
                        "expected_integrity_met": dims["commitment_integrity"] == spec["expected_integrity"],
                        "external_truth_ref": "assessor_truth.json"})
    result = {"schema": "chainguard-e10-development-signed-wrong-v1",
              "classification": "ENGINEERING_DEVELOPMENT_ONLY; NOT E10 RESEARCH",
              "source_revision_pin": context["revision_pin"],
              "source_package_sha256": sha(original_bytes),
              "plan_sha256": sha(plan_bytes),
              "ended_local": datetime.now().astimezone().isoformat(),
              "cases": results,
              "research_denominator": 0,
              "limitation": "Test signer is freshly generated; exact wrong-fact population and independent omission oracle are not frozen for research"}
    write(OUT / "case_results.json", (json.dumps(result, indent=2) + "\n").encode())
    print(f"cases={len(results)} signature_and_integrity_expected={sum(r['expected_signature_met'] and r['expected_integrity_met'] for r in results)} research=0")
    return 0 if all(r["expected_signature_met"] and r["expected_integrity_met"] for r in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
