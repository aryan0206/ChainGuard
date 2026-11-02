"""Retain existing E02/E13 DEVELOPMENT inputs and checks; no experiment or Git."""

from dataclasses import asdict, replace
from hashlib import sha256
import json
from pathlib import Path
import sys

OUT = Path(__file__).resolve().parent
ROOT = OUT.parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from workflow_fixtures import BY_ID, MATCHED_GROUPS  # noqa: E402
from chainguard.m2 import ReplayLedger, run_fixture  # noqa: E402
from chainguard.oracle import Fixture  # noqa: E402
from chainguard.semantics import Policy, b1_input_bytes, extract_current, project_b1  # noqa: E402
from chainguard.workflows import unordered_signature, validate_contract, validate_group  # noqa: E402


def retain(name, data):
    path = OUT / name
    with path.open("xb") as stream:
        stream.write(data)
    return {"file": name, "bytes": len(data), "sha256": sha256(data).hexdigest()}


def json_bytes(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def b1_at(contract, call_id):
    policy = Policy(contract.resources)
    ledger = ReplayLedger(policy)
    history = []
    for entry in contract.journal:
        if entry.kind == "PROPOSAL" and entry.call_id == call_id:
            return b1_input_bytes(extract_current(entry.body, policy),
                                  project_b1(tuple(history), contract.task_id))
        history.extend(ledger.accept(entry))
    raise ValueError("Target proposal absent")


def replay_summary(contract):
    fixture = Fixture(contract.workflow_id, contract.journal, contract.resources,
                      contract.expected_output, ())
    result = run_fixture(fixture)
    return {
        "evidence_class": result["evidence_class"],
        "rows": [{"call_id": row["call_id"],
                  "b1_input_hex": row["b1_input"].hex(),
                  "findings": [asdict(finding) for finding in row["findings"]]}
                 for row in result["rows"]],
        "staged_oracle": [asdict(observation) for observation in result["oracle"]],
    }


group = MATCHED_GROUPS[0]
assert group.group_id == "revocation_boundary_01"
validate_group(group)
pair = []
for case_id, (contract, call_id) in zip(("CG-DEV-004", "CG-DEV-005"), group.members, strict=True):
    validate_contract(contract)
    payload = b1_at(contract, call_id)
    label = next(c.authorization for c in contract.calls if c.call_id == call_id)
    pair.append({"case_id": case_id, "workflow_id": contract.workflow_id,
                 "call_id": call_id, "development_authored_label": label,
                 "b1": retain(f"{case_id}.b1.bin", payload),
                 "journal": retain(f"{case_id}.journal.json", json_bytes(asdict(contract))),
                 "replay": replay_summary(contract)})
assert pair[0]["b1"]["sha256"] == pair[1]["b1"]["sha256"]
assert (OUT / pair[0]["b1"]["file"]).read_bytes() == (OUT / pair[1]["b1"]["file"]).read_bytes()
assert [row["development_authored_label"] for row in pair] == ["UNAUTHORIZED", "AUTHORIZED"]
retain("e02_development_pair.json", json_bytes({
    "status": "DEVELOPMENT_STAGED_ONLY", "group_id": group.group_id,
    "byte_equal": True, "members": pair,
    "label_source": "tests/workflow_fixtures.py authored CallExpectation, validated by unchanged staged M2 assessor; no independently observed live control/commit/effect witness",
}))

original = BY_ID["matched-revoke-grant"]
journal = []
for entry in original.journal:
    body = entry.body
    if body.get("grant_id"):
        body["grant_id"] = "renamed-grant"
    for grant in body.get("selected_grants", []):
        grant["grant_id"] = "renamed-grant"
    journal.append(replace(entry, event_id="renamed-" + entry.event_id,
                           body_json=json.dumps(body)))
calls = tuple(replace(c, consumed_grants=("renamed-grant",)) if c.consumed_grants else c
              for c in original.calls)
renamed = replace(original, journal=tuple(journal), calls=calls)
validate_contract(original)
validate_contract(renamed)
before_signature = unordered_signature(original, "release")
after_signature = unordered_signature(renamed, "release")
assert before_signature == after_signature
before = replay_summary(original)
after = replay_summary(renamed)
retain("e13_original_input.json", json_bytes(asdict(original)))
retain("e13_renamed_input.json", json_bytes(asdict(renamed)))
retain("e13_original_output.json", json_bytes(before))
retain("e13_renamed_output.json", json_bytes(after))

def decisions(report):
    return [(row["call_id"], [(f["detector_id"], f["authorization"], f["behavior"], f["rule_id"])
                               for f in row["findings"]]) for row in report["rows"]]

retain("e13_development_check.json", json_bytes({
    "status": "DEVELOPMENT_STAGED_ONLY",
    "original_case_id": "CG-DEV-005", "transformed_case_id": "CG-DEV-005-RENAME-01",
    "changed": ["event_id", "grant_id and selected/consumed grant references"],
    "unordered_signature_equal": True,
    "decision_rule_tuple_equal": decisions(before) == decisions(after),
    "original_decision_rule_tuples": decisions(before),
    "transformed_decision_rule_tuples": decisions(after),
    "expected_reference_mapping": "each original event_id maps to 'renamed-' + event_id; not checked as a population-level invariant",
    "label_basis": "same prewritten development contract with opaque identifier bijection; validated by staged M2 assessor, not live observed effects",
}))
print("E02: two staged development inputs retained; byte-identical SHA-256", pair[0]["b1"]["sha256"])
print("E13: original and renamed development inputs/outputs retained; unordered signature equal")
