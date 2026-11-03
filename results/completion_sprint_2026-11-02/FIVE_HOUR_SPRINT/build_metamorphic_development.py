"""Construct new E01/E13 DEVELOPMENT pairs; never score as research."""

from dataclasses import asdict
import hashlib
import json
import os
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
SUFFIX = "_revision" if os.environ.get("CHAINGUARD_META_RETRY") == "1" else ""
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from workflow_fixtures import Author, CANARY_A, CANARY_B  # noqa: E402
from chainguard.m2 import run_fixture  # noqa: E402
from chainguard.oracle import Fixture  # noqa: E402
from chainguard.workflows import validate_contract  # noqa: E402


def raw(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode()


def save(name, data):
    path = HERE / (Path(name).stem + SUFFIX + Path(name).suffix)
    with path.open("xb") as stream:
        stream.write(data)
    return {"path": path.name, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def e01(public_first, name):
    t = Author(name, "S1")
    if public_first:
        t.call("public-read", "read", authorization="AUTHORIZED", resource="public")
        t.call("public-echo", "echo", authorization="AUTHORIZED", payload="neutral")
    else:
        t.call("public-echo", "echo", authorization="AUTHORIZED", payload="neutral")
        t.call("public-read", "read", authorization="AUTHORIZED", resource="public")
    t.call("release", "send", authorization="AUTHORIZED", payload="public output")
    return t.finish()


def e13_gap(include_gap, name):
    t = Author(name, "S3")
    t.call("sensitive-read", "read", authorization="AUTHORIZED", resource="secret-a")
    t.control("grant", "grant-a")
    if include_gap:
        t.call("neutral-gap", "echo", authorization="AUTHORIZED", payload="neutral")
    t.call("release", "send", authorization="AUTHORIZED", payload=CANARY_A,
           required=("secret-a",), selected=(("grant-a", "secret-a"),), disclosure=("secret-a",))
    return t.finish()


def e13_interleave(reverse_grants, name):
    t = Author(name, "S6")
    t.call("read-a", "read", authorization="AUTHORIZED", resource="secret-a")
    t.call("read-b", "read", authorization="AUTHORIZED", resource="secret-b")
    order = (("grant-b", "secret-b"), ("grant-a", "secret-a")) if reverse_grants else (
        ("grant-a", "secret-a"), ("grant-b", "secret-b"))
    for grant, resource in order:
        t.control("grant", grant, resource=resource)
    t.call("release", "send", authorization="AUTHORIZED", payload=CANARY_A + " " + CANARY_B,
           required=("secret-a", "secret-b"),
           selected=(("grant-a", "secret-a"), ("grant-b", "secret-b")),
           disclosure=("secret-a", "secret-b"))
    return t.finish()


def capture(case_id, contract):
    validate_contract(contract)
    fixture = Fixture(contract.workflow_id, contract.journal, contract.resources,
                      contract.expected_output, ())
    replay = run_fixture(fixture)
    release = next(row for row in replay["rows"] if row["call_id"] == "release")
    return {
        "case_id": case_id,
        "workflow_id": contract.workflow_id,
        "parent_class": "DEVELOPMENT_ONLY",
        "input": save(f"{case_id}.input.json", raw(asdict(contract))),
        "release_b1": save(f"{case_id}.release.b1.bin", release["b1_input"]),
        "output": save(f"{case_id}.output.json", raw({
            "rows": [{"call_id": row["call_id"],
                      "findings": [asdict(f) for f in row["findings"]]} for row in replay["rows"]],
            "staged_oracle": [asdict(o) for o in replay["oracle"]],
            "evidence_class": replay["evidence_class"],
        })),
        "release_findings": {f.detector_id: {"authorization": f.authorization,
                                             "behavior": f.behavior, "rule_id": f.rule_id,
                                             "supporting_event_ids": f.supporting_event_ids}
                             for f in release["findings"]},
        "release_staged_oracle": next(asdict(o) for o in replay["oracle"] if o.call_id == "release"),
    }


def main():
    pairs = []
    for name, left, right, expected_equal_b1 in (
        ("E01_benign_reordering", e01(True, "fiveh-e01-public-read-echo"),
         e01(False, "fiveh-e01-public-echo-read"), True),
        ("E13_harmless_gap", e13_gap(False, "fiveh-e13-gap-base"),
         e13_gap(True, "fiveh-e13-gap-added"), False),
        ("E13_valid_scope_interleaving", e13_interleave(False, "fiveh-e13-scope-ab"),
         e13_interleave(True, "fiveh-e13-scope-ba"), True),
    ):
        a = capture(name + "-A", left)
        b = capture(name + "-B", right)
        b1_equal = a["release_b1"]["sha256"] == b["release_b1"]["sha256"]
        verdicts_equal = all(
            tuple(a["release_findings"][d][k] for k in ("authorization", "behavior", "rule_id")) ==
            tuple(b["release_findings"][d][k] for k in ("authorization", "behavior", "rule_id"))
            for d in ("B0", "B1", "B2-R", "B2-S")
        )
        labels_equal = a["release_staged_oracle"]["authorization"] == b["release_staged_oracle"]["authorization"]
        pairs.append({"pair_id": name, "left": a, "right": b,
                      "expected_b1_equal": expected_equal_b1, "actual_b1_equal": b1_equal,
                      "release_verdict_rule_equal": verdicts_equal,
                      "staged_oracle_label_equal": labels_equal,
                      "qualified_research_observation": False,
                      "missing": "independent live commit/effect witnesses, frozen research parent/split and reference-bijection review"})
    save("metamorphic_development_pairs.json", raw({
        "classification": "DEVELOPMENT_STAGED_ONLY",
        "research_observations": 0,
        "pairs": pairs,
    }))
    print("development_pairs=3 research_observations=0")
    return 0 if all(p["actual_b1_equal"] == p["expected_b1_equal"] and p["release_verdict_rule_equal"] and
                    p["staged_oracle_label_equal"] for p in pairs) else 1


if __name__ == "__main__":
    raise SystemExit(main())
