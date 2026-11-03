"""Pinned R02 reference-rule/label-tracker differential conformance; no E08 outcome."""

from datetime import datetime
import hashlib
import json
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
REF = HERE / "e08_reference" / "prototype"
PROVENANCE = HERE / "e08_reference_provenance.json"
CASES = HERE / "e08_conformance_cases.json"
OUT = HERE / "e08_conformance_results.json"


def require(value, message):
    if not value:
        raise ValueError(message)


def load_reference():
    provenance = json.loads(PROVENANCE.read_text(encoding="utf-8"))
    require(provenance["all_exact"] is True, "Reference provenance did not pass")
    require(provenance["approved_commit"] == "3dd9690b5b6f9c4ef385289714b314d13f6ad9a1", "Reference pin")
    for row in provenance["rows"]:
        path = HERE / "e08_reference" / row["path"]
        require(hashlib.sha256(path.read_bytes()).hexdigest() == row["sha256"], "Reference bytes changed")
    sys.path.insert(0, str(REF))
    from datatypes import DS, SI, LabeledData  # noqa: E402
    from pep.label_tracker import LabelTracker  # noqa: E402
    from pep.rules import RuleEngine  # noqa: E402
    return DS, SI, LabeledData, LabelTracker, RuleEngine


def reference_steps(case, types):
    DS, SI, LabeledData, LabelTracker, RuleEngine = types
    tracker = LabelTracker()
    state = tracker.init_trace(session_id=case["case_id"], trace_id=case["case_id"])
    rules = RuleEngine()
    outputs = []
    for step in case["steps"]:
        if step["kind"] == "reconnect":
            outputs.append({"post_ds": tracker.get_state(case["case_id"]).current_ds})
            continue
        effective = DS.merge(state.current_ds, step["arg_ds"])
        decision = rules.evaluate(step["tool"], SI.MED, effective, {}, state)
        if decision.action == "ALLOW" and step["result_status"] == "succeeded":
            tracker.update_after_tool_return(case["case_id"], LabeledData(
                value="common-fact-result", si=SI.MED, ds=step["result_ds"],
                source_tool=step["tool"], trace_id=case["case_id"]))
        elif decision.action == "DENY":
            tracker.advance_step(case["case_id"])
        outputs.append({"decision": decision.action, "rule": decision.matched_rule,
                        "effective_ds": effective, "post_ds": state.current_ds})
    return outputs


def adapter_steps(case):
    """Independent declared R02 subset adaptation over supplied common facts."""
    accumulated = "DS:NORMAL"
    outputs = []
    for step in case["steps"]:
        if step["kind"] == "reconnect":
            outputs.append({"post_ds": accumulated})
            continue
        effective = "DS:SENSITIVE" if "DS:SENSITIVE" in (accumulated, step["arg_ds"]) else "DS:NORMAL"
        outbound = step["tool"] == "http_post.post"
        action = "DENY" if outbound and effective == "DS:SENSITIVE" else "ALLOW"
        rule = "R02" if action == "DENY" else None
        if action == "ALLOW" and step["result_status"] == "succeeded" and step["result_ds"] == "DS:SENSITIVE":
            accumulated = "DS:SENSITIVE"
        outputs.append({"decision": action, "rule": rule,
                        "effective_ds": effective, "post_ds": accumulated})
    return outputs


def main():
    if OUT.exists():
        raise FileExistsError(OUT)
    types = load_reference()
    raw = CASES.read_bytes()
    ledger = json.loads(raw)
    require(ledger["schema"] == "chainguard-e08-r02-conformance-cases-v1", "Case schema")
    require(ledger["reference_commit"] == "3dd9690b5b6f9c4ef385289714b314d13f6ad9a1", "Case pin")
    results = []
    seen = set()
    for case in ledger["cases"]:
        require(case["case_id"] not in seen and case["steps"], "Unique nonempty cases")
        seen.add(case["case_id"])
        for step in case["steps"]:
            if step["kind"] == "proposal":
                require(step["tool"] in {"http_post.post", "filesystem.read_file", "transform.neutral"}, "Common-domain tool")
                require(step["arg_ds"] in {"DS:NORMAL", "DS:SENSITIVE"}, "Common-domain arg label")
                require(step["result_status"] in {"none", "succeeded", "failed", "denied"}, "Result status")
                if step["tool"] == "http_post.post":
                    require(step.get("destination") in {"sink", "other-sink"}, "Destination mapping")
                if step["result_status"] == "succeeded":
                    require(step.get("result_ds") in {"DS:NORMAL", "DS:SENSITIVE"}, "Result sensitivity")
            else:
                require(step["kind"] == "reconnect", "Unknown step")
        reference = reference_steps(case, types)
        adapter = adapter_steps(case)
        expected = [s["expected"] for s in case["steps"]]
        pass_case = reference == adapter == expected
        results.append({"case_id": case["case_id"], "reference": reference,
                        "adapter": adapter, "predeclared_expected": expected,
                        "passed": pass_case})
    report = {"schema": "chainguard-e08-r02-conformance-v1",
              "classification": "REFERENCE_SUBSET_CONFORMANCE_ONLY; NOT E08 COMPARATIVE RESEARCH",
              "reference_commit": ledger["reference_commit"],
              "reference_source": ["prototype/datatypes.py", "prototype/pep/label_tracker.py", "prototype/pep/rules.py"],
              "enforcer_source_retained_but_not_executed": True,
              "input_sha256": hashlib.sha256(raw).hexdigest(),
              "reference_provenance_sha256": hashlib.sha256(PROVENANCE.read_bytes()).hexdigest(),
              "ended_local": datetime.now().astimezone().isoformat(),
              "case_count": len(results), "pass_count": sum(r["passed"] for r in results),
              "all_pass": all(r["passed"] for r in results), "cases": results,
              "limitations": ["Common sensitivity facts supplied, not extracted by either system",
                              "R02 rule/label tracker subset only; full enforcer, token, rate, path, intent, logger and tool execution excluded",
                              "Conformance does not establish independent workflow-oracle correctness or E08 performance"]}
    OUT.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"conformance={report['pass_count']}/{report['case_count']}")
    return 0 if report["all_pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
