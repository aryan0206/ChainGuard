"""Synthetic transcript replay. No tools execute and no durable commits occur."""

from dataclasses import asdict, replace
from pathlib import Path
import runpy

from chainguard.detectors import B2Reference, B2Streaming, b0, b1, equivalent
from chainguard.oracle import assess
from chainguard.semantics import (B0_OPERATING_POINT, EVIDENCE_CLASS, EXTRACTION_VERSION,
                                 Fact, Policy, Scope, attach_references, b1_input_bytes,
                                 canonical, extract_current, project_b1)


class ReplayLedger:
    """Trusted fixture admission/projection boundary, independent of shadows.

    This validates staged witnesses only. It is NOT a live permission manager,
    audit writer, transaction observer, or replacement for M3/M6 persistence.
    """

    def __init__(self, policy):
        self.policy = policy
        self.tasks = {}
        self.events = set()

    def scope(self, task, body):
        return Scope(task, body["resource"], body["destination"], body["release"])

    def accept(self, entry):
        if entry.evidence_class != EVIDENCE_CLASS or entry.event_id in self.events:
            raise ValueError("Non-staged or duplicate journal entry")
        self.events.add(entry.event_id)
        body, task = entry.body, entry.task_id
        if entry.kind == "TASK_START":
            if task in self.tasks:
                raise ValueError("Cannot reopen a context")
            self.tasks[task] = {"lifecycle": "ACTIVE", "halted": False, "ordinal": 0,
                                "controls": {}, "history": [], "active": {}, "issued": set(),
                                "pending": None, "calls": set(), "turn": None,
                                "override": body.get("synthetic_local_sink_override", False)}
            return ()
        if task not in self.tasks or self.tasks[task]["lifecycle"] != "ACTIVE":
            raise ValueError("Unknown/closed context")
        state = self.tasks[task]
        generated = []
        if entry.kind in {"CONTROL_ADMITTED", "PROPOSAL"}:
            if state["halted"] or state["pending"] or state["turn"]:
                raise ValueError("Task turn is unresolved or incomplete")
            if type(body.get("admission_ordinal")) is not int or body["admission_ordinal"] != state["ordinal"] + 1:
                raise ValueError("Admission order must be contiguous")
            state["ordinal"] += 1
        if entry.kind == "CONTROL_ISSUED":
            if entry.call_id in state["controls"]:
                raise ValueError("Repeated control identity")
            state["controls"][entry.call_id] = {"body": body, "admitted": False, "done": False}
        elif entry.kind == "CONTROL_ADMITTED":
            control = state["controls"][entry.call_id]
            if control["admitted"]:
                raise ValueError("Repeated control admission")
            control["admitted"] = True
            state["pending"] = entry.call_id
        elif entry.kind == "CONTROL_WITNESS":
            control = state["controls"][entry.call_id]
            if state["pending"] != entry.call_id or control["done"]:
                raise ValueError("Invalid control witness phase")
            control["done"] = True
            state["pending"] = None
            if body.get("commit") != "confirmed":
                state["halted"] = True
                return ()
            command = control["body"]
            scope = self.scope(task, command)
            if command["control"] == "grant":
                grant_id = command["grant_id"]
                if not grant_id or grant_id in state["issued"]:
                    raise ValueError("Grant IDs are unique opaque values")
                state["issued"].add(grant_id)
                state["active"][grant_id] = scope
                generated.append(Fact("GRANT", entry.event_id, scope=scope, grant_id=grant_id))
            elif command["control"] == "revoke":
                state["active"] = {g: s for g, s in state["active"].items() if s != scope}
                generated.append(Fact("REVOKE_SCOPE", entry.event_id, scope=scope))
            else:
                raise ValueError("Unknown fixture control")
        elif entry.kind == "PROPOSAL":
            if not entry.call_id or entry.call_id in state["calls"]:
                raise ValueError("Repeated call attempt")
            state["calls"].add(entry.call_id)
            state["turn"] = {"call": entry.call_id, "current": extract_current(body, self.policy),
                             "reservation": False, "intent_seen": False, "forward": False, "arrival": False,
                             "denied": False, "source": False, "sink": False}
        elif entry.kind in {"RESERVATION_WITNESS", "FORWARD", "ARRIVAL", "DENIED", "SOURCE", "SINK", "TOOL_OUTCOME"}:
            turn = state["turn"]
            if turn is None or turn["call"] != entry.call_id:
                raise ValueError("Uncorrelated call phase")
            if entry.kind == "RESERVATION_WITNESS":
                if turn["intent_seen"] or turn["denied"] or turn["forward"]:
                    raise ValueError("Repeated or late intent")
                turn["intent_seen"] = True
                turn["reservation"] = True
                if body.get("commit") != "confirmed":
                    state["halted"] = True
                    turn["reservation"] = False
                    return ()
                current = turn["current"]
                exposed = {f.resource for f in state["history"] if f.category == "TOOL_OUTCOME"
                           and f.operation == "read" and f.outcome == "succeeded" and f.sensitivity == "sensitive"}
                resources = exposed | set(current.sensitive_resources) if current.operation == "send" else set()
                expected = tuple(Scope(task, r, current.destination) for r in sorted(resources))
                required = tuple(self.scope(task, s) for s in body["required_scopes"])
                selected = body["selected_grants"]
                ids = tuple(s["grant_id"] for s in selected)
                if required != expected or ids != tuple(sorted(set(ids))):
                    raise ValueError("Incomplete, duplicate or unsorted reservation")
                if not current.supported or current.static_prohibition:
                    raise ValueError("Unsupported/static-prohibited proposal cannot dispatch")
                chosen = []
                for scope in expected:
                    matching = sorted(g for g, s in state["active"].items() if s == scope)
                    if matching:
                        chosen.append(matching[0])
                status = body["reservation_status"]
                if status == "AUTHORIZED":
                    if not expected or len(chosen) != len(expected) or ids != tuple(sorted(chosen)):
                        raise ValueError("Reservation must cover all scopes with deterministic selection")
                elif status == "NO_RELEASE_OBLIGATION":
                    if expected or selected:
                        raise ValueError("No-obligation intent must be empty")
                elif status == "OBSERVATION_OVERRIDE":
                    if (state["override"] is not True or not expected or selected
                            or current.destination != "sink" or len(chosen) == len(expected)):
                        raise ValueError("Invalid synthetic override transcript")
                else:
                    raise ValueError("Invalid reservation status")
                for selection in selected:
                    scope = self.scope(task, selection)
                    if state["active"].get(selection["grant_id"]) != scope:
                        raise ValueError("Mismatched grant scope")
                    generated.append(Fact("USE", entry.event_id, scope=scope, grant_id=selection["grant_id"]))
                for grant_id in ids:
                    del state["active"][grant_id]
            elif entry.kind == "FORWARD":
                if state["halted"] or not turn["reservation"] or turn["forward"] or turn["denied"]:
                    raise ValueError("Forward without valid staged reservation")
                turn["forward"] = True
            elif entry.kind == "ARRIVAL":
                if not turn["forward"] or turn["arrival"]:
                    raise ValueError("Invalid handler arrival")
                turn["arrival"] = True
            elif entry.kind == "DENIED":
                if turn["reservation"] or turn["forward"] or turn["denied"]:
                    raise ValueError("Invalid denial")
                turn["denied"] = True
            elif entry.kind in {"SOURCE", "SINK"}:
                phase = entry.kind.lower()
                expected_operation = "read" if phase == "source" else "send"
                if not turn["arrival"] or turn[phase] or turn["current"].operation != expected_operation:
                    raise ValueError("Invalid independent handler observation")
                turn[phase] = True
            else:
                status = body.get("status")
                if status not in {"succeeded", "failed", "denied", "unknown"}:
                    raise ValueError("Unsupported terminal outcome")
                if (status == "denied") != turn["denied"]:
                    raise ValueError("Denied outcome phase mismatch")
                if status in {"succeeded", "failed"} and not turn["arrival"]:
                    raise ValueError("Terminal outcome without handler arrival")
                current = turn["current"]
                if (body.get("operation"), body.get("resource", ""), body.get("destination", "")) != (
                        current.operation, current.resource, current.destination):
                    raise ValueError("Outcome/current identity mismatch")
                if current.operation == "read" and status != "succeeded" and body.get("payload"):
                    raise ValueError("Partial sensitive acquisition is unsupported")
                if current.operation == "read" and status == "succeeded" and current.sensitivity == "sensitive":
                    if body.get("payload") != dict(self.policy.resources)[current.resource]:
                        raise ValueError("Ambiguous sensitive acquisition")
                generated.append(Fact("TOOL_OUTCOME", entry.event_id, current.operation, current.resource,
                                      current.destination, status, current.sensitivity, current.transformation))
                state["turn"] = None
                state["halted"] |= status == "unknown"
        elif entry.kind == "TASK_END":
            if state["turn"] or state["pending"]:
                raise ValueError("Cannot close an unresolved turn")
            state["lifecycle"] = "CLOSED"
        elif entry.kind == "RECONNECT":
            if state["halted"] or state["turn"] or state["pending"]:
                raise ValueError("Reconnect cannot repair unknown state")
        elif entry.kind == "RESTART":
            state["halted"] = True
            state["active"].clear()
        elif entry.kind != "TASK_OUTPUT":
            raise ValueError("Nonsemantic/unrecognized journal record")
        state["history"].extend(generated)
        return tuple(generated)


def run_fixture(fixture, finding_transform=None):
    policy = Policy(fixture.resources, fixture.destinations)
    ledger, streaming, rows = ReplayLedger(policy), {}, []
    for entry in fixture.journal:
        facts = ledger.accept(entry)
        if entry.kind == "TASK_START":
            streaming[entry.task_id] = B2Streaming(entry.task_id, policy)
        for fact in facts:
            streaming[entry.task_id].observe(fact)
        if entry.kind == "PROPOSAL":
            current = extract_current(entry.body, policy)
            history = tuple(ledger.tasks[entry.task_id]["history"])
            counts = project_b1(history, entry.task_id)
            zero = replace(b0(current, policy), supporting_event_ids=(entry.event_id,))
            one = attach_references(b1(current, counts, policy), entry.event_id, current, history)
            reference = B2Reference(entry.task_id, policy).evaluate(current, history, entry.event_id)
            incremental = streaming[entry.task_id].evaluate(current, entry.event_id)
            if not equivalent(reference, incremental):
                raise AssertionError(f"B2-R/B2-S disagreement at {fixture.name}/{entry.call_id}")
            findings = (zero, one, reference, incremental)
            if finding_transform:
                findings = tuple(finding_transform(f) for f in findings)
            rows.append({"task_id": entry.task_id, "call_id": entry.call_id,
                         "findings": findings, "b1_input": b1_input_bytes(current, counts),
                         "history": history})
    # Neither findings nor ledger state is an oracle input.
    observations = assess(fixture)
    return {"fixture": fixture.name, "rows": rows, "oracle": observations,
            "evidence_class": EVIDENCE_CLASS}


def verify_expectations(fixture, result):
    by_call = {(o.task_id, o.call_id): o for o in result["oracle"]}
    if len(fixture.expectations) != len(result["rows"]):
        raise AssertionError("Every evaluated proposal needs a prewritten expectation")
    for row, expected in zip(result["rows"], fixture.expectations, strict=True):
        if row["call_id"] != expected.call_id:
            raise AssertionError("Expectation order does not match admitted proposals")
        observation = by_call[(row["task_id"], row["call_id"])]
        for field in ("authorization", "dispatch", "permission_consumption", "consumed_grants",
                      "disclosure_resources", "unauthorized_disclosure", "task_completion"):
            if getattr(observation, field) != getattr(expected, field):
                raise AssertionError(f"{fixture.name}/{expected.call_id}: {field}: {getattr(observation, field)!r} != {getattr(expected, field)!r}")
        if observation.reservation_correctness not in {"VALID", "NOT_APPLICABLE", "UNKNOWN", "FAILED"}:
            raise AssertionError("Invalid staged reservation")
        comparable = row["findings"][:2] + (row["findings"][3],)
        if tuple(f.authorization for f in comparable) != expected.detector_authorizations:
            raise AssertionError(f"{fixture.name}/{expected.call_id}: detector authorization mismatch")
        if tuple(f.behavior for f in comparable) != expected.detector_behaviors:
            raise AssertionError(f"{fixture.name}/{expected.call_id}: detector behavior mismatch")


def load_fixtures():
    path = Path(__file__).resolve().parent.parent / "tests" / "m2_fixtures.py"
    return runpy.run_path(str(path))["FIXTURES"]


def experiment(fixtures):
    if len({Policy(f.resources, f.destinations).digest for f in fixtures}) != 1:
        raise ValueError("A representation comparison requires one frozen static policy")
    results = [run_fixture(f) for f in fixtures]
    for fixture, result in zip(fixtures, results, strict=True):
        verify_expectations(fixture, result)
    groups = {}
    for result in results:
        for row, oracle in zip(result["rows"], result["oracle"], strict=True):
            group = groups.setdefault(row["b1_input"], {"AUTHORIZED": 0, "UNAUTHORIZED": 0, "INDETERMINATE": 0})
            group[oracle.authorization] += 1
    mixed = [g for g in groups.values() if g["AUTHORIZED"] and g["UNAUTHORIZED"]]
    return {"evidence_class": EVIDENCE_CLASS, "execution": "REPLAY_ONLY_NO_TOOL_EXECUTION",
            "b0_operating_point": B0_OPERATING_POINT, "extraction_version": EXTRACTION_VERSION,
            "fixture_count": len(results), "valid_proposal_prefixes": sum(len(r["rows"]) for r in results),
            "b2_equivalence": "PASS_AT_EVERY_VALID_PROPOSAL_PREFIX",
            "mixed_b1_input_groups": len(mixed),
            "observed_minimum_binary_errors": sum(min(g["AUTHORIZED"], g["UNAUTHORIZED"]) for g in mixed),
            "oracle_indeterminate_count": sum(g["INDETERMINATE"] for g in groups.values()),
            "fixtures": [{"name": r["fixture"], "proposals": [
                {"call_id": row["call_id"], "detectors": [asdict(f) for f in row["findings"]],
                 "oracle": asdict(o)} for row, o in zip(r["rows"], r["oracle"], strict=True)]} for r in results]}


def main():
    print(canonical(experiment(load_fixtures())))


if __name__ == "__main__":
    main()
