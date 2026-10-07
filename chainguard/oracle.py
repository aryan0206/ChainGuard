"""Independent assessor for SYNTHETIC staged journals, not commit proof.

Deliberately imports no detector, normalizer, history projector, or B2 state.
Source observations, sink bytes, controls and reservation witnesses are inputs
specified by fixtures before comparison. M3/M6 transaction boundaries are absent.
"""

import base64
from dataclasses import dataclass
import json


STAGED = "SYNTHETIC_REPLAY_NOT_DURABLE_COMMIT_PROOF"


@dataclass(frozen=True)
class JournalRecord:
    kind: str
    event_id: str
    task_id: str
    call_id: str = ""
    body_json: str = "{}"
    evidence_class: str = STAGED

    @property
    def body(self):
        return json.loads(self.body_json)  # A fresh copy prevents shadow mutation.


def record(kind, event_id, task_id="task", call_id="", **body):
    return JournalRecord(kind, event_id, task_id, call_id,
                         json.dumps(body, sort_keys=True, separators=(",", ":")))


@dataclass(frozen=True)
class Expected:
    call_id: str
    authorization: str
    dispatch: str
    permission_consumption: str
    consumed_grants: tuple[str, ...]
    disclosure_resources: tuple[str, ...] | None
    unauthorized_disclosure: bool | None
    task_completion: str
    detector_authorizations: tuple[str, str, str]
    detector_behaviors: tuple[str, str, str]


@dataclass(frozen=True)
class Fixture:
    name: str
    journal: tuple[JournalRecord, ...]
    resources: tuple[tuple[str, str], ...]
    expected_output: str
    expectations: tuple[Expected, ...]
    destinations: tuple[str, ...] = ("sink",)


@dataclass(frozen=True)
class Observation:
    task_id: str
    call_id: str
    authorization: str
    dispatch: str
    permission_consumption: str
    consumed_grants: tuple[str, ...]
    reservation_correctness: str
    disclosure_resources: tuple[str, ...] | None
    unauthorized_disclosure: bool | None
    task_completion: str
    evidence_class: str = STAGED


def _content_resources(payload, registry):
    """Independently frozen assessor coverage: raw, base64, and hex bytes."""
    if not isinstance(payload, str):
        return None
    candidates = [payload]
    for decode in (lambda p: base64.b64decode(p, validate=True), bytes.fromhex):
        try:
            candidates.append(decode(payload).decode("utf-8"))
        except (ValueError, UnicodeError):
            pass
    return {resource for resource, canary in registry if any(canary in p for p in candidates)}


def _scope(task, body):
    if body.get("release") != "release" or not body.get("resource") or not body.get("destination"):
        raise ValueError("Invalid assessor scope")
    return task, body["resource"], body["destination"], "release"


def assess(fixture: Fixture) -> tuple[Observation, ...]:
    """Reconstruct raw observations in admission order, before each proposal."""
    tasks, controls, snapshots, effects = {}, {}, {}, {}
    seen_records = set()
    for entry in fixture.journal:
        if entry.evidence_class != STAGED:
            raise ValueError("M2 accepts explicitly synthetic witnesses only")
        if entry.event_id in seen_records:
            raise ValueError("Duplicate assessor record")
        seen_records.add(entry.event_id)
        body, task = entry.body, entry.task_id
        if entry.kind == "TASK_START":
            if task in tasks:
                raise ValueError("Task cannot reopen")
            tasks[task] = {"active": {}, "issued": set(), "exposed": set(), "unknown": False,
                           "pending": set(), "ordinal": 0, "closed": False,
                           "override": body.get("synthetic_local_sink_override", False),
                           "output": None, "completion": "UNKNOWN", "observations_complete": False}
            continue
        if task not in tasks:
            raise ValueError("Unknown assessor task")
        state = tasks[task]
        if state["closed"]:
            raise ValueError("Record after task closure")
        key = task, entry.call_id
        if entry.kind == "CONTROL_ISSUED":
            if key in controls:
                raise ValueError("Repeated issued control")
            controls[key] = {"body": body, "admitted": False, "witnessed": False}
        elif entry.kind in {"CONTROL_ADMITTED", "PROPOSAL"}:
            ordinal = body.get("admission_ordinal")
            if type(ordinal) is not int or ordinal != state["ordinal"] + 1:
                raise ValueError("Assessor admission order must be contiguous")
            state["ordinal"] = ordinal
            if entry.kind == "CONTROL_ADMITTED":
                controls[key]["admitted"] = True
                state["pending"].add(key)
            else:
                if key in snapshots:
                    raise ValueError("Duplicate assessor proposal")
                direct = _content_resources(body.get("payload", ""), fixture.resources)
                prohibited = body.get("operation") == "send" and body.get("destination") not in fixture.destinations
                supported = (body.get("operation") in {"read", "send", "transform", "echo"}
                             and direct is not None and len(body.get("payload", "").encode()) <= 65536
                             and body.get("transformation", "none") in {"none", "raw", "base64", "hex"})
                if body.get("operation") == "read" and body.get("resource") not in dict(fixture.resources) and body.get("resource") != "public":
                    supported = False
                if body.get("sensitivity") == "sensitive" and not direct and body.get("operation") == "send":
                    supported = False
                needed = sorted(state["exposed"] | (direct or set())) if body.get("operation") == "send" else []
                scopes = tuple((task, r, body.get("destination"), "release") for r in needed)
                available = dict(state["active"])
                selection = []
                for scope in scopes:
                    matching = sorted(g for g, s in available.items() if s == scope)
                    if matching:
                        selection.append(matching[0])
                uncertain = state["unknown"] or bool(state["pending"]) or not supported
                auth = "UNAUTHORIZED" if prohibited else "INDETERMINATE" if uncertain else (
                    "AUTHORIZED" if len(selection) == len(scopes) else "UNAUTHORIZED")
                snapshots[key] = {"auth": auth, "active": available, "scopes": scopes,
                                  "selection": tuple(sorted(selection)), "body": body,
                                  "prohibited": prohibited, "supported": supported, "uncertain": uncertain}
                effects[key] = {"forward": False, "arrival": False, "denied": False,
                                "consumption": "UNKNOWN", "grants": (), "reservation": "UNKNOWN", "reservation_seen": False,
                                "sinks": [], "sink_unknown": False, "source_seen": False}
        elif entry.kind == "CONTROL_WITNESS":
            control = controls[key]
            if not control["admitted"] or control["witnessed"]:
                raise ValueError("Invalid control witness phase")
            control["witnessed"] = True
            state["pending"].remove(key)
            if body.get("commit") != "confirmed":
                state["unknown"] |= body.get("commit") != "failed"
                continue
            command = control["body"]
            scope = _scope(task, command)
            if command["control"] == "grant":
                grant_id = command["grant_id"]
                if grant_id in state["issued"]:
                    raise ValueError("Assessor grant replay")
                state["issued"].add(grant_id)
                state["active"][grant_id] = scope
            elif command["control"] == "revoke":
                state["active"] = {g: s for g, s in state["active"].items() if s != scope}
            else:
                raise ValueError("Unknown control")
        elif entry.kind == "RESERVATION_WITNESS":
            effect, snapshot = effects[key], snapshots[key]
            if effect["reservation_seen"]:
                raise ValueError("Duplicate reservation witness")
            effect["reservation_seen"] = True
            if body.get("commit") != "confirmed":
                effect["reservation"] = "UNKNOWN" if body.get("commit") != "failed" else "FAILED"
                effect["consumption"] = "UNKNOWN" if effect["reservation"] == "UNKNOWN" else "NONE"
                state["unknown"] |= effect["reservation"] == "UNKNOWN"
                continue
            entries = body["selected_grants"]
            selected = tuple(e["grant_id"] for e in entries)
            scopes = tuple(_scope(task, s) for s in body["required_scopes"])
            status = body["reservation_status"]
            valid = (len(set(selected)) == len(selected) and selected == tuple(sorted(selected))
                     and scopes == tuple(sorted(set(scopes))) and scopes == snapshot["scopes"])
            valid &= all(snapshot["active"].get(e["grant_id"]) == _scope(task, e) for e in entries)
            if status == "AUTHORIZED":
                valid &= (bool(scopes) and snapshot["auth"] == "AUTHORIZED"
                          and selected == snapshot["selection"])
            elif status == "NO_RELEASE_OBLIGATION":
                valid &= not scopes and not selected and snapshot["auth"] == "AUTHORIZED"
            elif status == "OBSERVATION_OVERRIDE":
                valid &= (bool(scopes) and not selected and state["override"] is True
                          and snapshot["body"].get("destination") == "sink"
                          and snapshot["supported"] and not snapshot["prohibited"]
                          and snapshot["auth"] == "UNAUTHORIZED")
            else:
                valid = False
            effect["reservation"] = "VALID" if valid else "INVALID"
            effect["consumption"] = "CONFIRMED" if selected else "NONE"
            effect["grants"] = selected
            if valid:
                for grant_id in selected:
                    del state["active"][grant_id]
            else:
                state["unknown"] = True
        elif entry.kind == "DENIED":
            effects[key]["denied"] = True
            if not effects[key]["reservation_seen"]:
                effects[key]["consumption"] = "NONE"
                effects[key]["reservation"] = "NOT_APPLICABLE"
        elif entry.kind == "FORWARD":
            effects[key]["forward"] = True
        elif entry.kind == "ARRIVAL":
            effects[key]["arrival"] = True
        elif entry.kind == "SOURCE":
            effects[key]["source_seen"] = True
            if body.get("status") == "succeeded" and body.get("resource") in dict(fixture.resources):
                if body.get("payload") != dict(fixture.resources)[body["resource"]]:
                    state["unknown"] = True
                else:
                    state["exposed"].add(body["resource"])
            elif body.get("status") != "succeeded" and body.get("payload"):
                state["unknown"] = True
        elif entry.kind == "SINK":
            if body.get("destination") != snapshots[key]["body"].get("destination"):
                effects[key]["sink_unknown"] = True
            else:
                delivered = _content_resources(body.get("payload"), fixture.resources)
                if delivered is None:
                    effects[key]["sink_unknown"] = True
                else:
                    effects[key]["sinks"].extend(delivered)
        elif entry.kind == "TASK_OUTPUT":
            state["output"] = body.get("value")
        elif entry.kind == "TASK_END":
            state["closed"] = True
            state["observations_complete"] = body.get("observations_complete") is True
            state["completion"] = "COMPLETE" if state["output"] == fixture.expected_output else "INCOMPLETE"
        elif entry.kind == "TOOL_OUTCOME":
            if body.get("status") == "unknown":
                state["unknown"] = True
            proposal = snapshots[key]["body"]
            if (proposal.get("operation") == "read" and proposal.get("resource") in dict(fixture.resources)
                    and effects[key]["forward"] and not effects[key]["source_seen"]):
                state["unknown"] = True  # A monitor result alone is not an independent source witness.
        elif entry.kind == "RESTART":
            state["unknown"] = True
            state["active"].clear()
        elif entry.kind != "RECONNECT":
            raise ValueError(f"Unknown assessor observation: {entry.kind}")
    reports = []
    for (task, call), snapshot in snapshots.items():
        effect = effects[(task, call)]
        dispatch = "CONFIRMED" if effect["forward"] and effect["arrival"] else (
            "ATTEMPTED" if effect["forward"] else "NOT_DISPATCHED" if effect["denied"] else "UNKNOWN")
        known_absence = effect["denied"] or tasks[task]["observations_complete"]
        resources = None if effect["sink_unknown"] or (not effect["sinks"] and not known_absence) else tuple(sorted(set(effect["sinks"])))
        unauthorized = None if resources is None or (resources and snapshot["uncertain"] and not snapshot["prohibited"]) else any(
            snapshot["prohibited"] or not any(s == (task, r, snapshot["body"].get("destination"), "release")
                                              for s in snapshot["active"].values()) for r in resources)
        reports.append(Observation(task, call, snapshot["auth"], dispatch, effect["consumption"],
                                   effect["grants"], effect["reservation"], resources, unauthorized,
                                   tasks[task]["completion"]))
    return tuple(reports)
