"""Development workflow contracts and independent observation qualification.

No execution, controller, detector or live permission implementation. The old
M2 assessor is reused ONLY for explicitly staged contract/observation journals.
Environment receipts are separate inputs, never manufactured from the plan.
"""

from collections import Counter
from dataclasses import dataclass
import json

from chainguard.oracle import Fixture, JournalRecord, STAGED, assess, _content_resources


AUTHORIZATION = {"AUTHORIZED", "UNAUTHORIZED", "INDETERMINATE"}
DISPATCH = {"CONFIRMED", "ATTEMPTED", "NOT_DISPATCHED", "UNKNOWN"}
CONSUMPTION = {"CONFIRMED", "NONE", "UNKNOWN"}
CHECK = {"PASS", "FAIL", "INCOMPLETE", "NOT_CHECKED"}
KINDS = {"TASK_START", "CONTROL_ISSUED", "CONTROL_ADMITTED", "CONTROL_WITNESS",
         "PROPOSAL", "RESERVATION_WITNESS", "DENIED", "FORWARD", "ARRIVAL",
         "SOURCE", "SINK", "TASK_OUTPUT", "TASK_END", "TOOL_OUTCOME", "RECONNECT", "RESTART"}
BODY_KEYS = {
    "TASK_START": {"synthetic_local_sink_override"},
    "CONTROL_ISSUED": {"control", "grant_id", "resource", "destination", "release"},
    "CONTROL_ADMITTED": {"admission_ordinal"}, "CONTROL_WITNESS": {"commit"},
    "PROPOSAL": {"operation", "resource", "payload", "destination", "transformation", "admission_ordinal", "sensitivity"},
    "RESERVATION_WITNESS": {"commit", "reservation_status", "required_scopes", "selected_grants"},
    "DENIED": set(), "FORWARD": set(), "ARRIVAL": set(),
    "SOURCE": {"resource", "status", "payload"}, "SINK": {"destination", "payload"},
    "TASK_OUTPUT": {"value"}, "TASK_END": {"observations_complete"},
    "TOOL_OUTCOME": {"operation", "resource", "destination", "transformation", "status", "payload"},
    "RECONNECT": set(), "RESTART": set(),
}


@dataclass(frozen=True)
class CallExpectation:
    """Authored before detector execution; contains no detector expectation."""

    call_id: str
    authorization: str
    dispatch: str
    permission_consumption: str
    consumed_grants: tuple[str, ...]
    disclosure_resources: tuple[str, ...] | None
    unauthorized_disclosure: bool | None
    handler_arrival: str
    result_status: str


@dataclass(frozen=True)
class WorkflowContract:
    workflow_id: str
    task_id: str
    stratum: str
    journal: tuple[JournalRecord, ...]
    resources: tuple[tuple[str, str], ...]
    expected_output: str
    expected_completion: str
    failure_behavior: str
    calls: tuple[CallExpectation, ...]
    destinations: tuple[str, ...] = ("sink",)
    split: str = "development"


@dataclass(frozen=True)
class CallObservation:
    """Independently supplied receipts; defaults mean missing evidence.

    Empty sink_receipts means explicitly observed empty capture coverage;
    None means capture unavailable. No DENIED/controller flag is accepted.
    Selected IDs require an independent reservation-commit witness.
    """

    call_id: str
    forwarding: str = "UNKNOWN"
    handler_arrival: str = "UNKNOWN"
    result_status: str = "unknown"
    returned_bytes: bytes | None = None
    sink_receipts: tuple[tuple[str, bytes], ...] | None = None
    permission_consumption: str = "UNKNOWN"
    consumed_grants: tuple[str, ...] = ()
    audit_persistence: str = "NOT_CHECKED"


@dataclass(frozen=True)
class EnvironmentObservations:
    workflow_id: str
    task_id: str
    provenance: str
    calls: tuple[CallObservation, ...] = ()
    task_output: str | None = None
    task_observation_complete: bool = False
    audit_closure: str = "NOT_CHECKED"
    # Optional independently retained M2-style replay journal, NOT live proof.
    staged_journal: tuple[JournalRecord, ...] | None = None


@dataclass(frozen=True)
class OutcomeAxes:
    # Detector-relative comparisons belong downstream, not in truth inference.
    authorization_correctness: str = "NOT_CHECKED"
    decision_coverage: str = "NOT_CHECKED"
    unnecessary_denial: str = "NOT_CHECKED"
    unauthorized_disclosure: bool | None = None
    legitimate_task_completion: str = "UNKNOWN"


@dataclass(frozen=True)
class QualifiedCall:
    expected: CallExpectation
    observation: CallObservation
    authorization: str
    dispatch: str
    disclosure_resources: tuple[str, ...] | None
    consumption_matches_contract: str
    axes: OutcomeAxes
    authorization_evidence_class: str = "NOT_CHECKED"


@dataclass(frozen=True)
class Qualification:
    workflow_id: str
    task_id: str
    calls: tuple[QualifiedCall, ...]
    audit_closure: str
    provenance: str


def _fixture(contract, journal=None):
    return Fixture(contract.workflow_id, contract.journal if journal is None else journal,
                   contract.resources, contract.expected_output, (), contract.destinations)


def _validate_journal(contract, journal):
    if not isinstance(journal, tuple) or not journal:
        raise ValueError("A nonempty immutable staged journal is required")
    for entry in journal:
        if not isinstance(entry, JournalRecord) or entry.evidence_class != STAGED:
            raise ValueError("Only explicitly staged journals are supported here")
        if entry.task_id != contract.task_id or not entry.event_id or entry.kind not in KINDS:
            raise ValueError("Invalid journal identity or kind")
        body = entry.body
        if not isinstance(body, dict) or set(body) - BODY_KEYS[entry.kind]:
            raise ValueError("Unrecognized journal input (findings/decisions are forbidden)")
        if set(body) != BODY_KEYS[entry.kind]:
            raise ValueError("Missing journal fields")
        if entry.kind in {"TASK_START", "TASK_END"} and any(type(v) is not bool for v in body.values()):
            raise ValueError("Coverage/override flags must be explicit booleans")
        if entry.kind in {"CONTROL_ISSUED", "PROPOSAL", "SOURCE", "SINK", "TOOL_OUTCOME"}:
            if any(not isinstance(v, str) for v in body.values() if v is not None and type(v) is not int):
                raise ValueError("Malformed raw observation")
        if "commit" in body and body["commit"] not in {"confirmed", "failed", "unknown"}:
            raise ValueError("Invalid commit witness")
        if "status" in body and body["status"] not in {"succeeded", "failed", "denied", "unknown"}:
            raise ValueError("Invalid result status")
    if journal[0].kind != "TASK_START" or journal[-1].kind != "TASK_END":
        raise ValueError("Development journals need explicit start/end")


def validate_contract(contract):
    """Reject bad structure and golden-label mismatches without detectors."""
    if (not isinstance(contract, WorkflowContract) or not isinstance(contract.calls, tuple)
            or not all(isinstance(c, CallExpectation) for c in contract.calls)):
        raise ValueError("Expected immutable workflow and call contracts")
    if (not contract.workflow_id or not contract.task_id or contract.stratum not in {f"S{i}" for i in range(1, 7)}
            or contract.split != "development" or not contract.expected_output or not contract.failure_behavior
            or contract.expected_completion not in {"COMPLETE", "INCOMPLETE", "UNKNOWN"}):
        raise ValueError("Invalid workflow metadata")
    if (not contract.resources or len(dict(contract.resources)) != len(contract.resources)
            or any(not r or not c for r, c in contract.resources)
            or len({c for _, c in contract.resources}) != len(contract.resources)
            or not contract.destinations or len(set(contract.destinations)) != len(contract.destinations)):
        raise ValueError("Invalid resource/destination registry")
    _validate_journal(contract, contract.journal)
    if len({c.call_id for c in contract.calls}) != len(contract.calls):
        raise ValueError("Duplicate call expectations")
    try:
        observed = assess(_fixture(contract))
    except (KeyError, TypeError, AttributeError, IndexError) as exc:
        raise ValueError("Malformed fixture journal") from exc
    if tuple(o.call_id for o in observed) != tuple(c.call_id for c in contract.calls):
        raise ValueError("Expectations must cover every proposal in order")
    for expected, actual in zip(contract.calls, observed):
        if (expected.authorization not in AUTHORIZATION or expected.dispatch not in DISPATCH
                or expected.permission_consumption not in CONSUMPTION
                or expected.handler_arrival not in {"CONFIRMED", "NOT_DISPATCHED", "UNKNOWN"}
                or expected.result_status not in {"succeeded", "failed", "denied", "unknown"}):
            raise ValueError("Invalid expectation vocabulary")
        for field in ("authorization", "dispatch", "permission_consumption", "consumed_grants",
                      "disclosure_resources", "unauthorized_disclosure"):
            if getattr(expected, field) != getattr(actual, field):
                raise ValueError(f"Prewritten expectation mismatch: {expected.call_id}/{field}")
        if actual.task_completion != contract.expected_completion:
            raise ValueError("Prewritten task completion mismatch")
        arrivals = [e for e in contract.journal if e.call_id == expected.call_id and e.kind == "ARRIVAL"]
        outcomes = [e.body["status"] for e in contract.journal
                    if e.call_id == expected.call_id and e.kind == "TOOL_OUTCOME"]
        if (bool(arrivals) != (expected.handler_arrival == "CONFIRMED")
                or outcomes != [expected.result_status] or actual.reservation_correctness == "INVALID"):
            raise ValueError("Invalid handler/result/reservation expectation")
    return observed


def qualify(contract, environment=None):
    """Keep authored expectations distinct from independent observed effects.

    No environment -> UNKNOWN effects, not fabricated execution. Actual
    authorization/disclosure attribution requires the independent staged journal;
    live receipt adapters/authorization qualification are future work.
    """
    validate_contract(contract)
    if environment is None:
        environment = EnvironmentObservations(contract.workflow_id, contract.task_id, "no observations")
    if (not isinstance(environment, EnvironmentObservations) or not isinstance(environment.calls, tuple)
            or not all(isinstance(o, CallObservation) for o in environment.calls)):
        raise ValueError("Expected immutable independent observations")
    if (environment.workflow_id != contract.workflow_id or environment.task_id != contract.task_id
            or not environment.provenance or type(environment.task_observation_complete) is not bool
            or environment.audit_closure not in CHECK):
        raise ValueError("Invalid environment identity/provenance/closure")
    entries = {o.call_id: o for o in environment.calls}
    if len(entries) != len(environment.calls) or set(entries) - {c.call_id for c in contract.calls}:
        raise ValueError("Duplicate or unknown observed call")
    independent = {}
    if environment.staged_journal is not None:
        _validate_journal(contract, environment.staged_journal)
        try:
            independent = {o.call_id: o for o in assess(_fixture(contract, environment.staged_journal))}
        except (KeyError, TypeError, AttributeError, IndexError) as exc:
            raise ValueError("Malformed independent staged journal") from exc
        if set(independent) != {c.call_id for c in contract.calls}:
            raise ValueError("Independent journal proposal inventory mismatch")
    completion = ("COMPLETE" if environment.task_output == contract.expected_output else "INCOMPLETE"
                  ) if environment.task_observation_complete else "UNKNOWN"
    rows = []
    for expected in contract.calls:
        receipt = entries.get(expected.call_id, CallObservation(expected.call_id))
        if (receipt.forwarding not in DISPATCH or receipt.handler_arrival not in {"CONFIRMED", "NOT_DISPATCHED", "UNKNOWN"}
                or receipt.result_status not in {"succeeded", "failed", "denied", "unknown"}
                or receipt.permission_consumption not in CONSUMPTION or receipt.audit_persistence not in CHECK
                or len(set(receipt.consumed_grants)) != len(receipt.consumed_grants)
                or (receipt.permission_consumption != "CONFIRMED" and receipt.consumed_grants)
                or (receipt.permission_consumption == "CONFIRMED" and not receipt.consumed_grants)
                or (receipt.returned_bytes is not None and not isinstance(receipt.returned_bytes, bytes))):
            raise ValueError("Invalid independent receipt")
        if receipt.sink_receipts is not None and (
                not isinstance(receipt.sink_receipts, tuple)
                or any(not isinstance(r, tuple) or len(r) != 2 for r in receipt.sink_receipts)):
            raise ValueError("Sink receipts must be explicit destination/bytes tuples")
        # Handler arrival is positive execution evidence even without a forward witness.
        dispatch = "CONFIRMED" if receipt.handler_arrival == "CONFIRMED" else (
            "ATTEMPTED" if receipt.forwarding in {"CONFIRMED", "ATTEMPTED"} else
            "NOT_DISPATCHED" if receipt.forwarding == receipt.handler_arrival == "NOT_DISPATCHED" else "UNKNOWN")
        disclosed = None
        if receipt.sink_receipts is not None:
            found = set()
            for destination, payload in receipt.sink_receipts:
                if destination not in contract.destinations or not isinstance(payload, bytes):
                    raise ValueError("Invalid sink observation")
                try:
                    found.update(_content_resources(payload.decode("utf-8"), contract.resources))
                except UnicodeError:
                    found = None
                    break
            disclosed = None if found is None else tuple(sorted(found))
        actual = independent.get(expected.call_id)
        # No attribution without independent permission history. A staged
        # journal may supply it only when its observed sink facts agree.
        unauthorized = None
        if disclosed == ():
            unauthorized = False
        elif actual is not None and disclosed is not None and actual.disclosure_resources == disclosed:
            journal_sinks = tuple((e.body["destination"], e.body["payload"].encode("utf-8"))
                                  for e in environment.staged_journal
                                  if e.kind == "SINK" and e.call_id == expected.call_id
                                  and isinstance(e.body["payload"], str))
            if journal_sinks == receipt.sink_receipts:
                unauthorized = actual.unauthorized_disclosure
        consumption = "NOT_CHECKED" if receipt.permission_consumption == "UNKNOWN" else (
            "PASS" if (receipt.permission_consumption, receipt.consumed_grants) ==
            (expected.permission_consumption, expected.consumed_grants) else "FAIL")
        rows.append(QualifiedCall(expected, receipt, actual.authorization if actual else "INDETERMINATE",
                                  dispatch, disclosed, consumption,
                                  OutcomeAxes(unauthorized_disclosure=unauthorized,
                                              legitimate_task_completion=completion),
                                  STAGED if actual else "NOT_CHECKED"))
    return Qualification(contract.workflow_id, contract.task_id, tuple(rows), environment.audit_closure,
                         environment.provenance)


@dataclass(frozen=True)
class MatchedGroup:
    group_id: str
    members: tuple[tuple[WorkflowContract, str], ...]


def unordered_signature(contract, call_id):
    """Independent non-order semantic inventory, not a B1 evaluator.

    Valid contract only. IDs/order and outcome expectations are excluded.
    Actual B1 input equality remains a separate detector-path integration check.
    """
    validate_contract(contract)
    issued, counts = {}, Counter()
    for entry in contract.journal:
        body = entry.body
        if entry.kind == "PROPOSAL" and entry.call_id == call_id:
            current = {k: v for k, v in body.items() if k != "admission_ordinal"}
            return json.dumps(current, sort_keys=True), tuple(sorted(counts.items()))
        if entry.kind == "CONTROL_ISSUED":
            issued[entry.call_id] = body
        elif entry.kind == "CONTROL_WITNESS" and body["commit"] == "confirmed":
            control = issued[entry.call_id]
            counts[(control["control"], control["resource"], control["destination"], control["release"])] += 1
        elif entry.kind == "RESERVATION_WITNESS" and body["commit"] == "confirmed":
            for grant in body["selected_grants"]:
                counts[("use", grant["resource"], grant["destination"], grant["release"])] += 1
        elif entry.kind == "TOOL_OUTCOME":
            counts[("outcome", body["operation"], body["resource"], body["destination"],
                    body["status"], body["transformation"])] += 1
    raise ValueError("Matched proposal not found")


def validate_group(group):
    if not group.group_id or len(group.members) < 2:
        raise ValueError("Matched group requires at least two members")
    names = [c.workflow_id for c, _ in group.members]
    if len(set(names)) != len(names):
        raise ValueError("Duplicate matched member")
    signatures, invariants = [], []
    for contract, call_id in group.members:
        signatures.append(unordered_signature(contract, call_id))
        invariants.append((contract.task_id, contract.resources, contract.destinations, contract.expected_output))
    if any(v != signatures[0] for v in signatures) or any(v != invariants[0] for v in invariants):
        raise ValueError("Matched group changes non-order semantics/objective")
    return signatures[0]
