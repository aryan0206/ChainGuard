"""M6.2: separate structural and synthetic offline lifecycle validation.

No package inspection, hashing/signing, persistence, authority, or execution.
Version tuples are descriptors, not new serialized fields. Package manifest,
configuration/registry binding and controller reason enum remain deferred.
Step 2 accepts an explicit synthetic execution profile as a caller trust input.
"""

from datetime import datetime
from dataclasses import dataclass
from types import MappingProxyType

from chainguard.authorization import plan_reservation
from chainguard.canonical import MAX_INTEGER, encode
from chainguard.semantics import Current, Fact, Policy, Scope


PACKAGE_FORMAT = "m6-evidence-v1"
MANIFEST_SCHEMA = "m6-manifest-v1"
RECORD_SCHEMA = "m6-record-v1"
COMMITMENT_SCHEMA = "m6-commitment-v1"
CONFIGURATION_SCHEMA = "m6-configuration-v1"
# Order: package, manifest, record, commitment, configuration. No fallback to v1.
PROFILE_VERSIONS = (PACKAGE_FORMAT, MANIFEST_SCHEMA, RECORD_SCHEMA,
                    COMMITMENT_SCHEMA, CONFIGURATION_SCHEMA)
ALLOWED_PROFILE_VERSIONS = frozenset({PROFILE_VERSIONS})

IDENTITY_KEYS = ("run_id", "task_id", "session_id", "monitor_instance_id")
COMMON_KEYS = frozenset({"schema_version", *IDENTITY_KEYS, "event_id", "seq",
                         "observed_at_utc", "event_type", "body", "prev_hash"})
SCOPE_KEYS = frozenset({"resource", "destination", "release"})
INTENT_KEYS = frozenset({"call_id", "required_scopes", "selected_grants", "reservation_status"})
# Existing control bodies plus admission_ordinal: §15.1 requires one FIFO order
# for controls/proposals. event_id correlates controls; task stays in envelope.
PERMISSION_BODY_KEYS = MappingProxyType({
    "GRANT": frozenset({"grant_id", "scope", "host_origin", "admission_ordinal"}),
    "REVOKE_SCOPE": frozenset({"scope", "host_origin", "admission_ordinal"}),
    "DISPATCH_INTENT": INTENT_KEYS,
})


def _require(condition, message):
    if not condition:
        raise ValueError(message)


def _text(value, label):
    _require(type(value) is str and bool(value), f"Invalid {label}")
    value.encode("utf-8", errors="strict")


def _object(value, keys, label):
    _require(type(value) is dict and set(value) == keys, f"Invalid {label} fields")
    try:
        encode(value)  # Preserve existing canonical type, integer and Unicode rules.
    except RecursionError as exc:
        raise ValueError(f"Recursive or excessively nested {label}") from exc


def _ordinal(value, label):
    _require(type(value) is int and 1 <= value <= MAX_INTEGER, f"Invalid {label}")


def _scope(value, task_id, selected=False):
    _object(value, SCOPE_KEYS | ({"grant_id"} if selected else set()), "scope")
    for field in SCOPE_KEYS:
        _text(value[field], field)
    if selected:
        _text(value["grant_id"], "grant ID")
    return Scope(task_id, value["resource"], value["destination"], value["release"])


def validate_profile_versions(versions):
    """Require the exact allowlisted five-string tuple, never a guessed profile."""
    _require(type(versions) is tuple and len(versions) == 5
             and all(type(v) is str for v in versions), "Invalid profile version tuple")
    _require(versions in ALLOWED_PROFILE_VERSIONS, "Unknown or mixed profile versions")


def validate_intent_body(body, task_id, call_id):
    """Check local intent structure/coverage; not active grants or authorization.

    Requirements use Scope order; selections use replay's grant-ID order.
    Override mode/sink eligibility and required-scope derivation need later
    trusted-context/semantic validation; this function does not establish them.
    """
    _text(task_id, "task ID")
    _text(call_id, "call ID")
    _object(body, INTENT_KEYS, "intent body")
    _require(body["call_id"] == call_id, "Intent call ID mismatch")
    required, selected = body["required_scopes"], body["selected_grants"]
    _require(type(required) is list and type(selected) is list, "Scope arrays must be lists")
    scopes = [_scope(s, task_id) for s in required]
    selected_scopes = [_scope(s, task_id, selected=True) for s in selected]
    ids = [s["grant_id"] for s in selected]
    _require(scopes == sorted(set(scopes)), "Duplicate or unsorted required scopes")
    _require(ids == sorted(set(ids)), "Duplicate or unsorted selected grant IDs")
    _require(len(set(selected_scopes)) == len(selected_scopes), "Duplicate selected scope")
    status = body["reservation_status"]
    _text(status, "reservation status")
    if status == "AUTHORIZED":
        _require(bool(scopes) and sorted(selected_scopes) == scopes,
                 "AUTHORIZED must cover every required scope exactly once")
    elif status == "NO_RELEASE_OBLIGATION":
        _require(not scopes and not selected, "No-obligation intent must be empty")
    elif status == "OBSERVATION_OVERRIDE":
        _require(bool(scopes) and not selected, "Override requires scopes and empty selection")
    else:
        raise ValueError("Unknown reservation status")


def validate_record(record, versions=PROFILE_VERSIONS):
    """Validate one permission record, not its lifecycle, hashes or provenance.

    Only GRANT, REVOKE_SCOPE and DISPATCH_INTENT are supported in this step.
    host_origin is a checked classification string, not host authentication.
    """
    validate_profile_versions(versions)
    _require(type(record) is dict, "Record must be an object")
    kind = record.get("event_type")
    _text(kind, "event type")
    _require(kind in PERMISSION_BODY_KEYS, "Record type outside Step 1")
    _object(record, COMMON_KEYS | ({"call_id"} if kind == "DISPATCH_INTENT" else set()), "record")
    _require(record["schema_version"] == RECORD_SCHEMA, "Unknown or mixed record schema")
    for field in (*IDENTITY_KEYS, "event_id"):
        _text(record[field], field)
    _ordinal(record["seq"], "seq")
    head = record["prev_hash"]
    _require(type(head) is str and len(head) == 64
             and all(c in "0123456789abcdef" for c in head), "Invalid prev_hash")
    stamp = record["observed_at_utc"]
    _require(type(stamp) is str and stamp.endswith("Z"), "UTC display timestamp required")
    datetime.fromisoformat(stamp)
    body = record["body"]
    _object(body, PERMISSION_BODY_KEYS[kind], "body")
    if kind == "DISPATCH_INTENT":
        validate_intent_body(body, record["task_id"], record["call_id"])
    else:
        _scope(body["scope"], record["task_id"])
        _require(body["host_origin"] == "trusted_host", "Invalid host origin classification")
        _ordinal(body["admission_ordinal"], "admission ordinal")
        if kind == "GRANT":
            _text(body["grant_id"], "grant ID")


def validate_permission_records(records, versions=PROFILE_VERSIONS):
    """Check a single-stream fragment and duplicate IDs, not a complete session.

    Gaps are permitted because non-permission records are outside this step.
    No transition state, contiguous sequence/FIFO, phase or closure validation.
    """
    validate_profile_versions(versions)
    _require(type(records) is list, "Permission records must be a list")
    seen_events, seen_grants, seen_calls, seen_sequences = set(), set(), set(), set()
    identity = None
    for record in records:
        validate_record(record, versions)
        current_identity = tuple(record[k] for k in IDENTITY_KEYS)
        if identity is None:
            identity = current_identity
        _require(current_identity == identity, "Mixed stream identities")
        for value, seen, label in ((record["event_id"], seen_events, "event ID"),
                                   (record["seq"], seen_sequences, "seq")):
            _require(value not in seen, f"Duplicate {label}")
            seen.add(value)
        kind, body = record["event_type"], record["body"]
        if kind == "GRANT":
            _require(body["grant_id"] not in seen_grants, "Duplicate grant ID")
            seen_grants.add(body["grant_id"])
        elif kind == "DISPATCH_INTENT":
            _require(record["call_id"] not in seen_calls, "Duplicate intent call ID")
            seen_calls.add(record["call_id"])


# Step 2 reuses existing M4 call/start/end field names, without changing the
# Step 1 validators. These are synthetic record schemas, not package support.
RECORD_CLASS = "M6_PERMISSION_CHAINED_UNSEALED"
EXECUTION_PROFILE_KEYS = frozenset({"mode", "supported_tools",
    "synthetic_local_sink_override", "release_calls_enabled"})
DETECTOR_IDS = ("B0", "B1", "B2-R", "B2-S")
LIFECYCLE_BODY_KEYS = MappingProxyType({
    **PERMISSION_BODY_KEYS,
    "SESSION_START": frozenset({"record_class", "run_challenge", "execution_profile", "manifest_digest"}),
    "SESSION_END": frozenset({"closure_status"}),
    "CALL_PROPOSAL": frozenset({"server", "tool", "request_id", "admission_ordinal", "current"}),
    "DISPATCH_DECISION": frozenset({"dispatch_decision", "authorization_assessment", "reason"}),
    "TOOL_OUTCOME": frozenset({"server", "tool", "operation", "resource", "destination",
                              "status", "sensitivity", "transformation"}),
    "DETECTOR_FINDING": frozenset({"evaluated_event_id", "detector_id", "detector_version",
        "detector_digest", "policy_digest", "extraction_version", "behavioral_verdict",
        "authorization_assessment", "hypothetical_recommendation", "rule_id",
        "supporting_event_ids", "explanation"}),
})
LIFECYCLE_CALL_TYPES = frozenset({"CALL_PROPOSAL", "DISPATCH_DECISION", "DISPATCH_INTENT",
                                 "DETECTOR_FINDING", "TOOL_OUTCOME"})


def _digest(value, label):
    _require(type(value) is str and len(value) == 64
             and all(c in "0123456789abcdef" for c in value), f"Invalid {label}")


def _execution_profile(profile):
    _object(profile, EXECUTION_PROFILE_KEYS, "execution profile")
    _text(profile["mode"], "mode")
    _require(profile["mode"] in {"observation", "enforcement"}, "Unknown execution mode")
    tools = profile["supported_tools"]
    _require(type(tools) is list and bool(tools), "Invalid supported tools")
    for tool in tools:
        _text(tool, "supported tool")
    _require(tools == sorted(set(tools)), "Duplicate or unsorted supported tools")
    for flag in ("synthetic_local_sink_override", "release_calls_enabled"):
        _require(type(profile[flag]) is bool, f"Invalid {flag}")
    _require(profile["mode"] != "enforcement" or not profile["synthetic_local_sink_override"],
             "Enforcement cannot enable observation override")


def _current(value):
    _object(value, frozenset(Current.__dataclass_fields__), "current")
    for field in ("operation", "resource", "destination", "sensitivity", "transformation"):
        _require(type(value[field]) is str, f"Invalid current {field}")
    _require(value["sensitivity"] in {"public", "sensitive"}, "Invalid current sensitivity")
    _require(value["transformation"] in {"none", "raw", "base64", "hex"}, "Invalid transformation")
    for flag in ("supported", "static_prohibition"):
        _require(type(value[flag]) is bool, f"Invalid current {flag}")
    resources = value["sensitive_resources"]
    _require(type(resources) is list, "Invalid recognized resources")
    for resource in resources:
        _text(resource, "recognized resource")
    _require(resources == sorted(set(resources)), "Duplicate or unsorted recognized resources")
    _require(value["operation"] in {"read", "send", "transform", "echo"}
             or (value["operation"] == "unsupported" and not value["supported"]), "Invalid operation")
    return Current(**{**value, "sensitive_resources": tuple(resources)})


def validate_lifecycle_record(record, versions=PROFILE_VERSIONS):
    """Separate Step 2 record shapes; no lifecycle or cryptographic proof here.

    Decision reason remains a nonempty explanation string, not an invented
    reason enum or an authorization input. Finding reproduction is Step 3.
    """
    validate_profile_versions(versions)
    _require(type(record) is dict, "Record must be an object")
    kind = record.get("event_type")
    _text(kind, "event type")
    _require(kind in LIFECYCLE_BODY_KEYS, "Unknown lifecycle record type")
    if kind in PERMISSION_BODY_KEYS:
        validate_record(record, versions)
        return
    _object(record, COMMON_KEYS | ({"call_id"} if kind in LIFECYCLE_CALL_TYPES else set()), "record")
    _require(record["schema_version"] == RECORD_SCHEMA, "Unknown or mixed record schema")
    for field in (*IDENTITY_KEYS, "event_id"):
        _text(record[field], field)
    _ordinal(record["seq"], "seq")
    _digest(record["prev_hash"], "prev_hash")
    stamp = record["observed_at_utc"]
    _require(type(stamp) is str and stamp.endswith("Z"), "UTC display timestamp required")
    datetime.fromisoformat(stamp)
    if kind in LIFECYCLE_CALL_TYPES:
        _text(record["call_id"], "call ID")
    body = record["body"]
    _object(body, LIFECYCLE_BODY_KEYS[kind], "body")
    if kind == "SESSION_START":
        _require(body["record_class"] == RECORD_CLASS, "Unknown lifecycle record class")
        _digest(body["run_challenge"], "run challenge")
        _digest(body["manifest_digest"], "manifest digest")
        _execution_profile(body["execution_profile"])
    elif kind == "SESSION_END":
        _require(body["closure_status"] == "CLOSED", "Invalid closure status")
    elif kind == "CALL_PROPOSAL":
        _text(body["server"], "server")
        _text(body["tool"], "tool")
        _require(type(body["request_id"]) in (str, int), "Invalid request ID")
        _ordinal(body["admission_ordinal"], "admission ordinal")
        _current(body["current"])
    elif kind == "DISPATCH_DECISION":
        for field in body:
            _text(body[field], field)
        _require(body["dispatch_decision"] in {"ALLOW", "DENY"}, "Invalid dispatch decision")
        _require(body["authorization_assessment"] in {"AUTHORIZED", "UNAUTHORIZED", "INDETERMINATE"},
                 "Invalid authorization assessment")
    elif kind == "TOOL_OUTCOME":
        for field in body:
            _require(type(body[field]) is str, f"Invalid outcome {field}")
        _text(body["server"], "server")
        _text(body["tool"], "tool")
        _require(body["status"] in {"succeeded", "failed", "denied", "unknown"}, "Invalid outcome status")
        _require(body["sensitivity"] in {"public", "sensitive"}, "Invalid outcome sensitivity")
    elif kind == "DETECTOR_FINDING":
        for field in body.keys() - {"supporting_event_ids"}:
            _text(body[field], field)
        for field in ("detector_digest", "policy_digest"):
            _digest(body[field], field)
        _require(body["detector_id"] in DETECTOR_IDS, "Unknown detector ID")
        _require(body["behavioral_verdict"] in {"ALLOW", "SUSPICIOUS", "POLICY_VIOLATION"}, "Invalid verdict")
        _require(body["authorization_assessment"] in {"AUTHORIZED", "UNAUTHORIZED", "INDETERMINATE"},
                 "Invalid finding assessment")
        _require(body["hypothetical_recommendation"] ==
                 ("ALLOW" if body["behavioral_verdict"] == "ALLOW" else "DENY"), "Finding recommendation mismatch")
        refs = body["supporting_event_ids"]
        _require(type(refs) is list, "Invalid supporting references")
        for ref in refs:
            _text(ref, "supporting reference")
        _require(refs == sorted(set(refs)), "Duplicate or unsorted supporting references")


def _policy_resources(policy):
    _require(type(policy) is Policy, "Expected existing Policy instance")
    resources = getattr(policy, "resources", None)
    destinations = getattr(policy, "destinations", None)
    limit = getattr(policy, "max_payload_bytes", None)
    _require(type(resources) is tuple and type(destinations) is tuple, "Invalid policy collections")
    _require(type(limit) is int and 1 <= limit <= MAX_INTEGER, "Invalid payload limit")
    ids, canaries = set(), set()
    for pair in resources:
        _require(type(pair) is tuple and len(pair) == 2, "Invalid policy resource")
        resource, canary = pair
        _text(resource, "policy resource")
        _text(canary, "policy canary")
        _require(resource not in ids and canary not in canaries, "Ambiguous policy resource")
        ids.add(resource)
        canaries.add(canary)
    for destination in destinations:
        _text(destination, "policy destination")
    _require(len(set(destinations)) == len(destinations), "Duplicate policy destination")
    return ids


@dataclass(frozen=True)
class LifecycleReconstruction:
    """Offline asserted state, never execution authority or proof of commitment."""

    identity: tuple[str, ...]
    facts: tuple[Fact, ...]
    active_grants: tuple[tuple[str, Scope], ...]
    issued_grant_ids: frozenset[str]
    exposed_resources: frozenset[str]
    admission_ordinal: int
    closed: bool
    halted: bool
    pending_call_id: str


def reconstruct_lifecycle(records, policy, execution_profile, *, require_complete=True,
                          synthetic_experiment=False, synthetic_sink="sink", enforcement_detector="B2-S"):
    """Validate ordered synthetic records and return immutable reconstructed facts.

    Policy/profile and synthetic approval are explicit caller trust inputs, not
    client metadata or assertions of this API. Controls/intents are treated as
    asserted committed records; actual durability, capture, hashes, signatures,
    manifest/config binding and deterministic finding reproduction are deferred.
    No detector evaluator or ReplayLedger is called. The controller contract is
    reconstructed independently, using the approved pure reservation planner.

    By default a clean end is required. require_complete=False inspects a valid
    unfinished prefix (including unknown outcome) without treating it as closed
    evidence. Unknown outcomes halt; no subsequent record or refund is allowed.
    Invalid input raises ValueError. No partial reconstruction escapes failure.
    """
    _require(type(records) is list and bool(records), "Missing lifecycle records")
    registered = _policy_resources(policy)
    _execution_profile(execution_profile)
    for flag in (require_complete, synthetic_experiment):
        _require(type(flag) is bool, "Invalid inspection/experiment flag")
    _text(synthetic_sink, "synthetic sink")
    _text(enforcement_detector, "enforcement detector")
    _require(enforcement_detector in {"B0", "B1", "B2-S"}, "Invalid enforcement detector")
    identity = None
    events, calls, issued = set(), set(), set()
    active, exposed, facts = {}, set(), []
    ordinal, started, closed, halted, pending = 0, False, False, False, None
    for seq, record in enumerate(records, 1):
        validate_lifecycle_record(record)
        current_identity = tuple(record[k] for k in IDENTITY_KEYS)
        if identity is None:
            identity = current_identity
        _require(current_identity == identity, "Mixed stream identities")
        _require(record["seq"] == seq, "Noncontiguous or reordered sequence")
        _require(record["event_id"] not in events, "Duplicate event ID")
        kind, body, event = record["event_type"], record["body"], record["event_id"]
        task = record["task_id"]
        _require(not closed and not halted, "Closed or unknown-outcome stream cannot continue")
        if kind == "SESSION_START":
            _require(seq == 1 and not started, "Repeated or misplaced start")
            _require(body["execution_profile"] == execution_profile, "Expected execution profile mismatch")
            started = True
        else:
            _require(started, "Missing session start")
        if kind in {"GRANT", "REVOKE_SCOPE", "CALL_PROPOSAL"}:
            _require(pending is None, "Control/proposal during pending proposal turn")
            _require(body["admission_ordinal"] == ordinal + 1, "Noncontiguous FIFO admission")
            ordinal += 1
        if kind in {"GRANT", "REVOKE_SCOPE"}:
            scope = _scope(body["scope"], task)
            if kind == "GRANT":
                grant = body["grant_id"]
                _require(grant not in issued, "Reissued grant ID")
                issued.add(grant)
                active[grant] = scope
                facts.append(Fact("GRANT", event, scope=scope, grant_id=grant))
            else:
                active = {g: s for g, s in active.items() if s != scope}
                facts.append(Fact("REVOKE_SCOPE", event, scope=scope))
        elif kind == "CALL_PROPOSAL":
            call = record["call_id"]
            _require(call not in calls, "Repeated call attempt ID")
            calls.add(call)
            current = _current(body["current"])
            _require(set(current.sensitive_resources) <= registered, "Unregistered recognized resource")
            _require(current.operation == "send" or not current.sensitive_resources, "Non-release direct resources")
            if current.supported:
                _require(body["tool"] in execution_profile["supported_tools"], "Supported tool absent from profile")
                if current.operation == "read":
                    _require(current.resource in registered or current.resource == "public", "Unregistered acquisition")
                    _require(current.sensitivity == ("sensitive" if current.resource in registered else "public"),
                             "Acquisition sensitivity contradicts policy")
                if current.operation == "send":
                    _text(current.destination, "release destination")
                    _require(current.static_prohibition == (current.destination not in policy.destinations),
                             "Static prohibition contradicts destination policy")
                    _require(current.sensitivity != "sensitive" or bool(current.sensitive_resources),
                             "Unresolved sensitive resource mapping")
                    _require(not current.sensitive_resources or current.sensitivity == "sensitive",
                             "Recognized resources contradict sensitivity")
            resources = exposed | set(current.sensitive_resources) if current.operation == "send" else set()
            required = tuple(Scope(task, r, current.destination) for r in sorted(resources))
            plan = plan_reservation(task, required, active)
            auth = ("UNAUTHORIZED" if current.static_prohibition else "INDETERMINATE" if not current.supported
                    else "AUTHORIZED" if plan.complete else "UNAUTHORIZED")
            ready = current.supported and not current.static_prohibition and (
                current.operation != "send" or execution_profile["release_calls_enabled"])
            override = (auth == "UNAUTHORIZED" and ready and execution_profile["mode"] == "observation"
                and execution_profile["synthetic_local_sink_override"] and synthetic_experiment
                and current.destination == synthetic_sink and synthetic_sink in policy.destinations)
            pending = {"call": call, "proposal": event, "body": body, "current": current,
                "required": required, "plan": plan, "auth": auth, "ready": ready, "override": override,
                "findings": {}, "decision": None, "intent": False}
        elif kind in LIFECYCLE_CALL_TYPES:
            _require(pending is not None and record["call_id"] == pending["call"], "Uncorrelated call phase")
            current = pending["current"]
            if kind == "DETECTOR_FINDING":
                _require(current.supported and pending["decision"] is None, "Unsupported or late finding")
                detector = body["detector_id"]
                _require(detector not in pending["findings"], "Duplicate detector finding")
                _require(body["evaluated_event_id"] == pending["proposal"], "Wrong finding proposal")
                _require(set(body["supporting_event_ids"]) <= events, "Future or missing finding reference")
                pending["findings"][detector] = body
            elif kind == "DISPATCH_DECISION":
                _require(pending["decision"] is None, "Repeated decision")
                expected_findings = set(DETECTOR_IDS) if current.supported else set()
                _require(set(pending["findings"]) == expected_findings, "Missing required findings")
                _require(body["authorization_assessment"] == pending["auth"], "Controller assessment contradicts history")
                allow = pending["ready"] and (pending["auth"] == "AUTHORIZED" or pending["override"])
                if execution_profile["mode"] == "enforcement" and current.supported:
                    allow &= pending["findings"][enforcement_detector]["hypothetical_recommendation"] == "ALLOW"
                _require(body["dispatch_decision"] == ("ALLOW" if allow else "DENY"), "Invalid controller decision")
                pending["decision"] = body["dispatch_decision"]
            elif kind == "DISPATCH_INTENT":
                _require(pending["decision"] == "ALLOW" and not pending["intent"], "Denied, early or duplicate intent")
                required = tuple(_scope(s, task) for s in body["required_scopes"])
                _require(required == pending["required"], "Intent requirements contradict prior exposure/current facts")
                status = ("NO_RELEASE_OBLIGATION" if not required else
                          "AUTHORIZED" if pending["plan"].complete else "OBSERVATION_OVERRIDE")
                _require(body["reservation_status"] == status, "Intent status contradicts permission state")
                expected_ids = sorted(g for _, g in pending["plan"].selections) if status == "AUTHORIZED" else []
                selected = body["selected_grants"]
                _require([s["grant_id"] for s in selected] == expected_ids, "Inactive or nonminimum selected grant")
                for selection in selected:
                    _require(active.get(selection["grant_id"]) == _scope(selection, task, selected=True),
                             "Selected grant scope mismatch")
                for selection in selected:
                    grant = selection["grant_id"]
                    facts.append(Fact("USE", event, scope=active[grant], grant_id=grant))
                    del active[grant]
                pending["intent"] = True
            elif kind == "TOOL_OUTCOME":
                _require(pending["decision"] is not None, "Outcome before decision")
                denied = pending["decision"] == "DENY"
                _require((body["status"] == "denied") == denied, "Denied outcome contradicts decision")
                _require(denied or pending["intent"], "Outcome without dispatch intent")
                _require(body["server"] == pending["body"]["server"] and body["tool"] == pending["body"]["tool"],
                         "Outcome tool identity changed")
                _require(all(body[k] == getattr(current, k) for k in (
                    "operation", "resource", "destination", "sensitivity", "transformation")), "Outcome facts changed")
                facts.append(Fact("TOOL_OUTCOME", event, current.operation, current.resource,
                    current.destination, body["status"], current.sensitivity, current.transformation))
                if current.operation == "read" and current.sensitivity == "sensitive" and body["status"] == "succeeded":
                    exposed.add(current.resource)
                halted = body["status"] == "unknown"
                pending = None
        elif kind == "SESSION_END":
            _require(pending is None, "Pending proposal cannot close")
            closed = True
            active.clear()  # Grants cannot outlive the task (§15.1).
        events.add(event)
    if require_complete:
        _require(closed and not halted and pending is None, "Incomplete lifecycle evidence")
    return LifecycleReconstruction(identity, tuple(facts), tuple(sorted(active.items())), frozenset(issued),
        frozenset(exposed), ordinal, closed, halted, pending["call"] if pending else "")


def project_use_facts(records, policy, execution_profile, **inspection_options):
    """Project USE only after whole-input lifecycle validation; never from findings/outcomes."""
    result = reconstruct_lifecycle(records, policy, execution_profile, **inspection_options)
    return tuple(fact for fact in result.facts if fact.category == "USE")
