"""M6.2 structural/lifecycle fixtures; no live or cryptographic evidence claims."""

from copy import deepcopy
from sys import getrecursionlimit
import unittest

from chainguard.audit import validate_record as validate_m3
from chainguard.canonical import MAX_INTEGER, decode, encode
from chainguard.evidence import validate_record as validate_m4
from chainguard.permission_evidence import (PROFILE_VERSIONS, RECORD_SCHEMA,
    validate_intent_body, validate_permission_records, validate_profile_versions,
    validate_record, DETECTOR_IDS, RECORD_CLASS, project_use_facts, reconstruct_lifecycle,
    validate_lifecycle_record)
from chainguard.semantics import Policy


def scope(resource="secret-a", destination="sink"):
    return {"resource": resource, "destination": destination, "release": "release"}


def intent(status="AUTHORIZED"):
    required = [scope()] if status != "NO_RELEASE_OBLIGATION" else []
    selected = [{"grant_id": "g", **scope()}] if status == "AUTHORIZED" else []
    return {"call_id": "call", "required_scopes": required,
            "selected_grants": selected, "reservation_status": status}


def control(kind="GRANT"):
    body = {"scope": scope(), "host_origin": "trusted_host", "admission_ordinal": 1}
    if kind == "GRANT":
        body["grant_id"] = "g"
    return body


def record(kind="GRANT", body=None, event_id="event", seq=1):
    if body is None:
        body = intent() if kind == "DISPATCH_INTENT" else control(kind)
    result = {"schema_version": RECORD_SCHEMA, "run_id": "run", "task_id": "task",
              "session_id": "session", "monitor_instance_id": "monitor",
              "event_id": event_id, "seq": seq, "prev_hash": "ab" * 32,
              "observed_at_utc": "2026-10-15T00:00:00Z", "event_type": kind, "body": body}
    if kind == "DISPATCH_INTENT":
        result["call_id"] = "call"
    return result


class PermissionStructureTests(unittest.TestCase):
    def test_explicit_version_tuple(self):
        self.assertEqual(PROFILE_VERSIONS, ("m6-evidence-v1", "m6-manifest-v1",
            "m6-record-v1", "m6-commitment-v1", "m6-configuration-v1"))
        validate_profile_versions(PROFILE_VERSIONS)

    def test_unknown_and_mixed_version_tuples_rejected(self):
        legacy = ("m4-evidence-v1", "m4-manifest-v1", "m4-record-v1",
                  "m4-commitment-v1", "m4-configuration-v1")
        with self.assertRaises(ValueError):
            validate_profile_versions(legacy)
        for index in range(5):
            for value in (legacy[index], "unknown", None, True, []):
                mixed = list(PROFILE_VERSIONS)
                mixed[index] = value
                with self.subTest(index=index, value=value), self.assertRaises(ValueError):
                    validate_profile_versions(tuple(mixed))

    def test_version_tuple_shapes_rejected(self):
        for versions in (None, list(PROFILE_VERSIONS), PROFILE_VERSIONS[:-1],
                         PROFILE_VERSIONS + ("extra",), "m6-evidence-v1"):
            with self.subTest(versions=versions), self.assertRaises(ValueError):
                validate_profile_versions(versions)

    def test_valid_permission_records(self):
        for kind in ("GRANT", "REVOKE_SCOPE", "DISPATCH_INTENT"):
            with self.subTest(kind=kind):
                validate_record(record(kind))

    def test_profile_tuple_checked_by_record_and_fragment_validators(self):
        mixed = ("m4-evidence-v1", *PROFILE_VERSIONS[1:])
        with self.assertRaises(ValueError):
            validate_record(record(), mixed)
        with self.assertRaises(ValueError):
            validate_permission_records([], mixed)

    def test_record_unknown_and_legacy_schema_rejected(self):
        for version in ("unknown", "m3-record-v1", "m4-record-v1", None):
            with self.subTest(version=version), self.assertRaises(ValueError):
                validate_record({**record(), "schema_version": version})

    def test_unsupported_record_types_and_kind_types_rejected(self):
        for kind in ("USE", "DISPATCH_DECISION", "SESSION_START", "CALL_PROPOSAL", None, [], True):
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                validate_record({**record(), "event_type": kind})

    def test_missing_and_extra_envelope_fields_rejected(self):
        for kind in ("GRANT", "REVOKE_SCOPE", "DISPATCH_INTENT"):
            good = record(kind)
            for field in good:
                bad = deepcopy(good)
                del bad[field]
                with self.subTest(kind=kind, missing=field), self.assertRaises(ValueError):
                    validate_record(bad)
            with self.subTest(kind=kind, extra=True), self.assertRaises(ValueError):
                validate_record({**good, "extra": "x"})
        with self.assertRaises(ValueError):
            validate_record({**record(), "call_id": "not-a-call-control"})

    def test_missing_and_extra_body_fields_rejected(self):
        for kind in ("GRANT", "REVOKE_SCOPE", "DISPATCH_INTENT"):
            good = record(kind)
            for field in good["body"]:
                bad = deepcopy(good)
                del bad["body"][field]
                with self.subTest(kind=kind, missing=field), self.assertRaises(ValueError):
                    validate_record(bad)
            bad = deepcopy(good)
            bad["body"]["extra"] = "x"
            with self.subTest(kind=kind, extra=True), self.assertRaises(ValueError):
                validate_record(bad)

    def test_invalid_identity_and_grant_id_types_rejected(self):
        for field in ("run_id", "task_id", "session_id", "monitor_instance_id", "event_id"):
            for value in ("", None, True, 7, "\ud800"):
                with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                    validate_record({**record(), field: value})
        for value in ("", None, True, 7, "\ud800"):
            with self.subTest(grant_id=value), self.assertRaises(ValueError):
                validate_record(record(body={**control(), "grant_id": value}))

    def test_invalid_sequence_and_admission_ordinal_rejected(self):
        for value in (0, -1, True, "1", 1.0, MAX_INTEGER + 1):
            with self.subTest(seq=value), self.assertRaises(ValueError):
                validate_record({**record(), "seq": value})
            with self.subTest(ordinal=value), self.assertRaises(ValueError):
                validate_record(record(body={**control(), "admission_ordinal": value}))

    def test_invalid_hash_timestamp_and_host_origin_rejected(self):
        for value in ("AB" * 32, "short", None, True):
            with self.subTest(head=value), self.assertRaises(ValueError):
                validate_record({**record(), "prev_hash": value})
        for value in ("not-a-dateZ", "2026-10-15T00:00:00", None, 7):
            with self.subTest(stamp=value), self.assertRaises(ValueError):
                validate_record({**record(), "observed_at_utc": value})
        with self.assertRaises(ValueError):
            validate_record(record(body={**control(), "host_origin": "client"}))

    def test_malformed_scopes_rejected(self):
        bad_scopes = [None, [], "secret-a", {**scope(), "task_id": "other"}]
        for field in scope():
            missing = scope()
            del missing[field]
            bad_scopes.append(missing)
            for value in ("", None, 7, True, "\ud800"):
                bad_scopes.append({**scope(), field: value})
        bad_scopes.append({**scope(), "release": "read"})
        for bad_scope in bad_scopes:
            with self.subTest(scope=bad_scope):
                with self.assertRaises(ValueError):
                    validate_record(record(body={**control(), "scope": bad_scope}))
                bad = intent()
                bad["required_scopes"] = [bad_scope]
                with self.assertRaises(ValueError):
                    validate_intent_body(bad, "task", "call")

    def test_three_intent_status_shapes(self):
        for status in ("AUTHORIZED", "NO_RELEASE_OBLIGATION", "OBSERVATION_OVERRIDE"):
            validate_intent_body(intent(status), "task", "call")
        for status in ("unknown", "", True, []):
            with self.subTest(status=status), self.assertRaises(ValueError):
                validate_intent_body({**intent(), "reservation_status": status}, "task", "call")

    def test_intent_status_constraints(self):
        bad = [intent("AUTHORIZED"), intent("NO_RELEASE_OBLIGATION"), intent("OBSERVATION_OVERRIDE")]
        bad[0]["required_scopes"] = []
        bad[1]["selected_grants"] = [{"grant_id": "g", **scope()}]
        bad[2]["selected_grants"] = [{"grant_id": "g", **scope()}]
        bad.extend([{**intent(), "selected_grants": []}, intent("OBSERVATION_OVERRIDE")])
        bad[-1]["required_scopes"] = []
        for body in bad:
            with self.subTest(body=body), self.assertRaises(ValueError):
                validate_intent_body(body, "task", "call")

    def test_canonical_array_orders_are_distinct(self):
        body = intent()
        body["required_scopes"] = [scope("a"), scope("b")]
        body["selected_grants"] = [{"grant_id": "a-id", **scope("b")},
                                   {"grant_id": "z-id", **scope("a")}]
        validate_intent_body(body, "task", "call")
        for field in ("required_scopes", "selected_grants"):
            bad = deepcopy(body)
            bad[field].reverse()
            with self.subTest(field=field), self.assertRaises(ValueError):
                validate_intent_body(bad, "task", "call")

    def test_duplicate_required_scopes_and_selected_ids_rejected(self):
        for field in ("required_scopes", "selected_grants"):
            body = intent()
            body[field] *= 2
            with self.subTest(field=field), self.assertRaises(ValueError):
                validate_intent_body(body, "task", "call")
        body = intent()
        body["required_scopes"].append(scope("secret-b"))
        body["selected_grants"].append({"grant_id": "g", **scope("secret-b")})
        with self.assertRaises(ValueError):
            validate_intent_body(body, "task", "call")

    def test_partial_extra_wrong_and_duplicate_selected_scopes_rejected(self):
        for selected in ([], [{"grant_id": "g", **scope("other")}],
                         [{"grant_id": "a", **scope()}, {"grant_id": "b", **scope()}],
                         [{"grant_id": "a", **scope()}, {"grant_id": "b", **scope("extra")}],
                         [{"grant_id": "g", **scope(destination="other")}],
                         [{"grant_id": "g", **scope(), "release": "read"}],
                         [{"grant_id": "g", **scope(), "task_id": "other"}],
                         [scope()], [{"grant_id": "", **scope()}]):
            with self.subTest(selected=selected), self.assertRaises(ValueError):
                validate_intent_body({**intent(), "selected_grants": selected}, "task", "call")

    def test_intent_correlation_and_array_types_rejected(self):
        with self.assertRaises(ValueError):
            validate_intent_body(intent(), "task", "different-call")
        for field in ("required_scopes", "selected_grants"):
            for value in (None, (), {}, "", True):
                with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                    validate_intent_body({**intent(), field: value}, "task", "call")
        for task, call in (("", "call"), (True, "call"), ("task", ""), ("task", 1)):
            with self.subTest(task=task, call=call), self.assertRaises(ValueError):
                validate_intent_body(intent(), task, call)

    def test_cyclic_required_scopes_raise_value_error(self):
        body = intent("OBSERVATION_OVERRIDE")
        required = []
        required.append(required)
        body["required_scopes"] = required
        with self.assertRaises(ValueError) as raised:
            validate_intent_body(body, "task", "call")
        self.assertIsInstance(raised.exception.__cause__, RecursionError)

    def test_excessively_nested_resource_raises_value_error(self):
        nested = "secret-a"
        for _ in range(getrecursionlimit() + 1):
            nested = [nested]
        body = intent()
        body["required_scopes"][0]["resource"] = nested
        with self.assertRaises(ValueError) as raised:
            validate_intent_body(body, "task", "call")
        self.assertIsInstance(raised.exception.__cause__, RecursionError)

    def test_valid_fragment_with_gaps(self):
        validate_permission_records([record(event_id="grant", seq=2),
            record("REVOKE_SCOPE", event_id="revoke", seq=4),
            record("DISPATCH_INTENT", event_id="intent", seq=7)])
        validate_permission_records([])

    def test_fragment_duplicate_identifiers_rejected(self):
        first = record()
        second = record(event_id="different", seq=2)
        with self.assertRaisesRegex(ValueError, "Duplicate grant ID"):
            validate_permission_records([first, second])
        for field in ("event_id", "seq"):
            second = record("REVOKE_SCOPE", event_id="other", seq=2)
            second[field] = first[field]
            with self.subTest(field=field), self.assertRaises(ValueError):
                validate_permission_records([first, second])
        with self.assertRaisesRegex(ValueError, "Duplicate intent call ID"):
            validate_permission_records([record("DISPATCH_INTENT"),
                record("DISPATCH_INTENT", event_id="other", seq=2)])

    def test_fragment_mixed_identity_and_invalid_container_rejected(self):
        for field in ("run_id", "task_id", "session_id", "monitor_instance_id"):
            second = record("REVOKE_SCOPE", event_id="other", seq=2)
            second[field] = "other"
            with self.subTest(field=field), self.assertRaises(ValueError):
                validate_permission_records([record(), second])
        for value in (None, (), {}, [None]):
            with self.subTest(records=value), self.assertRaises(ValueError):
                validate_permission_records(value)

    def test_structural_validation_does_not_establish_live_authority(self):
        # No grant prefix, keys, expected inventory, registry or execution input.
        validate_record(record("DISPATCH_INTENT"))
        validate_permission_records([record("DISPATCH_INTENT")])

    def test_canonical_intent_and_grant_body_vectors(self):
        expected = (b'{"call_id":"call","required_scopes":[{"destination":"sink",'
            b'"release":"release","resource":"secret-a"}],"reservation_status":"AUTHORIZED",'
            b'"selected_grants":[{"destination":"sink","grant_id":"g","release":"release",'
            b'"resource":"secret-a"}]}')
        self.assertEqual(encode(intent()), expected)
        self.assertEqual(encode(control()), b'{"admission_ordinal":1,"grant_id":"g",'
            b'"host_origin":"trusted_host","scope":{"destination":"sink",'
            b'"release":"release","resource":"secret-a"}}')
        validate_intent_body(decode(expected), "task", "call")

    def test_canonical_decoder_rejects_duplicates_and_aliases(self):
        for raw in (b'{"grant_id":"a","grant_id":"b"}', b'{ "a":1}',
                    b'{"a":1.0}', b'{"a":NaN}', b'9007199254740992'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                decode(raw)

    def test_inputs_not_mutated(self):
        records = [record(), record("DISPATCH_INTENT", event_id="other", seq=2)]
        before = deepcopy(records)
        validate_permission_records(records)
        self.assertEqual(records, before)
        bad = deepcopy(records)
        bad[1]["body"]["selected_grants"] *= 2
        before = deepcopy(bad)
        with self.assertRaises(ValueError):
            validate_permission_records(bad)
        self.assertEqual(bad, before)

    def test_old_validators_reject_new_records_and_nonempty_old_intents(self):
        for validator, version in ((validate_m3, "m3-record-v1"), (validate_m4, "m4-record-v1")):
            for kind in ("GRANT", "REVOKE_SCOPE", "DISPATCH_INTENT"):
                new = record(kind)
                if version == "m3-record-v1":
                    del new["prev_hash"]
                with self.subTest(version=version, kind=kind), self.assertRaises(ValueError):
                    validator(new)
            old = record("DISPATCH_INTENT")
            old["schema_version"] = version
            if version == "m3-record-v1":
                del old["prev_hash"]
            with self.subTest(version=version, nonempty=True), self.assertRaises(ValueError):
                validator(old)
            old["body"] = intent("NO_RELEASE_OBLIGATION")
            validator(old)


LIFECYCLE_POLICY = Policy((("secret-a", "SYNTHETIC_CANARY_A"), ("secret-b", "SYNTHETIC_CANARY_B")),
                          destinations=("sink", "other-sink"))
LIFECYCLE_PROFILE = {"mode": "observation", "supported_tools": ["echo", "read", "send", "transform"],
                     "synthetic_local_sink_override": False, "release_calls_enabled": True}


class LifecycleTranscript:
    """Record construction only. Expected decisions/selections are author inputs."""

    def __init__(self, profile=None):
        self.profile = deepcopy(LIFECYCLE_PROFILE if profile is None else profile)
        self.records, self.ordinal, self.calls = [], 0, 0
        self.add("SESSION_START", {"record_class": RECORD_CLASS, "run_challenge": "ab" * 32,
            "manifest_digest": "cd" * 32, "execution_profile": deepcopy(self.profile)})

    def add(self, kind, body, call=None):
        event = record(kind, deepcopy(body), f"event-{len(self.records) + 1}", len(self.records) + 1)
        if call is not None:
            event["call_id"] = call
        self.records.append(event)
        return event

    def grant(self, grant="g", resource="secret-a", destination="sink"):
        self.ordinal += 1
        return self.add("GRANT", {"grant_id": grant, "scope": scope(resource, destination),
            "host_origin": "trusted_host", "admission_ordinal": self.ordinal})

    def revoke(self, resource="secret-a", destination="sink"):
        self.ordinal += 1
        return self.add("REVOKE_SCOPE", {"scope": scope(resource, destination),
            "host_origin": "trusted_host", "admission_ordinal": self.ordinal})

    def call(self, operation="send", *, resource="", destination=None, direct=("secret-a",),
             required=("secret-a",), selected=(("g", "secret-a"),), assessment="AUTHORIZED",
             dispatch=True, outcome="succeeded", behavior="ALLOW", static=False, supported=True,
             reservation_status=None):
        self.calls += 1
        self.ordinal += 1
        call = f"call-{self.calls}"
        destination = ("sink" if operation == "send" else "") if destination is None else destination
        if operation != "send":
            direct, required, selected = (), (), ()
        current = {"operation": operation, "resource": resource, "destination": destination,
            "sensitivity": "sensitive" if direct or resource in {"secret-a", "secret-b"} else "public",
            "transformation": "none", "sensitive_resources": list(direct),
            "supported": supported, "static_prohibition": static}
        proposal = self.add("CALL_PROPOSAL", {"server": "synthetic-server", "tool": operation,
            "request_id": self.calls, "admission_ordinal": self.ordinal, "current": current}, call)
        if supported:
            for detector in DETECTOR_IDS:
                self.add("DETECTOR_FINDING", {"evaluated_event_id": proposal["event_id"],
                    "detector_id": detector, "detector_version": "m2-v1", "detector_digest": "ab" * 32,
                    "policy_digest": "cd" * 32, "extraction_version": "m2-raw-base64-v1",
                    "behavioral_verdict": behavior, "authorization_assessment": "INDETERMINATE",
                    "hypothetical_recommendation": "ALLOW" if behavior == "ALLOW" else "DENY",
                    "rule_id": "SYNTHETIC_FIXTURE", "supporting_event_ids": [proposal["event_id"]],
                    "explanation": "Author-supplied fixture; finding reproduction is not exercised."}, call)
        self.add("DISPATCH_DECISION", {"dispatch_decision": "ALLOW" if dispatch else "DENY",
            "authorization_assessment": assessment, "reason": "synthetic fixture"}, call)
        if dispatch:
            status = reservation_status or ("AUTHORIZED" if required else "NO_RELEASE_OBLIGATION")
            self.add("DISPATCH_INTENT", {"call_id": call, "required_scopes": [scope(r, destination) for r in required],
                "selected_grants": [{"grant_id": g, **scope(r, destination)} for g, r in selected],
                "reservation_status": status}, call)
        self.add("TOOL_OUTCOME", {"server": "synthetic-server", "tool": operation,
            **{k: current[k] for k in ("operation", "resource", "destination", "sensitivity", "transformation")},
            "status": outcome if dispatch else "denied"}, call)
        return call

    def finish(self):
        self.add("SESSION_END", {"closure_status": "CLOSED"})
        return self.records


def lifecycle_event(records, kind, occurrence=0):
    return [r for r in records if r["event_type"] == kind][occurrence]


def resequence(records):
    for seq, item in enumerate(records, 1):
        item["seq"] = seq


class PermissionLifecycleTests(unittest.TestCase):
    def reconstruct(self, transcript, **options):
        return reconstruct_lifecycle(transcript.records, LIFECYCLE_POLICY, transcript.profile, **options)

    def assert_invalid(self, transcript, **options):
        with self.assertRaises(ValueError):
            self.reconstruct(transcript, **options)

    def released(self, **call_options):
        transcript = LifecycleTranscript()
        transcript.grant()
        transcript.call(**call_options)
        transcript.finish()
        return transcript

    def test_valid_release_exactly_one_use_from_intent(self):
        t = self.released()
        result = self.reconstruct(t)
        uses = project_use_facts(t.records, LIFECYCLE_POLICY, t.profile)
        self.assertEqual(len(uses), 1)
        self.assertEqual((uses[0].grant_id, uses[0].scope.task_id, uses[0].scope.resource,
                          uses[0].scope.destination, uses[0].scope.release),
                         ("g", "task", "secret-a", "sink", "release"))
        self.assertEqual(uses[0].event_id, lifecycle_event(t.records, "DISPATCH_INTENT")["event_id"])
        self.assertEqual([f.category for f in result.facts], ["GRANT", "USE", "TOOL_OUTCOME"])
        self.assertTrue(result.closed)
        self.assertFalse(result.halted)
        self.assertEqual(result.active_grants, ())

    def test_valid_active_state_and_exact_scope_revocation(self):
        t = LifecycleTranscript()
        t.grant("a")
        t.grant("z")
        t.grant("b", "secret-b")
        t.grant("other", destination="other-sink")
        t.revoke()
        result = self.reconstruct(t, require_complete=False)
        self.assertEqual([g for g, _ in result.active_grants], ["b", "other"])
        self.assertEqual(result.admission_ordinal, 5)
        self.assertEqual(result.issued_grant_ids, frozenset({"a", "z", "b", "other"}))
        self.assertFalse(result.closed)
        self.assert_invalid(t)

    def test_noop_revoke_then_new_grant_restores_permission(self):
        t = LifecycleTranscript()
        t.revoke()
        t.grant("new")
        t.call(selected=(("new", "secret-a"),))
        t.finish()
        self.assertEqual(project_use_facts(t.records, LIFECYCLE_POLICY, t.profile)[0].grant_id, "new")

    def test_unused_exact_control_scope_does_not_require_sensitive_registration(self):
        t = LifecycleTranscript()
        t.revoke("unused-resource")
        t.grant("unused", "unused-resource")
        t.revoke("unused-resource")
        t.grant()
        t.call()
        t.finish()
        result = self.reconstruct(t)
        self.assertEqual(result.issued_grant_ids, frozenset({"unused", "g"}))
        self.assertEqual([f.grant_id for f in result.facts if f.category == "USE"], ["g"])

    def test_revoked_grant_cannot_authorize_release(self):
        t = LifecycleTranscript()
        t.grant()
        t.revoke()
        t.call()
        t.finish()
        self.assert_invalid(t)

    def test_consumed_grant_cannot_be_reused(self):
        t = LifecycleTranscript()
        t.grant()
        t.call()
        t.call()
        t.finish()
        self.assert_invalid(t)

    def test_consumed_or_revoked_id_cannot_be_reissued(self):
        for consumed in (False, True):
            t = LifecycleTranscript()
            t.grant()
            if consumed:
                t.call()
            else:
                t.revoke()
            t.grant()
            t.finish()
            with self.subTest(consumed=consumed):
                self.assert_invalid(t)

    def test_wrong_scope_grant_selection_rejected(self):
        for resource, destination in (("secret-b", "sink"), ("secret-a", "other-sink")):
            t = LifecycleTranscript()
            t.grant("g", resource, destination)
            t.grant("valid")
            t.call()
            t.finish()
            with self.subTest(resource=resource, destination=destination):
                self.assert_invalid(t)

    def test_nonminimum_selection_rejected_and_minimum_accepted(self):
        for grant in ("a", "z"):
            t = LifecycleTranscript()
            t.grant("z")
            t.grant("a")
            t.call(selected=((grant, "secret-a"),))
            t.finish()
            with self.subTest(grant=grant):
                if grant == "a":
                    self.assertEqual(project_use_facts(t.records, LIFECYCLE_POLICY, t.profile)[0].grant_id, "a")
                else:
                    self.assert_invalid(t)

    def test_multiscope_complete_selection_and_once_only_use(self):
        t = LifecycleTranscript()
        t.grant("a", "secret-b")
        t.grant("z", "secret-a")
        t.call(direct=("secret-a", "secret-b"), required=("secret-a", "secret-b"),
               selected=(("a", "secret-b"), ("z", "secret-a")))
        t.finish()
        uses = project_use_facts(t.records, LIFECYCLE_POLICY, t.profile)
        self.assertEqual([(f.grant_id, f.scope.resource) for f in uses], [("a", "secret-b"), ("z", "secret-a")])
        self.assertEqual(len({(f.event_id, f.grant_id) for f in uses}), 2)

    def test_multiscope_partial_and_underdeclared_requirements_rejected(self):
        for required in (("secret-a", "secret-b"), ("secret-a",)):
            t = LifecycleTranscript()
            t.grant()
            t.call(direct=("secret-a", "secret-b"), required=required)
            t.finish()
            with self.subTest(required=required):
                self.assert_invalid(t)

    def test_successful_acquisition_and_direct_resources_are_unioned(self):
        t = LifecycleTranscript()
        t.call("read", resource="secret-a")
        t.grant("a")
        t.grant("b", "secret-b")
        t.call(direct=("secret-b",), required=("secret-a", "secret-b"),
               selected=(("a", "secret-a"), ("b", "secret-b")))
        t.finish()
        result = self.reconstruct(t)
        self.assertEqual(result.exposed_resources, frozenset({"secret-a"}))
        self.assertEqual(len(project_use_facts(t.records, LIFECYCLE_POLICY, t.profile)), 2)
        bad = deepcopy(t)
        body = lifecycle_event(bad.records, "DISPATCH_INTENT", 1)["body"]
        body["required_scopes"] = [scope("secret-b")]
        body["selected_grants"] = [{"grant_id": "b", **scope("secret-b")}]
        self.assert_invalid(bad)

    def test_failed_read_does_not_expose_resource(self):
        t = LifecycleTranscript()
        t.call("read", resource="secret-a", outcome="failed")
        t.call(direct=(), required=(), selected=())
        t.finish()
        self.assertEqual(self.reconstruct(t).exposed_resources, frozenset())
        self.assertEqual(project_use_facts(t.records, LIFECYCLE_POLICY, t.profile), ())

    def test_denied_and_unknown_reads_do_not_expose_resource(self):
        for status in ("denied", "unknown"):
            t = LifecycleTranscript()
            denied = status == "denied"
            t.call("read", resource="secret-a", supported=not denied, dispatch=not denied,
                   assessment="INDETERMINATE" if denied else "AUTHORIZED", outcome=status)
            if denied:
                t.call(direct=(), required=(), selected=())
                t.finish()
            result = self.reconstruct(t, require_complete=False)
            with self.subTest(status=status):
                self.assertEqual(result.exposed_resources, frozenset())
                self.assertEqual([f for f in result.facts if f.category == "USE"], [])
                self.assertEqual(result.halted, not denied)
                if not denied:
                    self.assert_invalid(t)

    def test_public_transform_echo_and_failed_read_do_not_clear_exposure(self):
        t = LifecycleTranscript()
        t.call("read", resource="secret-a")
        t.call("echo")
        t.call("transform")
        t.call("read", resource="public")
        t.call("read", resource="secret-b", outcome="failed")
        t.grant()
        t.call(direct=(), required=("secret-a",))
        t.finish()
        self.assertEqual(self.reconstruct(t).exposed_resources, frozenset({"secret-a"}))

    def test_denied_calls_do_not_generate_use(self):
        t = LifecycleTranscript()
        t.call(assessment="UNAUTHORIZED", dispatch=False)
        t.finish()
        self.assertEqual(project_use_facts(t.records, LIFECYCLE_POLICY, t.profile), ())
        self.assertEqual([f.category for f in self.reconstruct(t).facts], ["TOOL_OUTCOME"])

    def test_failed_dispatch_retains_consumption_and_retry_is_denied(self):
        t = LifecycleTranscript()
        t.grant()
        t.call(outcome="failed")
        t.call(assessment="UNAUTHORIZED", dispatch=False)
        t.finish()
        result = self.reconstruct(t)
        self.assertEqual(len(project_use_facts(t.records, LIFECYCLE_POLICY, t.profile)), 1)
        self.assertEqual([f.outcome for f in result.facts if f.category == "TOOL_OUTCOME"], ["failed", "denied"])

    def test_unknown_outcome_retains_use_but_prevents_clean_completion(self):
        t = LifecycleTranscript()
        t.grant()
        t.call(outcome="unknown")
        result = self.reconstruct(t, require_complete=False)
        self.assertTrue(result.halted)
        self.assertFalse(result.closed)
        self.assertEqual(result.active_grants, ())
        self.assertEqual(len(project_use_facts(t.records, LIFECYCLE_POLICY, t.profile, require_complete=False)), 1)
        self.assert_invalid(t)
        t.finish()
        self.assert_invalid(t, require_complete=False)

    def test_unknown_outcome_cannot_be_followed_by_control_or_proposal(self):
        for control_turn in (False, True):
            t = LifecycleTranscript()
            t.grant()
            t.call(outcome="unknown")
            if control_turn:
                t.grant("new")
            else:
                t.call("echo")
            with self.subTest(control=control_turn):
                self.assert_invalid(t, require_complete=False)

    def test_outcomes_and_findings_do_not_infer_use(self):
        t = LifecycleTranscript()
        t.grant()
        t.call("echo")
        for event in t.records:
            if event["event_type"] == "DETECTOR_FINDING":
                event["body"]["explanation"] = "USE g (ignored fixture text)"
        t.finish()
        self.assertEqual(project_use_facts(t.records, LIFECYCLE_POLICY, t.profile), ())
        bad = LifecycleTranscript()
        bad.add("TOOL_OUTCOME", lifecycle_event(t.records, "TOOL_OUTCOME")["body"], "call")
        bad.finish()
        with self.assertRaises(ValueError):
            project_use_facts(bad.records, LIFECYCLE_POLICY, bad.profile)

    def test_control_and_proposal_admission_order_violations_rejected(self):
        for kind in ("GRANT", "CALL_PROPOSAL"):
            for ordinal in ((0, True, 2, 9) if kind == "GRANT" else (0, True, 1, 9)):
                t = self.released()
                lifecycle_event(t.records, kind)["body"]["admission_ordinal"] = ordinal
                with self.subTest(kind=kind, ordinal=ordinal):
                    self.assert_invalid(t)

    def test_control_during_proposal_turn_rejected(self):
        for after_kind in ("CALL_PROPOSAL", "DISPATCH_INTENT", "DETECTOR_FINDING"):
            t = self.released()
            control_event = record("REVOKE_SCOPE", {**control("REVOKE_SCOPE"), "admission_ordinal": 3}, "queued-revoke")
            index = t.records.index(lifecycle_event(t.records, after_kind)) + 1
            t.records.insert(index, control_event)
            resequence(t.records)
            with self.subTest(after=after_kind):
                self.assert_invalid(t)

    def test_duplicate_event_grant_call_and_intent_rejected(self):
        for kind in ("GRANT", "CALL_PROPOSAL", "DISPATCH_INTENT"):
            t = self.released()
            duplicate = deepcopy(lifecycle_event(t.records, kind))
            index = t.records.index(lifecycle_event(t.records, kind)) + 1
            t.records.insert(index, duplicate)
            resequence(t.records)
            with self.subTest(kind=kind):
                self.assert_invalid(t)
        t = LifecycleTranscript()
        t.call("echo")
        t.call("echo")
        t.finish()
        second = lifecycle_event(t.records, "CALL_PROPOSAL", 1)
        second["call_id"] = lifecycle_event(t.records, "CALL_PROPOSAL")["call_id"]
        self.assert_invalid(t)

    def test_missing_reordered_sequence_and_mixed_identity_rejected(self):
        for field, value in (("seq", 9), ("task_id", "other"), ("session_id", "other"),
                             ("monitor_instance_id", "other"), ("run_id", "other")):
            t = self.released()
            t.records[1][field] = value
            with self.subTest(field=field):
                self.assert_invalid(t)
        t = self.released()
        t.records[1], t.records[2] = t.records[2], t.records[1]
        self.assert_invalid(t)

    def test_wrong_release_and_embedded_task_scope_rejected(self):
        for field, value in (("release", "read"), ("task_id", "other")):
            t = self.released()
            lifecycle_event(t.records, "DISPATCH_INTENT")["body"]["selected_grants"][0][field] = value
            with self.subTest(field=field):
                self.assert_invalid(t)

    def test_missing_start_end_or_pending_terminal_rejected(self):
        for kind in ("SESSION_START", "SESSION_END", "DISPATCH_DECISION", "DISPATCH_INTENT", "TOOL_OUTCOME"):
            t = self.released()
            t.records.remove(lifecycle_event(t.records, kind))
            resequence(t.records)
            with self.subTest(missing=kind):
                self.assert_invalid(t)

    def test_prefix_inspection_reports_pending_without_clean_completion(self):
        t = self.released()
        t.records = t.records[:t.records.index(lifecycle_event(t.records, "TOOL_OUTCOME"))]
        result = self.reconstruct(t, require_complete=False)
        self.assertEqual(result.pending_call_id, "call-1")
        self.assertFalse(result.closed)
        self.assertEqual(len([f for f in result.facts if f.category == "USE"]), 1)
        self.assert_invalid(t)

    def test_denied_intent_and_contradictory_outcome_rejected(self):
        t = LifecycleTranscript()
        t.call(assessment="UNAUTHORIZED", dispatch=False)
        t.finish()
        bad = deepcopy(t)
        index = bad.records.index(lifecycle_event(bad.records, "TOOL_OUTCOME"))
        bad.records.insert(index, record("DISPATCH_INTENT", intent(), "forged-intent"))
        bad.records[index]["call_id"] = "call-1"
        bad.records[index]["body"]["call_id"] = "call-1"
        resequence(bad.records)
        self.assert_invalid(bad)
        lifecycle_event(t.records, "TOOL_OUTCOME")["body"]["status"] = "succeeded"
        self.assert_invalid(t)

    def test_outcome_correlation_or_facts_cannot_change(self):
        for field, value in (("server", "other"), ("tool", "read"), ("resource", "secret-b"),
                             ("sensitivity", "public"), ("destination", "other-sink")):
            t = self.released()
            lifecycle_event(t.records, "TOOL_OUTCOME")["body"][field] = value
            with self.subTest(field=field):
                self.assert_invalid(t)

    def test_controller_cannot_relabel_unauthorized_as_authorized(self):
        t = LifecycleTranscript()
        t.call(assessment="UNAUTHORIZED", dispatch=False)
        t.finish()
        lifecycle_event(t.records, "DISPATCH_DECISION")["body"]["authorization_assessment"] = "AUTHORIZED"
        self.assert_invalid(t)

    def test_normal_observation_ignores_shadow_denial_but_requires_authorization(self):
        t = self.released(behavior="SUSPICIOUS")
        self.assertEqual(len(project_use_facts(t.records, LIFECYCLE_POLICY, t.profile)), 1)
        t = LifecycleTranscript()
        t.call(assessment="UNAUTHORIZED", dispatch=False, behavior="ALLOW")
        t.finish()
        self.assertEqual(project_use_facts(t.records, LIFECYCLE_POLICY, t.profile), ())

    def test_enforcement_denial_does_not_consume_available_grant(self):
        t = LifecycleTranscript({**LIFECYCLE_PROFILE, "mode": "enforcement"})
        t.grant()
        t.call(dispatch=False, behavior="SUSPICIOUS")
        result = self.reconstruct(t, require_complete=False)
        self.assertEqual([g for g, _ in result.active_grants], ["g"])
        self.assertEqual(project_use_facts(t.records, LIFECYCLE_POLICY, t.profile, require_complete=False), ())
        t.finish()
        self.reconstruct(t)

    def test_override_is_explicit_synthetic_and_consumes_no_partial_set(self):
        profile = {**LIFECYCLE_PROFILE, "synthetic_local_sink_override": True}
        t = LifecycleTranscript(profile)
        t.grant()
        t.call(direct=("secret-a", "secret-b"), required=("secret-a", "secret-b"), selected=(),
               assessment="UNAUTHORIZED", reservation_status="OBSERVATION_OVERRIDE")
        result = self.reconstruct(t, synthetic_experiment=True, require_complete=False)
        self.assertEqual([g for g, _ in result.active_grants], ["g"])
        self.assertEqual([f for f in result.facts if f.category == "USE"], [])
        t.finish()
        self.reconstruct(t, synthetic_experiment=True)
        self.assert_invalid(t)
        self.assert_invalid(t, synthetic_experiment=True, synthetic_sink="other-sink")

    def test_override_cannot_replace_complete_authorized_reservation(self):
        t = LifecycleTranscript({**LIFECYCLE_PROFILE, "synthetic_local_sink_override": True})
        t.grant()
        t.call(selected=(), reservation_status="OBSERVATION_OVERRIDE")
        t.finish()
        self.assert_invalid(t, synthetic_experiment=True)

    def test_static_prohibition_and_release_disabled_cannot_dispatch(self):
        for disabled in (False, True):
            profile = {**LIFECYCLE_PROFILE, "release_calls_enabled": not disabled}
            t = LifecycleTranscript(profile)
            t.grant(destination="forbidden" if not disabled else "sink")
            t.call(destination="forbidden" if not disabled else "sink", static=not disabled,
                   assessment="UNAUTHORIZED" if not disabled else "AUTHORIZED", dispatch=False)
            t.finish()
            self.assertEqual(project_use_facts(t.records, LIFECYCLE_POLICY, t.profile), ())
            lifecycle_event(t.records, "DISPATCH_DECISION")["body"]["dispatch_decision"] = "ALLOW"
            with self.subTest(disabled=disabled):
                self.assert_invalid(t)

    def test_unregistered_and_inconsistent_current_facts_rejected(self):
        for field, value in (("sensitive_resources", ["unregistered"]), ("sensitivity", "public"),
                             ("static_prohibition", True), ("supported", 1)):
            t = self.released()
            lifecycle_event(t.records, "CALL_PROPOSAL")["body"]["current"][field] = value
            with self.subTest(field=field):
                self.assert_invalid(t)

    def test_unsupported_proposal_is_denied_without_use(self):
        t = LifecycleTranscript()
        t.call("unsupported", assessment="INDETERMINATE", dispatch=False, supported=False)
        t.finish()
        self.assertEqual(project_use_facts(t.records, LIFECYCLE_POLICY, t.profile), ())

    def test_missing_duplicate_late_or_future_referencing_findings_rejected(self):
        for action in ("missing", "duplicate", "late", "future"):
            t = self.released()
            finding = lifecycle_event(t.records, "DETECTOR_FINDING")
            if action == "missing":
                t.records.remove(finding)
            elif action == "duplicate":
                duplicate = deepcopy(finding)
                duplicate["event_id"] = "duplicate-finding"
                t.records.insert(t.records.index(finding) + 1, duplicate)
            elif action == "late":
                t.records.remove(finding)
                t.records.insert(t.records.index(lifecycle_event(t.records, "DISPATCH_INTENT")), finding)
            else:
                finding["body"]["supporting_event_ids"] = [t.records[-1]["event_id"]]
            resequence(t.records)
            with self.subTest(action=action):
                self.assert_invalid(t)

    def test_invalid_inputs_raise_value_error_without_partial_projection(self):
        for records in (None, [], (), [None]):
            with self.subTest(records=records), self.assertRaises(ValueError):
                reconstruct_lifecycle(records, LIFECYCLE_POLICY, LIFECYCLE_PROFILE)
        t = self.released()
        before = deepcopy(t.records)
        result = self.reconstruct(t)
        self.assertEqual(t.records, before)
        lifecycle_event(t.records, "TOOL_OUTCOME")["body"]["status"] = "invalid"
        before = deepcopy(t.records)
        with self.assertRaises(ValueError):
            project_use_facts(t.records, LIFECYCLE_POLICY, t.profile)
        self.assertEqual(t.records, before)
        self.assertEqual(len([f for f in result.facts if f.category == "USE"]), 1)

    def test_malformed_policy_profile_flags_and_nested_input_rejected(self):
        t = self.released()
        for policy in (None, {}, Policy((("a", "A"),), max_payload_bytes=True)):
            with self.subTest(policy=policy), self.assertRaises(ValueError):
                reconstruct_lifecycle(t.records, policy, t.profile)
        with self.assertRaises(ValueError):
            self.reconstruct(t, require_complete=1)
        with self.assertRaises(ValueError):
            self.reconstruct(t, synthetic_experiment=1)
        with self.assertRaises(ValueError):
            self.reconstruct(t, enforcement_detector="B2-R")
        nested = []
        nested.append(nested)
        lifecycle_event(t.records, "CALL_PROPOSAL")["body"]["current"]["resource"] = nested
        self.assert_invalid(t)

    def test_step_one_validator_still_rejects_new_call_records(self):
        t = self.released()
        for kind in ("SESSION_START", "CALL_PROPOSAL", "DISPATCH_DECISION", "TOOL_OUTCOME", "SESSION_END"):
            event = lifecycle_event(t.records, kind)
            validate_lifecycle_record(event)
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                validate_record(event)


if __name__ == "__main__":
    unittest.main()
