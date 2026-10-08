"""Real SQLite transactions and the bounded live M3 non-release path."""

from copy import deepcopy
from contextlib import closing
from dataclasses import asdict
import json
import io
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch
from uuid import uuid4

from chainguard.audit import (AuditError, AmbiguousCommit, AuditSession, LiveAudit, RECORD_CLASS,
                             draft, read_records, reconstruct_history, validate_record)
from chainguard.canonical import MAX_INTEGER, decode, encode
from chainguard.m3 import execute_demo, shadows
from chainguard.proxy import run
from chainguard.semantics import Current


ROOT = Path(__file__).resolve().parent.parent
META = {"io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientCapabilities": {}}


def request(request_id=1, name="echo", token="synthetic-token"):
    return {"jsonrpc": "2.0", "id": request_id, "method": "tools/call",
            "params": {"_meta": META, "name": name, "arguments": {"token": token}}}


def response(token="synthetic-token", failed=False):
    return {"result": {"isError": failed, "content": [{"type": "text", "text": token}]}}


def new_session(path, observer=None):
    return AuditSession(path, *(str(uuid4()) for _ in range(4)), observer=observer)


def transaction(call="call", event="proposal"):
    current = asdict(Current("echo"))
    current["sensitive_resources"] = []
    return (draft("CALL_PROPOSAL", {"server": "chainguard-controlled-m1", "tool": "echo",
                 "request_id": 1, "admission_ordinal": 1, "current": current}, call, event),
            draft("DISPATCH_DECISION", {"dispatch_decision": "ALLOW", "authorization_assessment": "AUTHORIZED",
                 "reason": "NON_RELEASE_M1"}, call),
            draft("DISPATCH_INTENT", {"call_id": call, "required_scopes": [], "selected_grants": [],
                 "reservation_status": "NO_RELEASE_OBLIGATION"}, call))


class CanonicalTests(unittest.TestCase):
    def test_fixed_typed_session_end_vector(self):
        record = {"schema_version": "m3-record-v1", "run_id": "run", "task_id": "task",
                  "session_id": "session", "monitor_instance_id": "monitor", "event_id": "end",
                  "seq": 6, "observed_at_utc": "2026-10-08T00:00:00.000000Z", "event_type": "SESSION_END",
                  "body": {"closure_status": "CLOSED_UNSEALED"}}
        expected = (b'{"body":{"closure_status":"CLOSED_UNSEALED"},"event_id":"end",'
                    b'"event_type":"SESSION_END","monitor_instance_id":"monitor",'
                    b'"observed_at_utc":"2026-10-08T00:00:00.000000Z","run_id":"run",'
                    b'"schema_version":"m3-record-v1","seq":6,"session_id":"session","task_id":"task"}')
        validate_record(record)
        self.assertEqual(encode(record), expected)
        self.assertEqual(decode(expected), record)

    def test_fixed_empty_intent_body_vector(self):
        self.assertEqual(transaction()[-1].body_bytes,
            b'{"call_id":"call","required_scopes":[],"reservation_status":"NO_RELEASE_OBLIGATION","selected_grants":[]}')

    def test_fixed_utf8_sorted_compact_vector(self):
        value = {"z": [True, None, -MAX_INTEGER], "a": "λ"}
        expected = b'{"a":"\xce\xbb","z":[true,null,-9007199254740991]}'
        self.assertEqual(encode(value), expected)
        self.assertEqual(decode(expected), value)

    def test_unicode_is_not_normalized(self):
        self.assertNotEqual(encode("é"), encode("e\u0301"))

    def test_invalid_types_ranges_and_unicode(self):
        for value in (1.0, float("nan"), float("inf"), MAX_INTEGER + 1, -MAX_INTEGER - 1,
                      (1,), {1: "key"}, {"raw": b"bytes"}, "\ud800"):
            with self.subTest(value=repr(value)), self.assertRaises((ValueError, UnicodeError)):
                encode(value)

    def test_duplicate_keys_and_noncanonical_bytes_rejected(self):
        for data in (b'{"a":1,"a":1}', b'{ "a":1}', b'{"a":1.0}', b'{"a":NaN}',
                     b'{"a":"\\u03bb"}', b'{"z":0,"a":1}', b'1\n', b'9007199254740992'):
            with self.subTest(data=data), self.assertRaises(ValueError):
                decode(data)


class AuditTests(unittest.TestCase):
    def setUp(self):
        self.directory = TemporaryDirectory(prefix="m3-unit-")
        self.path = Path(self.directory.name) / "audit.sqlite"
        self.witnesses = []
        self.session = new_session(self.path, self.witnesses.append)
        self.session_id = self.session.identity["session_id"]

    def tearDown(self):
        self.session.close()
        self.directory.cleanup()

    def rows(self):
        return read_records(self.path, self.session_id)

    def trigger(self, kind):
        with closing(sqlite3.connect(self.path)) as connection:
            connection.execute(f"""CREATE TRIGGER reject_write BEFORE INSERT ON audit_records
                WHEN NEW.event_type='{kind}' BEGIN SELECT RAISE(ABORT, 'test audit failure'); END""")

    def test_successful_durable_append_and_trusted_head(self):
        gate = LiveAudit(self.session)
        call = gate.before(request())
        self.assertEqual(self.session.state.count, 4)
        self.assertEqual(self.session.state.head, (4, self.rows()[-1]["event_id"]))
        self.assertEqual(self.session.history, ())
        gate.after(call, response())
        self.assertEqual(self.session.state.count, 5)
        self.assertEqual([f.outcome for f in self.session.history], ["succeeded"])
        self.assertEqual(reconstruct_history(self.rows()), self.session.history)
        self.session.finish()
        self.assertEqual(self.session.state.lifecycle, "CLOSED")
        self.assertEqual(self.rows()[-1]["body"], {"closure_status": "CLOSED_UNSEALED"})
        self.assertNotIn("prev_hash", self.rows()[0])

    def test_commit_witness_observes_durable_rows_and_advanced_continuity(self):
        observed = []

        def observer(receipt):
            rows = self.rows()  # A separate SQLite connection sees only committed rows.
            observed.append((receipt.last_seq, len(rows), self.session.state.head))

        self.session._observer = observer
        self.session.append_batch(transaction())
        self.assertEqual(observed, [(4, 4, (4, self.rows()[-1]["event_id"]))])

    def test_prepared_transaction_is_not_commit(self):
        connection = sqlite3.connect(self.path, isolation_level=None)
        try:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute("""INSERT INTO audit_records SELECT session_id, 2, 'uncommitted', event_type,
                call_id,run_id,task_id,monitor_instance_id,record_bytes FROM audit_records WHERE seq=1""")
            self.assertEqual(len(self.rows()), 1)
            self.assertEqual(self.session.state.count, 1)
            connection.execute("ROLLBACK")
        finally:
            connection.close()
        self.assertEqual(len(self.rows()), 1)

    def test_partial_batch_rolls_back_and_never_advances(self):
        self.trigger("DISPATCH_INTENT")
        head = self.session.state.head
        with self.assertRaisesRegex(AuditError, "rolled back"):
            LiveAudit(self.session).before(request())
        self.assertEqual(len(self.rows()), 1)
        self.assertEqual(self.session.state.head, head)
        self.assertEqual(self.session.history, ())
        self.assertEqual(self.session.state.failure, "ROLLED_BACK")
        self.assertEqual(len(self.witnesses), 1)

    def test_ambiguous_after_commit_does_not_adopt_retry_or_claim_rollback(self):
        head = self.session.state.head
        actual_commit = self.session._commit

        def lost_ack():
            actual_commit()
            raise OSError("Injected loss of acknowledgement after SQLite COMMIT")

        with patch.object(self.session, "_commit", side_effect=lost_ack) as commit:
            with self.assertRaises(AmbiguousCommit):
                LiveAudit(self.session).before(request())
            with self.assertRaises(AuditError):
                self.session.append_batch(transaction("retry", "retry-proposal"))
            self.assertEqual(commit.call_count, 1)
        self.assertEqual(len(self.rows()), 4)  # Inspection only: this never advances trusted authority.
        self.assertEqual(self.session.state.head, head)
        self.assertEqual(self.session.state.failure, "AMBIGUOUS_COMMIT")
        self.assertEqual(self.session.history, ())
        self.assertEqual(len(self.witnesses), 1)

    def test_unacknowledged_uncommitted_transaction_also_halts(self):
        with patch.object(self.session, "_commit", side_effect=sqlite3.OperationalError("COMMIT unavailable")):
            with self.assertRaises(AmbiguousCommit):
                LiveAudit(self.session).before(request())
        self.assertEqual(len(self.rows()), 1)
        self.assertEqual(self.session.state.count, 1)
        self.assertEqual(self.session.state.failure, "AMBIGUOUS_COMMIT")

    def test_incomplete_child_transaction_is_rolled_back_on_process_exit(self):
        child = """import sqlite3,sys,os
c=sqlite3.connect(sys.argv[1],isolation_level=None)
c.execute('BEGIN IMMEDIATE')
c.execute("INSERT INTO audit_records SELECT session_id,2,'unfinished',event_type,call_id,run_id,task_id,monitor_instance_id,record_bytes FROM audit_records WHERE seq=1")
os._exit(23)
"""
        result = subprocess.run([sys.executable, "-B", "-c", child, str(self.path)], timeout=10)
        self.assertEqual(result.returncode, 23)
        self.assertEqual(len(self.rows()), 1)
        self.assertEqual(self.session.state.count, 1)

    def test_proposal_cannot_commit_without_decision_and_intent(self):
        with self.assertRaises(AuditError):
            self.session.append_batch(transaction()[:2])
        self.assertEqual(len(self.rows()), 1)
        self.assertEqual(self.session.state.count, 1)

    def test_restart_rejects_old_context_and_inspection_does_not_restore_it(self):
        old = dict(self.session.identity)
        gate = LiveAudit(self.session)
        gate.after(gate.before(request()), response())
        self.session.close()
        history = reconstruct_history(self.rows())
        self.assertEqual(len(history), 1)
        with self.assertRaisesRegex(ValueError, "fresh"):
            AuditSession(self.path, old["run_id"], old["task_id"], old["session_id"], "new-challenge")
        fresh = new_session(self.path)
        try:
            self.assertNotEqual(fresh.identity["monitor_instance_id"], old["monitor_instance_id"])
            self.assertEqual(fresh.state.count, 1)
            self.assertEqual(fresh.history, ())
            self.assertEqual(fresh.state.lifecycle, "ACTIVE")
        finally:
            fresh.close()

    def test_no_append_after_closure(self):
        self.session.finish()
        head = self.session.state.head
        with self.assertRaises(AuditError):
            self.session.append_batch(transaction())
        self.assertEqual(self.session.state.head, head)

    def test_unknown_outcome_commits_then_halts_and_prevents_closure(self):
        gate = LiveAudit(self.session)
        call = gate.before(request())
        gate.unknown(call)
        self.assertEqual(self.session.state.count, 5)
        self.assertEqual(self.session.state.failure, "UNKNOWN_OUTCOME")
        self.assertEqual(self.session.history[-1].outcome, "unknown")
        with self.assertRaises(AuditError):
            gate.before(request(2))
        with self.assertRaises(AuditError):
            self.session.finish()

    def test_duplicate_event_rejected(self):
        original = self.rows()[0]["event_id"]
        with self.assertRaises(AuditError):
            self.session.append_batch(transaction(event=original))
        self.assertEqual(len(self.rows()), 1)

    def test_duplicate_intent_rejected_atomically(self):
        batch = transaction()
        duplicate = draft("DISPATCH_INTENT", decode(batch[-1].body_bytes), "call")
        with self.assertRaises(AuditError):
            self.session.append_batch((*batch, duplicate))
        self.assertEqual(len(self.rows()), 1)

    def test_repeated_call_attempt_id_rejected(self):
        self.session.append_batch(transaction())
        current = Current("echo")
        self.session.append_batch((LiveAudit(self.session)._outcome("call", "echo", current, "succeeded"),))
        with self.assertRaises(AuditError):
            self.session.append_batch(transaction(event="new-proposal"))
        self.assertEqual(len(self.rows()), 5)

    def test_control_roundtrip_primitives_do_not_activate_permissions(self):
        scope = {"resource": "synthetic-resource", "destination": "sink", "release": "release"}
        self.session.append_batch((draft("GRANT", {"grant_id": "opaque-g", "scope": scope, "host_origin": "trusted_host"}),))
        self.session.append_batch((draft("REVOKE_SCOPE", {"scope": scope, "host_origin": "trusted_host"}),))
        self.assertEqual([f.category for f in reconstruct_history(self.rows())], ["GRANT", "REVOKE_SCOPE"])
        denied = LiveAudit(self.session).before(request(name="send"))
        self.assertIsNone(denied)  # Stored controls cannot enable an M3 release call.
        self.assertFalse(any(r["event_type"] == "DISPATCH_INTENT" for r in self.rows()))

    def test_duplicate_grant_id_rejected(self):
        body = {"grant_id": "g", "scope": {"resource": "r", "destination": "sink", "release": "release"},
                "host_origin": "trusted_host"}
        self.session.append_batch((draft("GRANT", body),))
        with self.assertRaises(AuditError):
            self.session.append_batch((draft("GRANT", body),))
        self.assertEqual(len(self.rows()), 2)

    def test_use_is_not_an_independently_appendable_record(self):
        with self.assertRaises(AuditError):
            self.session.append_batch((draft("USE", {"grant_id": "g"}),))
        self.assertEqual(self.session.history, ())

    def test_drafts_and_reader_outputs_cannot_mutate_committed_bytes(self):
        body = {"grant_id": "g", "scope": {"resource": "r", "destination": "sink", "release": "release"},
                "host_origin": "trusted_host"}
        item = draft("GRANT", body)
        body["scope"]["resource"] = "changed"
        self.session.append_batch((item,))
        rows = self.rows()
        rows[1]["body"]["scope"]["resource"] = "changed-again"
        self.assertEqual(self.rows()[1]["body"]["scope"]["resource"], "r")
        self.assertEqual(self.session.history[0].scope.resource, "r")

    def test_detector_findings_cannot_authorize_or_create_semantic_facts(self):
        def contradict(current, history, proposal, task):
            results = deepcopy(shadows(current, history, proposal, task))
            for body in results:
                body["behavioral_verdict"] = "POLICY_VIOLATION"
                body["authorization_assessment"] = "UNAUTHORIZED"
                body["hypothetical_recommendation"] = "DENY"
            return results

        gate = LiveAudit(self.session, contradict)
        call = gate.before(request())
        self.assertIsNotNone(call)  # Approved M3 non-release controller decision.
        self.assertEqual(self.session.history, ())
        gate.after(call, response())
        self.assertEqual([f.category for f in self.session.history], ["TOOL_OUTCOME"])
        self.assertEqual(reconstruct_history(self.rows()), self.session.history)
        self.assertEqual(len([r for r in self.rows() if r["event_type"] == "DETECTOR_FINDING"]), 4)

    def test_unknown_fields_and_versions_rejected(self):
        record = self.rows()[0]
        for mutated in ({**record, "prev_hash": "pretend"}, {**record, "schema_version": "m4"},
                        {**record, "body": {**record["body"], "payload": "raw"}}):
            with self.subTest(mutated=mutated), self.assertRaises(ValueError):
                validate_record(mutated)

    def test_nonempty_intent_selection_rejected(self):
        batch = transaction()
        body = decode(batch[-1].body_bytes)
        body["selected_grants"] = [{"grant_id": "g"}]
        with self.assertRaises(AuditError):
            self.session.append_batch((*batch[:-1], draft("DISPATCH_INTENT", body, "call")))
        self.assertEqual(len(self.rows()), 1)

    def test_only_terminal_outcome_enters_history_on_controlled_error(self):
        gate = LiveAudit(self.session)
        call = gate.before(request(name="controlled_failure", token="x"))
        self.assertEqual(self.session.history, ())
        gate.after(call, response("controlled failure: x", True))
        self.assertEqual([f.outcome for f in reconstruct_history(self.rows())], ["failed"])

    def test_client_delivery_failure_retains_known_committed_tool_outcome(self):
        class BrokenClient(io.BytesIO):
            def write(self, data):
                raise OSError("Injected upstream pipe closure")

        real_popen = subprocess.Popen

        def quiet_server(command, **kwargs):
            return real_popen(command, stderr=subprocess.DEVNULL, **kwargs)

        with patch("chainguard.proxy.subprocess.Popen", side_effect=quiet_server), patch("chainguard.proxy.diagnostic"):
            with self.assertRaises(OSError):
                run(io.BytesIO(json.dumps(request()).encode() + b"\n"), BrokenClient(), LiveAudit(self.session))
        self.assertEqual(self.session.state.failure, "CLIENT_RESPONSE_DELIVERY_FAILED")
        self.assertEqual([f.outcome for f in self.session.history], ["succeeded"])
        self.assertEqual([f.outcome for f in reconstruct_history(self.rows())], ["succeeded"])


class DurabilityGateTests(unittest.TestCase):
    def setUp(self):
        self.directory = TemporaryDirectory(prefix="m3-durability-")
        self.path = Path(self.directory.name) / "audit.sqlite"
        self.receipts = []
        self.session = new_session(self.path, self.receipts.append)

    def tearDown(self):
        self.session.close()
        self.directory.cleanup()

    def assert_failed_without_advancement(self, action):
        before, receipts, history = self.session.state, list(self.receipts), self.session.history
        with self.assertRaises(AuditError):
            action()
        self.assertEqual(self.session.state.count, before.count)
        self.assertEqual(self.session.state.head, before.head)
        self.assertEqual(self.session.history, history)
        self.assertEqual(self.receipts, receipts)
        self.assertEqual(self.session.state.failure, "ROLLED_BACK")
        self.assertFalse(self.session._connection.in_transaction)
        self.assertEqual(len(read_records(self.path, self.session.identity["session_id"])), before.count)

    def test_silent_suppression_schema_is_rejected(self):
        with closing(sqlite3.connect(self.path)) as connection:
            connection.execute("""CREATE TRIGGER ignore_intent BEFORE INSERT ON audit_records
                WHEN NEW.event_type='DISPATCH_INTENT' BEGIN SELECT RAISE(IGNORE); END""")
        self.assert_failed_without_advancement(lambda: LiveAudit(self.session).before(request()))

    def test_exact_bytes_readback_failure_rolls_back_noncryptographic_batch(self):
        insert = self.session._insert_prepared

        def rewrite(rows):
            insert(rows)
            event = decode(rows[-1][8])
            event["observed_at_utc"] = "2099-01-01T00:00:00Z"
            self.session._connection.execute("UPDATE audit_records SET record_bytes=? WHERE seq=?",
                                             (encode(event), rows[-1][1]))

        with patch.object(self.session, "_insert_prepared", side_effect=rewrite):
            self.assert_failed_without_advancement(lambda: LiveAudit(self.session).before(request()))
        self.assertFalse(hasattr(self.session.state, "cryptographic_head"))

    def test_whole_batch_missing_record_rolls_back(self):
        insert = self.session._insert_prepared

        def remove(rows):
            insert(rows)
            self.session._connection.execute("DELETE FROM audit_records WHERE seq=?", (rows[0][1],))

        with patch.object(self.session, "_insert_prepared", side_effect=remove):
            self.assert_failed_without_advancement(lambda: LiveAudit(self.session).before(request()))

    def test_write_lock_protects_schema_and_readback_until_commit(self):
        validate = self.session._validate_storage_schema
        verify = self.session._verify_stored_batch
        checked = []

        def other_writer_blocked(operation):
            with closing(sqlite3.connect(self.path, timeout=0)) as other:
                with self.assertRaises(sqlite3.OperationalError):
                    other.execute("CREATE TRIGGER concurrent_sabotage BEFORE INSERT ON audit_records BEGIN SELECT RAISE(IGNORE); END")
            checked.append(operation)

        def validated():
            validate()
            other_writer_blocked("schema")

        def verified(rows):
            verify(rows)
            other_writer_blocked("readback")

        with patch.object(self.session, "_validate_storage_schema", side_effect=validated), \
             patch.object(self.session, "_verify_stored_batch", side_effect=verified):
            LiveAudit(self.session).before(request())
        self.assertEqual(checked, ["schema", "readback"])
        self.assertEqual(self.session.state.count, 4)

    def test_validation_failure_with_uncertain_rollback_is_ambiguous(self):
        connection = self.session._connection

        class UncertainRollback:
            def __getattr__(self, name):
                return getattr(connection, name)

            def rollback(self):
                raise sqlite3.OperationalError("Fixture rollback acknowledgement lost")

        before, receipts = self.session.state, list(self.receipts)
        with patch.object(self.session, "_connection", UncertainRollback()), \
             patch.object(self.session, "_verify_stored_batch", side_effect=ValueError("Fixture mismatch")), \
             self.assertRaises(AmbiguousCommit):
            LiveAudit(self.session).before(request())
        self.assertEqual(self.session.state.count, before.count)
        self.assertEqual(self.session.state.head, before.head)
        self.assertEqual(self.receipts, receipts)
        self.assertEqual(self.session.state.failure, "ROLLBACK_UNCONFIRMED")
        connection.rollback()  # Test cleanup only; the monitor never reconciles/retries.


class LiveIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.directory = TemporaryDirectory(prefix="m3-live-")
        self.path = Path(self.directory.name) / "audit.sqlite"

    def tearDown(self):
        self.directory.cleanup()

    def launch(self, requests, child=None):
        identities = {k: str(uuid4()) for k in ("run_id", "task_id", "session_id", "challenge")}
        if child is None:
            command = [sys.executable, "-B", "-u", "-m", "chainguard.m3", "proxy", "--db", str(self.path)]
            for key, value in identities.items():
                command.extend(["--" + key.replace("_", "-"), value])
        else:
            command = [sys.executable, "-B", "-u", "-c", child, str(self.path), *identities.values()]
        result = subprocess.run(command, cwd=ROOT, env={**os.environ, "PYTHONUTF8": "1"},
            input=b"".join(json.dumps(r).encode() + b"\n" for r in requests),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
        trace = [json.loads(line) for line in result.stderr.decode().splitlines() if line.startswith("{")]
        return result, trace, read_records(self.path, identities["session_id"])

    def failing_write_child(self, kind):
        # Install only inside the target transaction via a trusted test hook.
        # Preinstalled triggers now correctly fail initialization, which would
        # no longer exercise these tests' dispatch/outcome SQL-error boundaries.
        return f"""import sys
from chainguard.audit import AuditSession,LiveAudit
from chainguard.m3 import shadows
from chainguard.proxy import run
class FailWrite(AuditSession):
 def _insert_prepared(self,rows):
  if any(row[3]=='{kind}' for row in rows):
   self._connection.execute(\"CREATE TRIGGER reject_live_write BEFORE INSERT ON audit_records WHEN NEW.event_type='{kind}' BEGIN SELECT RAISE(ABORT, 'injected real write failure'); END\")
  super()._insert_prepared(rows)
s=FailWrite(*sys.argv[1:])
status=run(sys.stdin.buffer,sys.stdout.buffer,LiveAudit(s,shadows))
s.close()
raise SystemExit(status)
"""

    def test_real_audited_success_error_success_and_redaction(self):
        report = execute_demo(self.path)
        self.assertEqual(report["tool_outcomes"], ["succeeded", "failed", "succeeded"])
        self.assertEqual(report["handler_request_ids"], [3, 4, 5])
        self.assertEqual(report["confirmed_transactions"], 8)
        self.assertEqual(report["record_count"], 26)
        self.assertEqual(report["record_class"], RECORD_CLASS)
        records = read_records(self.path, report["expected_context"]["session_id"])
        persisted = encode(list(records))
        self.assertNotIn(b"m3-success-A", persisted)
        self.assertNotIn(b"m3-failure-B", persisted)
        self.assertNotIn(b"m3-success-C", persisted)
        for intent in (r for r in records if r["event_type"] == "DISPATCH_INTENT"):
            self.assertEqual(intent["body"]["selected_grants"], [])
        self.assertEqual([r["body"]["admission_ordinal"] for r in records if r["event_type"] == "CALL_PROPOSAL"], [1, 2, 3])
        witnesses = report["commit_witnesses"]
        self.assertEqual([w["first_seq"] for w in witnesses], [1, 2, 9, 10, 17, 18, 25, 26])
        self.assertEqual([w["last_seq"] for w in witnesses], [1, 8, 9, 16, 17, 24, 25, 26])

    def test_failed_required_transaction_blocks_real_forwarding(self):
        result, trace, records = self.launch([request(1), request(2)], self.failing_write_child("DISPATCH_INTENT"))
        self.assertEqual(result.returncode, 2)
        self.assertEqual(len(result.stdout.splitlines()), 1)
        self.assertFalse(any(r.get("phase") in {"forwarded", "tool_received"} for r in trace))
        self.assertEqual(len(records), 1)
        self.assertEqual([r["failure"] for r in trace if r.get("phase") == "audit_failure"], ["ROLLED_BACK"])

    def test_outcome_audit_failure_cannot_undo_executed_call_or_cleanly_close(self):
        result, trace, records = self.launch([request(1), request(2)], self.failing_write_child("TOOL_OUTCOME"))
        self.assertEqual(result.returncode, 2)
        self.assertEqual(len([r for r in trace if r.get("phase") == "tool_received"]), 1)
        self.assertEqual(len([r for r in trace if r.get("phase") == "forwarded"]), 1)
        self.assertEqual(len(records), 8)
        self.assertFalse(any(r["event_type"] in {"TOOL_OUTCOME", "SESSION_END"} for r in records))

    def test_m3_release_surface_is_denied_before_dispatch(self):
        result, trace, records = self.launch([request(1, "send"), request(2)])
        self.assertEqual(result.returncode, 0)
        self.assertEqual(json.loads(result.stdout.splitlines()[0])["error"]["code"], -32602)
        self.assertEqual([r["request_id"] for r in trace if r.get("phase") == "tool_received"], [2])
        history = reconstruct_history(records)
        self.assertEqual([f.outcome for f in history], ["denied", "succeeded"])
        self.assertEqual(len([r for r in records if r["event_type"] == "DISPATCH_INTENT"]), 1)

    def test_ambiguous_commit_blocks_actual_relay_and_is_not_retried(self):
        child = """import sys,sqlite3
from chainguard.audit import AuditSession,LiveAudit
from chainguard.proxy import run,diagnostic
class LostAck(AuditSession):
 def _commit(self):
  super()._commit()
  if self.state.count: raise sqlite3.OperationalError('lost acknowledgement')
s=LostAck(*sys.argv[1:])
status=run(sys.stdin.buffer,sys.stdout.buffer,LiveAudit(s))
diagnostic('trusted_test_state',count=s.state.count,failure=s.state.failure)
s.close()
raise SystemExit(status)
"""
        result, trace, records = self.launch([request(1), request(2)], child)
        self.assertEqual(result.returncode, 2)
        self.assertFalse(any(r.get("phase") in {"forwarded", "tool_received"} for r in trace))
        self.assertEqual(len(records), 4)
        state = next(r for r in trace if r.get("phase") == "trusted_test_state")
        self.assertEqual((state["count"], state["failure"]), (1, "AMBIGUOUS_COMMIT"))
        self.assertEqual(len(result.stdout.splitlines()), 1)

    def test_downstream_loss_records_unknown_and_stops_without_replay(self):
        child = """import sys,subprocess
from unittest.mock import patch
from chainguard.audit import AuditSession,LiveAudit
from chainguard.proxy import run
s=AuditSession(*sys.argv[1:])
real_popen=subprocess.Popen
def disconnect(command,**kwargs):
 return real_popen([sys.executable,'-u','-c','import sys; sys.stdin.buffer.readline()'],**kwargs)
with patch('chainguard.proxy.subprocess.Popen',side_effect=disconnect):
 status=run(sys.stdin.buffer,sys.stdout.buffer,LiveAudit(s))
s.close()
raise SystemExit(status)
"""
        result, trace, records = self.launch([request(1), request(2)], child)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(len([r for r in trace if r.get("phase") == "forwarded"]), 1)
        self.assertEqual([f.outcome for f in reconstruct_history(records)], ["unknown"])
        self.assertFalse(any(r["event_type"] == "SESSION_END" for r in records))
        self.assertEqual(len(result.stdout.splitlines()), 1)


if __name__ == "__main__":
    unittest.main()
