"""Focused tests for the unsealed M6 live writer (temporary databases only)."""

from contextlib import closing
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict
from pathlib import Path
import sqlite3
import tempfile
from threading import Barrier
import unittest
from unittest.mock import patch

from chainguard.canonical import decode, encode
from chainguard.evidence import event_hash, genesis, manifest_digest
from chainguard.m6_live_audit import (LiveAmbiguousCommit, LiveAuditError,
    LiveAuditSession, LiveDraft, live_draft, validate_live_record)
from chainguard.m6_live_profile import (EXECUTION_PROFILE, SERVER_ID,
    live_configuration, make_live_manifest)
from chainguard.permission_evidence import DETECTOR_IDS, RECORD_SCHEMA
from chainguard.semantics import Current


def inventory():
    return {"schema_version": "m4-expected-inventory-v1", "run_id": "live-run",
            "run_challenge": "a" * 64,
            "sessions": [{"task_id": "live-task", "session_id": "live-session",
                          "monitor_instance_id": "live-monitor"}]}


def grant(ordinal=1, grant_id="grant-1"):
    return live_draft("GRANT", {"grant_id": grant_id,
        "scope": {"resource": "secret-a", "destination": "sink", "release": "release"},
        "host_origin": "trusted_host", "admission_ordinal": ordinal})


def revoke(ordinal=2):
    return live_draft("REVOKE_SCOPE", {
        "scope": {"resource": "secret-a", "destination": "sink", "release": "release"},
        "host_origin": "trusted_host", "admission_ordinal": ordinal})


def allowed_turn(ordinal=1, call_id="call-1"):
    proposal = live_draft("CALL_PROPOSAL", {"server": SERVER_ID, "tool": "read_public",
        "request_id": 7, "admission_ordinal": ordinal,
        "current": {**asdict(Current("read", "public")), "sensitive_resources": []}},
        call_id=call_id)
    findings = [live_draft("DETECTOR_FINDING", {
        "evaluated_event_id": proposal.event_id, "detector_id": detector,
        "detector_version": "m2-v1", "detector_digest": "b" * 64,
        "policy_digest": "c" * 64, "extraction_version": "m2-v1",
        "behavioral_verdict": "ALLOW", "authorization_assessment": "AUTHORIZED",
        "hypothetical_recommendation": "ALLOW", "rule_id": "none",
        "supporting_event_ids": [], "explanation": "Synthetic fixture finding"},
        call_id=call_id) for detector in DETECTOR_IDS]
    decision = live_draft("DISPATCH_DECISION", {"dispatch_decision": "ALLOW",
        "authorization_assessment": "AUTHORIZED", "reason": "No release obligation"},
        call_id=call_id)
    intent = live_draft("DISPATCH_INTENT", {"call_id": call_id,
        "required_scopes": [], "selected_grants": [],
        "reservation_status": "NO_RELEASE_OBLIGATION"}, call_id=call_id)
    return (proposal, *findings, decision, intent)


def outcome(status="succeeded", call_id="call-1"):
    return live_draft("TOOL_OUTCOME", {"server": SERVER_ID, "tool": "read_public",
        "operation": "read", "resource": "public", "destination": "",
        "status": status, "sensitivity": "public", "transformation": "none"},
        call_id=call_id)


class LiveWriterTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "m6-live.sqlite"
        self.inventory = inventory()
        self.manifest = make_live_manifest(self.inventory, live_configuration(),
            "live-task", "live-session", "live-monitor")
        self.session = LiveAuditSession(self.path, self.manifest, self.inventory)
        self.addCleanup(self.session.close)

    def rows(self):
        with closing(sqlite3.connect(self.path)) as connection:
            return connection.execute("""SELECT seq,record_bytes,event_hash FROM m6_live_records
                ORDER BY seq""").fetchall()

    def test_single_control_and_batched_proposal_append(self):
        control = self.session.append_batch((grant(),))
        self.assertEqual((control.first_seq, control.last_seq, control.batch_count,
                          control.record_count), (2, 2, 1, 2))
        proposal = self.session.append_batch(allowed_turn(2))
        self.assertEqual((proposal.first_seq, proposal.last_seq, proposal.batch_count,
                          proposal.record_count), (3, 9, 7, 9))
        self.assertEqual(proposal.event_types[0], "CALL_PROPOSAL")
        self.assertEqual(proposal.event_types[-1], "DISPATCH_INTENT")
        terminal = self.session.append_batch((outcome(),))
        self.assertEqual((terminal.first_seq, terminal.last_seq), (10, 10))
        self.assertEqual(self.session.state.record_count, 10)
        self.assertEqual(self.session.state.final_head, terminal.final_head)

    def test_exact_readback_receipt_chain_and_canonical_bytes(self):
        receipt = self.session.append_batch((grant(),))
        rows = self.rows()
        self.assertEqual(len(rows), receipt.record_count)
        head = genesis(self.manifest)
        for seq, raw, stored_hash in rows:
            record = decode(raw)
            self.assertEqual(record["schema_version"], RECORD_SCHEMA)
            self.assertEqual(record["seq"], seq)
            self.assertEqual(record["prev_hash"], head)
            self.assertEqual(raw, encode(record))
            validate_live_record(record, self.manifest)
            head = event_hash(record)
            self.assertEqual(stored_hash, head)
        self.assertEqual(receipt.final_head, head)
        self.assertEqual(receipt.event_ids, (decode(rows[-1][1])["event_id"],))
        self.assertEqual(decode(rows[0][1])["body"]["manifest_digest"],
                         manifest_digest(self.manifest))

    def test_canonical_draft_is_independent_of_dict_order(self):
        one = {"grant_id": "g", "scope": {"resource": "secret-a",
               "destination": "sink", "release": "release"},
               "host_origin": "trusted_host", "admission_ordinal": 1}
        two = {"admission_ordinal": 1, "host_origin": "trusted_host",
               "scope": {"release": "release", "destination": "sink",
                         "resource": "secret-a"}, "grant_id": "g"}
        self.assertEqual(live_draft("GRANT", one).body_bytes,
                         live_draft("GRANT", two).body_bytes)

    def test_caller_body_and_draft_are_not_mutated(self):
        body = {"grant_id": "original", "scope": {"resource": "secret-a",
                "destination": "sink", "release": "release"},
                "host_origin": "trusted_host", "admission_ordinal": 1}
        item = live_draft("GRANT", body)
        frozen = item.body_bytes
        body["grant_id"] = "changed"
        body["scope"]["resource"] = "secret-b"
        self.session.append_batch((item,))
        self.assertEqual(item.body_bytes, frozen)
        self.assertEqual(decode(self.rows()[-1][1])["body"]["grant_id"], "original")

    def test_strict_schema_types_and_phase_rejection(self):
        record = decode(self.rows()[0][1])
        record["extra"] = 1
        with self.assertRaises(ValueError):
            validate_live_record(record, self.manifest)
        del record["extra"]
        record["seq"] = True
        with self.assertRaises(ValueError):
            validate_live_record(record, self.manifest)
        with self.assertRaises(ValueError):
            live_draft("USE", {})
        with self.assertRaises(LiveAuditError):
            self.session.append_batch((revoke(),))  # admission skips 1
        self.assertEqual(self.session.state.lifecycle, "HALTED")
        self.assertEqual(len(self.rows()), 1)

    def test_proposal_cannot_be_split_or_forge_a_pre_dispatch_outcome(self):
        turn = allowed_turn()
        with self.assertRaises(LiveAuditError):
            self.session.append_batch((turn[0],))
        self.assertEqual(len(self.rows()), 1)

    def test_duplicate_grant_id_and_control_inside_pending_turn_rejected(self):
        self.session.append_batch((grant(),))
        self.session.append_batch(allowed_turn(2))
        with self.assertRaises(LiveAuditError):
            self.session.append_batch((revoke(3),))
        self.assertEqual(len(self.rows()), 9)

    def test_issued_grant_id_cannot_be_reused_after_revoke(self):
        self.session.append_batch((grant(),))
        self.session.append_batch((revoke(),))
        with self.assertRaises(LiveAuditError):
            self.session.append_batch((grant(3),))
        self.assertEqual(self.session.state.failure, "INVALID_RECORD")
        self.assertEqual(len(self.rows()), 3)

    def test_confirmed_rollback_leaves_head_and_rows_unchanged(self):
        before = self.session.state
        original = self.session._insert_prepared

        def partial(rows):
            original(rows[:1])
            raise sqlite3.IntegrityError("injected after first insert")

        with patch.object(self.session, "_insert_prepared", side_effect=partial):
            with self.assertRaises(LiveAuditError):
                self.session.append_batch(allowed_turn())
        self.assertEqual((self.session.state.record_count, self.session.state.final_head),
                         (before.record_count, before.final_head))
        self.assertEqual(self.session.state.failure, "ROLLED_BACK")
        self.assertEqual(len(self.rows()), 1)

    def test_injected_commit_failure_with_confirmed_rollback(self):
        before = self.session.state
        with patch.object(self.session, "_commit",
                          side_effect=sqlite3.OperationalError("commit refused")) as commit:
            with self.assertRaises(LiveAuditError) as raised:
                self.session.append_batch((grant(),))
        self.assertNotIsInstance(raised.exception, LiveAmbiguousCommit)
        self.assertEqual(commit.call_count, 1)
        self.assertEqual(self.session.state.failure, "ROLLED_BACK")
        self.assertEqual(self.session.state.final_head, before.final_head)
        self.assertEqual(len(self.rows()), 1)

    def test_commit_hook_returning_with_open_transaction_cannot_issue_receipt(self):
        before = self.session.state
        with patch.object(self.session, "_commit", return_value=None) as commit:
            with self.assertRaises(LiveAuditError) as raised:
                self.session.append_batch((grant(),))
        self.assertNotIsInstance(raised.exception, LiveAmbiguousCommit)
        self.assertEqual(commit.call_count, 1)
        self.assertEqual(self.session.state.failure, "ROLLED_BACK")
        self.assertEqual(self.session.state.final_head, before.final_head)
        self.assertEqual(len(self.rows()), 1)

    def test_lost_commit_acknowledgement_is_ambiguous_and_never_retried(self):
        before = self.session.state
        original = self.session._commit

        def lost_ack():
            original()
            raise OSError("lost acknowledgement after commit")

        with patch.object(self.session, "_commit", side_effect=lost_ack) as commit:
            with self.assertRaises(LiveAmbiguousCommit):
                self.session.append_batch((grant(),))
            with self.assertRaises(LiveAuditError):
                self.session.append_batch((grant(),))
        self.assertEqual(commit.call_count, 1)
        self.assertEqual(self.session.state.failure, "AMBIGUOUS_COMMIT")
        self.assertEqual(self.session.state.final_head, before.final_head)
        self.assertEqual(self.session.state.record_count, before.record_count)
        self.assertEqual(len(self.rows()), 2)  # Inspection, never state adoption.

    def test_closed_connection_after_real_commit_halts_without_receipt(self):
        before = self.session.state
        original = self.session._commit

        def committed_then_closed():
            original()
            self.session._connection.close()
            raise OSError("acknowledgement lost after connection closed")

        with patch.object(self.session, "_commit", side_effect=committed_then_closed) as commit:
            with self.assertRaises(LiveAmbiguousCommit):
                self.session.append_batch((grant(),))
            with self.assertRaises(LiveAuditError):
                self.session.append_batch((grant(),))
        self.assertEqual(commit.call_count, 1)
        self.assertEqual(self.session.state.lifecycle, "HALTED")
        self.assertEqual(self.session.state.failure, "TRANSACTION_STATE_UNKNOWN")
        self.assertEqual((self.session.state.record_count, self.session.state.final_head),
                         (before.record_count, before.final_head))
        self.assertEqual(len(self.rows()), 2)  # Durable row is never adopted as authority.

    def test_constructor_cleanup_failure_preserves_ambiguous_start_commit(self):
        path = Path(self.directory.name) / "ambiguous-start.sqlite"
        real_connect = sqlite3.connect

        class LostStartAcknowledgement:
            def __init__(self, connection):
                self.connection = connection
                self.commits = 0
                self.close_calls = 0

            def execute(self, sql, *args):
                result = self.connection.execute(sql, *args)
                if sql == "COMMIT":
                    self.commits += 1
                    if self.commits == 2:
                        raise OSError("SESSION_START acknowledgement lost")
                return result

            def close(self):
                self.close_calls += 1
                self.connection.close()
                raise OSError("cleanup close failed")

            def __getattr__(self, name):
                return getattr(self.connection, name)

        writer = LiveAuditSession.__new__(LiveAuditSession)
        with patch("chainguard.m6_live_audit.sqlite3.connect",
                   side_effect=lambda *args, **kwargs:
                   LostStartAcknowledgement(real_connect(*args, **kwargs))):
            with self.assertRaises(LiveAmbiguousCommit):
                writer.__init__(path, self.manifest, self.inventory)
        self.assertEqual(writer._connection.close_calls, 1)
        self.assertEqual(writer.state.lifecycle, "HALTED")
        self.assertEqual(writer.state.failure, "AMBIGUOUS_COMMIT")
        self.assertEqual(writer.state.record_count, 0)
        self.assertFalse(writer._phase["started"])
        with closing(real_connect(path)) as connection:
            count = connection.execute("""SELECT count(*) FROM m6_live_records
                WHERE event_type='SESSION_START'""").fetchone()[0]
        self.assertEqual(count, 1)

    def test_uninspectable_rollback_state_halts(self):
        connection = self.session._connection

        class UninspectableConnection:
            inspections = 0

            @property
            def in_transaction(self):
                self.inspections += 1
                if self.inspections > 1:
                    raise sqlite3.ProgrammingError("transaction state unavailable")
                return connection.in_transaction

            def __getattr__(self, name):
                return getattr(connection, name)

        with patch.object(self.session, "_connection", UninspectableConnection()):
            with patch.object(self.session, "_insert_prepared",
                              side_effect=sqlite3.IntegrityError("injected insert failure")):
                with self.assertRaises(LiveAmbiguousCommit):
                    self.session.append_batch((grant(),))
        self.assertEqual(self.session.state.lifecycle, "HALTED")
        self.assertEqual(self.session.state.failure, "TRANSACTION_STATE_UNKNOWN")
        self.assertEqual(len(self.rows()), 1)

    def test_rollback_exception_halts_as_ambiguous(self):
        connection = self.session._connection

        class FailedRollbackConnection:
            def rollback(self):
                raise OSError("rollback acknowledgement unavailable")

            def __getattr__(self, name):
                return getattr(connection, name)

        with patch.object(self.session, "_connection", FailedRollbackConnection()):
            with patch.object(self.session, "_insert_prepared",
                              side_effect=sqlite3.IntegrityError("injected insert failure")):
                with self.assertRaises(LiveAmbiguousCommit):
                    self.session.append_batch((grant(),))
        self.assertEqual(self.session.state.lifecycle, "HALTED")
        self.assertEqual(self.session.state.failure, "ROLLBACK_UNCONFIRMED")
        connection.rollback()  # Test cleanup of the deliberately unresolved transaction.
        self.assertEqual(len(self.rows()), 1)

    def test_readback_mismatch_rolls_back(self):
        original = self.session._verify_stored_batch

        def altered(rows):
            self.session._connection.execute("""UPDATE main.m6_live_records
                SET event_hash=? WHERE session_id=? AND seq=?""",
                ("0" * 64, rows[0][0], rows[0][1]))
            original(rows)

        with patch.object(self.session, "_verify_stored_batch", side_effect=altered):
            with self.assertRaises(LiveAuditError):
                self.session.append_batch((grant(),))
        self.assertEqual(self.session.state.failure, "ROLLED_BACK")
        self.assertEqual(len(self.rows()), 1)

    def test_cyclic_and_excessively_nested_inputs_fail_closed(self):
        cycle = {}
        cycle["self"] = cycle
        with self.assertRaises(ValueError):
            live_draft("GRANT", cycle)
        deep = "x"
        for _ in range(1500):
            deep = [deep]
        with self.assertRaises(ValueError):
            live_draft("GRANT", deep)
        raw = b"[" * 1500 + b"0" + b"]" * 1500
        with self.assertRaises(LiveAuditError):
            self.session.append_batch((LiveDraft("GRANT", raw, "", "deep-event"),))
        self.assertEqual(self.session.state.lifecycle, "HALTED")
        self.assertEqual(len(self.rows()), 1)

    def test_unknown_outcome_halts_and_cannot_close(self):
        self.session.append_batch(allowed_turn())
        self.session.append_batch((outcome("unknown"),))
        self.assertEqual(self.session.state.failure, "UNKNOWN_OUTCOME")
        with self.assertRaises(LiveAuditError):
            self.session.append_batch((live_draft("SESSION_END",
                {"closure_status": "CLOSED"}),))

    def test_reopen_does_not_restore_task_or_grant_authority(self):
        self.session.append_batch((grant(),))
        self.session.close()
        with self.assertRaises(LiveAuditError):
            LiveAuditSession(self.path, self.manifest, self.inventory)
        self.assertFalse(hasattr(self.session, "active_grants"))

    def test_concurrent_constructors_cannot_claim_same_task(self):
        path = Path(self.directory.name) / "identity-race.sqlite"
        seed_inventory = {**inventory(), "sessions": [{"task_id": "seed-task",
            "session_id": "seed-session", "monitor_instance_id": "seed-monitor"}]}
        seed_manifest = make_live_manifest(seed_inventory, live_configuration(),
            "seed-task", "seed-session", "seed-monitor")
        seed = LiveAuditSession(path, seed_manifest, seed_inventory)
        seed.close()

        barrier = Barrier(2, timeout=10)
        original = LiveAuditSession._initialize_storage

        def initialize_then_wait(session):
            original(session)
            barrier.wait()

        def construct(number):
            association = {"task_id": "race-task", "session_id": f"race-session-{number}",
                           "monitor_instance_id": "race-monitor"}
            expected = {**inventory(), "sessions": [association]}
            manifest = make_live_manifest(expected, live_configuration(),
                association["task_id"], association["session_id"],
                association["monitor_instance_id"])
            try:
                writer = LiveAuditSession(path, manifest, expected)
                try:
                    return writer.state.lifecycle
                finally:
                    writer.close()
            except LiveAuditError as exc:
                return exc

        with patch.object(LiveAuditSession, "_initialize_storage", initialize_then_wait):
            with ThreadPoolExecutor(max_workers=2) as pool:
                results = list(pool.map(construct, (1, 2)))
        self.assertEqual(results.count("ACTIVE"), 1, results)
        self.assertEqual(len([item for item in results if isinstance(item, LiveAuditError)]), 1)
        with closing(sqlite3.connect(path)) as connection:
            count = connection.execute("""SELECT count(*) FROM m6_live_records
                WHERE task_id='race-task' AND event_type='SESSION_START'""").fetchone()[0]
        self.assertEqual(count, 1)

    def test_distinct_tasks_can_share_one_monitor_instance(self):
        path = Path(self.directory.name) / "shared-monitor.sqlite"
        expected = {**inventory(), "sessions": [
            {"task_id": "task-a", "session_id": "session-a", "monitor_instance_id": "monitor-1"},
            {"task_id": "task-b", "session_id": "session-b", "monitor_instance_id": "monitor-1"}]}
        for task, session_id in (("task-a", "session-a"), ("task-b", "session-b")):
            manifest = make_live_manifest(expected, live_configuration(),
                task, session_id, "monitor-1")
            writer = LiveAuditSession(path, manifest, expected)
            self.addCleanup(writer.close)
            self.assertEqual(writer.state.lifecycle, "ACTIVE")

    def test_reused_session_id_with_distinct_task_is_rejected(self):
        path = Path(self.directory.name) / "session-collision.sqlite"
        for task in ("task-a", "task-b"):
            expected = {**inventory(), "sessions": [{"task_id": task,
                "session_id": "same-session", "monitor_instance_id": f"monitor-{task}"}]}
            manifest = make_live_manifest(expected, live_configuration(),
                task, "same-session", f"monitor-{task}")
            if task == "task-a":
                writer = LiveAuditSession(path, manifest, expected)
                self.addCleanup(writer.close)
            else:
                with self.assertRaises(LiveAuditError):
                    LiveAuditSession(path, manifest, expected)

    def test_disabled_observation_override_rejects_entire_batch(self):
        turn = list(allowed_turn())
        turn[-1] = live_draft("DISPATCH_INTENT", {"call_id": "call-1",
            "required_scopes": [{"resource": "secret-a", "destination": "sink",
                                 "release": "release"}],
            "selected_grants": [], "reservation_status": "OBSERVATION_OVERRIDE"},
            call_id="call-1")
        with self.assertRaises(LiveAuditError) as raised:
            self.session.append_batch(turn)
        self.assertIn("Observation override disabled", str(raised.exception.__cause__))
        self.assertEqual(self.session.state.failure, "INVALID_RECORD")
        self.assertEqual(len(self.rows()), 1)


if __name__ == "__main__":
    unittest.main()
