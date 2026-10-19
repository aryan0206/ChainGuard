"""Confirmed-write tests for the standalone M6 task authority."""

from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from dataclasses import replace
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch
from uuid import uuid4

from chainguard.canonical import decode
from chainguard.m6_live_audit import LiveAmbiguousCommit, LiveAuditError, LiveAuditSession
from chainguard.m6_live_authorization import (AuthorizationError, DispatchPermit,
                                               LiveAuthorizationTask)
from chainguard.m6_live_profile import live_configuration, make_live_manifest
from chainguard.permission_evidence import DETECTOR_IDS
from chainguard.semantics import Scope


def findings():
    return {detector: {"evaluated_event_id": "filled-by-authority",
        "detector_id": detector, "detector_version": "m2-v1",
        "detector_digest": "b" * 64, "policy_digest": "c" * 64,
        "extraction_version": "m2-v1", "behavioral_verdict": "ALLOW",
        "authorization_assessment": "AUTHORIZED",
        "hypothetical_recommendation": "ALLOW", "rule_id": "none",
        "supporting_event_ids": [], "explanation": "Synthetic fixture finding"}
        for detector in DETECTOR_IDS}


class LiveAuthorizationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "live.sqlite"
        self.run_id = uuid4().hex
        self.task_a = "task-a-" + self.run_id
        self.task_b = "task-b-" + self.run_id
        self.inventory = {"schema_version": "m4-expected-inventory-v1", "run_id": self.run_id,
            "run_challenge": "a" * 64, "sessions": [
                {"task_id": self.task_a, "session_id": "session-a",
                 "monitor_instance_id": "monitor-a"},
                {"task_id": self.task_b, "session_id": "session-b",
                 "monitor_instance_id": "monitor-b"}]}
        self.audit = self.make_audit(self.task_a, "session-a", "monitor-a")
        self.task = LiveAuthorizationTask(self.audit)
        self.a = Scope(self.task_a, "secret-a", "sink")
        self.b = Scope(self.task_a, "secret-b", "sink")

    def make_audit(self, task, session, monitor, path=None):
        manifest = make_live_manifest(self.inventory, live_configuration(),
                                      task, session, monitor)
        audit = LiveAuditSession(path or self.path, manifest, self.inventory)
        self.addCleanup(audit.close)
        return audit

    def call(self, call_id, tool, arguments=None, task=None):
        return (task or self.task).admit_call(call_id, tool, call_id, arguments or {}, findings())

    def intent_bodies(self, session="session-a"):
        with closing(sqlite3.connect(self.path)) as connection:
            rows = connection.execute("""SELECT record_bytes FROM m6_live_records
                WHERE session_id=? AND event_type='DISPATCH_INTENT' ORDER BY seq""",
                (session,)).fetchall()
        return [decode(raw)["body"] for (raw,) in rows]

    def read_secret(self, resource="a"):
        permit = self.call("read-" + resource, "read_secret_" + resource)
        self.task.take_dispatch(permit)
        self.task.record_outcome(permit, "succeeded")

    def test_grant_one_use_and_consumed_retry_denial(self):
        self.task.grant("g-1", self.a)
        self.read_secret()
        permit = self.call("send-1", "send_sink", {"payload": "public"})
        self.assertIsInstance(permit, DispatchPermit)
        self.assertEqual((permit.run_id, permit.task_id, permit.session_id,
                          permit.call_id, permit.request_id),
                         (self.run_id, self.task_a, "session-a", "send-1", "send-1"))
        with self.assertRaises(AuthorizationError):
            self.task.record_outcome(permit, "succeeded")  # Not yet dispatched.
        self.task.take_dispatch(permit)
        with self.assertRaises(AuthorizationError):
            self.task.take_dispatch(permit)
        self.task.record_outcome(permit, "failed")
        self.assertIsNone(self.call("send-2", "send_sink", {"payload": "public"}))
        self.task.close()
        self.assertEqual(self.audit.state.lifecycle, "CLOSED_UNSEALED")

    def test_wrong_task_exact_revoke_tombstones_and_new_id(self):
        wrong = Scope(self.task_b, "secret-a", "sink")
        with self.assertRaises(ValueError):
            self.task.grant("wrong", wrong)
        with self.assertRaises(ValueError):
            self.task.revoke(wrong)
        self.task.grant("g-a", self.a)
        self.task.grant("g-b", self.b)
        self.task.revoke(Scope(self.task_a, "secret-a", "other-sink"))
        self.read_secret("a")
        self.assertIsInstance(self.call("send-1", "send_sink", {"payload": "public"}),
                              DispatchPermit)  # Wrong-destination revoke did not apply.
        self.task.halt_uncertain()  # Intent remains consumed; no automatic refund.

    def test_active_unconsumed_revoke_denies_then_new_grant_restores(self):
        self.task.grant("old", self.a)
        self.task.revoke(self.a)
        with self.assertRaises(ValueError):
            self.task.grant("old", self.a)
        self.read_secret()
        self.assertIsNone(self.call("denied", "send_sink", {"payload": "public"}))
        self.task.grant("new", self.a)
        permit = self.call("allowed", "send_sink", {"payload": "public"})
        self.assertIsInstance(permit, DispatchPermit)

    def test_multi_scope_all_or_nothing_and_minimum_id(self):
        self.task.grant("z", self.a)
        self.task.grant("a", self.a)
        self.read_secret("a")
        self.read_secret("b")
        self.assertIsNone(self.call("missing-b", "send_sink", {"payload": "public"}))
        self.task.grant("b", self.b)
        permit = self.call("covered", "send_sink", {"payload": "public"})
        self.assertIsInstance(permit, DispatchPermit)
        self.assertEqual([row["grant_id"] for row in
                          self.intent_bodies()[-1]["selected_grants"]], ["a", "b"])
        # The unused z grant still covers A, but B was consumed.
        self.task.take_dispatch(permit)
        self.task.record_outcome(permit, "succeeded")
        self.assertIsNone(self.call("missing-b-again", "send_sink", {"payload": "public"}))

    def test_task_isolation_and_owner_exclusivity(self):
        with self.assertRaises(ValueError):
            LiveAuthorizationTask(self.audit)
        other_audit = self.make_audit(self.task_b, "session-b", "monitor-b")
        other = LiveAuthorizationTask(other_audit)
        other.grant("g-1", Scope(self.task_b, "secret-a", "sink"))
        self.assertIsNone(self.call("a-send", "send_sink", {"payload": "SYNTHETIC_CANARY_A"}))
        with self.assertRaises(ValueError):
            other.revoke(self.a)
        self.assertIsInstance(self.call("b-send", "send_sink",
                                        {"payload": "SYNTHETIC_CANARY_A"}, other),
                              DispatchPermit)

    def test_same_task_on_different_database_cannot_claim_second_authority(self):
        second = self.make_audit(self.task_a, "session-a", "monitor-a",
                                 Path(self.temp.name) / "second.sqlite")
        with self.assertRaisesRegex(ValueError, "identity already"):
            LiveAuthorizationTask(second)
        self.task.grant("still-owned", self.a)

    def test_same_task_id_in_another_run_cannot_claim_authority(self):
        inventory = {"schema_version": "m4-expected-inventory-v1",
                     "run_id": uuid4().hex, "run_challenge": "b" * 64,
                     "sessions": [{"task_id": self.task_a, "session_id": "new-session",
                                   "monitor_instance_id": "new-monitor"}]}
        manifest = make_live_manifest(inventory, live_configuration(),
                                      self.task_a, "new-session", "new-monitor")
        second = LiveAuditSession(Path(self.temp.name) / "new-run.sqlite",
                                  manifest, inventory)
        self.addCleanup(second.close)
        with self.assertRaisesRegex(ValueError, "identity already"):
            LiveAuthorizationTask(second)

    def test_failed_initialization_cannot_use_or_release_another_claim(self):
        second = self.make_audit(self.task_a, "session-a", "monitor-a",
                                 Path(self.temp.name) / "second.sqlite")
        failed = LiveAuthorizationTask.__new__(LiveAuthorizationTask)
        with self.assertRaisesRegex(ValueError, "identity already"):
            failed.__init__(second)
        with self.assertRaises(AuthorizationError):
            failed.grant("unauthorized", self.a)
        third = self.make_audit(self.task_a, "session-a", "monitor-a",
                                Path(self.temp.name) / "third.sqlite")
        with self.assertRaisesRegex(ValueError, "identity already"):
            LiveAuthorizationTask(third)
        self.task.grant("original-owner", self.a)
        other_audit = self.make_audit(self.task_b, "session-b", "monitor-b",
                                      Path(self.temp.name) / "other.sqlite")
        other = LiveAuthorizationTask(other_audit)
        other.grant("independent", Scope(self.task_b, "secret-a", "sink"))

    def test_concurrent_cross_thread_admission_is_rejected(self):
        def issue(_):
            try:
                self.task.grant("same", self.a)
                return "issued"
            except AuthorizationError:
                return "wrong-thread"
        with ThreadPoolExecutor(max_workers=2) as pool:
            self.assertEqual(sorted(pool.map(issue, range(2))),
                             ["wrong-thread", "wrong-thread"])
        self.task.grant("same", self.a)
        with self.assertRaises(ValueError):
            self.task.grant("same", self.a)
        self.task.grant("next", self.b)  # Ordinal remained contiguous.

    def test_wrong_permit_copy_and_cross_task_permit_fail(self):
        permit = self.call("read", "read_public")
        with self.assertRaises(AuthorizationError):
            self.task.grant("late", self.a)
        with self.assertRaises(AuthorizationError):
            self.task.revoke(self.a)
        with self.assertRaises(AuthorizationError):
            self.task.take_dispatch(replace(permit))
        other_audit = self.make_audit(self.task_b, "session-b", "monitor-b")
        other = LiveAuthorizationTask(other_audit)
        with self.assertRaises(AuthorizationError):
            other.take_dispatch(permit)
        self.task.take_dispatch(permit)
        self.task.record_outcome(permit, "succeeded")

    def test_wrong_thread_cannot_take_permit(self):
        permit = self.call("read", "read_public")
        with ThreadPoolExecutor(max_workers=1) as pool:
            with self.assertRaises(AuthorizationError):
                pool.submit(self.task.take_dispatch, permit).result()
        self.task.take_dispatch(permit)
        self.task.record_outcome(permit, "succeeded")

    def test_consumed_grant_id_cannot_be_reissued(self):
        self.task.grant("used", self.a)
        self.read_secret()
        permit = self.call("send", "send_sink", {"payload": "public"})
        self.task.take_dispatch(permit)
        self.task.record_outcome(permit, "failed")
        with self.assertRaises(ValueError):
            self.task.grant("used", self.a)
        self.task.grant("new", self.a)

    def test_confirmed_rollback_never_activates_grant_or_permit(self):
        with patch.object(self.audit, "_commit",
                          side_effect=sqlite3.OperationalError("commit refused")):
            with self.assertRaises(LiveAuditError):
                self.task.grant("g", self.a)
        self.assertEqual(self.audit.state.failure, "ROLLED_BACK")
        with self.assertRaises(AuthorizationError):
            self.call("later", "read_public")

    def test_lost_commit_acknowledgement_never_activates_grant(self):
        real_commit = self.audit._commit
        def lost_ack():
            real_commit()
            raise OSError("acknowledgement lost")
        with patch.object(self.audit, "_commit", side_effect=lost_ack):
            with self.assertRaises(LiveAmbiguousCommit):
                self.task.grant("g", self.a)
        self.assertEqual(self.audit.state.failure, "AMBIGUOUS_COMMIT")
        with self.assertRaises(AuthorizationError):
            self.task.grant("g-new", self.a)

    def test_failed_and_ambiguous_pre_dispatch_batch_never_returns_permit(self):
        for ambiguous in (False, True):
            with self.subTest(ambiguous=ambiguous):
                audit = self.make_audit(self.task_b, "session-b", "monitor-b") if ambiguous else self.audit
                task = LiveAuthorizationTask(audit) if ambiguous else self.task
                real_commit = audit._commit
                effect = (lambda: (real_commit(), (_ for _ in ()).throw(OSError("lost ack")))) \
                    if ambiguous else sqlite3.OperationalError("commit refused")
                with patch.object(audit, "_commit", side_effect=effect):
                    with self.assertRaises(LiveAuditError):
                        self.call("read", "read_public", task=task)
                with self.assertRaises(AuthorizationError):
                    self.call("retry", "read_public", task=task)

    def test_failed_reservation_keeps_whole_grant_set_unconsumed(self):
        self.task.grant("g-a", self.a)
        self.task.grant("g-b", self.b)
        self.read_secret("a")
        self.read_secret("b")
        before = dict(self.task._active)
        with patch.object(self.audit, "_commit",
                          side_effect=sqlite3.OperationalError("reservation refused")):
            with self.assertRaises(LiveAuditError):
                self.call("send", "send_sink", {"payload": "public"})
        self.assertEqual(self.task._active, before)
        self.assertEqual(self.intent_bodies(), [
            {"call_id": "read-a", "required_scopes": [], "selected_grants": [],
             "reservation_status": "NO_RELEASE_OBLIGATION"},
            {"call_id": "read-b", "required_scopes": [], "selected_grants": [],
             "reservation_status": "NO_RELEASE_OBLIGATION"}])

    def test_unknown_outcome_halts_with_consumed_intent(self):
        self.task.grant("g", self.a)
        self.read_secret()
        permit = self.call("send", "send_sink", {"payload": "public"})
        self.task.take_dispatch(permit)
        self.task.record_outcome(permit, "unknown")
        self.assertEqual(self.audit.state.failure, "UNKNOWN_OUTCOME")
        with self.assertRaises(AuthorizationError):
            self.call("retry", "send_sink", {"payload": "public"})

    def test_failed_outcome_write_cannot_refund_intent(self):
        self.task.grant("g", self.a)
        self.read_secret()
        permit = self.call("send", "send_sink", {"payload": "public"})
        self.task.take_dispatch(permit)
        with patch.object(self.audit, "_commit",
                          side_effect=sqlite3.OperationalError("outcome commit refused")):
            with self.assertRaises(LiveAuditError):
                self.task.record_outcome(permit, "failed")
        self.assertEqual(self.audit.state.failure, "ROLLED_BACK")
        self.assertEqual(self.intent_bodies()[-1]["selected_grants"][0]["grant_id"], "g")
        with self.assertRaises(AuthorizationError):
            self.call("retry", "send_sink", {"payload": "public"})

    def test_mismatched_receipt_after_commit_cannot_issue_permit(self):
        real_append = self.audit.append_batch
        def wrong_receipt(drafts):
            receipt = real_append(drafts)
            return replace(receipt, event_ids=("other",) + receipt.event_ids[1:])
        with patch.object(self.audit, "append_batch", side_effect=wrong_receipt):
            with self.assertRaises(AuthorizationError):
                self.call("read", "read_public")
        with self.assertRaises(AuthorizationError):
            self.call("retry", "read_public")

    def test_cross_session_receipt_cannot_issue_permit(self):
        other = self.make_audit(self.task_b, "session-b", "monitor-b")
        with patch.object(self.audit, "append_batch", side_effect=other.append_batch):
            with self.assertRaises(AuthorizationError):
                self.call("read", "read_public")
        self.assertEqual(self.audit.state.record_count, 1)
        with self.assertRaises(AuthorizationError):
            self.call("retry", "read_public")

    def test_readback_failure_through_authority_issues_no_permit(self):
        real_verify = self.audit._verify_stored_batch
        def changed_hash(rows):
            self.audit._connection.execute("""UPDATE main.m6_live_records
                SET event_hash=? WHERE session_id=? AND seq=?""",
                ("0" * 64, rows[0][0], rows[0][1]))
            real_verify(rows)
        with patch.object(self.audit, "_verify_stored_batch", side_effect=changed_hash):
            with self.assertRaises(LiveAuditError):
                self.call("read", "read_public")
        self.assertEqual(self.audit.state.failure, "ROLLED_BACK")
        self.assertEqual(self.audit.state.record_count, 1)
        with self.assertRaises(AuthorizationError):
            self.call("retry", "read_public")

    def test_external_writer_append_is_detected_before_authority_use(self):
        from chainguard.m6_live_audit import live_draft
        self.audit.append_batch((live_draft("GRANT", {"grant_id": "external",
            "scope": {"resource": "secret-a", "destination": "sink", "release": "release"},
            "host_origin": "trusted_host", "admission_ordinal": 1}),))
        with self.assertRaises(AuthorizationError):
            self.task.grant("own", self.a)

    def test_findings_factory_receives_actual_proposal_and_confirmed_facts(self):
        self.task.grant("g", self.a)
        self.read_secret()
        seen = []

        def produce(current, proposal_id, facts):
            seen.append((current, proposal_id, facts))
            return findings()

        permit = self.task.admit_call("send", "send_sink", "request", {"payload": "public"},
                                      findings_factory=produce)
        self.assertIsInstance(permit, DispatchPermit)
        self.assertEqual([fact.category for fact in seen[0][2]], ["GRANT", "TOOL_OUTCOME"])
        self.assertEqual(seen[0][1], self.audit._connection.execute(
            "SELECT event_id FROM m6_live_records WHERE call_id='send' AND event_type='CALL_PROPOSAL'").fetchone()[0])
        self.assertEqual(seen[0][2], self.task._facts[:2])
        self.assertEqual(self.task._facts[-1].category, "USE")
        self.assertEqual(self.task._facts[-1].event_id, permit.intent_event_id)
        self.assertIs(type(seen[0][2]), tuple)

    def test_findings_factory_reentry_halts_before_intent(self):
        def reenter(_current, _proposal_id, _facts):
            self.task.grant("nested", self.a)
            return findings()

        with self.assertRaises(AuthorizationError):
            self.task.admit_call("call", "read_public", "request", {},
                                 findings_factory=reenter)
        self.assertEqual(self.audit.state.record_count, 1)
        self.assertEqual(self.task._facts, ())
        with self.assertRaises(AuthorizationError):
            self.task.grant("later", self.a)

    def test_failed_fact_write_does_not_advance_semantic_history(self):
        with patch.object(self.audit, "_commit",
                          side_effect=sqlite3.OperationalError("grant refused")):
            with self.assertRaises(LiveAuditError):
                self.task.grant("g", self.a)
        self.assertEqual(self.task._facts, ())


if __name__ == "__main__":
    unittest.main()
