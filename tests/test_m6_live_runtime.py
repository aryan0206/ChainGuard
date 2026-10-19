"""Real M6 gateway dispatch, ordering, and persistence-failure boundaries."""

from concurrent.futures import Future, TimeoutError as FutureTimeout
from contextlib import closing
from dataclasses import replace
from io import BytesIO
import inspect
import json
from pathlib import Path
import queue
import sqlite3
import tempfile
from threading import Event
import unittest
from unittest.mock import patch
from uuid import uuid4

from chainguard.canonical import decode
from chainguard.m6_live_audit import LiveAuditError, LiveAuditSession
from chainguard.m6_live_authorization import (AuthorizationError, DispatchPermit,
                                               LiveAuthorizationTask)
from chainguard.m6_live_profile import POLICY
from chainguard.m6_live_runtime import (_Auxiliary, _Proposal, _canonical_bytes,
                                        HostTask, LiveRuntimeError, M6Host)
from chainguard.semantics import Scope
from tests.test_m1 import request


def wire(request_value):
    return json.dumps(request_value, ensure_ascii=False).encode("utf-8") + b"\n"


class RuntimeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.open_new_task()
        self.addCleanup(self.stop_task)

    def open_new_task(self):
        nonce = uuid4().hex
        self.task_id = "runtime-task-" + nonce
        self.session_id = "runtime-session-" + nonce
        self.monitor_id = "runtime-monitor-" + nonce
        self.path = Path(self.temp.name) / "live.sqlite"
        self.inventory = {"schema_version": "m4-expected-inventory-v1",
                          "run_id": "runtime-run-" + nonce,
                          "run_challenge": "a" * 64,
                          "sessions": [{"task_id": self.task_id,
                                        "session_id": self.session_id,
                                        "monitor_instance_id": self.monitor_id}]}
        self.task = M6Host().open_task(db_path=self.path,
            trusted_inventory=self.inventory, task_id=self.task_id,
            session_id=self.session_id, monitor_instance_id=self.monitor_id)
        self.scope = Scope(self.task_id, "secret-a", "sink")

    def stop_task(self):
        try:
            self.task.shutdown().result(timeout=10)
        except (LiveRuntimeError, FutureTimeout):
            pass
        self.task._thread.join(timeout=10)

    def exchange(self, request_id, tool, arguments=None):
        output = BytesIO()
        item = request(request_id, "tools/call", name=tool,
                       arguments={} if arguments is None else arguments)
        self.task._submit_client_frame(wire(item), output).result(timeout=15)
        return json.loads(output.getvalue())

    def read_secret(self, request_id="read"):
        response = self.exchange(request_id, "read_secret_a")
        self.assertEqual(response["result"]["content"][0]["text"],
                         dict(POLICY.resources)["secret-a"])

    def rows(self, kind=None):
        with closing(sqlite3.connect(self.path)) as connection:
            if kind is None:
                data = connection.execute(
                    "SELECT record_bytes FROM m6_live_records ORDER BY seq").fetchall()
            else:
                data = connection.execute("""SELECT record_bytes FROM m6_live_records
                    WHERE event_type=? ORDER BY seq""", (kind,)).fetchall()
        return [decode(raw) for (raw,) in data]

    def test_real_handler_requires_taken_permit(self):
        with patch.object(LiveAuthorizationTask, "take_dispatch",
                          side_effect=AuthorizationError("permit blocked")):
            with self.assertRaises(AuthorizationError):
                self.exchange("blocked", "read_public")
        self.task._thread.join(timeout=10)
        self.assertFalse(any(event["phase"] == "tool_received"
                             for event in self.task.child_events))
        self.assertEqual(len(self.rows("DISPATCH_INTENT")), 1)

    def test_nonworker_cannot_write_even_auxiliary_request(self):
        item = _Auxiliary("tools/list", "outside", b"invalid\n", None, None)
        with self.assertRaisesRegex(LiveRuntimeError, "Only the task worker"):
            self.task._write_downstream(item)
        self.assertIn("result", self.exchange("after", "read_public"))

    def test_worker_rejects_auxiliary_label_with_tool_call_frame(self):
        call = request("bypass", "tools/call", name="send_sink",
                       arguments={"payload": "SYNTHETIC_CANARY_A"})
        done, output = Future(), BytesIO()
        self.task._queue.put_nowait(_Auxiliary("tools/list", "bypass",
            _canonical_bytes(call), output, done))
        with self.assertRaises(LiveRuntimeError):
            done.result(timeout=10)
        self.task._thread.join(timeout=10)
        self.assertFalse(any(e["phase"] in {"tool_received", "sink_arrival"}
                             for e in self.task.child_events))
        self.assertEqual(self.rows("DISPATCH_INTENT"), [])
        with self.assertRaises(LiveRuntimeError):
            self.exchange("retry", "read_public")

    def test_worker_rejects_proposal_snapshot_mismatches_before_permit_take(self):
        for kind in ("tool", "arguments", "request_id"):
            with self.subTest(kind=kind):
                if kind != "tool":
                    self.stop_task()
                    self.open_new_task()
                self.task.grant("g", self.scope).result(timeout=10)
                self.read_secret()
                before = len([e for e in self.task.child_events
                              if e["phase"] == "tool_received"])
                before_intents = len(self.rows("DISPATCH_INTENT"))
                typed_arguments = {"payload": "public"}
                call = request("blocked", "tools/call", name="send_sink",
                               arguments=typed_arguments)
                params = call["params"]
                if kind == "tool":
                    params = {**params, "name": "read_public"}
                elif kind == "arguments":
                    params = {**params, "arguments": {"payload": "SYNTHETIC_CANARY_A"}}
                else:
                    params = {**call, "id": "different-request"}
                done, output = Future(), BytesIO()
                self.task._queue.put_nowait(_Proposal(0, "blocked", uuid4().hex,
                    "send_sink", _canonical_bytes(typed_arguments),
                    _canonical_bytes(params), output, done))
                with self.assertRaises(LiveRuntimeError):
                    done.result(timeout=10)
                self.task._thread.join(timeout=10)
                self.assertEqual(len([e for e in self.task.child_events
                                      if e["phase"] == "tool_received"]), before)
                self.assertFalse(any(e["phase"] == "sink_arrival"
                                     for e in self.task.child_events))
                self.assertIsNone(self.task._authority._pending)
                self.assertEqual(len(self.rows("DISPATCH_INTENT")), before_intents)
                with self.assertRaises(LiveRuntimeError):
                    self.exchange("retry", "send_sink", typed_arguments)

    def test_denied_proposal_mismatch_halts_before_admission(self):
        arguments = {"payload": "SYNTHETIC_CANARY_A"}
        call = request("blocked", "tools/call", name="send_sink",
                       arguments=arguments)
        params = {**call["params"], "name": "read_public"}
        facts_before = self.task._authority._facts
        done, output = Future(), BytesIO()
        with (patch.object(self.task._authority, "admit_call",
                           wraps=self.task._authority.admit_call) as admit,
              patch.object(self.task._authority, "take_dispatch",
                           wraps=self.task._authority.take_dispatch) as take):
            self.task._queue.put_nowait(_Proposal(0, "blocked", uuid4().hex,
                "send_sink", _canonical_bytes(arguments), _canonical_bytes(params),
                output, done))
            with self.assertRaises(LiveRuntimeError):
                done.result(timeout=10)
            admit.assert_not_called()
            take.assert_not_called()
        self.task._thread.join(timeout=10)
        self.assertEqual(self.task._state, "HALTED")
        self.assertFalse(any(e["phase"] in {"tool_received", "sink_arrival"}
                             for e in self.task.child_events))
        self.assertEqual(self.rows("DISPATCH_DECISION"), [])
        self.assertEqual(self.rows("DISPATCH_INTENT"), [])
        self.assertEqual(self.task._authority._facts, facts_before)
        self.assertIsNone(self.task._authority._pending)

    def test_one_use_release_and_second_denial(self):
        self.task.grant("g-1", self.scope).result(timeout=10)
        self.read_secret()
        first = self.exchange("send-1", "send_sink", {"payload": "public"})
        second = self.exchange("send-2", "send_sink", {"payload": "public"})
        self.assertIn("result", first)
        self.assertEqual(second["error"]["code"], -32003)
        self.stop_task()
        self.assertEqual(len([e for e in self.task.child_events
                              if e["phase"] == "sink_arrival"]), 1)
        self.assertEqual(len(self.rows("DISPATCH_INTENT")), 2)  # Read and first send.
        self.assertEqual([r["body"]["status"] for r in self.rows("TOOL_OUTCOME")],
                         ["succeeded", "succeeded", "denied"])

    def test_exact_revoke_and_new_grant_restore_scope(self):
        self.task.grant("old", self.scope).result(timeout=10)
        self.task.revoke(Scope(self.task_id, "secret-a", "other-sink")).result(timeout=10)
        self.read_secret()
        self.assertIn("result", self.exchange("first", "send_sink", {"payload": "public"}))
        self.task.grant("later", self.scope).result(timeout=10)
        self.task.revoke(self.scope).result(timeout=10)
        self.assertEqual(self.exchange("denied", "send_sink", {"payload": "public"})
                         ["error"]["code"], -32003)
        self.task.grant("restored", self.scope).result(timeout=10)
        self.assertIn("result", self.exchange("restored", "send_sink", {"payload": "public"}))
        self.stop_task()
        self.assertEqual(len([e for e in self.task.child_events
                              if e["phase"] == "sink_arrival"]), 2)

    def test_duplicate_request_id_wrong_task_permit_and_no_auxiliary_bypass(self):
        self.exchange(7, "read_public")
        with self.assertRaisesRegex(ValueError, "Duplicate request ID"):
            self.exchange(7, "read_public")
        self.exchange("7", "read_public")  # Type-sensitive identity.
        with patch.object(LiveAuthorizationTask, "admit_call",
                          return_value=DispatchPermit("wrong-run", "wrong-task",
                              "wrong-session", "wrong-monitor", "forged", "wrong",
                              "wrong-intent", "nonce")):
            with self.assertRaises(LiveRuntimeError):
                self.exchange("wrong", "read_public")
        self.task._thread.join(timeout=10)
        self.assertEqual(len([e for e in self.task.child_events
                              if e["phase"] == "tool_received"]), 2)
        source = inspect.getsource(HostTask)
        self.assertEqual(source.count(".stdin.write("), 1)

    def test_fifo_revocation_waits_for_pending_intent(self):
        self.task.grant("g", self.scope).result(timeout=10)
        self.read_secret()
        entered, resume = Event(), Event()
        real_wait = self.task._await_response

        def pause(request_id, timeout=30):
            if request_id == "pending":
                entered.set()
                self.assertTrue(resume.wait(timeout=10))
            return real_wait(request_id, timeout)

        output = BytesIO()
        with patch.object(self.task, "_await_response", side_effect=pause):
            pending = self.task._submit_client_frame(wire(request("pending", "tools/call",
                name="send_sink", arguments={"payload": "public"})), output)
            self.assertTrue(entered.wait(timeout=10))
            revoke = self.task.revoke(self.scope)
            self.assertEqual(self.task.admissions[-2:][0][1], "CALL_PROPOSAL")
            self.assertEqual(self.task.admissions[-1][1], "REVOKE_SCOPE")
            self.assertFalse(revoke.done())
            resume.set()
            pending.result(timeout=15)
            revoke.result(timeout=15)
        self.assertIn("result", json.loads(output.getvalue()))
        self.assertEqual(self.exchange("after", "send_sink", {"payload": "public"})
                         ["error"]["code"], -32003)

    def test_findings_bind_actual_proposal_to_confirmed_prefix(self):
        self.task.grant("g", self.scope).result(timeout=10)
        self.read_secret()
        self.exchange("send", "send_sink", {"payload": "public"})
        records = self.rows()
        proposal = next(r for r in records if r["event_type"] == "CALL_PROPOSAL"
                        and r["body"]["request_id"] == "send")
        findings = [r for r in records if r["event_type"] == "DETECTOR_FINDING"
                    and r["call_id"] == proposal["call_id"]]
        self.assertEqual(len(findings), 4)
        self.assertTrue(all(r["body"]["evaluated_event_id"] == proposal["event_id"]
                            and proposal["event_id"] in r["body"]["supporting_event_ids"]
                            for r in findings))
        prior = {r["event_id"] for r in records if r["seq"] < proposal["seq"]
                 and r["event_type"] in {"GRANT", "TOOL_OUTCOME", "DISPATCH_INTENT"}}
        refs = set().union(*(r["body"]["supporting_event_ids"] for r in findings))
        self.assertTrue(refs <= prior | {proposal["event_id"]})

    def test_rollback_lost_ack_receipt_and_readback_fail_before_dispatch(self):
        cases = ("rollback", "lost_ack", "receipt", "readback")
        for kind in cases:
            with self.subTest(kind=kind):
                # Each subcase needs a fresh task because a failure retains its claim.
                if kind != "rollback":
                    self.stop_task()
                    self.open_new_task()
                audit = self.task._audit
                if kind == "rollback":
                    context = patch.object(audit, "_commit",
                        side_effect=sqlite3.OperationalError("commit refused"))
                elif kind == "lost_ack":
                    real_commit = audit._commit
                    def lost_ack():
                        real_commit()
                        raise OSError("ack lost")
                    context = patch.object(audit, "_commit", side_effect=lost_ack)
                elif kind == "receipt":
                    real_append = audit.append_batch
                    def wrong_receipt(drafts):
                        result = real_append(drafts)
                        return replace(result, session_id="other-session")
                    context = patch.object(audit, "append_batch", side_effect=wrong_receipt)
                else:
                    context = patch.object(audit, "_verify_stored_batch",
                        side_effect=sqlite3.OperationalError("readback refused"))
                with context, self.assertRaises(Exception):
                    self.exchange("blocked", "read_public")
                self.task._thread.join(timeout=10)
                self.assertFalse(any(e["phase"] == "tool_received"
                                     for e in self.task.child_events))
                with self.assertRaises(LiveRuntimeError):
                    self.exchange("retry", "read_public")

    def test_outcome_write_failure_never_refunds_or_replays(self):
        self.task.grant("g", self.scope).result(timeout=10)
        self.read_secret()
        audit = self.task._audit
        real_commit = audit._commit
        writes = 0

        def fail_outcome():
            nonlocal writes
            writes += 1
            if writes == 2:
                raise sqlite3.OperationalError("outcome refused")
            return real_commit()

        with patch.object(audit, "_commit", side_effect=fail_outcome):
            with self.assertRaises(LiveAuditError):
                self.exchange("send", "send_sink", {"payload": "public"})
        self.task._thread.join(timeout=10)
        intents = self.rows("DISPATCH_INTENT")
        self.assertEqual(intents[-1]["body"]["selected_grants"][0]["grant_id"], "g")
        self.assertEqual(len([e for e in self.task.child_events
                              if e["phase"] == "sink_arrival"]), 1)
        with self.assertRaises(LiveRuntimeError):
            self.exchange("retry", "send_sink", {"payload": "public"})

    def test_timeout_and_malformed_response_halt_without_replay(self):
        for malformed in (False, True):
            with self.subTest(malformed=malformed):
                if malformed:
                    self.stop_task()
                    self.open_new_task()
                real_wait = self.task._await_response

                def broken(request_id, timeout=30):
                    result = real_wait(request_id, timeout)
                    if malformed:
                        return {"id": request_id, "result": {"content": []}}
                    raise queue.Empty()

                with patch.object(self.task, "_await_response", side_effect=broken):
                    with self.assertRaises(Exception):
                        self.exchange("uncertain", "read_public")
                self.task._thread.join(timeout=10)
                self.assertEqual(len([e for e in self.task.child_events
                                      if e["phase"] == "tool_received"]), 1)
                self.assertEqual(self.rows("TOOL_OUTCOME")[-1]["body"]["status"], "unknown")
                with self.assertRaises(LiveRuntimeError):
                    self.exchange("retry", "read_public")


class InitializationTests(unittest.TestCase):
    def test_failed_session_start_returns_no_handle_or_child(self):
        with tempfile.TemporaryDirectory() as directory:
            nonce = uuid4().hex
            task_id, session_id, monitor_id = (prefix + nonce for prefix in
                                               ("task-", "session-", "monitor-"))
            inventory = {"schema_version": "m4-expected-inventory-v1",
                         "run_id": "run-" + nonce, "run_challenge": "b" * 64,
                         "sessions": [{"task_id": task_id, "session_id": session_id,
                                       "monitor_instance_id": monitor_id}]}
            with patch.object(LiveAuditSession, "_commit",
                              side_effect=sqlite3.OperationalError("start refused")):
                with self.assertRaises(LiveRuntimeError):
                    M6Host().open_task(db_path=Path(directory) / "start.sqlite",
                        trusted_inventory=inventory, task_id=task_id,
                        session_id=session_id, monitor_instance_id=monitor_id)
            with self.assertRaises(LiveRuntimeError):
                M6Host().open_task(db_path=Path(directory) / "second.sqlite",
                    trusted_inventory=inventory, task_id=task_id,
                    session_id=session_id, monitor_instance_id=monitor_id)


if __name__ == "__main__":
    unittest.main()
