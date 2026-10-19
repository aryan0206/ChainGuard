"""Gate 2 clean-close export tests using temporary live databases only."""

from copy import deepcopy
from contextlib import closing
from io import BytesIO
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch
from uuid import uuid4

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import (Encoding, NoEncryption,
    PrivateFormat)

from chainguard.canonical import decode, encode
from chainguard.evidence import event_hash, manifest_digest
from chainguard.m6_live_audit import LiveAmbiguousCommit, LiveAuditError
from chainguard.m6_live_evidence import validate_live_package_structure
from chainguard.m6_live_profile import live_configuration
from chainguard.m6_live_runtime import LiveRuntimeError, M6Host
from chainguard.m6_live_seal import verify_live_signature
from chainguard.semantics import Scope
from tests.test_m1 import request


KEY_ID = "external-live-test-key"


class ShortWrite:
    def __init__(self, stream):
        self.stream = stream

    def write(self, data):
        return 0

    def flush(self):
        self.stream.flush()

    def close(self):
        self.stream.close()


class LiveSealTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.start_task()
        self.addCleanup(self.stop_task)

    def start_task(self):
        nonce = uuid4().hex
        self.task_id = "seal-task-" + nonce
        self.session_id = "seal-session-" + nonce
        self.monitor_id = "seal-monitor-" + nonce
        self.database = Path(self.temp.name) / ("live-" + nonce + ".sqlite")
        self.output = Path(self.temp.name) / ("package-" + nonce + ".json")
        self.inventory = {"schema_version": "m4-expected-inventory-v1",
                          "run_id": "seal-run-" + nonce,
                          "run_challenge": "a" * 64,
                          "sessions": [{"task_id": self.task_id,
                                        "session_id": self.session_id,
                                        "monitor_instance_id": self.monitor_id}]}
        self.expected_inventory = deepcopy(self.inventory)
        self.expected_configuration = live_configuration()
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.pins = {KEY_ID: self.key.public_key()}
        self.task = M6Host().open_task(db_path=self.database,
            trusted_inventory=self.inventory, task_id=self.task_id,
            session_id=self.session_id, monitor_instance_id=self.monitor_id)

    def stop_task(self):
        try:
            self.task.shutdown().result(timeout=10)
        except Exception:
            pass
        self.task._thread.join(timeout=10)

    def call(self, request_id, name, arguments=None):
        frame = json.dumps(request(request_id, "tools/call", name=name,
            arguments={} if arguments is None else arguments),
            separators=(",", ":")).encode("utf-8") + b"\n"
        output = BytesIO()
        self.task._submit_client_frame(frame, output).result(timeout=15)
        return json.loads(output.getvalue())

    def clean_close(self):
        self.task.shutdown().result(timeout=15)
        self.assertEqual(self.task._state, "CLOSED")
        self.assertEqual(self.task._audit.state.lifecycle, "CLOSED_UNSEALED")

    def export(self, **changes):
        args = {"expected_inventory": self.expected_inventory,
                "expected_configuration": self.expected_configuration,
                "private_key": self.key, "signer_key_id": KEY_ID,
                "pinned_public_keys": self.pins, "output_path": self.output}
        args.update(changes)
        return self.task.export_live_evidence(**args)

    def test_clean_run_exports_exact_snapshot_and_valid_signature(self):
        self.assertIn("result", self.call("read", "read_public"))
        self.clean_close()
        trusted = self.task._audit.state
        package_bytes = self.export()
        self.assertEqual(self.output.read_bytes(), package_bytes)
        package = validate_live_package_structure(package_bytes)
        closure = package["commitment"]
        self.assertEqual((closure["record_count"], closure["final_seq"],
                          closure["final_head"]),
                         (trusted.record_count, trusted.record_count, trusted.final_head))
        self.assertEqual(closure["manifest_digest"], manifest_digest(package["manifest"]))
        self.assertEqual(package["manifest"]["configuration"],
                         self.expected_configuration)
        self.assertEqual(package["manifest"]["expected_inventory_digest"],
                         closure["expected_inventory_digest"])
        verify_live_signature(self.pins[KEY_ID], closure, package["signature"])
        private_pem = self.key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8,
                                             NoEncryption())
        self.assertNotIn(private_pem, package_bytes)
        self.assertNotIn(b"PRIVATE KEY", package_bytes)
        self.assertNotIn("PRIVATE KEY", json.dumps(self.task.child_events))
        with self.assertRaises(LiveRuntimeError):
            self.export(output_path=Path(self.temp.name) / "second.json")

    def test_storage_mutants_cannot_replace_trusted_count_or_head(self):
        for mutation in ("delete", "missing_end", "duplicate", "reorder",
                         "bytes", "noncanonical", "hash", "recomputed_tail",
                         "schema"):
            with self.subTest(mutation=mutation):
                if mutation != "delete":
                    self.stop_task()
                    self.start_task()
                self.assertIn("result", self.call("read", "read_public"))
                self.clean_close()
                trusted = self.task._audit.state
                with closing(sqlite3.connect(self.database)) as connection, connection:
                    if mutation == "delete":
                        connection.execute("DELETE FROM m6_live_records WHERE seq=2")
                    elif mutation == "missing_end":
                        connection.execute("""DELETE FROM m6_live_records
                            WHERE event_type='SESSION_END'""")
                    elif mutation == "duplicate":
                        connection.execute("""INSERT INTO m6_live_records
                            SELECT session_id,seq+100,event_id||'-copy',event_type,call_id,
                                   run_id,task_id,monitor_instance_id,record_bytes,event_hash
                        FROM m6_live_records WHERE event_type='SESSION_END'""")
                    elif mutation == "reorder":
                        connection.execute("UPDATE m6_live_records SET seq=100 WHERE seq=2")
                        connection.execute("UPDATE m6_live_records SET seq=2 WHERE seq=3")
                        connection.execute("UPDATE m6_live_records SET seq=3 WHERE seq=100")
                    elif mutation == "bytes":
                        connection.execute("UPDATE m6_live_records SET record_bytes=? WHERE seq=2",
                                           (b"{}",))
                    elif mutation == "noncanonical":
                        old = connection.execute("""SELECT record_bytes FROM m6_live_records
                            WHERE seq=2""").fetchone()[0]
                        connection.execute("UPDATE m6_live_records SET record_bytes=? WHERE seq=2",
                                           (old + b" ",))
                    elif mutation == "hash":
                        connection.execute("UPDATE m6_live_records SET event_hash=? WHERE seq=2",
                                           ("0" * 64,))
                    elif mutation == "recomputed_tail":
                        row = connection.execute("""SELECT seq,record_bytes FROM m6_live_records
                            ORDER BY seq DESC LIMIT 1""").fetchone()
                        event = decode(row[1])
                        event["event_id"] = "altered-end"
                        connection.execute("""UPDATE m6_live_records
                            SET event_id=?,record_bytes=?,event_hash=? WHERE seq=?""",
                            (event["event_id"], encode(event), event_hash(event), row[0]))
                    else:
                        connection.execute("CREATE TABLE injected (value TEXT)")
                with self.assertRaises(LiveRuntimeError):
                    self.export()
                self.assertFalse(self.output.exists())
                self.assertEqual(self.task._audit.state, trusted)

    def test_export_uses_only_the_validated_snapshot(self):
        self.assertIn("result", self.call("read", "read_public"))
        self.clean_close()
        snapshot = self.task._audit._snapshot_for_export

        def snapshot_then_mutate(frozen):
            manifest, entries = snapshot(frozen)
            with closing(sqlite3.connect(self.database)) as connection, connection:
                connection.execute("UPDATE m6_live_records SET record_bytes=? WHERE seq=2",
                                   (b"{}",))
            return manifest, entries

        with patch.object(self.task._audit, "_snapshot_for_export",
                          side_effect=snapshot_then_mutate) as reads:
            package = self.export()
        reads.assert_called_once()
        self.assertEqual(decode(package)["records"][1]["event"]["seq"], 2)
        self.assertEqual(self.output.read_bytes(), package)

    def test_export_requires_shutdown_without_pending_or_halt(self):
        with self.assertRaises(LiveRuntimeError):
            self.export()
        self.clean_close()
        self.task._authority._pending = object()
        with self.assertRaises(LiveRuntimeError):
            self.export()
        self.assertFalse(self.output.exists())

    def test_unconfirmed_cleanup_prevents_export(self):
        real_close = self.task._audit.close

        def close_then_fail():
            real_close()
            raise OSError("audit close acknowledgement failed")

        with patch.object(self.task._audit, "close", side_effect=close_then_fail):
            with self.assertRaises(OSError):
                self.task.shutdown().result(timeout=15)
        self.task._thread.join(timeout=10)
        self.assertEqual(self.task._state, "HALTED")
        with self.assertRaises(LiveRuntimeError):
            self.export()
        self.assertFalse(self.output.exists())

    def test_unknown_outcome_and_ambiguous_append_prevent_export(self):
        self.task._child.stdin = ShortWrite(self.task._child.stdin)
        with self.assertRaises(LiveRuntimeError):
            self.call("unknown", "read_public")
        self.task._thread.join(timeout=10)
        self.assertEqual(self.task._audit.state.lifecycle, "HALTED")
        with self.assertRaises(LiveRuntimeError):
            self.export()
        self.assertFalse(self.output.exists())

    def test_ambiguous_append_prevents_export(self):
        original = self.task._audit._commit

        def lost_ack():
            original()
            raise OSError("commit acknowledgement lost")

        with patch.object(self.task._audit, "_commit", side_effect=lost_ack):
            with self.assertRaises(LiveAmbiguousCommit):
                self.task.grant("g", Scope(self.task_id, "secret-a", "sink")).result(timeout=10)
        self.task._thread.join(timeout=10)
        self.assertEqual(self.task._audit.state.lifecycle, "HALTED")
        with self.assertRaises(LiveRuntimeError):
            self.export()
        self.assertFalse(self.output.exists())

    def test_confirmed_failed_append_prevents_export(self):
        with patch.object(self.task._audit, "_insert_prepared",
                          side_effect=OSError("injected storage failure")):
            with self.assertRaises(LiveAuditError):
                self.task.grant("g", Scope(self.task_id, "secret-a", "sink")).result(timeout=10)
        self.task._thread.join(timeout=10)
        self.assertEqual(self.task._audit.state.lifecycle, "HALTED")
        with self.assertRaises(LiveRuntimeError):
            self.export()
        self.assertFalse(self.output.exists())

    def test_wrong_assessor_identity_inventory_challenge_and_configuration(self):
        for change in ("task", "session", "challenge", "configuration",
                       "empty_schema", "pin"):
            with self.subTest(change=change):
                if change != "task":
                    self.stop_task()
                    self.start_task()
                self.clean_close()
                expected = deepcopy(self.expected_inventory)
                config = deepcopy(self.expected_configuration)
                pins = self.pins
                if change == "task":
                    expected["sessions"][0]["task_id"] = "wrong-task"
                elif change == "session":
                    expected["sessions"][0]["session_id"] = "wrong-session"
                elif change == "challenge":
                    expected["run_challenge"] = "b" * 64
                elif change == "configuration":
                    config["policy"]["resources"][0][1] = "changed-canary"
                elif change == "empty_schema":
                    config["tool_registry"]["definition"]["tools"][0]["input_schema"] = {}
                else:
                    pins = {KEY_ID: ec.generate_private_key(ec.SECP256R1()).public_key()}
                with self.assertRaises(LiveRuntimeError):
                    self.export(expected_inventory=expected,
                                expected_configuration=config,
                                pinned_public_keys=pins)
                self.assertFalse(self.output.exists())

    def test_signing_inspection_and_durable_export_fail_closed(self):
        for stage, target in (("sign", "sign_live_commitment"),
                              ("package", "encode"),
                              ("inspect", "validate_live_package_structure"),
                              ("fsync", "os.fsync")):
            with self.subTest(stage=stage):
                if stage != "sign":
                    self.stop_task()
                    self.start_task()
                self.clean_close()
                with patch("chainguard.m6_live_seal." + target,
                           side_effect=OSError("injected " + stage)):
                    with self.assertRaises(LiveRuntimeError):
                        self.export()
                self.assertFalse(self.output.exists())
                with self.assertRaises(LiveRuntimeError):
                    self.export()


if __name__ == "__main__":
    unittest.main()
