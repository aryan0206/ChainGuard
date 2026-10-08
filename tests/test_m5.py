"""M5 acceptance lifecycle, actual SQLite faults, restart and declared attacks."""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path
import sqlite3
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric import ec

from chainguard.acceptance import AcceptanceRegistry, RegistryError, commitment_digest
from chainguard.canonical import decode, encode
from chainguard.evidence import configuration, sign_commitment
from chainguard.m4 import KEY_ID, execute_demo
from chainguard.m5 import campaign, submit_process
from chainguard.verifier import inspect_package, inspect_run
from tests.m5_fixtures import attacks, context, packages


class AcceptanceTests(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory(prefix="m5-unit-")
        self.directory = Path(self.temp.name)
        self.inventory, self.config = context(), configuration()
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.pins = {KEY_ID: self.key.public_key()}
        self.data = packages(self.directory, self.inventory, self.config, self.key)
        self.path = self.directory / "registry.sqlite"
        self.registry = AcceptanceRegistry.create(self.path)
        self.expected = self.registry.register(self.inventory, self.config, self.pins)

    def tearDown(self):
        self.registry.close()
        self.temp.cleanup()

    def submit(self, data=None):
        return self.registry.submit(self.inventory["run_id"], self.data if data is None else data)

    def assertActive(self):
        self.assertEqual(self.registry.expected(self.inventory["run_id"]), self.expected)
        self.assertEqual(self.registry._connection.execute("SELECT count(*) FROM accepted_sessions").fetchone(), (0,))

    def test_confirmed_complete_acceptance_exact_persisted_identity(self):
        result = self.submit()
        self.assertEqual(result["status"], "ACCEPTED", result)
        self.assertEqual(result["registry_durability"], "COMMITTED")
        self.assertEqual(result["identity"], self.expected.identity)
        self.assertEqual(self.registry.expected(self.inventory["run_id"]), replace(self.expected, state="ACCEPTED"))
        self.assertEqual(result["commitments"], [{"session_id": self.inventory["sessions"][0]["session_id"],
            "commitment_digest": commitment_digest(decode(self.data[0])["commitment"])}])

    def test_repeatable_inspection_never_consumes_expectation(self):
        for _ in range(2):
            self.assertTrue(inspect_run(self.data, self.inventory, self.config, self.pins)["inspection_passed"])
            self.assertActive()
        self.assertEqual(self.submit()["status"], "ACCEPTED")

    def test_declared_adversarial_matrix_no_false_acceptance(self):
        for case in attacks(self.data[0], self.key):
            with self.subTest(case=case.name):
                result = self.submit([case.data])
                self.assertEqual(result["status"], case.expected, result)
                if case.expected == "ACCEPTED":
                    # Each attack gets the SAME immutable, initially active context.
                    self.registry.close()
                    replacement_path = self.directory / "matrix.sqlite"
                    self.registry = AcceptanceRegistry.create(replacement_path)
                    self.registry.register(self.inventory, self.config, self.pins)
                else:
                    self.assertActive()

    def test_duplicate_signature_bytes_do_not_define_identity(self):
        self.assertEqual(self.submit()["status"], "ACCEPTED")
        changed = decode(self.data[0])
        changed["signature"] = sign_commitment(self.key, changed["commitment"])
        self.assertEqual(self.submit([encode(changed)])["reason"], "ALREADY_ACCEPTED")
        changed["manifest"]["task_id"] = "wrong-after-accepted"
        self.assertEqual(self.submit([encode(changed)])["reason"], "ALREADY_ACCEPTED")

    def test_acceptance_and_duplicate_survive_separate_process_restart(self):
        source = self.directory / "package.json"
        source.write_bytes(self.data[0])
        self.registry.close()
        first = submit_process(self.path, self.inventory["run_id"], [source])
        second = submit_process(self.path, self.inventory["run_id"], [source])
        self.assertEqual(first["status"], "ACCEPTED")
        self.assertEqual(second["reason"], "ALREADY_ACCEPTED")
        self.assertEqual(first["identity"], second["identity"])
        self.registry = AcceptanceRegistry(self.path)

    def test_old_valid_evidence_against_new_context_rejected(self):
        new = context()
        self.registry.register(new, self.config, self.pins)
        result = self.registry.submit(new["run_id"], self.data)
        self.assertEqual(result["status"], "REJECTED")
        self.assertEqual(result["verification"]["dimensions"]["trusted_signature"]["status"], "PASS")
        self.assertEqual(result["verification"]["dimensions"]["expected_binding"]["status"], "FAIL")
        self.assertEqual(self.registry.expected(new["run_id"]).state, "ACTIVE")

    def test_wrong_external_pin_rejected(self):
        other = ec.generate_private_key(ec.SECP256R1())
        alternate = AcceptanceRegistry.create(self.directory / "wrong-pin.sqlite")
        try:
            alternate.register(self.inventory, self.config, {KEY_ID: other.public_key()})
            result = alternate.submit(self.inventory["run_id"], self.data)
            self.assertEqual(result["status"], "REJECTED")
            self.assertEqual(result["verification"]["dimensions"]["trusted_signature"]["status"], "FAIL")
        finally:
            alternate.close()

    def test_trusted_signed_wrong_finding_fails_only_reproduction(self):
        case = next(c for c in attacks(self.data[0], self.key) if c.name == "trusted-signed-incorrect-finding")
        result = self.submit([case.data])
        dims = result["verification"]["dimensions"]
        self.assertEqual(result["status"], "REJECTED")
        self.assertEqual(dims["finding_reproduction"]["status"], "FAIL")
        self.assertTrue(all(dims[d]["status"] == "PASS" for d in dims if d != "finding_reproduction"))
        self.assertActive()

    def test_missing_and_unreadable_registry_never_created_implicitly(self):
        missing = self.directory / "missing.sqlite"
        with self.assertRaises((sqlite3.Error, RegistryError)):
            AcceptanceRegistry(missing)
        self.assertFalse(missing.exists())
        source = self.directory / "package.json"
        source.write_bytes(self.data[0])
        result = submit_process(missing, self.inventory["run_id"], [source])
        self.assertEqual(result["status"], "NOT_CHECKED")
        with self.assertRaises(FileExistsError):
            AcceptanceRegistry.create(self.path)

    def test_unknown_expectation_and_malformed_bytes_rejected(self):
        self.assertEqual(self.registry.submit("unknown", self.data)["reason"], "UNKNOWN_EXPECTATION")
        self.assertEqual(self.submit([bytearray(self.data[0])])["reason"], "MALFORMED_SUBMISSION")
        self.assertActive()

    def test_immutable_registration_and_challenge_reuse_refused(self):
        with self.assertRaises(ValueError):
            self.registry.register(self.inventory, self.config, self.pins)
        changed = context()
        changed["run_challenge"] = self.inventory["run_challenge"]
        with self.assertRaises(sqlite3.IntegrityError):
            self.registry.register(changed, self.config, self.pins)
        self.assertActive()

    def test_cancelled_and_failed_terminal_contexts_survive_restart(self):
        for state in ("CANCELLED", "FAILED"):
            inv = context()
            self.registry.register(inv, self.config, self.pins)
            self.registry.terminate(inv["run_id"], state)
            self.registry.close()
            self.registry = AcceptanceRegistry(self.path)
            self.assertEqual(self.registry.submit(inv["run_id"], self.data)["reason"], "EXPECTATION_" + state)
            with self.assertRaises(ValueError):
                self.registry.terminate(inv["run_id"], "FAILED")
            with self.assertRaises(ValueError):
                self.registry.register(inv, self.config, self.pins)

    def test_real_insert_failure_rolls_back_without_consuming(self):
        original = self.registry._store_acceptance
        def fail(expectation, rows):
            original(expectation, rows)
            self.registry._connection.execute("INSERT INTO absent VALUES (1)")
        with patch.object(self.registry, "_store_acceptance", side_effect=fail):
            self.assertEqual(self.submit()["status"], "NOT_CHECKED")
        self.assertActive()
        self.assertEqual(self.submit()["status"], "ACCEPTED")

    def test_successful_sql_with_suppressed_acceptance_not_accepted(self):
        with patch.object(self.registry, "_store_acceptance", return_value=None):
            self.assertEqual(self.submit()["status"], "NOT_CHECKED")
        self.assertActive()

    def test_exact_registry_readback_rejects_altered_commitment(self):
        original = self.registry._store_acceptance
        def corrupt(expectation, rows):
            original(expectation, rows)
            self.registry._connection.execute("UPDATE accepted_sessions SET commitment_digest=?", ("cd" * 32,))
        with patch.object(self.registry, "_store_acceptance", side_effect=corrupt):
            self.assertEqual(self.submit()["status"], "NOT_CHECKED")
        self.assertActive()

    def test_schema_trigger_rejected_before_acceptance(self):
        self.registry._connection.execute("CREATE TRIGGER suppress BEFORE INSERT ON accepted_sessions BEGIN SELECT RAISE(IGNORE); END")
        self.assertEqual(self.submit()["status"], "NOT_CHECKED")
        self.registry._connection.execute("DROP TRIGGER suppress")
        self.assertActive()

    def test_ambiguous_committed_ack_never_reports_acceptance_then_retry_reconciles(self):
        commit = self.registry._commit
        def lost_ack():
            commit()
            raise OSError("lost registry acknowledgement")
        with patch.object(self.registry, "_commit", side_effect=lost_ack) as call:
            result = self.submit()
        self.assertEqual(call.call_count, 1)
        self.assertEqual(result["status"], "NOT_CHECKED")
        self.assertEqual(result["registry_durability"], "UNKNOWN")
        self.registry = AcceptanceRegistry(self.path)
        self.assertEqual(self.submit()["reason"], "ALREADY_ACCEPTED")

    def test_ambiguous_uncommitted_ack_explicit_retry_can_accept(self):
        with patch.object(self.registry, "_commit", side_effect=OSError("before commit")) as call:
            result = self.submit()
        self.assertEqual(call.call_count, 1)
        self.assertEqual(result["status"], "NOT_CHECKED")
        self.registry = AcceptanceRegistry(self.path)
        self.assertActive()
        self.assertEqual(self.submit()["status"], "ACCEPTED")

    def test_prepared_transaction_is_not_confirmed_registry_commit(self):
        with patch.object(self.registry, "_commit", return_value=None):
            result = self.submit()
        self.assertEqual(result["status"], "NOT_CHECKED")
        self.assertEqual(result["registry_durability"], "UNKNOWN")
        self.registry = AcceptanceRegistry(self.path)
        self.assertActive()

    def test_context_cancelled_during_verification_rechecked_in_transaction(self):
        original = inspect_run
        def cancel(*args):
            result = original(*args)
            self.registry.terminate(self.inventory["run_id"], "CANCELLED")
            return result
        with patch("chainguard.acceptance.inspect_run", side_effect=cancel):
            self.assertEqual(self.submit()["reason"], "EXPECTATION_CHANGED")
        self.assertEqual(self.registry.expected(self.inventory["run_id"]).state, "CANCELLED")

    def test_frozen_file_snapshot_remains_original_after_source_mutation(self):
        source = self.directory / "package.json"
        source.write_bytes(self.data[0])
        frozen = source.read_bytes()
        source.write_bytes(b"{}")
        self.assertEqual(self.submit([frozen])["status"], "ACCEPTED")
        self.assertFalse(inspect_run([source.read_bytes()], self.inventory, self.config, self.pins)["inspection_passed"])

    def test_concurrent_processes_accept_exactly_once(self):
        source = self.directory / "package.json"
        source.write_bytes(self.data[0])
        self.registry.close()
        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(submit_process, self.path, self.inventory["run_id"], [source]) for _ in range(2)]
            results = [f.result() for f in futures]
        self.assertEqual(sorted(r["status"] for r in results), ["ACCEPTED", "REJECTED"])
        self.registry = AcceptanceRegistry(self.path)
        self.assertEqual(self.registry.expected(self.inventory["run_id"]).state, "ACCEPTED")

    def test_partial_registry_state_and_corrupt_file_fail_closed(self):
        self.registry._connection.execute("UPDATE expected_runs SET state='ACCEPTED'")
        self.registry.close()
        with self.assertRaises(RegistryError):
            AcceptanceRegistry(self.path)
        bad = self.directory / "corrupt.sqlite"
        bad.write_bytes(b"not a database")
        with self.assertRaises(RegistryError):
            AcceptanceRegistry(bad)


class WholeRunTests(unittest.TestCase):
    def test_failed_pre_input_registration_prevents_monitor_execution(self):
        with TemporaryDirectory(prefix="m5-register-fail-") as directory:
            def fail(inventory, config, pins):
                self.assertFalse((Path(directory) / "audit.sqlite").exists())
                raise RegistryError("registration failed before bootstrap")
            with self.assertRaises(RegistryError):
                execute_demo(directory, register_expected=fail)
            self.assertFalse((Path(directory) / "audit.sqlite").exists())
            self.assertFalse((Path(directory) / "evidence.json").exists())

    def test_multi_session_full_inventory_atomic_acceptance_and_singleton_unchanged(self):
        with TemporaryDirectory(prefix="m5-multi-") as directory:
            inv, config = context(2), configuration()
            key = ec.generate_private_key(ec.SECP256R1())
            pins = {KEY_ID: key.public_key()}
            data = packages(directory, inv, config, key)
            registry = AcceptanceRegistry.create(Path(directory) / "registry.sqlite")
            try:
                registry.register(inv, config, pins)
                self.assertFalse(inspect_package(data[0], inv, config, pins)["inspection_passed"])
                self.assertTrue(inspect_run(data, inv, config, pins)["inspection_passed"])
                for subset, status in ((data[:1], "INCOMPLETE"), ((data[0], data[0]), "REJECTED"), ((), "INCOMPLETE")):
                    result = registry.submit(inv["run_id"], subset)
                    self.assertEqual(result["status"], status, result)
                    self.assertEqual(registry.expected(inv["run_id"]).state, "ACTIVE")
                    self.assertEqual(registry._connection.execute("SELECT count(*) FROM accepted_sessions").fetchone(), (0,))
                extra_inv = context()
                extra = packages(directory, extra_inv, config, key)
                self.assertEqual(registry.submit(inv["run_id"], (*data, *extra))["status"], "REJECTED")
                self.assertEqual(registry.submit(inv["run_id"], tuple(reversed(data)))["status"], "ACCEPTED")
                self.assertEqual(registry._connection.execute("SELECT count(*) FROM accepted_sessions").fetchone(), (2,))
            finally:
                registry.close()

    def test_multi_session_failed_write_rolls_back_all_commitments(self):
        with TemporaryDirectory(prefix="m5-multi-fault-") as directory:
            inv, config = context(2), configuration()
            key = ec.generate_private_key(ec.SECP256R1())
            data = packages(directory, inv, config, key)
            registry = AcceptanceRegistry.create(Path(directory) / "registry.sqlite")
            try:
                registry.register(inv, config, {KEY_ID: key.public_key()})
                def partial(expectation, rows):
                    registry._connection.execute("INSERT INTO accepted_sessions VALUES (?,?,?,?)", rows[0])
                    raise sqlite3.OperationalError("second insert failure")
                with patch.object(registry, "_store_acceptance", side_effect=partial):
                    self.assertEqual(registry.submit(inv["run_id"], data)["status"], "NOT_CHECKED")
                self.assertEqual(registry.expected(inv["run_id"]).state, "ACTIVE")
                self.assertEqual(registry._connection.execute("SELECT count(*) FROM accepted_sessions").fetchone(), (0,))
            finally:
                registry.close()

    def test_real_campaign_registration_before_execution_and_restart(self):
        with TemporaryDirectory(prefix="m5-live-") as directory:
            report = campaign(directory)
        self.assertTrue(report["passed"], report["synthetic_campaign"])
        self.assertEqual(report["false_acceptances"], 0)
        self.assertEqual(report["false_rejections"], 0)
        self.assertEqual(report["live_M4"]["handler_request_ids"], [3, 4, 5])
        self.assertEqual(report["live_M4"]["record_count"], 26)
        self.assertEqual(report["live_M4"]["confirmed_transactions"], 8)


if __name__ == "__main__":
    unittest.main()
