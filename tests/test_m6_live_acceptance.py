"""M5 registry integration for complete, signed M6 live runs."""

from copy import deepcopy
from dataclasses import replace
from io import BytesIO
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from uuid import uuid4

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from chainguard.acceptance import AcceptanceRegistry, RegistryAmbiguous, commitment_digest
from chainguard.canonical import decode, encode
from chainguard.evidence import DETECTOR_IDS, SUITE, event_hash, genesis, manifest_digest
from chainguard.m6_live_profile import POLICY, PROFILE_VERSIONS, live_configuration, make_live_manifest
from chainguard.m6_live_runtime import M6Host
from chainguard.m6_live_seal import make_live_commitment, sign_live_commitment
from chainguard.m6_live_verifier import inspect_live_run
from chainguard.permission_evidence import reconstruct_lifecycle
from chainguard.semantics import Scope
from tests.test_m1 import request
from tests.test_m6_live_evidence import fixture_package


KEY_ID = "assessor-live-signer"


class LiveAcceptanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture_dir = tempfile.TemporaryDirectory(prefix="m6-live-accept-fixture-")
        cls.addClassCleanup(cls.fixture_dir.cleanup)
        suffix = uuid4().hex
        cls.inventory = {"schema_version": "m4-expected-inventory-v1",
            "run_id": "live-accept-run-" + suffix, "run_challenge": "a" * 64,
            "sessions": [{"task_id": "live-accept-task-" + suffix,
                          "session_id": "live-accept-session-" + suffix,
                          "monitor_instance_id": "live-accept-monitor-" + suffix}]}
        cls.config = live_configuration()
        cls.key = ec.generate_private_key(ec.SECP256R1())
        cls.pins = {KEY_ID: cls.key.public_key()}
        identity = cls.inventory["sessions"][0]
        database = Path(cls.fixture_dir.name) / "fixture.sqlite"
        task = M6Host().open_task(db_path=database, trusted_inventory=cls.inventory,
            **identity)
        try:
            def call(request_id, name, arguments=None):
                frame = json.dumps(request(request_id, "tools/call", name=name,
                    arguments={} if arguments is None else arguments),
                    separators=(",", ":")).encode() + b"\n"
                output = BytesIO()
                task._submit_client_frame(frame, output).result(timeout=15)
                return json.loads(output.getvalue())

            if "result" not in call("read", "read_secret_a"):
                raise AssertionError("Sensitive read fixture failed")
            scope = Scope(identity["task_id"], "secret-a", "sink")
            if "error" not in call("denied-before", "send_sink",
                                   {"payload": "SYNTHETIC_CANARY_A"}):
                raise AssertionError("Missing initial denial")
            task.grant("grant-1", scope).result(timeout=15)
            if "result" not in call("allowed", "send_sink",
                                    {"payload": "SYNTHETIC_CANARY_A"}):
                raise AssertionError("Granted release fixture failed")
            if "error" not in call("denied-after", "send_sink",
                                   {"payload": "SYNTHETIC_CANARY_A"}):
                raise AssertionError("One-use denial missing")
            task.grant("grant-2", scope).result(timeout=15)
            task.revoke(scope).result(timeout=15)
            if "error" not in call("denied-revoked", "send_sink",
                                   {"payload": "SYNTHETIC_CANARY_A"}):
                raise AssertionError("Revoked denial missing")
            task.shutdown().result(timeout=15)
            cls.package_bytes = task.export_live_evidence(
                expected_inventory=cls.inventory, expected_configuration=cls.config,
                private_key=cls.key, signer_key_id=KEY_ID, pinned_public_keys=cls.pins,
                output_path=Path(cls.fixture_dir.name) / "package.json")
        finally:
            if task._state == "ACTIVE":
                task.shutdown().result(timeout=15)
            task._thread.join(timeout=15)
        database.unlink()  # The package is inspected without its temporary source DB.

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="m6-live-accept-registry-")
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "registry.sqlite"
        self.registry = AcceptanceRegistry.create(self.path)
        self.addCleanup(lambda: self.registry.close())
        self.expected = self.registry.register(self.inventory, self.config, self.pins)

    def submit(self, snapshots=None, run_id=None):
        return self.registry.submit(self.inventory["run_id"] if run_id is None else run_id,
            [self.package_bytes] if snapshots is None else snapshots)

    def assert_active(self):
        self.assertEqual(self.registry.expected(self.inventory["run_id"]), self.expected)
        self.assertEqual(self.registry._connection.execute(
            "SELECT count(*) FROM accepted_sessions").fetchone(), (0,))

    def resign(self, package):
        head = genesis(package["manifest"])
        for seq, entry in enumerate(package["records"], 1):
            event = entry["event"]
            event["seq"] = seq
            event["prev_hash"] = head
            head = entry["event_hash"] = event_hash(event)
        package["commitment"] = make_live_commitment(
            package["manifest"], len(package["records"]), head, KEY_ID)
        package["signature"] = sign_live_commitment(self.key, package["commitment"])
        return encode(package)

    def signed_minimal(self, inventory, identity):
        manifest = make_live_manifest(inventory, self.config, **identity)
        package = fixture_package(manifest)
        package["commitment"] = make_live_commitment(manifest, 2,
            package["records"][-1]["event_hash"], KEY_ID)
        package["signature"] = sign_live_commitment(self.key, package["commitment"])
        return encode(package)

    def start_preregistered_live_task(self, path, database, inventory, config,
                                      pins, host, ordering):
        registry = AcceptanceRegistry.create(path)
        try:
            expected = registry.register(inventory, config, pins)
        finally:
            registry.close()
        ordering.append("registration-confirmed")
        registry = AcceptanceRegistry(path)
        try:
            self.assertEqual(registry.expected(inventory["run_id"]), expected)
            ordering.append("durable-readback")
            task = host.open_task(db_path=database, trusted_inventory=inventory,
                **inventory["sessions"][0])
            return registry, expected, task
        except BaseException:
            registry.close()
            raise

    def test_confirmed_preregistration_precedes_real_live_execution(self):
        suffix = uuid4().hex
        inventory = {"schema_version": "m4-expected-inventory-v1",
            "run_id": "live-preregister-run-" + suffix, "run_challenge": "b" * 64,
            "sessions": [{"task_id": "live-preregister-task-" + suffix,
                          "session_id": "live-preregister-session-" + suffix,
                          "monitor_instance_id": "live-preregister-monitor-" + suffix}]}
        config = live_configuration()
        key = ec.generate_private_key(ec.SECP256R1())
        pins = {KEY_ID: key.public_key()}
        path = Path(self.temp.name) / "preregister-registry.sqlite"
        database = Path(self.temp.name) / "preregister-audit.sqlite"
        ordering = []
        host = M6Host()
        open_task = host.open_task

        def guarded_open(**kwargs):
            self.assertEqual(ordering, ["registration-confirmed", "durable-readback"])
            ordering.append("live-open")
            return open_task(**kwargs)

        with patch.object(host, "open_task", side_effect=guarded_open) as opened:
            registry, expected, task = self.start_preregistered_live_task(
                path, database, inventory, config, pins, host, ordering)
        try:
            opened.assert_called_once()
            self.assertEqual(ordering, ["registration-confirmed", "durable-readback",
                                        "live-open"])
            try:
                frame = json.dumps(request("preregister-read", "tools/call",
                    name="read_secret_a", arguments={}), separators=(",", ":")).encode() + b"\n"
                output = BytesIO()
                task._submit_client_frame(frame, output).result(timeout=15)
                self.assertIn("result", json.loads(output.getvalue()))
                task.shutdown().result(timeout=15)
                package = task.export_live_evidence(
                    expected_inventory=inventory, expected_configuration=config,
                    private_key=key, signer_key_id=KEY_ID, pinned_public_keys=pins,
                    output_path=Path(self.temp.name) / "preregister-package.json")
            finally:
                if task._state == "ACTIVE":
                    task.shutdown().result(timeout=15)
                task._thread.join(timeout=15)
            inspection = inspect_live_run([package], expected_inventory=inventory,
                expected_configuration=config, trusted_signer_key_id=KEY_ID,
                pinned_public_key=key.public_key(), accepted_versions=PROFILE_VERSIONS,
                accepted_suite=SUITE)
            self.assertIs(inspection["inspection_passed"], True, inspection)
            self.assertEqual(inspection["fresh_submission"], "NOT_CHECKED")
            self.assertEqual(registry.expected(inventory["run_id"]), expected)
            result = registry.submit(inventory["run_id"], [package])
            self.assertEqual((result["status"], result["reason"],
                              result["registry_durability"]),
                             ("ACCEPTED", "FRESH_COMPLETE_RUN", "COMMITTED"), result)
            self.assertIs(result["verification"]["inspection_passed"], True)
            registry.close()
            registry = AcceptanceRegistry(path)
            self.assertEqual(registry.submit(inventory["run_id"], [package])["reason"],
                             "ALREADY_ACCEPTED")
        finally:
            registry.close()

    def test_ambiguous_registration_ack_cannot_start_live_execution(self):
        original_commit = AcceptanceRegistry._commit
        for committed in (False, True):
            with self.subTest(committed=committed):
                suffix = uuid4().hex
                inventory = {"schema_version": "m4-expected-inventory-v1",
                    "run_id": "ambiguous-preregister-run-" + suffix,
                    "run_challenge": "c" * 64,
                    "sessions": [{"task_id": "ambiguous-preregister-task-" + suffix,
                                  "session_id": "ambiguous-preregister-session-" + suffix,
                                  "monitor_instance_id": "ambiguous-preregister-monitor-" + suffix}]}
                path = Path(self.temp.name) / ("ambiguous-" + suffix + ".sqlite")
                ordering = []
                host = M6Host()

                def uncertain_commit(registry):
                    if committed:
                        original_commit(registry)
                    raise OSError("registration acknowledgement unavailable")

                with patch.object(AcceptanceRegistry, "_commit", uncertain_commit), \
                     patch.object(host, "open_task",
                                  side_effect=AssertionError("execution started")) as opened:
                    with self.assertRaisesRegex(RegistryAmbiguous,
                                                "REGISTRY_COMMIT_AMBIGUOUS"):
                        self.start_preregistered_live_task(path,
                            Path(self.temp.name) / ("ambiguous-audit-" + suffix + ".sqlite"),
                            inventory, self.config, self.pins, host, ordering)
                    opened.assert_not_called()
                self.assertEqual(ordering, [])
                registry = AcceptanceRegistry(path)
                try:
                    reconciled = registry.expected(inventory["run_id"])
                    if committed:
                        self.assertIsNotNone(reconciled)
                        self.assertEqual(reconciled.state, "ACTIVE")
                        self.assertEqual(decode(reconciled.inventory_bytes), inventory)
                        self.assertEqual(decode(reconciled.config_bytes), self.config)
                        self.assertEqual(reconciled.pins_bytes, encode({KEY_ID:
                            self.pins[KEY_ID].public_bytes(serialization.Encoding.PEM,
                                serialization.PublicFormat.SubjectPublicKeyInfo).decode("ascii")}))
                    else:
                        self.assertIsNone(reconciled)
                finally:
                    registry.close()

    def test_accepts_only_pre_registered_complete_live_run(self):
        self.assertEqual(self.registry.submit("unknown", [self.package_bytes])["reason"],
                         "UNKNOWN_EXPECTATION")
        for _ in range(2):
            inspection = inspect_live_run([self.package_bytes],
                expected_inventory=self.inventory, expected_configuration=self.config,
                trusted_signer_key_id=KEY_ID, pinned_public_key=self.key.public_key(),
                accepted_versions=PROFILE_VERSIONS, accepted_suite=SUITE)
            self.assertTrue(inspection["inspection_passed"], inspection)
            self.assertEqual(inspection["fresh_submission"], "NOT_CHECKED")
            self.assert_active()
        result = self.submit()
        self.assertEqual((result["status"], result["reason"], result["registry_durability"]),
                         ("ACCEPTED", "FRESH_COMPLETE_RUN", "COMMITTED"), result)
        closure = decode(self.package_bytes)["commitment"]
        self.assertEqual(result["commitments"], [{"session_id": closure["session_id"],
            "commitment_digest": commitment_digest(closure)}])
        self.assertEqual(result["verification"]["inspection_passed"], True)
        self.assertEqual(self.registry.expected(self.inventory["run_id"]),
                         replace(self.expected, state="ACCEPTED"))

    def test_overall_gate_rejects_even_when_inventory_dimension_passes(self):
        fake = inspect_live_run([self.package_bytes],
            expected_inventory=self.inventory, expected_configuration=self.config,
            trusted_signer_key_id=KEY_ID, pinned_public_key=self.key.public_key(),
            accepted_versions=PROFILE_VERSIONS, accepted_suite=SUITE)
        fake["inspection_passed"] = False
        fake["dimensions"]["lifecycle_semantics"]["status"] = "INCOMPLETE"
        with patch("chainguard.m6_live_verifier.inspect_live_run", return_value=fake):
            result = self.submit()
        self.assertEqual((result["status"], result["reason"]),
                         ("INCOMPLETE", "VERIFICATION_INCOMPLETE"), result)
        self.assert_active()

        fake["inspection_passed"] = "true"
        fake["dimensions"]["lifecycle_semantics"]["status"] = "PASS"
        with patch("chainguard.m6_live_verifier.inspect_live_run", return_value=fake):
            result = self.submit()
        self.assertEqual((result["status"], result["reason"]),
                         ("NOT_CHECKED", "VERIFICATION_NOT_CHECKED"), result)
        self.assert_active()

    def test_malformed_positive_live_inspection_cannot_commit(self):
        class EqualTo:
            def __init__(self, expected):
                self.expected = expected

            def __eq__(self, other):
                return self.expected == other

        class StringAlias(str):
            pass

        valid = inspect_live_run([self.package_bytes],
            expected_inventory=self.inventory, expected_configuration=self.config,
            trusted_signer_key_id=KEY_ID, pinned_public_key=self.key.public_key(),
            accepted_versions=PROFILE_VERSIONS, accepted_suite=SUITE)
        self.assertIs(valid["inspection_passed"], True)
        reproduction = valid["sessions"][0]["reproduction"]
        proposals = sum(entry["event"]["event_type"] == "CALL_PROPOSAL"
            for entry in decode(self.package_bytes)["records"])
        self.assertEqual(reproduction, {"proposals": proposals,
            "findings_reproduced": proposals * len(DETECTOR_IDS),
            "b2_agreeing_prefixes": proposals,
            "basis": "recorded_normalized_facts_only"})
        mutations = {
            "empty-dimensions": lambda r: r["dimensions"].clear(),
            "missing-dimension": lambda r: r["dimensions"].pop("lifecycle_semantics"),
            "unknown-dimension": lambda r: r["dimensions"].update(
                {"other": {"status": "PASS", "reason": "OTHER"}}),
            "non-pass-dimension": lambda r: r["dimensions"]["lifecycle_semantics"].update(
                {"status": "INCOMPLETE"}),
            "malformed-dimension": lambda r: r["dimensions"]["trusted_signature"].update(
                {"status": ["PASS"]}),
            "missing-reason": lambda r: r["dimensions"]["trusted_signature"].pop("reason"),
            "contradictory-session-reason": lambda r: r["sessions"][0]["dimensions"]
                ["trusted_signature"].update({"reason": "SIGNER_OR_SIGNATURE_MISMATCH"}),
            "unknown-session-reason": lambda r: r["sessions"][0]["dimensions"]
                ["trusted_signature"].update({"reason": "UNRECOGNIZED"}),
            "cross-dimension-reason": lambda r: r["sessions"][0]["dimensions"]
                ["trusted_signature"].update({"reason": "CHAIN_AND_CLOSURE_MATCH"}),
            "contradictory-run-reason": lambda r: r["dimensions"]["trusted_signature"]
                .update({"reason": "SIGNER_OR_SIGNATURE_MISMATCH"}),
            "unknown-run-reason": lambda r: r["dimensions"]["trusted_signature"]
                .update({"reason": "UNRECOGNIZED"}),
            "missing-reproduction": lambda r: r["sessions"][0].pop("reproduction"),
            "null-reproduction": lambda r: r["sessions"][0].update({"reproduction": None}),
            "missing-reproduction-field": lambda r: r["sessions"][0]["reproduction"]
                .pop("basis"),
            "extra-reproduction-field": lambda r: r["sessions"][0]["reproduction"]
                .update({"extra": 1}),
            "boolean-proposal-count": lambda r: r["sessions"][0]["reproduction"]
                .update({"proposals": True}),
            "negative-proposal-count": lambda r: r["sessions"][0]["reproduction"]
                .update({"proposals": -1}),
            "wrong-finding-count": lambda r: r["sessions"][0]["reproduction"]
                .update({"findings_reproduced": 0}),
            "wrong-prefix-count": lambda r: r["sessions"][0]["reproduction"]
                .update({"b2_agreeing_prefixes": 0}),
            "wrong-reproduction-basis": lambda r: r["sessions"][0]["reproduction"]
                .update({"basis": "raw_arguments_verified"}),
            "wrong-mode": lambda r: r.update({"mode": "INSPECT"}),
            "missing-freshness": lambda r: r.pop("fresh_submission"),
            "run-mode-equality-object": lambda r: r.update({"mode": EqualTo("INSPECT_RUN")}),
            "run-freshness-equality-object": lambda r: r.update(
                {"fresh_submission": EqualTo("NOT_CHECKED")}),
            "session-mode-equality-object": lambda r: r["sessions"][0].update(
                {"mode": EqualTo("INSPECT")}),
            "session-freshness-equality-object": lambda r: r["sessions"][0].update(
                {"fresh_submission": EqualTo("NOT_CHECKED")}),
            "run-mode-string-subclass": lambda r: r.update(
                {"mode": StringAlias("INSPECT_RUN")}),
            "session-freshness-string-subclass": lambda r: r["sessions"][0].update(
                {"fresh_submission": StringAlias("NOT_CHECKED")}),
            "integer-true": lambda r: r.update({"inspection_passed": 1}),
            "truthy-string": lambda r: r.update({"inspection_passed": "true"}),
            "missing-sessions": lambda r: r.update({"sessions": []}),
            "failed-session": lambda r: r["sessions"][0].update({"inspection_passed": False}),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                fake = deepcopy(valid)
                mutate(fake)
                with patch("chainguard.m6_live_verifier.inspect_live_run", return_value=fake), \
                     patch.object(self.registry, "_store_acceptance",
                                  side_effect=AssertionError("commit path reached")):
                    result = self.submit()
                self.assertEqual((result["status"], result["reason"]),
                                 ("NOT_CHECKED", "VERIFICATION_NOT_CHECKED"), result)
                self.assert_active()
        for name, fake in (("none", None), ("wrong-type", True)):
            with self.subTest(name=name):
                with patch("chainguard.m6_live_verifier.inspect_live_run", return_value=fake), \
                     patch.object(self.registry, "_store_acceptance",
                                  side_effect=AssertionError("commit path reached")):
                    result = self.submit()
                self.assertNotEqual(result["status"], "ACCEPTED", result)
                self.assert_active()
        with patch("chainguard.m6_live_verifier.inspect_live_run",
                   side_effect=RuntimeError("verifier unavailable")), \
             patch.object(self.registry, "_store_acceptance",
                          side_effect=AssertionError("commit path reached")):
            result = self.submit()
        self.assertEqual((result["status"], result["reason"]),
                         ("NOT_CHECKED", "VERIFICATION_NOT_CHECKED"))
        self.assert_active()

    def test_builtin_string_report_fields_accept(self):
        valid = inspect_live_run([self.package_bytes],
            expected_inventory=self.inventory, expected_configuration=self.config,
            trusted_signer_key_id=KEY_ID, pinned_public_key=self.key.public_key(),
            accepted_versions=PROFILE_VERSIONS, accepted_suite=SUITE)
        for report in (valid, valid["sessions"][0]):
            self.assertIs(type(report["mode"]), str)
            self.assertIs(type(report["fresh_submission"]), str)
        with patch("chainguard.m6_live_verifier.inspect_live_run", return_value=valid):
            result = self.submit()
        self.assertEqual((result["status"], result["reason"]),
                         ("ACCEPTED", "FRESH_COMPLETE_RUN"), result)

    def test_signed_missing_terminal_outcome_is_not_accepted(self):
        package = decode(self.package_bytes)
        position = next(i for i, entry in enumerate(package["records"])
            if entry["event"]["event_type"] == "DISPATCH_INTENT")
        del package["records"][position + 1:]
        result = self.submit([self.resign(package)])
        self.assertEqual(result["status"], "INCOMPLETE", result)
        dimensions = result["verification"]["dimensions"]
        self.assertEqual(dimensions["inventory_completeness"]["status"], "PASS")
        self.assertEqual(dimensions["lifecycle_semantics"]["status"], "INCOMPLETE")
        self.assert_active()

    def test_wrong_signer_key_configuration_challenge_and_inventory_rejected(self):
        other_key = ec.generate_private_key(ec.SECP256R1())
        cases = (("wrong-signer", {"different-id": self.key.public_key()}),
                 ("wrong-key", {KEY_ID: other_key.public_key()}))
        for name, pins in cases:
            with self.subTest(name=name):
                path = Path(self.temp.name) / (name + ".sqlite")
                registry = AcceptanceRegistry.create(path)
                try:
                    registry.register(self.inventory, self.config, pins)
                    result = registry.submit(self.inventory["run_id"], [self.package_bytes])
                    self.assertEqual(result["status"], "REJECTED", result)
                    self.assertEqual(result["verification"]["dimensions"]
                                     ["trusted_signature"]["status"], "FAIL")
                finally:
                    registry.close()
        changed = deepcopy(self.config)
        changed["policy"]["digest"] = "0" * 64
        with self.assertRaises(ValueError):
            self.registry.register(self.inventory, changed, self.pins)
        package = decode(self.package_bytes)
        package["manifest"]["configuration"]["policy"]["digest"] = "0" * 64
        package["records"][0]["event"]["body"]["manifest_digest"] = \
            manifest_digest(package["manifest"])
        result = self.submit([self.resign(package)])
        self.assertEqual(result["status"], "REJECTED", result)
        self.assertEqual(result["verification"]["dimensions"]["expected_binding"]
                         ["status"], "FAIL")
        for name, altered in (("challenge", "run_challenge"), ("inventory", "sessions")):
            with self.subTest(name=name):
                inventory = deepcopy(self.inventory)
                if altered == "run_challenge":
                    inventory["run_challenge"] = "b" * 64
                else:
                    inventory["sessions"].append({"task_id": "zzz-task",
                        "session_id": "zzz-session", "monitor_instance_id": "zzz-monitor"})
                registry = AcceptanceRegistry.create(Path(self.temp.name) / (name + ".sqlite"))
                try:
                    registry.register(inventory, self.config, self.pins)
                    result = registry.submit(inventory["run_id"], [self.package_bytes])
                    self.assertEqual(result["status"], "REJECTED", result)
                    self.assertEqual(result["verification"]["dimensions"]
                                     ["expected_binding"]["status"], "FAIL")
                finally:
                    registry.close()
        self.assert_active()

    def test_missing_duplicate_and_unexpected_sessions_rejected(self):
        inventory = deepcopy(self.inventory)
        inventory["sessions"].append({"task_id": "zzz-task", "session_id": "zzz-session",
                                      "monitor_instance_id": "zzz-monitor"})
        snapshots = [self.signed_minimal(inventory, identity)
                     for identity in inventory["sessions"]]
        registry = AcceptanceRegistry.create(Path(self.temp.name) / "multi.sqlite")
        try:
            expected = registry.register(inventory, self.config, self.pins)
            run_id = inventory["run_id"]
            self.assertEqual(registry.submit(run_id, snapshots[:1])["status"], "INCOMPLETE")
            self.assertEqual(registry.submit(run_id, [snapshots[0]] * 2)["status"], "REJECTED")
            self.assertEqual(registry.submit(run_id, snapshots + [self.package_bytes])
                             ["status"], "REJECTED")
            self.assertEqual(registry.expected(run_id), expected)
            self.assertEqual(registry.submit(run_id, snapshots)["status"], "ACCEPTED")
        finally:
            registry.close()

    def test_duplicate_and_resigned_replay_rejected_after_restart(self):
        self.assertEqual(self.submit()["status"], "ACCEPTED")
        self.assertEqual(self.submit()["reason"], "ALREADY_ACCEPTED")
        package = decode(self.package_bytes)
        package["signature"] = sign_live_commitment(self.key, package["commitment"])
        self.assertEqual(self.submit([encode(package)])["reason"], "ALREADY_ACCEPTED")
        self.registry.close()
        self.registry = AcceptanceRegistry(self.path)
        self.assertEqual(self.submit()["reason"], "ALREADY_ACCEPTED")

    def test_ambiguous_post_commit_ack_never_guesses_accepted(self):
        commit = self.registry._commit
        def lost_ack():
            commit()
            raise OSError("lost acceptance acknowledgement")
        with patch.object(self.registry, "_commit", side_effect=lost_ack):
            result = self.submit()
        self.assertEqual((result["status"], result["registry_durability"]),
                         ("NOT_CHECKED", "UNKNOWN"))
        self.registry.close()
        self.registry = AcceptanceRegistry(self.path)
        self.assertEqual(self.submit()["reason"], "ALREADY_ACCEPTED")

    def test_ambiguous_pre_commit_ack_requires_reconciliation(self):
        with patch.object(self.registry, "_commit", side_effect=OSError("before commit")):
            result = self.submit()
        self.assertEqual((result["status"], result["registry_durability"]),
                         ("NOT_CHECKED", "UNKNOWN"))
        self.registry.close()
        self.registry = AcceptanceRegistry(self.path)
        self.assert_active()
        self.assertEqual(self.submit()["status"], "ACCEPTED")

    def test_signed_revocation_deletion_without_ordinal_gap_rejected(self):
        package = decode(self.package_bytes)
        revoke_ids = {entry["event"]["event_id"] for entry in package["records"]
            if entry["event"]["event_type"] == "REVOKE_SCOPE"}
        package["records"] = [entry for entry in package["records"]
            if entry["event"]["event_type"] != "REVOKE_SCOPE"]
        ordinal = 0
        for entry in package["records"]:
            event = entry["event"]
            if event["event_type"] in {"GRANT", "REVOKE_SCOPE", "CALL_PROPOSAL"}:
                ordinal += 1
                event["body"]["admission_ordinal"] = ordinal
            if event["event_type"] == "DETECTOR_FINDING":
                event["body"]["supporting_event_ids"] = [reference for reference in
                    event["body"]["supporting_event_ids"] if reference not in revoke_ids]
        altered = self.resign(package)
        records = [entry["event"] for entry in decode(altered)["records"]]
        with self.assertRaisesRegex(ValueError, "Controller assessment contradicts history"):
            reconstruct_lifecycle(records, POLICY, package["manifest"]["execution_profile"],
                require_complete=False, synthetic_experiment=self.config["synthetic_experiment"],
                synthetic_sink=self.config["synthetic_sink"],
                enforcement_detector=self.config["enforcement_detector"])
        result = self.submit([altered])
        self.assertEqual(result["status"], "REJECTED", result)
        dimensions = result["verification"]["dimensions"]
        self.assertEqual(dimensions["commitment_integrity"]["status"], "PASS")
        self.assertEqual(dimensions["trusted_signature"]["status"], "PASS")
        self.assertEqual(dimensions["lifecycle_semantics"]["status"], "FAIL")
        self.assert_active()

    def test_signed_reuse_of_consumed_grant_rejected(self):
        package = decode(self.package_bytes)
        records = package["records"]
        target = next(i for i, entry in enumerate(records)
            if entry["event"]["event_type"] == "CALL_PROPOSAL" and
            entry["event"]["body"]["request_id"] == "denied-after")
        available = deepcopy(next(entry for entry in records
            if entry["event"]["event_type"] == "GRANT" and
            entry["event"]["body"]["grant_id"] == "grant-2"))
        available["event"]["event_id"] = "extra-active-grant"
        available["event"]["body"]["grant_id"] = "grant-extra"
        records.insert(target, available)
        call_id = records[target + 1]["event"]["call_id"]
        decision_index = next(i for i, entry in enumerate(records)
            if entry["event"]["event_type"] == "DISPATCH_DECISION" and
            entry["event"]["call_id"] == call_id)
        decision = records[decision_index]["event"]["body"]
        decision.update({"authorization_assessment": "AUTHORIZED",
                         "dispatch_decision": "ALLOW", "reason": "Confirmed task permission"})
        intent = deepcopy(next(entry for entry in records
            if entry["event"]["event_type"] == "DISPATCH_INTENT" and
            any(selection["grant_id"] == "grant-1" for selection in
                entry["event"]["body"]["selected_grants"])))
        self.assertEqual([selection["grant_id"] for selection in
                         intent["event"]["body"]["selected_grants"]], ["grant-1"])
        intent["event"]["event_id"] = "reused-consumed-grant-intent"
        intent["event"]["call_id"] = call_id
        intent["event"]["body"]["call_id"] = call_id
        records.insert(decision_index + 1, intent)
        outcome = next(entry["event"] for entry in records
            if entry["event"]["event_type"] == "TOOL_OUTCOME" and
            entry["event"]["call_id"] == call_id)
        outcome["body"]["status"] = "succeeded"
        ordinal = 0
        for entry in records:
            event = entry["event"]
            if event["event_type"] in {"GRANT", "REVOKE_SCOPE", "CALL_PROPOSAL"}:
                ordinal += 1
                event["body"]["admission_ordinal"] = ordinal
        altered = self.resign(package)
        records_for_check = [entry["event"] for entry in decode(altered)["records"]]
        with self.assertRaisesRegex(ValueError, "Inactive or nonminimum selected grant"):
            reconstruct_lifecycle(records_for_check, POLICY,
                package["manifest"]["execution_profile"], require_complete=False,
                synthetic_experiment=self.config["synthetic_experiment"],
                synthetic_sink=self.config["synthetic_sink"],
                enforcement_detector=self.config["enforcement_detector"])
        result = self.submit([altered])
        self.assertEqual(result["status"], "REJECTED", result)
        dimensions = result["verification"]["dimensions"]
        self.assertEqual(dimensions["commitment_integrity"]["status"], "PASS")
        self.assertEqual(dimensions["trusted_signature"]["status"], "PASS")
        self.assertEqual(dimensions["lifecycle_semantics"]["status"], "FAIL")
        self.assert_active()

    def test_live_registration_requires_one_assessor_pin(self):
        with self.assertRaises(ValueError):
            self.registry.register(self.inventory, self.config, {})
        with self.assertRaises(ValueError):
            self.registry.register(self.inventory, self.config,
                {**self.pins, "other": ec.generate_private_key(ec.SECP256R1()).public_key()})
        self.assert_active()


if __name__ == "__main__":
    unittest.main()
