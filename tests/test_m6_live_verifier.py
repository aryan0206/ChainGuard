"""Offline live verifier tests against a genuine clean-close export and mutants."""

from copy import deepcopy
from io import BytesIO
import base64
import json
from pathlib import Path
import tempfile
import unittest
from uuid import uuid4

from cryptography.hazmat.primitives.asymmetric import ec

from chainguard.canonical import decode, encode
from chainguard.evidence import SUITE, event_hash, genesis
from chainguard.m6_live_profile import (PROFILE_VERSIONS, live_configuration,
    make_live_manifest)
from chainguard.m6_live_runtime import M6Host
from chainguard.m6_live_seal import make_live_commitment, sign_live_commitment
from chainguard.m6_live_verifier import (DIMENSIONS, inspect_live_package,
    inspect_live_run)
from chainguard.semantics import Scope
from tests.test_m1 import request
from tests.test_m6_live_evidence import fixture_package


KEY_ID = "verifier-test-key"


class LiveVerifierTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temp.cleanup)
        suffix = uuid4().hex
        cls.inventory = {"schema_version": "m4-expected-inventory-v1",
            "run_id": "verify-run-" + suffix, "run_challenge": "a" * 64,
            "sessions": [{"task_id": "verify-task-" + suffix,
                          "session_id": "verify-session-" + suffix,
                          "monitor_instance_id": "verify-monitor-" + suffix}]}
        cls.config = live_configuration()
        cls.key = ec.generate_private_key(ec.SECP256R1())
        identity = cls.inventory["sessions"][0]
        database = Path(cls.temp.name) / "fixture.sqlite"
        task = M6Host().open_task(db_path=database, trusted_inventory=cls.inventory,
            **identity)
        try:
            def call(number, name, arguments=None):
                frame = json.dumps(request(number, "tools/call", name=name,
                    arguments={} if arguments is None else arguments),
                    separators=(",", ":")).encode() + b"\n"
                output = BytesIO()
                task._submit_client_frame(frame, output).result(timeout=15)
                return json.loads(output.getvalue())

            assert "result" in call("read", "read_secret_a")
            assert "error" in call("denied-before", "send_sink",
                                    {"payload": "SYNTHETIC_CANARY_A"})
            scope = Scope(identity["task_id"], "secret-a", "sink")
            task.grant("grant-1", scope).result(timeout=15)
            assert "result" in call("allowed", "send_sink",
                                    {"payload": "SYNTHETIC_CANARY_A"})
            assert "error" in call("denied-after", "send_sink",
                                    {"payload": "SYNTHETIC_CANARY_A"})
            task.grant("grant-2", scope).result(timeout=15)
            task.revoke(scope).result(timeout=15)
            assert "error" in call("denied-revoked", "send_sink",
                                    {"payload": "SYNTHETIC_CANARY_A"})
            assert call("failed", "controlled_failure", {"token": "x"})["result"]["isError"]
            task.shutdown().result(timeout=15)
            cls.package_bytes = task.export_live_evidence(
                expected_inventory=cls.inventory, expected_configuration=cls.config,
                private_key=cls.key, signer_key_id=KEY_ID,
                pinned_public_keys={KEY_ID: cls.key.public_key()},
                output_path=Path(cls.temp.name) / "export.json")
        finally:
            if task._state == "ACTIVE":
                task.shutdown().result(timeout=15)
            task._thread.join(timeout=15)
        database.unlink()  # Inspection is strictly offline; the test DB is temporary.

    def inspect(self, data=None, **changes):
        options = {"expected_inventory": self.inventory,
            "expected_configuration": self.config, "trusted_signer_key_id": KEY_ID,
            "pinned_public_key": self.key.public_key(),
            "accepted_versions": PROFILE_VERSIONS, "accepted_suite": SUITE}
        options.update(changes)
        return inspect_live_package(self.package_bytes if data is None else data, **options)

    def inspect_run(self, snapshots, **changes):
        options = {"expected_inventory": self.inventory,
            "expected_configuration": self.config, "trusted_signer_key_id": KEY_ID,
            "pinned_public_key": self.key.public_key(),
            "accepted_versions": PROFILE_VERSIONS, "accepted_suite": SUITE}
        options.update(changes)
        return inspect_live_run(snapshots, **options)

    def signed_mutant(self, change):
        package = decode(self.package_bytes)
        change(package)
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

    def assert_dimension(self, report, name, status):
        self.assertEqual(report["dimensions"][name]["status"], status, report)
        self.assertFalse(report["inspection_passed"])
        self.assertEqual(report["fresh_submission"], "NOT_CHECKED")

    def test_genuine_clean_close_reconstructs_all_dimensions_offline(self):
        report = self.inspect()
        self.assertEqual(tuple(report["dimensions"]), DIMENSIONS)
        self.assertTrue(report["inspection_passed"], report)
        self.assertEqual(report["fresh_submission"], "NOT_CHECKED")
        self.assertEqual(report["reproduction"]["basis"],
                         "recorded_normalized_facts_only")
        self.assertEqual(report["reproduction"]["findings_reproduced"],
                         4 * report["reproduction"]["proposals"])

    def test_raw_encoding_and_profile_mutations_fail_schema(self):
        package = decode(self.package_bytes)
        for mutation in (self.package_bytes + b" ",
                         self.package_bytes.replace(b'"format_version":',
                             b'"format_version":"m6-live-evidence-v1","format_version":', 1)):
            with self.subTest(mutation=mutation[-30:]):
                self.assert_dimension(self.inspect(mutation), "package_schema", "FAIL")
        for value in ("m4-evidence-v1", "m6-evidence-v1"):
            with self.subTest(profile=value):
                changed = deepcopy(package)
                changed["format_version"] = value
                self.assert_dimension(self.inspect(encode(changed)), "package_schema", "FAIL")
        self.assert_dimension(self.inspect(accepted_versions=("m6-evidence-v1",),
                           ), "package_schema", "FAIL")
        self.assert_dimension(self.inspect(accepted_suite="none"), "package_schema", "FAIL")

    def test_modified_deleted_duplicated_and_reordered_records_fail(self):
        for kind in ("modified", "deleted", "duplicated", "reordered"):
            with self.subTest(kind=kind):
                package = decode(self.package_bytes)
                records = package["records"]
                if kind == "modified":
                    records[2]["event"]["event_id"] = "altered"
                elif kind == "deleted":
                    del records[2]
                elif kind == "duplicated":
                    records.insert(3, deepcopy(records[2]))
                else:
                    records[2], records[3] = records[3], records[2]
                report = self.inspect(encode(package))
                self.assertFalse(report["inspection_passed"], report)
                self.assertIn("FAIL", [item["status"] for item in report["dimensions"].values()])

    def test_wrong_pin_and_assessor_context_fail_distinct_dimensions(self):
        self.assert_dimension(self.inspect(pinned_public_key=
            ec.generate_private_key(ec.SECP256R1()).public_key()),
            "trusted_signature", "FAIL")
        self.assert_dimension(self.inspect(trusted_signer_key_id="other-key"),
            "trusted_signature", "FAIL")
        wrong = deepcopy(self.inventory)
        wrong["run_challenge"] = "b" * 64
        self.assert_dimension(self.inspect(expected_inventory=wrong),
            "expected_binding", "FAIL")
        wrong_config = deepcopy(self.config)
        wrong_config["policy"]["max_payload_bytes"] += 1
        self.assert_dimension(self.inspect(expected_configuration=wrong_config),
            "expected_binding", "FAIL")

    def test_invalid_signature_and_recomputed_chain_without_resigning(self):
        package = decode(self.package_bytes)
        signature = bytearray(base64.b64decode(package["signature"]))
        signature[-1] ^= 1
        package["signature"] = base64.b64encode(signature).decode("ascii")
        report = self.inspect(encode(package))
        self.assert_dimension(report, "trusted_signature", "FAIL")
        self.assert_dimension(report, "commitment_integrity", "PASS")

        package = decode(self.package_bytes)
        package["records"][-1]["event"]["event_id"] = "rewritten-tail"
        package["records"][-1]["event_hash"] = event_hash(package["records"][-1]["event"])
        package["commitment"]["final_head"] = package["records"][-1]["event_hash"]
        report = self.inspect(encode(package))
        self.assert_dimension(report, "commitment_integrity", "PASS")
        self.assert_dimension(report, "trusted_signature", "FAIL")

    def test_valid_signature_does_not_cover_invalid_lifecycle(self):
        def wrong_grant(package):
            for entry in package["records"]:
                event = entry["event"]
                if event["event_type"] == "DISPATCH_INTENT" and event["body"]["selected_grants"]:
                    event["body"]["selected_grants"][0]["grant_id"] = "nonexistent-grant"
                    return
            self.fail("Expected a consumed grant")
        report = self.inspect(self.signed_mutant(wrong_grant))
        self.assert_dimension(report, "lifecycle_semantics", "FAIL")
        self.assert_dimension(report, "trusted_signature", "PASS")
        self.assert_dimension(report, "commitment_integrity", "PASS")

    def test_valid_signature_cannot_justify_wrong_tool_or_result_contract(self):
        def wrong_tool(package):
            for entry in package["records"]:
                event = entry["event"]
                if event["event_type"] == "CALL_PROPOSAL":
                    event["body"]["tool"] = "echo"
                    return
        def wrong_result(package):
            for entry in package["records"]:
                event = entry["event"]
                if event["event_type"] == "TOOL_OUTCOME" and event["body"]["status"] == "succeeded":
                    event["body"]["status"] = "failed"
                    return
        def wrong_server(package):
            call_id = None
            for entry in package["records"]:
                event = entry["event"]
                if event["event_type"] == "CALL_PROPOSAL":
                    event["body"]["server"] = "forged-server"
                    call_id = event["call_id"]
                elif event["event_type"] == "TOOL_OUTCOME" and event["call_id"] == call_id:
                    event["body"]["server"] = "forged-server"
                    return
        for mutation in (wrong_tool, wrong_result):
            with self.subTest(mutation=mutation.__name__):
                report = self.inspect(self.signed_mutant(mutation))
                self.assert_dimension(report, "lifecycle_semantics", "FAIL")
                self.assert_dimension(report, "trusted_signature", "PASS")
        self.assert_dimension(self.inspect(self.signed_mutant(wrong_server)),
                              "package_schema", "FAIL")

    def test_valid_signature_cannot_justify_wrong_finding(self):
        def wrong_finding(package):
            for entry in package["records"]:
                event = entry["event"]
                if event["event_type"] == "DETECTOR_FINDING":
                    event["body"]["explanation"] += " forged"
                    return
        report = self.inspect(self.signed_mutant(wrong_finding))
        self.assert_dimension(report, "finding_reproduction", "FAIL")
        self.assert_dimension(report, "lifecycle_semantics", "PASS")
        self.assert_dimension(report, "trusted_signature", "PASS")

    def test_signed_denial_grant_and_revocation_inconsistencies_fail_lifecycle(self):
        def forwarded_denial(package):
            for entry in package["records"]:
                event = entry["event"]
                if event["event_type"] == "TOOL_OUTCOME" and event["body"]["status"] == "denied":
                    event["body"]["status"] = "succeeded"
                    return
        def duplicate_grant(package):
            for entry in package["records"]:
                event = entry["event"]
                if event["event_type"] == "GRANT" and event["body"]["grant_id"] == "grant-2":
                    event["body"]["grant_id"] = "grant-1"
                    return
        def missing_revocation(package):
            package["records"] = [entry for entry in package["records"]
                if entry["event"]["event_type"] != "REVOKE_SCOPE"]
        for mutation in (forwarded_denial, duplicate_grant, missing_revocation):
            with self.subTest(mutation=mutation.__name__):
                report = self.inspect(self.signed_mutant(mutation))
                self.assert_dimension(report, "lifecycle_semantics", "FAIL")
                self.assert_dimension(report, "trusted_signature", "PASS")

    def test_signed_truncation_and_unknown_outcome_are_incomplete(self):
        def missing_end(package):
            package["records"].pop()
        def unknown(package):
            for entry in package["records"]:
                event = entry["event"]
                if event["event_type"] == "TOOL_OUTCOME" and event["body"]["status"] == "succeeded":
                    event["body"]["status"] = "unknown"
                    break
            del package["records"][next(i for i, entry in enumerate(package["records"])
                if entry["event"]["event_type"] == "TOOL_OUTCOME" and
                entry["event"]["body"]["status"] == "unknown") + 1:]
        for mutation in (missing_end, unknown):
            with self.subTest(mutation=mutation.__name__):
                report = self.inspect(self.signed_mutant(mutation))
                self.assert_dimension(report, "lifecycle_semantics", "INCOMPLETE")
                self.assert_dimension(report, "trusted_signature", "PASS")
                self.assertNotIn("reproduction", report)

    def test_signed_intent_without_terminal_outcome_is_incomplete(self):
        def missing_outcome(package):
            position = next(i for i, entry in enumerate(package["records"])
                if entry["event"]["event_type"] == "DISPATCH_INTENT")
            del package["records"][position + 1:]
        report = self.inspect(self.signed_mutant(missing_outcome))
        self.assert_dimension(report, "lifecycle_semantics", "INCOMPLETE")
        self.assert_dimension(report, "trusted_signature", "PASS")

    def test_complete_run_requires_exact_inventory_once(self):
        report = self.inspect_run([self.package_bytes])
        self.assertTrue(report["inspection_passed"], report)
        self.assert_dimension(self.inspect_run([]), "inventory_completeness", "INCOMPLETE")
        self.assert_dimension(self.inspect_run([self.package_bytes] * 2),
                              "inventory_completeness", "FAIL")
        second = deepcopy(self.inventory)
        second["sessions"].append({"task_id": "zzz-task", "session_id": "zzz-session",
                                   "monitor_instance_id": "zzz-monitor"})
        self.assert_dimension(self.inspect_run([self.package_bytes], expected_inventory=second),
                              "inventory_completeness", "INCOMPLETE")
        self.assert_dimension(self.inspect(expected_inventory=second),
                              "expected_binding", "FAIL")

    def test_complete_multisession_run_and_extra_session(self):
        inventory = deepcopy(self.inventory)
        inventory["sessions"].append({"task_id": "zzz-task", "session_id": "zzz-session",
                                      "monitor_instance_id": "zzz-monitor"})
        snapshots = []
        for identity in inventory["sessions"]:
            manifest = make_live_manifest(inventory, self.config, **identity)
            package = fixture_package(manifest)
            package["records"][0]["event"]["body"]["manifest_digest"] = \
                package["commitment"]["manifest_digest"]
            head = package["commitment"]["final_head"]
            package["commitment"] = make_live_commitment(manifest, 2, head, KEY_ID)
            package["signature"] = sign_live_commitment(self.key, package["commitment"])
            snapshots.append(encode(package))
        report = self.inspect_run(snapshots, expected_inventory=inventory)
        self.assertTrue(report["inspection_passed"], report)
        self.assert_dimension(self.inspect_run(snapshots + [self.package_bytes],
            expected_inventory=inventory), "inventory_completeness", "FAIL")


if __name__ == "__main__":
    unittest.main()
