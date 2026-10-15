"""Signed offline M6 permission packages; no live permission authority."""

from copy import deepcopy
from dataclasses import replace
from pathlib import Path
import subprocess
from tempfile import TemporaryDirectory
import unittest

from cryptography.hazmat.primitives.asymmetric import ec

from chainguard.acceptance import AcceptanceRegistry
from chainguard.canonical import decode, encode
from chainguard.detectors import B2Reference, B2Streaming, b0, b1
from chainguard.evidence import (ARTIFACT_NAMES as M4_ARTIFACT_NAMES, INVENTORY_SCHEMA,
    ROOT, event_hash, genesis, manifest_digest, configuration, sha256)
from chainguard.permission_profile import (EXECUTION_PROFILE, POLICY, _finding_body,
    inspect_permission_package, inspect_permission_run, make_permission_commitment,
    make_permission_manifest, permission_configuration, sign_permission_commitment)
from chainguard.semantics import Current, Fact, Scope, attach_references, project_b1
from chainguard.verifier import inspect_package
from tests.test_m6_evidence import LifecycleTranscript, lifecycle_event


KEY_ID = "m6-fixture-key"


def inventory(count=1):
    return {"schema_version": INVENTORY_SCHEMA, "run_id": "m6-run",
            "run_challenge": "ab" * 32,
            "sessions": [{"task_id": f"m6-task-{n}", "session_id": f"m6-session-{n}",
                          "monitor_instance_id": f"m6-monitor-{n}"} for n in range(count)]}


def signed_package(expected, config, key, association):
    manifest = make_permission_manifest(expected, config, **association)
    transcript = LifecycleTranscript(EXECUTION_PROFILE)
    transcript.grant()
    transcript.call()
    transcript.finish()
    records = deepcopy(transcript.records)
    for record in records:
        record["run_id"] = expected["run_id"]
        record.update(association)
    start = lifecycle_event(records, "SESSION_START")
    start["body"]["run_challenge"] = expected["run_challenge"]
    start["body"]["manifest_digest"] = manifest_digest(manifest)
    proposal = lifecycle_event(records, "CALL_PROPOSAL")
    current = Current(**{**proposal["body"]["current"],
                         "sensitive_resources": tuple(proposal["body"]["current"]["sensitive_resources"])})
    grant = lifecycle_event(records, "GRANT")
    history = (Fact("GRANT", grant["event_id"],
                    scope=Scope(association["task_id"], "secret-a", "sink"), grant_id="g"),)
    reference = B2Reference(association["task_id"], POLICY)
    streaming = B2Streaming(association["task_id"], POLICY)
    streaming.observe(history[0])
    proposal_id = proposal["event_id"]
    findings = (b0(current, POLICY), b1(current, project_b1(history, association["task_id"]), POLICY),
                reference.evaluate(current, history, proposal_id), streaming.evaluate(current, proposal_id))
    findings = (replace(findings[0], supporting_event_ids=(proposal_id,)),
                attach_references(findings[1], proposal_id, current, history), *findings[2:])
    finding_records = [r for r in records if r["event_type"] == "DETECTOR_FINDING"]
    for record, finding in zip(finding_records, findings, strict=True):
        record["body"] = _finding_body(finding, proposal_id)
    head, entries = genesis(manifest), []
    for record in records:
        record["prev_hash"] = head
        head = event_hash(record)
        entries.append({"event": record, "event_hash": head})
    closure = make_permission_commitment(manifest, len(entries), head, KEY_ID)
    return encode({"format_version": "m6-evidence-v1", "manifest": manifest,
                   "records": entries, "commitment": closure,
                   "signature": sign_permission_commitment(key, closure)})


def resign(package, key):
    head = genesis(package["manifest"])
    for entry in package["records"]:
        entry["event"]["prev_hash"] = head
        head = event_hash(entry["event"])
        entry["event_hash"] = head
    package["commitment"] = make_permission_commitment(package["manifest"],
        len(package["records"]), head, KEY_ID)
    package["signature"] = sign_permission_commitment(key, package["commitment"])
    return encode(package)


class PermissionProfileTests(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory(prefix="m6-profile-")
        self.expected = inventory()
        self.config = permission_configuration()
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.pins = {KEY_ID: self.key.public_key()}
        self.data = signed_package(self.expected, self.config, self.key, self.expected["sessions"][0])
        self.registry = AcceptanceRegistry.create(Path(self.temp.name) / "registry.sqlite")
        self.original = self.registry.register(self.expected, self.config, self.pins)

    def tearDown(self):
        self.registry.close()
        self.temp.cleanup()

    def inspect(self, data=None, config=None, pins=None):
        return inspect_permission_package(self.data if data is None else data, self.expected,
            self.config if config is None else config, self.pins if pins is None else pins)

    def assert_active(self):
        self.assertEqual(self.registry.expected(self.expected["run_id"]), self.original)
        self.assertEqual(self.registry._connection.execute("SELECT count(*) FROM accepted_sessions").fetchone(), (0,))

    def test_valid_permission_profile_and_repeatable_inspection(self):
        for _ in range(2):
            report = self.inspect()
            self.assertTrue(report["inspection_passed"], report)
            self.assertEqual(report["reproduction"], {"proposals": 1, "findings_reproduced": 4,
                                                       "b2_agreeing_prefixes": 1})
            self.assert_active()
        accepted = self.registry.submit(self.expected["run_id"], [self.data])
        self.assertEqual(accepted["status"], "ACCEPTED", accepted)
        self.assertEqual(self.registry.submit(self.expected["run_id"], [self.data])["reason"], "ALREADY_ACCEPTED")

    def test_accepted_permission_run_survives_registry_restart(self):
        path = Path(self.temp.name) / "registry.sqlite"
        self.assertEqual(self.registry.submit(self.expected["run_id"], [self.data])["status"], "ACCEPTED")
        self.registry.close()
        self.registry = AcceptanceRegistry(path)
        self.assertEqual(self.registry.submit(self.expected["run_id"], [self.data])["reason"], "ALREADY_ACCEPTED")

    def test_tampered_record_fails_chain_and_does_not_consume(self):
        package = decode(self.data)
        package["records"][1]["event"]["observed_at_utc"] = "2026-10-16T00:00:00Z"
        report = self.inspect(encode(package))
        self.assertEqual(report["dimensions"]["commitment_integrity"]["status"], "FAIL")
        self.assertEqual(self.registry.submit(self.expected["run_id"], [encode(package)])["status"], "REJECTED")
        self.assert_active()

    def test_changed_manifest_and_external_configuration_fail_binding(self):
        package = decode(self.data)
        package["manifest"]["configuration"]["policy"]["digest"] = "0" * 64
        start = package["records"][0]["event"]
        start["body"]["manifest_digest"] = manifest_digest(package["manifest"])
        altered = resign(package, self.key)
        report = self.inspect(altered)
        self.assertEqual(report["dimensions"]["commitment_integrity"]["status"], "PASS")
        self.assertEqual(report["dimensions"]["trusted_signature"]["status"], "PASS")
        self.assertEqual(report["dimensions"]["expected_binding"]["status"], "FAIL")
        self.assertEqual(self.registry.submit(self.expected["run_id"], [altered])["status"], "REJECTED")
        self.assert_active()
        changed = deepcopy(self.config)
        changed["normalizer"]["digest"] = "0" * 64
        self.assertEqual(self.inspect(config=changed)["dimensions"]["expected_binding"]["status"], "FAIL")

    def test_invalid_signature_and_wrong_pin_fail(self):
        package = decode(self.data)
        package["signature"] = "AAAA"
        self.assertEqual(self.inspect(encode(package))["dimensions"]["trusted_signature"]["status"], "FAIL")
        self.assertEqual(self.registry.submit(self.expected["run_id"], [encode(package)])["status"], "REJECTED")
        self.assert_active()
        wrong = ec.generate_private_key(ec.SECP256R1())
        self.assertEqual(self.inspect(pins={KEY_ID: wrong.public_key()})["dimensions"]["trusted_signature"]["status"], "FAIL")

    def test_no_m4_or_mixed_profile_fallback(self):
        package = decode(self.data)
        package["format_version"] = "m4-evidence-v1"
        self.assertEqual(self.inspect(encode(package))["dimensions"]["schema_lifecycle"]["status"], "FAIL")
        package = decode(self.data)
        package["manifest"]["record_schema_version"] = "m4-record-v1"
        self.assertEqual(self.inspect(encode(package))["dimensions"]["schema_lifecycle"]["status"], "FAIL")
        package = decode(self.data)
        package["commitment"]["schema_version"] = "m4-commitment-v1"
        self.assertEqual(self.inspect(encode(package))["dimensions"]["trusted_signature"]["status"], "FAIL")

    def test_authentic_altered_finding_fails_reproduction_only(self):
        package = decode(self.data)
        next(e["event"]["body"] for e in package["records"]
             if e["event"]["event_type"] == "DETECTOR_FINDING")["explanation"] = "fabricated"
        altered = resign(package, self.key)
        report = self.inspect(altered)
        self.assertEqual(report["dimensions"]["finding_reproduction"]["status"], "FAIL")
        self.assertTrue(all(d["status"] == "PASS" for name, d in report["dimensions"].items()
                            if name != "finding_reproduction"), report)
        self.assertEqual(self.registry.submit(self.expected["run_id"], [altered])["status"], "REJECTED")
        self.assert_active()

    def test_signed_invalid_lifecycle_is_distinct_from_crypto(self):
        package = decode(self.data)
        intent = next(e["event"]["body"] for e in package["records"]
                      if e["event"]["event_type"] == "DISPATCH_INTENT")
        intent["selected_grants"][0]["grant_id"] = "nonexistent"
        altered = resign(package, self.key)
        dims = self.inspect(altered)["dimensions"]
        self.assertEqual(dims["commitment_integrity"]["status"], "PASS")
        self.assertEqual(dims["trusted_signature"]["status"], "PASS")
        self.assertEqual(dims["lifecycle_semantics"]["status"], "FAIL")

    def test_missing_and_duplicate_sessions_do_not_consume(self):
        second_expected = inventory(2)
        second_config = self.config
        second_data = [signed_package(second_expected, second_config, self.key, entry)
                       for entry in second_expected["sessions"]]
        second_registry = AcceptanceRegistry.create(Path(self.temp.name) / "multi.sqlite")
        try:
            original = second_registry.register(second_expected, second_config, self.pins)
            missing = second_registry.submit(second_expected["run_id"], second_data[:1])
            self.assertEqual(missing["status"], "INCOMPLETE", missing)
            duplicate = second_registry.submit(second_expected["run_id"], [second_data[0]] * 2)
            self.assertEqual(duplicate["status"], "REJECTED", duplicate)
            self.assertEqual(second_registry.expected(second_expected["run_id"]), original)
            self.assertEqual(second_registry._connection.execute("SELECT count(*) FROM accepted_sessions").fetchone(), (0,))
            self.assertTrue(inspect_permission_run(second_data, second_expected, second_config, self.pins)["inspection_passed"])
            self.assertEqual(second_registry.submit(second_expected["run_id"], second_data)["status"], "ACCEPTED")
        finally:
            second_registry.close()

    def test_m4_profile_stays_separate_and_installed_digest_stable(self):
        self.assertEqual(self.inspect()["dimensions"]["expected_binding"]["status"], "PASS")
        m4_config = configuration()
        self.assertNotEqual(m4_config["schema_version"], self.config["schema_version"])
        for name in M4_ARTIFACT_NAMES:
            historical = subprocess.run(["git", "show", f"HEAD:chainguard/{name}"],
                cwd=ROOT, check=True, capture_output=True).stdout
            self.assertEqual(sha256((ROOT / "chainguard" / name).read_bytes()), sha256(historical), name)
        self.assertEqual(inspect_package(self.data, self.expected, m4_config, self.pins)
                         ["dimensions"]["schema_lifecycle"]["status"], "FAIL")
        self.assertEqual(self.registry.submit(self.expected["run_id"], [self.data])["status"], "ACCEPTED")

    def test_unbound_tool_operation_registry_is_explicit_limitation(self):
        self.assertEqual(self.config["tool_registry"]["definition"]["operation_mapping"],
                         "UNBOUND_IN_STEP_3")
        package = decode(self.data)
        proposal = next(e["event"]["body"] for e in package["records"]
                        if e["event"]["event_type"] == "CALL_PROPOSAL")
        proposal["tool"] = "echo"
        outcome = next(e["event"]["body"] for e in package["records"]
                       if e["event"]["event_type"] == "TOOL_OUTCOME")
        outcome["tool"] = "echo"
        altered = resign(package, self.key)
        # The signed assertion remains internally consistent. The current
        # registry cannot establish whether echo really performed a send.
        self.assertTrue(self.inspect(altered)["inspection_passed"])


if __name__ == "__main__":
    unittest.main()
