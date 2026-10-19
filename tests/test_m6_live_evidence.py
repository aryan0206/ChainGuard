"""M6.4 Gate 1 contract tests; no signing or live-database access."""

from copy import deepcopy
import hashlib
import unittest

from chainguard.canonical import encode
from chainguard.evidence import event_hash, genesis, manifest_digest
from chainguard.m6_live_evidence import (live_commitment_digest,
    live_commitment_signing_input, validate_live_commitment,
    validate_live_package_structure)
from chainguard.m6_live_profile import (EXECUTION_PROFILE, live_configuration,
    make_live_manifest)
from chainguard.permission_evidence import RECORD_CLASS, RECORD_SCHEMA


VECTOR_CLOSURE = {
    "schema_version": "m6-live-commitment-v1",
    "record_schema_version": "m6-record-v1",
    "canonicalization_version": "chainguard-json-v1",
    "run_id": "run", "task_id": "task", "session_id": "session",
    "monitor_instance_id": "monitor", "run_challenge": "a" * 64,
    "expected_inventory_digest": "b" * 64, "manifest_digest": "c" * 64,
    "record_count": 2, "final_seq": 2, "final_head": "d" * 64,
    "closure_status": "CLOSED", "hash_algorithm": "SHA256",
    "signature_suite": "ECDSA-P256-SHA256-DER-v1",
    "signature_encoding": "DER-base64", "signer_key_id": "live-key",
}
VECTOR_BYTES = (
    b'{"canonicalization_version":"chainguard-json-v1","closure_status":"CLOSED",'
    b'"expected_inventory_digest":"' + b'b' * 64 + b'","final_head":"' + b'd' * 64 +
    b'","final_seq":2,"hash_algorithm":"SHA256","manifest_digest":"' + b'c' * 64 +
    b'","monitor_instance_id":"monitor","record_count":2,"record_schema_version":"m6-record-v1",'
    b'"run_challenge":"' + b'a' * 64 +
    b'","run_id":"run","schema_version":"m6-live-commitment-v1","session_id":"session",'
    b'"signature_encoding":"DER-base64","signature_suite":"ECDSA-P256-SHA256-DER-v1",'
    b'"signer_key_id":"live-key","task_id":"task"}')
VECTOR_DIGEST = "0568ebd65503ad73a808f0b571da691bea22ce54bc52a09d31f9282640295ed5"


def fixture_package(manifest):
    identity = {k: manifest[k] for k in
                ("run_id", "task_id", "session_id", "monitor_instance_id")}
    first = {"schema_version": RECORD_SCHEMA, **identity, "event_id": "start-1",
             "seq": 1, "observed_at_utc": "2026-10-19T00:00:00Z",
             "event_type": "SESSION_START", "prev_hash": genesis(manifest),
             "body": {"record_class": RECORD_CLASS,
                      "run_challenge": manifest["run_challenge"],
                      "execution_profile": deepcopy(EXECUTION_PROFILE),
                      "manifest_digest": manifest_digest(manifest)}}
    first_hash = event_hash(first)
    last = {"schema_version": RECORD_SCHEMA, **identity, "event_id": "end-1",
            "seq": 2, "observed_at_utc": "2026-10-19T00:00:01Z",
            "event_type": "SESSION_END", "prev_hash": first_hash,
            "body": {"closure_status": "CLOSED"}}
    last_hash = event_hash(last)
    closure = {"schema_version": "m6-live-commitment-v1",
               "record_schema_version": RECORD_SCHEMA,
               "canonicalization_version": "chainguard-json-v1", **identity,
               "run_challenge": manifest["run_challenge"],
               "expected_inventory_digest": manifest["expected_inventory_digest"],
               "manifest_digest": manifest_digest(manifest),
               "record_count": 2, "final_seq": 2, "final_head": last_hash,
               "closure_status": "CLOSED", "hash_algorithm": "SHA256",
               "signature_suite": "ECDSA-P256-SHA256-DER-v1",
               "signature_encoding": "DER-base64", "signer_key_id": "live-test-key"}
    # Canonical base64 only; these bytes are deliberately not a valid signature.
    return {"format_version": "m6-live-evidence-v1", "manifest": deepcopy(manifest),
            "records": [{"event": first, "event_hash": first_hash},
                        {"event": last, "event_hash": last_hash}],
            "commitment": closure, "signature": "MAA="}


def rebind_fixture_manifest(package):
    """Keep a mutated fixture internally consistent so shape checks are reached."""
    manifest = package["manifest"]
    start, end = (entry["event"] for entry in package["records"])
    start["prev_hash"] = genesis(manifest)
    start["body"]["manifest_digest"] = manifest_digest(manifest)
    package["records"][0]["event_hash"] = event_hash(start)
    end["prev_hash"] = package["records"][0]["event_hash"]
    package["records"][1]["event_hash"] = event_hash(end)
    package["commitment"]["manifest_digest"] = manifest_digest(manifest)
    package["commitment"]["final_head"] = package["records"][1]["event_hash"]


class LiveEvidenceContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        inventory = {"schema_version": "m4-expected-inventory-v1",
                     "run_id": "live-run", "run_challenge": "a" * 64,
                     "sessions": [{"task_id": "live-task", "session_id": "live-session",
                                   "monitor_instance_id": "live-monitor"}]}
        cls.manifest = make_live_manifest(inventory, live_configuration(),
                                          "live-task", "live-session", "live-monitor")

    def package(self):
        return fixture_package(self.manifest)

    def assert_rejected(self, package):
        with self.assertRaises(ValueError):
            validate_live_package_structure(encode(package))

    def test_fixed_live_closure_bytes_and_digest_vector(self):
        self.assertEqual(live_commitment_signing_input(VECTOR_CLOSURE),
                         b"CHAIN GUARD COMMITMENT-v1\0" + VECTOR_BYTES)
        self.assertEqual(live_commitment_digest(VECTOR_CLOSURE), VECTOR_DIGEST)
        self.assertEqual(hashlib.sha256(b"CHAIN GUARD COMMITMENT-v1\0" +
                                        VECTOR_BYTES).hexdigest(), VECTOR_DIGEST)

    def test_well_formed_package_is_only_structurally_accepted(self):
        package = self.package()
        self.assertEqual(validate_live_package_structure(encode(package)), package)
        self.assertEqual(package["signature"], "MAA=")  # Not verified or accepted.

    def test_wrong_package_manifest_configuration_and_closure_profiles(self):
        for path, value in (
            (("format_version",), "m6-evidence-v1"),
            (("format_version",), "m4-evidence-v1"),
            (("format_version",), "m6-live-evidence-v2"),
            (("manifest", "schema_version"), "m6-manifest-v1"),
            (("manifest", "record_schema_version"), "m4-record-v1"),
            (("manifest", "configuration", "schema_version"), "m6-configuration-v1"),
            (("commitment", "schema_version"), "m6-commitment-v1"),
            (("commitment", "canonicalization_version"), "unknown"),
        ):
            with self.subTest(path=path, value=value):
                package = self.package()
                target = package
                for key in path[:-1]:
                    target = target[key]
                target[path[-1]] = value
                self.assert_rejected(package)

    def test_missing_extra_and_malformed_package_fields(self):
        package = self.package()
        del package["signature"]
        self.assert_rejected(package)
        package = self.package()
        package["public_key"] = "untrusted"
        self.assert_rejected(package)
        for bad in (None, 4, "", "not base64", "MAA", "MAA=="):
            with self.subTest(signature=bad):
                package = self.package()
                package["signature"] = bad
                self.assert_rejected(package)
        package = self.package()
        package["manifest"]["run_id"] = 1
        self.assert_rejected(package)
        package = self.package()
        del package["manifest"]["configuration"]
        self.assert_rejected(package)

    def test_manifest_and_configuration_field_types(self):
        changes = (
            (("manifest", "observation_scope"), "other"),
            (("manifest", "run_challenge"), "A" * 64),
            (("manifest", "execution_profile"), []),
            (("manifest", "configuration", "code_revision"), 7),
            (("manifest", "configuration", "artifacts"), {}),
            (("manifest", "configuration", "synthetic_experiment"), 0),
            (("manifest", "configuration", "controller_profile"), {}),
        )
        for path, value in changes:
            with self.subTest(path=path):
                package = self.package()
                target = package
                for key in path[:-1]:
                    target = target[key]
                target[path[-1]] = value
                self.assert_rejected(package)
        package = self.package()
        package["manifest"]["configuration"]["extra"] = "x"
        self.assert_rejected(package)
        package = self.package()
        del package["manifest"]["configuration"]["policy"]
        self.assert_rejected(package)
        for profile_path in (("manifest", "execution_profile"),
                             ("manifest", "configuration", "controller_profile")):
            with self.subTest(profile=profile_path):
                package = self.package()
                target = package
                for key in profile_path:
                    target = target[key]
                target["release_calls_enabled"] = 1  # Python considers 1 == True.
                self.assert_rejected(package)

    def test_nested_configuration_rejection_through_public_package_contract(self):
        changes = (
            lambda c: c.__setitem__("policy", {}),
            lambda c: c["policy"].pop("digest"),
            lambda c: c["policy"].__setitem__("extra", "x"),
            lambda c: c["policy"].__setitem__("max_payload_bytes", True),
            lambda c: c["policy"].__setitem__("resources", [["secret-a"]]),
            lambda c: c["policy"].__setitem__("destinations", ["sink", "sink"]),
            lambda c: c["artifacts"].pop(next(i for i, item in enumerate(c["artifacts"])
                if item["name"] == "m6_live_evidence.py")),
            lambda c: c["artifacts"][0].__setitem__("digest", "not-a-digest"),
            lambda c: c["tool_registry"].__setitem__("definition", {}),
            lambda c: c["tool_registry"]["definition"]["tools"][0].pop("result_contract"),
            lambda c: c["normalizer"].pop("digest"),
            lambda c: c["detectors"][0].__setitem__("id", "unknown"),
        )
        for mutate in changes:
            with self.subTest(mutate=mutate):
                package = self.package()
                mutate(package["manifest"]["configuration"])
                rebind_fixture_manifest(package)
                self.assert_rejected(package)

    def test_unicode_escape_aliases_rejected_in_raw_live_package(self):
        package = self.package()
        package["commitment"]["signer_key_id"] = "cl\u00e9-\U0001f512"
        raw = encode(package)
        self.assertEqual(validate_live_package_structure(raw), package)
        for literal, escaped in (("\u00e9".encode("utf-8"), b"\\u00e9"),
                                 ("\U0001f512".encode("utf-8"), b"\\ud83d\\udd12")):
            with self.subTest(escaped=escaped):
                self.assertIn(literal, raw)
                with self.assertRaises(ValueError):
                    validate_live_package_structure(raw.replace(literal, escaped, 1))

    def test_each_changeable_closure_field_changes_signing_input(self):
        original = live_commitment_signing_input(VECTOR_CLOSURE)
        for field in ("run_id", "task_id", "session_id", "monitor_instance_id",
                      "signer_key_id", "run_challenge", "expected_inventory_digest",
                      "manifest_digest", "final_head", "record_count", "final_seq"):
            with self.subTest(field=field):
                changed = deepcopy(VECTOR_CLOSURE)
                if field in ("record_count", "final_seq"):
                    changed["record_count"] = changed["final_seq"] = 3
                elif field in ("run_challenge", "expected_inventory_digest",
                               "manifest_digest", "final_head"):
                    changed[field] = "e" * 64
                else:
                    changed[field] += "-other"
                self.assertNotEqual(live_commitment_signing_input(changed), original)

    def test_malformed_closure_fields_and_changed_bindings(self):
        mutations = {
            "record_count": [True, 1, 3], "final_seq": [False, 3],
            "final_head": ["0" * 64, "A" * 64],
            "manifest_digest": ["0" * 64],
            "run_challenge": ["0" * 64],
            "expected_inventory_digest": ["0" * 64],
            "run_id": ["other"], "signer_key_id": ["", 7],
            "closure_status": ["OPEN", "INCOMPLETE"],
            "signature_suite": ["ECDSA-P384-SHA384-DER-v1"],
            "signature_encoding": ["raw"], "hash_algorithm": ["SHA1"],
        }
        for field, values in mutations.items():
            for value in values:
                with self.subTest(field=field, value=value):
                    package = self.package()
                    package["commitment"][field] = value
                    self.assert_rejected(package)
        package = self.package()
        package["commitment"]["extra"] = "x"
        self.assert_rejected(package)
        package = self.package()
        del package["commitment"]["signer_key_id"]
        self.assert_rejected(package)

    def test_record_count_sequence_identity_and_hash_wrapper(self):
        mutations = (
            lambda p: p["records"].pop(),
            lambda p: p["records"][1]["event"].__setitem__("seq", 3),
            lambda p: p["records"][1]["event"].__setitem__("task_id", "other"),
            lambda p: p["records"][1].__setitem__("event_hash", "x"),
            lambda p: p["records"][1].__setitem__("extra", "x"),
        )
        for mutate in mutations:
            package = self.package()
            mutate(package)
            self.assert_rejected(package)

    def test_noncanonical_bytes_and_recursive_duplicate_keys_rejected(self):
        raw = encode(self.package())
        with self.assertRaises(ValueError):
            validate_live_package_structure(raw + b" ")
        with self.assertRaises(ValueError):
            validate_live_package_structure(raw.replace(b'"format_version":',
                b'"format_version":"m6-live-evidence-v1","format_version":', 1))
        with self.assertRaises(ValueError):
            validate_live_package_structure(raw.replace(b'"closure_status":"CLOSED"',
                b'"closure_status":"OPEN","closure_status":"CLOSED"', 1))
        with self.assertRaises(ValueError):
            validate_live_package_structure(raw.replace(b'"event_id":"end-1"',
                b'"event_id":"other","event_id":"end-1"', 1))

    def test_commitment_validation_never_checks_signature_or_chain(self):
        validate_live_commitment(VECTOR_CLOSURE)
        package = self.package()
        package["records"][0]["event_hash"] = "0" * 64
        # Shape and field agreement can hold even when the chain is fabricated.
        self.assertEqual(validate_live_package_structure(encode(package)), package)


if __name__ == "__main__":
    unittest.main()
