"""Focused M4 cryptographic, durability, sealing and offline inspection checks."""

import base64
from contextlib import closing
from copy import deepcopy
import hashlib
import io
import json
from pathlib import Path
import secrets
import sqlite3
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch
from uuid import uuid4

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from chainguard.audit import (AmbiguousCommit, AuditError, AuditSession, LiveAudit,
                             validate_record as validate_m3)
from chainguard.canonical import decode, encode
from chainguard.evidence import (ARTIFACT_NAMES, DOMAINS, INVENTORY_SCHEMA, ROOT, ChainedAuditSession,
    configuration, event_hash, genesis, inventory_digest, load_private, load_public, make_commitment,
    make_manifest, manifest_digest, recompute_chain, sign_commitment,
    validate_inventory, validate_manifest, validate_record, validate_structure)
from chainguard.m3 import shadows
from chainguard.m4 import KEY_ID, execute_demo, provision_key
from chainguard.proxy import run
from chainguard.verifier import inspect_package


META = {"io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientCapabilities": {}}


def request(request_id=1, tool="echo"):
    return {"jsonrpc": "2.0", "id": request_id, "method": "tools/call",
            "params": {"_meta": META, "name": tool, "arguments": {"token": "fixture-public-token"}}}


def response():
    return {"result": {"isError": False, "content": [{"type": "text", "text": "fixture-public-token"}]}}


def inventory(run_id="run", task_id="task", session_id="session", monitor_id="monitor", challenge="ab" * 32):
    return {"schema_version": INVENTORY_SCHEMA, "run_id": run_id, "run_challenge": challenge,
            "sessions": [{"task_id": task_id, "session_id": session_id, "monitor_instance_id": monitor_id}]}


def fixed_manifest():
    # Static vector references are deliberately not trusted runtime configuration.
    config = configuration()
    config["code_revision"] = "0" * 40
    config["artifacts"] = [{"name": name, "digest": "0" * 64} for name in sorted(ARTIFACT_NAMES)]
    config["normalizer"]["digest"] = "0" * 64
    for detector in config["detectors"]:
        detector["digest"] = "0" * 64
    return make_manifest(inventory(), config, "task", "session", "monitor")


def fixed_start(manifest):
    return {"schema_version": "m4-record-v1", "run_id": "run", "task_id": "task", "session_id": "session",
            "monitor_instance_id": "monitor", "event_id": "start", "seq": 1,
            "observed_at_utc": "2026-10-08T00:00:00.000000Z", "event_type": "SESSION_START",
            "prev_hash": genesis(manifest), "body": {"record_class": "M4_CHAINED_UNSEALED",
                "run_challenge": "ab" * 32, "execution_profile": manifest["execution_profile"],
                "manifest_digest": manifest_digest(manifest)}}


def rechain(package, update_closure=True):
    head = genesis(package["manifest"])
    for entry in package["records"]:
        entry["event"]["prev_hash"] = head
        head = event_hash(entry["event"])
        entry["event_hash"] = head
    if update_closure:
        package["commitment"] = make_commitment(package["manifest"], len(package["records"]), head, KEY_ID)


class VectorTests(unittest.TestCase):
    def test_known_inventory_canonical_bytes(self):
        expected = (b'{"run_challenge":"' + b"ab" * 32 + b'","run_id":"run",'
            b'"schema_version":"m4-expected-inventory-v1","sessions":[{"monitor_instance_id":"monitor",'
            b'"session_id":"session","task_id":"task"}]}')
        self.assertEqual(encode(inventory()), expected)
        self.assertEqual(inventory_digest(inventory()), hashlib.sha256(expected).hexdigest())

    def test_known_manifest_genesis_event_vectors(self):
        manifest = fixed_manifest()
        event = fixed_start(manifest)
        # Independently calculated with literal domain bytes, stdlib JSON and hashlib.
        self.assertEqual(manifest_digest(manifest), "b2ed5b6bd814ba7b8ffd3466223095d99ef5b82af6c5f7402529b6cf646b3aaa")
        self.assertEqual(genesis(manifest), "b4553bb4d4e59e68bfb1c6c6e3567b5cae43ce39e526f5599f17ce2a4969905c")
        self.assertEqual(event_hash(event), "b784cc5553d7284fa991452f189d9214b67d3f636d5ce9d24cfc5471182916bb")
        validate_record(event)

    def test_identical_logical_event_bytes_and_hashes(self):
        event = fixed_start(fixed_manifest())
        shuffled = dict(reversed(list(event.items())))
        shuffled["body"] = dict(reversed(list(event["body"].items())))
        self.assertEqual(encode(event), encode(shuffled))
        self.assertEqual(event_hash(event), event_hash(shuffled))

    def test_fixed_closure_bytes(self):
        manifest = fixed_manifest()
        closure = make_commitment(manifest, 2, "cd" * 32, KEY_ID)
        expected = (b'{"canonicalization_version":"chainguard-json-v1","closure_status":"CLOSED",'
            b'"expected_inventory_digest":"' + inventory_digest(inventory()).encode() +
            b'","final_head":"' + b"cd" * 32 + b'","final_seq":2,"hash_algorithm":"SHA256",'
            b'"manifest_digest":"' + manifest_digest(manifest).encode() +
            b'","monitor_instance_id":"monitor","record_count":2,"record_schema_version":"m4-record-v1",'
            b'"run_challenge":"' + b"ab" * 32 + b'","run_id":"run","schema_version":"m4-commitment-v1",'
            b'"session_id":"session","signature_encoding":"DER-base64",'
            b'"signature_suite":"ECDSA-P256-SHA256-DER-v1","signer_key_id":"chainguard-m4-fixture-key","task_id":"task"}')
        self.assertEqual(encode(closure), expected)
        self.assertEqual(encode(decode(expected)), expected)

    def test_canonical_rejects_noncanonical_or_unsupported(self):
        for raw in (b'{ "a":1}', b'{"a":1,"a":2}', b'{"a":1.0}', b'{"a":NaN}', b'9007199254740992'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                decode(raw)
        with self.assertRaises(ValueError):
            encode({"a": 1.0})

    def test_unknown_manifest_configuration_and_record_versions(self):
        manifest = fixed_manifest()
        for field in ("schema_version", "record_schema_version", "canonicalization_version", "protocol_version"):
            with self.subTest(field=field), self.assertRaises(ValueError):
                validate_manifest({**manifest, field: "unknown"})
        bad = deepcopy(manifest)
        bad["configuration"]["schema_version"] = "unknown"
        with self.assertRaises(ValueError):
            validate_manifest(bad)
        with self.assertRaises(ValueError):
            validate_record({**fixed_start(manifest), "schema_version": "m3-record-v1"})

    def test_inventory_rejects_bad_challenge_duplicates_and_unsorted_entries(self):
        for challenge in ("short", "AB" * 32, 123):
            with self.subTest(challenge=challenge), self.assertRaises(ValueError):
                validate_inventory(inventory(challenge=challenge))
        duplicate = inventory()
        duplicate["sessions"] *= 2
        with self.assertRaises(ValueError):
            validate_inventory(duplicate)
        unordered = inventory()
        unordered["sessions"] = [{"task_id": "z", "session_id": "z", "monitor_instance_id": "m"},
                                 {"task_id": "a", "session_id": "a", "monitor_instance_id": "m"}]
        with self.assertRaises(ValueError):
            validate_inventory(unordered)


class M4Tests(unittest.TestCase):
    def setUp(self):
        self.directory = TemporaryDirectory(prefix="m4-unit-")
        self.path = Path(self.directory.name) / "audit.sqlite"
        self.expected = inventory(*(str(uuid4()) for _ in range(4)), challenge=secrets.token_hex(32))
        self.config = configuration()
        entry = self.expected["sessions"][0]
        self.manifest = make_manifest(self.expected, self.config, entry["task_id"], entry["session_id"], entry["monitor_instance_id"])
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.pins = {KEY_ID: self.key.public_key()}
        self.session = ChainedAuditSession(self.path, self.manifest, self.expected)

    def tearDown(self):
        self.session.close()
        self.directory.cleanup()

    def inspect(self, package, expected=None, pins=None, config=None):
        data = encode(package) if type(package) is dict else package
        return inspect_package(data, self.expected if expected is None else expected,
            self.config if config is None else config, self.pins if pins is None else pins)

    def package(self):
        gate = LiveAudit(self.session, shadows)
        gate.after(gate.before(request()), response())
        return decode(self.session.seal(self.key, KEY_ID, self.pins))

    def status(self, report, dimension):
        return report["dimensions"][dimension]["status"]

    def trigger(self, kind):
        with closing(sqlite3.connect(self.path)) as connection:
            connection.execute(f"""CREATE TRIGGER fail_insert BEFORE INSERT ON audit_records
                WHEN NEW.event_type='{kind}' BEGIN SELECT RAISE(ABORT, 'fixture persistence failure'); END""")

    def test_complete_package_all_dimensions_and_prefix_reproduction(self):
        package = self.package()
        report = self.inspect(package)
        self.assertTrue(report["inspection_passed"], report)
        self.assertTrue(all(d["status"] == "PASS" for d in report["dimensions"].values()))
        self.assertEqual(report["reproduction"], {"proposals": 1, "findings_reproduced": 4, "b2_agreeing_prefixes": 1})
        self.assertEqual(self.session.progress, {"durability": "COMMITTED", "sealing": "SEALED",
                                               "signature": "SIGNED", "verification": "VERIFIED"})

    def test_repeated_inspection_does_not_consume_expectation(self):
        package = self.package()
        self.assertEqual(self.inspect(package), self.inspect(package))
        self.assertEqual(self.inspect(package)["fresh_submission"], "NOT_IMPLEMENTED_M5")

    def test_hashes_and_both_trusted_heads_agree_after_confirmed_commit(self):
        observed = []
        self.session._observer = lambda receipt: observed.append((receipt.last_seq, self.session.state,
            self.session._connection.execute("SELECT count(*) FROM audit_records").fetchone()[0]))
        gate = LiveAudit(self.session, shadows)
        call = gate.before(request())
        self.assertEqual(self.session.state.count, 8)
        self.assertEqual(observed[0][0], observed[0][2])
        snapshot = self.session._snapshot()
        self.assertEqual(recompute_chain(self.manifest, snapshot), self.session.state.cryptographic_head)
        self.assertEqual(self.session.state.head, (8, snapshot[-1]["event"]["event_id"]))
        self.assertNotEqual(self.session.state.head, self.session.state.cryptographic_head)
        gate.after(call, response())

    def test_rollback_leaves_both_heads_and_history_unchanged(self):
        before = self.session.state
        self.trigger("DISPATCH_INTENT")
        with self.assertRaises(AuditError):
            LiveAudit(self.session, shadows).before(request())
        self.assertEqual(self.session.state.count, before.count)
        self.assertEqual(self.session.state.head, before.head)
        self.assertEqual(self.session.state.cryptographic_head, before.cryptographic_head)
        self.assertEqual(self.session.history, ())
        self.assertEqual(len(self.session._snapshot()), 1)

    def test_ambiguous_commit_does_not_adopt_persisted_chain_or_retry(self):
        before = self.session.state
        commit = self.session._commit

        def lost_ack():
            commit()
            raise OSError("Fixture lost acknowledgement")

        with patch.object(self.session, "_commit", side_effect=lost_ack) as called:
            with self.assertRaises(AmbiguousCommit):
                LiveAudit(self.session, shadows).before(request())
            with self.assertRaises(AuditError):
                LiveAudit(self.session).before(request(2))
            self.assertEqual(called.call_count, 1)
        self.assertEqual(self.session.state.cryptographic_head, before.cryptographic_head)
        self.assertEqual(self.session.state.head, before.head)
        self.assertEqual(len(self.session._snapshot()), 8)  # Explicit test inspection only.
        with self.assertRaises(AuditError):
            self.session.seal(self.key, KEY_ID, self.pins)
        self.assertEqual(self.session.state.failure, "AMBIGUOUS_COMMIT")

    def test_required_m4_persistence_failure_blocks_real_forwarding(self):
        self.trigger("DISPATCH_INTENT")
        observations = []
        with patch("chainguard.proxy.diagnostic", side_effect=lambda phase, **fields: observations.append(phase)):
            output = io.BytesIO()
            status = run(io.BytesIO(json.dumps(request()).encode() + b"\n"), output, LiveAudit(self.session, shadows))
        self.assertEqual(status, 2)
        self.assertNotIn("forwarded", observations)
        self.assertEqual(json.loads(output.getvalue())["error"]["code"], -32603)
        self.assertEqual(self.session.state.count, 1)

    def test_ambiguous_m4_commit_blocks_real_forwarding(self):
        before = self.session.state
        commit = self.session._commit

        def lost_ack():
            commit()
            raise OSError("Fixture lost acknowledgement after durable COMMIT")

        observations = []
        with patch.object(self.session, "_commit", side_effect=lost_ack), \
             patch("chainguard.proxy.diagnostic", side_effect=lambda phase, **fields: observations.append(phase)):
            output = io.BytesIO()
            status = run(io.BytesIO(json.dumps(request()).encode() + b"\n"), output, LiveAudit(self.session, shadows))
        self.assertEqual(status, 2)
        self.assertNotIn("forwarded", observations)
        self.assertEqual(self.session.state.cryptographic_head, before.cryptographic_head)
        self.assertEqual(self.session.state.failure, "AMBIGUOUS_COMMIT")

    def test_intent_with_unknown_outcome_cannot_seal(self):
        gate = LiveAudit(self.session, shadows)
        gate.unknown(gate.before(request()))
        with self.assertRaises(AuditError):
            self.session.seal(self.key, KEY_ID, self.pins)
        self.assertEqual(self.session.progress["sealing"], "INCOMPLETE")
        self.assertEqual(self.session.state.failure, "UNKNOWN_OUTCOME")

    def test_prepared_rows_do_not_advance_crypto_state(self):
        before = self.session.state
        with patch.object(self.session, "_commit", side_effect=sqlite3.OperationalError("COMMIT not acknowledged")):
            with self.assertRaises(AmbiguousCommit):
                LiveAudit(self.session).before(request())
        self.assertEqual(self.session.state.head, before.head)
        self.assertEqual(self.session.state.cryptographic_head, before.cryptographic_head)
        with closing(sqlite3.connect(self.path)) as other:
            self.assertEqual(other.execute("SELECT count(*) FROM audit_records").fetchone()[0], 1)

    def test_mutated_record_fails_chain_but_original_signature_still_authenticates_closure(self):
        package = self.package()
        package["records"][1]["event"]["body"]["request_id"] = "edited"
        report = self.inspect(package)
        self.assertEqual(self.status(report, "schema_lifecycle"), "PASS")
        self.assertEqual(self.status(report, "commitment_integrity"), "FAIL")
        self.assertEqual(self.status(report, "trusted_signature"), "PASS")
        self.assertFalse(report["inspection_passed"])

    def test_recomputed_mutated_chain_cannot_validate_original_signature(self):
        package = self.package()
        package["records"][1]["event"]["body"]["request_id"] = "edited"
        rechain(package)
        report = self.inspect(package)
        self.assertEqual(self.status(report, "commitment_integrity"), "PASS")
        self.assertEqual(self.status(report, "trusted_signature"), "FAIL")

    def test_sequence_gap_rejected(self):
        package = self.package()
        package["records"][1]["event"]["seq"] = 3
        self.assertEqual(self.status(self.inspect(package), "schema_lifecycle"), "FAIL")

    def test_previous_hash_discontinuity_rejected(self):
        package = self.package()
        package["records"][1]["event"]["prev_hash"] = "0" * 64
        self.assertEqual(self.status(self.inspect(package), "commitment_integrity"), "FAIL")

    def test_supplied_event_hash_is_not_trusted(self):
        package = self.package()
        package["records"][1]["event_hash"] = "0" * 64
        self.assertEqual(self.status(self.inspect(package), "commitment_integrity"), "FAIL")

    def test_modified_final_head_rejected(self):
        package = self.package()
        package["commitment"]["final_head"] = "0" * 64
        report = self.inspect(package)
        self.assertEqual(self.status(report, "commitment_integrity"), "FAIL")
        self.assertEqual(self.status(report, "trusted_signature"), "FAIL")

    def test_closure_count_and_final_sequence_are_bound(self):
        package = self.package()
        for field in ("record_count", "final_seq"):
            changed = deepcopy(package)
            changed["commitment"][field] += 1
            report = self.inspect(changed)
            self.assertEqual(self.status(report, "commitment_integrity"), "FAIL")
            self.assertEqual(self.status(report, "trusted_signature"), "FAIL")

    def test_closure_identity_schema_and_algorithm_fields_are_bound(self):
        package = self.package()
        for field in ("run_id", "task_id", "session_id", "monitor_instance_id", "schema_version",
                      "record_schema_version", "canonicalization_version", "hash_algorithm",
                      "signature_suite", "signature_encoding", "run_challenge", "expected_inventory_digest"):
            changed = deepcopy(package)
            changed["commitment"][field] = "unknown"
            with self.subTest(field=field):
                self.assertFalse(self.inspect(changed)["inspection_passed"])
                self.assertEqual(self.status(self.inspect(changed), "trusted_signature"), "FAIL")

    def test_modified_signature_rejected(self):
        package = self.package()
        signature = bytearray(base64.b64decode(package["signature"]))
        signature[-1] ^= 1
        package["signature"] = base64.b64encode(signature).decode()
        report = self.inspect(package)
        self.assertEqual(self.status(report, "trusted_signature"), "FAIL")
        self.assertEqual(self.status(report, "commitment_integrity"), "PASS")

    def test_wrong_public_key_unknown_key_id_and_curve_rejected(self):
        package = self.package()
        for pins in ({}, {KEY_ID: ec.generate_private_key(ec.SECP256R1()).public_key()},
                     {KEY_ID: ec.generate_private_key(ec.SECP384R1()).public_key()}):
            with self.subTest(pins=bool(pins)):
                self.assertEqual(self.status(self.inspect(package, pins=pins), "trusted_signature"), "FAIL")

    def test_library_signature_hashes_domain_separated_input_once(self):
        package = self.package()
        raw = base64.b64decode(package["signature"])
        message = DOMAINS["COMMITMENT"] + encode(package["commitment"])
        self.key.public_key().verify(raw, message, ec.ECDSA(hashes.SHA256()))
        with self.assertRaises(InvalidSignature):
            self.key.public_key().verify(raw, hashlib.sha256(message).digest(), ec.ECDSA(hashes.SHA256()))

    def test_wrong_expected_run_task_session_monitor_and_old_challenge(self):
        package = self.package()
        for field in ("run_id", "run_challenge", "task_id", "session_id", "monitor_instance_id"):
            changed = deepcopy(self.expected)
            target = changed if field in {"run_id", "run_challenge"} else changed["sessions"][0]
            target[field] = "cd" * 32 if field == "run_challenge" else "different"
            report = self.inspect(package, expected=changed)
            self.assertEqual(self.status(report, "trusted_signature"), "PASS")
            self.assertEqual(self.status(report, "expected_binding"), "FAIL")

    def test_external_configuration_mismatch_rejected(self):
        package = self.package()
        changed = deepcopy(self.config)
        changed["normalizer"]["digest"] = "0" * 64
        self.assertEqual(self.status(self.inspect(package, config=changed), "expected_binding"), "FAIL")

    def test_missing_close_and_truncated_package_are_incomplete(self):
        package = self.package()
        package["records"].pop()
        report = self.inspect(package)
        self.assertEqual(self.status(report, "inventory_completeness"), "INCOMPLETE")
        self.assertFalse(report["inspection_passed"])
        package["commitment"] = None
        missing = self.inspect(package)
        self.assertFalse(missing["inspection_passed"])
        self.assertEqual(self.status(missing, "trusted_signature"), "INCOMPLETE")
        self.assertEqual(self.status(missing, "inventory_completeness"), "INCOMPLETE")

    def test_empty_expected_stream_is_incomplete(self):
        package = self.package()
        package["records"] = []
        report = self.inspect(package)
        self.assertEqual(self.status(report, "schema_lifecycle"), "INCOMPLETE")
        self.assertEqual(self.status(report, "inventory_completeness"), "INCOMPLETE")
        self.assertFalse(report["inspection_passed"])

    def test_noncanonical_package_unknown_fields_and_format_rejected(self):
        package = self.package()
        noncanonical = json.dumps(package, indent=2).encode()
        self.assertEqual(self.status(self.inspect(noncanonical), "schema_lifecycle"), "FAIL")
        for changed in ({**package, "public_key": "bundle-selected-key"}, {**package, "format_version": "unknown"}):
            self.assertEqual(self.status(self.inspect(changed), "schema_lifecycle"), "FAIL")

    def test_missing_expected_session_cannot_pass_inventory_completeness(self):
        self.session.close()
        self.path = Path(self.directory.name) / "multi.sqlite"
        self.expected["sessions"].append({"task_id": "extra", "session_id": "extra", "monitor_instance_id": "extra"})
        self.expected["sessions"].sort(key=lambda s: (s["task_id"], s["session_id"], s["monitor_instance_id"]))
        own = next(s for s in self.expected["sessions"] if s["session_id"] != "extra")
        self.manifest = make_manifest(self.expected, self.config, own["task_id"], own["session_id"], own["monitor_instance_id"])
        self.session = ChainedAuditSession(self.path, self.manifest, self.expected)
        # Self-verification correctly refuses export of only part of the expected run.
        with self.assertRaises(AuditError):
            self.session.seal(self.key, KEY_ID, self.pins)
        self.assertEqual(self.session.progress["sealing"], "INCOMPLETE")

    def test_authentic_incorrect_finding_fails_reproduction(self):
        package = self.package()
        finding = next(e["event"]["body"] for e in package["records"] if e["event"]["event_type"] == "DETECTOR_FINDING")
        finding["behavioral_verdict"] = "POLICY_VIOLATION"
        finding["authorization_assessment"] = "UNAUTHORIZED"
        finding["hypothetical_recommendation"] = "DENY"
        rechain(package)
        package["signature"] = sign_commitment(self.key, package["commitment"])
        report = self.inspect(package)
        self.assertEqual(self.status(report, "trusted_signature"), "PASS")
        self.assertEqual(self.status(report, "commitment_integrity"), "PASS")
        self.assertEqual(self.status(report, "finding_reproduction"), "FAIL")

    def test_missing_required_finding_fails_reproduction(self):
        package = self.package()
        index = next(i for i, e in enumerate(package["records"]) if e["event"]["event_type"] == "DETECTOR_FINDING")
        package["records"].pop(index)
        for seq, entry in enumerate(package["records"], 1):
            entry["event"]["seq"] = seq
        rechain(package)
        package["signature"] = sign_commitment(self.key, package["commitment"])
        self.assertEqual(self.status(self.inspect(package), "finding_reproduction"), "FAIL")

    def test_findings_and_evidence_metadata_never_become_semantic_truth(self):
        package = self.package()
        self.assertEqual([f.category for f in self.session.history], ["TOOL_OUTCOME"])
        for entry in package["records"]:
            entry["event"]["observed_at_utc"] = "2099-01-01T00:00:00Z"
        rechain(package)
        package["signature"] = sign_commitment(self.key, package["commitment"])
        self.assertEqual(self.status(self.inspect(package), "finding_reproduction"), "PASS")

    def test_sealing_reconciles_fixed_snapshot_against_trusted_head(self):
        self.session.finish()
        frozen = self.session.state
        entries = self.session._snapshot()
        entries[0]["event"]["observed_at_utc"] = "2099-01-01T00:00:00Z"
        rechain({"manifest": self.manifest, "records": entries}, update_closure=False)
        # The attacker has made a structurally valid, fully recomputed chain.
        validate_structure(self.manifest, entries, require_closed=True)
        self.assertNotEqual(recompute_chain(self.manifest, entries), frozen.cryptographic_head)
        with closing(sqlite3.connect(self.path)) as connection:
            for entry in entries:
                connection.execute("UPDATE audit_records SET record_bytes=?,event_hash=? WHERE seq=?",
                    (encode(entry["event"]), entry["event_hash"], entry["event"]["seq"]))
            connection.commit()
        with self.assertRaises(AuditError):
            self.session.seal(self.key, KEY_ID, self.pins)
        self.assertEqual(self.session.state.cryptographic_head, frozen.cryptographic_head)
        self.assertEqual(self.session.progress["signature"], "NOT_SIGNED")

    def test_export_uses_validated_snapshot_without_storage_reread(self):
        snapshot = self.session._snapshot

        def snapshot_then_mutate():
            entries = snapshot()
            self.session._connection.execute("UPDATE audit_records SET event_hash=? WHERE seq=1", ("0" * 64,))
            return entries

        with patch.object(self.session, "_snapshot", side_effect=snapshot_then_mutate) as reads:
            package = self.session.seal(self.key, KEY_ID, self.pins)
        self.assertEqual(reads.call_count, 1)
        self.assertTrue(self.inspect(package)["inspection_passed"])

    def test_signing_failure_is_incomplete_without_undoing_committed_history(self):
        gate = LiveAudit(self.session, shadows)
        gate.after(gate.before(request()), response())
        with patch("chainguard.evidence.sign_commitment", side_effect=ValueError("Fixture signing failure")):
            with self.assertRaises(AuditError):
                self.session.seal(self.key, KEY_ID, self.pins)
        self.assertEqual([f.outcome for f in self.session.history], ["succeeded"])
        self.assertEqual(self.session.progress["signature"], "NOT_SIGNED")
        self.assertEqual(self.session.progress["sealing"], "INCOMPLETE")

    def test_export_failure_is_incomplete_and_not_retried(self):
        output = Path(self.directory.name) / "existing.json"
        output.write_bytes(b"existing")
        with self.assertRaises(AuditError):
            self.session.seal(self.key, KEY_ID, self.pins, output=output)
        self.assertEqual(output.read_bytes(), b"existing")
        self.assertEqual(self.session.progress["signature"], "SIGNED")
        self.assertEqual(self.session.progress["sealing"], "INCOMPLETE")
        with self.assertRaises(AuditError):
            self.session.seal(self.key, KEY_ID, self.pins)

    def test_old_m3_records_and_database_cannot_be_reclassified(self):
        old_path = Path(self.directory.name) / "m3.sqlite"
        old = AuditSession(old_path, "old-run", "old-task", "old-session", "old-challenge")
        old.finish()
        old.close()
        with self.assertRaises(ValueError):
            ChainedAuditSession(old_path, self.manifest, self.expected)
        with self.assertRaises(ValueError):
            validate_m3(self.session._snapshot()[0]["event"])

    def test_inspection_never_calls_live_proxy_or_live_shadow_callback(self):
        package = self.package()
        with patch("chainguard.proxy.run", side_effect=AssertionError("No tools offline")), \
             patch("chainguard.m3.shadows", side_effect=AssertionError("No live detector state")):
            self.assertTrue(self.inspect(package)["inspection_passed"])

    def test_no_append_after_close_and_no_permission_bearing_intents(self):
        self.session.finish()
        with self.assertRaises(AuditError):
            LiveAudit(self.session).before(request())


class KeyAndIntegrationTests(unittest.TestCase):
    def test_explicit_external_key_provisioning_and_pinning(self):
        with TemporaryDirectory(prefix="m4-key-") as directory:
            private_path, public_path = Path(directory) / "private.pem", Path(directory) / "public.pem"
            provision_key(private_path, public_path)
            private_key, public_key = load_private(private_path), load_public(public_path)
            self.assertEqual(private_key.public_key().public_numbers(), public_key.public_numbers())
            with self.assertRaises(ValueError):
                provision_key(private_path, public_path)
            with self.assertRaises(ValueError):
                provision_key(ROOT / "private-test.pem", public_path)

    def test_real_success_error_success_and_separate_process_offline_verifier(self):
        with TemporaryDirectory(prefix="m4-live-") as directory:
            report = execute_demo(directory)
            self.assertEqual([r["isError"] for r in report["live_results"]], [False, True, False])
            self.assertEqual(report["record_count"], 26)
            self.assertEqual(report["confirmed_transactions"], 8)
            self.assertEqual(report["handler_request_ids"], [3, 4, 5])
            self.assertEqual(report["offline_verifier_exit_code"], 0)
            self.assertTrue(report["monitor_exited_before_verification"])
            self.assertEqual(report["offline_verification"]["reproduction"]["findings_reproduced"], 12)
            package = (Path(directory) / "evidence.json").read_bytes()
            for token in (b"m4-success-A", b"m4-failure-B", b"m4-success-C", b"PRIVATE KEY"):
                self.assertNotIn(token, package)
            # Same retained public pin, another verifier process; no monitor, key generation or SQLite.
            arguments = [sys.executable, "-B", "-m", "chainguard.verifier", "--package", str(Path(directory) / "evidence.json"),
                         "--expected", str(Path(directory) / "expected.json"), "--config", str(Path(directory) / "configuration.json"),
                         "--public-key", str(Path(directory) / "fixture-public.pem"), "--key-id", KEY_ID]
            repeated = subprocess.run(arguments, cwd=ROOT, capture_output=True, timeout=60)
            self.assertEqual(repeated.returncode, 0, repeated.stderr.decode())
            self.assertEqual(json.loads(repeated.stdout), report["offline_verification"])


if __name__ == "__main__":
    unittest.main()
