"""Offline M6 permission-profile package inspection and trusted binding.

This profile authenticates asserted normalized records. It does not attest raw
tool behavior, run a live controller, or infer tool-to-operation semantics from
the currently list-only synthetic registry.
"""

import base64
from copy import deepcopy
from dataclasses import replace
import subprocess

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from chainguard import PROTOCOL_VERSION
from chainguard.audit import _require
from chainguard.canonical import CANONICALIZATION_VERSION, MAX_INTEGER, decode, encode
from chainguard.detectors import ARTIFACT_DIGEST, B2Reference, B2Streaming, b0, b1, equivalent
from chainguard.evidence import (COMMITMENT_KEYS, DETECTOR_IDS, DOMAINS, IDENTITY_KEYS,
    INVENTORY_SCHEMA, IncompleteEvidence, ROOT, SUITE, SIGNATURE_ENCODING, _p256,
    event_hash, genesis, inventory_digest, is_digest, manifest_digest, sha256,
    validate_inventory)
from chainguard.permission_evidence import (COMMITMENT_SCHEMA, CONFIGURATION_SCHEMA,
    MANIFEST_SCHEMA, PACKAGE_FORMAT, PROFILE_VERSIONS, RECORD_CLASS, RECORD_SCHEMA,
    reconstruct_lifecycle, validate_lifecycle_record, validate_profile_versions)
from chainguard.semantics import (EXTRACTION_VERSION, POLICY_VERSION, Current, Policy,
    attach_references, project_b1)
from chainguard.verifier import DIMENSIONS, _finding_body


# Frozen synthetic profile for this offline milestone. The trusted registry
# identifies supported names, but does not yet assert tool-to-operation mappings.
POLICY = Policy((("secret-a", "SYNTHETIC_CANARY_A"),
                 ("secret-b", "SYNTHETIC_CANARY_B")),
                destinations=("sink", "other-sink"))
EXECUTION_PROFILE = {"mode": "observation", "supported_tools": ["echo", "read", "send", "transform"],
                     "synthetic_local_sink_override": False, "release_calls_enabled": True}
OBSERVATION_SCOPE = "synthetic-asserted-permission-lifecycle/sequential-stdio"
ARTIFACT_NAMES = tuple(sorted(("__init__.py", "acceptance.py", "audit.py", "authorization.py",
    "canonical.py", "detectors.py", "evidence.py", "permission_evidence.py",
    "permission_profile.py", "semantics.py", "verifier.py")))
MANIFEST_KEYS = {"schema_version", "record_schema_version", "canonicalization_version",
                 "protocol_version", "observation_scope", "mode", "execution_profile",
                 "run_challenge", "expected_inventory_digest", "configuration"} | set(IDENTITY_KEYS)
PROFILE_DIMENSIONS = DIMENSIONS + ("lifecycle_semantics",)


def permission_configuration():
    """Read approved installed artifacts; never derive trust from a package."""
    revision = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, check=True,
                              capture_output=True, text=True).stdout.strip()
    registry = {"server": "synthetic-server", "tools": EXECUTION_PROFILE["supported_tools"],
                "operation_mapping": "UNBOUND_IN_STEP_3"}
    return {"schema_version": CONFIGURATION_SCHEMA, "code_revision": revision,
            "artifacts": [{"name": name, "digest": sha256((ROOT / "chainguard" / name).read_bytes())}
                          for name in ARTIFACT_NAMES],
            "policy": {"version": POLICY_VERSION, "digest": POLICY.digest,
                       "resources": [list(pair) for pair in POLICY.resources],
                       "destinations": list(POLICY.destinations),
                       "max_payload_bytes": POLICY.max_payload_bytes},
            "tool_registry": {"version": "m6-synthetic-list-only-v1",
                              "digest": sha256(encode(registry)), "definition": registry},
            "normalizer": {"version": "m6-asserted-normalized-v1",
                           "extraction_version": EXTRACTION_VERSION,
                           "digest": sha256(b"m6-asserted-normalized\0" +
                                            (ROOT / "chainguard/permission_evidence.py").read_bytes())},
            "detectors": [{"id": name, "version": "m2-v1", "digest": ARTIFACT_DIGEST}
                          for name in DETECTOR_IDS],
            "controller_profile": deepcopy(EXECUTION_PROFILE),
            "synthetic_experiment": False, "synthetic_sink": "sink",
            "enforcement_detector": "B2-S"}


def validate_permission_configuration(config):
    _require(type(config) is dict and set(config) == set(permission_configuration()),
             "Invalid permission configuration fields")
    _require(config["schema_version"] == CONFIGURATION_SCHEMA, "Unknown permission configuration")
    _require(encode(config) == encode(permission_configuration()),
             "Permission configuration differs from approved installed artifacts")


def make_permission_manifest(inventory, config, task_id, session_id, monitor_instance_id):
    validate_inventory(inventory)
    validate_permission_configuration(config)
    association = {"task_id": task_id, "session_id": session_id,
                   "monitor_instance_id": monitor_instance_id}
    _require(association in inventory["sessions"], "Unregistered monitor/task/session")
    manifest = {"schema_version": MANIFEST_SCHEMA, "record_schema_version": RECORD_SCHEMA,
                "canonicalization_version": CANONICALIZATION_VERSION,
                "protocol_version": PROTOCOL_VERSION, "observation_scope": OBSERVATION_SCOPE,
                "mode": EXECUTION_PROFILE["mode"], "execution_profile": deepcopy(EXECUTION_PROFILE),
                "run_id": inventory["run_id"], **association,
                "run_challenge": inventory["run_challenge"],
                "expected_inventory_digest": inventory_digest(inventory),
                "configuration": deepcopy(config)}
    validate_permission_manifest(manifest)
    return manifest


def validate_permission_manifest(manifest):
    _require(type(manifest) is dict and set(manifest) == MANIFEST_KEYS, "Invalid permission manifest fields")
    _require(type(manifest["configuration"]) is dict and
             (manifest["schema_version"], manifest["record_schema_version"],
              manifest["configuration"].get("schema_version")) ==
             (MANIFEST_SCHEMA, RECORD_SCHEMA, CONFIGURATION_SCHEMA),
             "Mixed permission profile versions")
    _require(manifest["canonicalization_version"] == CANONICALIZATION_VERSION
             and manifest["protocol_version"] == PROTOCOL_VERSION, "Unsupported canonical/protocol version")
    _require(all(type(manifest[k]) is str and bool(manifest[k]) for k in IDENTITY_KEYS),
             "Invalid permission manifest identity")
    _require(is_digest(manifest["run_challenge"]) and is_digest(manifest["expected_inventory_digest"]),
             "Invalid permission challenge/inventory digest")
    _require(type(manifest["execution_profile"]) is dict
             and manifest["observation_scope"] == OBSERVATION_SCOPE
             and manifest["mode"] == manifest["execution_profile"].get("mode")
             and manifest["execution_profile"] == manifest["configuration"].get("controller_profile"),
             "Permission execution profile mismatch")
    encode(manifest)


def validate_permission_structure(manifest, entries):
    """Schema and ordering only. Lifecycle and cryptographic status are separate."""
    validate_permission_manifest(manifest)
    _require(type(entries) is list, "Permission records must be an ordered array")
    if not entries:
        raise IncompleteEvidence("Missing permission session records")
    records = []
    for seq, entry in enumerate(entries, 1):
        _require(type(entry) is dict and set(entry) == {"event", "event_hash"},
                 "Invalid permission record/hash wrapper")
        event = entry["event"]
        validate_lifecycle_record(event)
        _require(is_digest(entry["event_hash"]), "Invalid permission event hash")
        _require(event["seq"] == seq and all(event[k] == manifest[k] for k in IDENTITY_KEYS),
                 "Noncontiguous permission sequence or identity")
        records.append(event)
    _require(records[0]["event_type"] == "SESSION_START", "Missing permission session start")
    start = records[0]["body"]
    _require(start["run_challenge"] == manifest["run_challenge"]
             and start["execution_profile"] == manifest["execution_profile"],
             "Permission start/manifest mismatch")
    return records


def validate_permission_commitment(closure):
    _require(type(closure) is dict and set(closure) == COMMITMENT_KEYS,
             "Invalid permission commitment fields")
    _require((closure["schema_version"], closure["record_schema_version"]) ==
             (COMMITMENT_SCHEMA, RECORD_SCHEMA), "Mixed permission commitment versions")
    _require(closure["canonicalization_version"] == CANONICALIZATION_VERSION
             and closure["hash_algorithm"] == "SHA256"
             and closure["signature_suite"] == SUITE
             and closure["signature_encoding"] == SIGNATURE_ENCODING
             and closure["closure_status"] == "CLOSED", "Invalid permission commitment suite/closure")
    _require(all(type(closure[k]) is str and bool(closure[k]) for k in (*IDENTITY_KEYS, "signer_key_id")),
             "Invalid permission commitment identity")
    _require(all(is_digest(closure[k]) for k in ("manifest_digest", "final_head",
             "run_challenge", "expected_inventory_digest")), "Invalid permission commitment digest")
    _require(all(type(closure[k]) is int and 2 <= closure[k] <= MAX_INTEGER
                 for k in ("record_count", "final_seq")), "Invalid permission commitment count")
    encode(closure)


def make_permission_commitment(manifest, count, head, key_id):
    closure = {"schema_version": COMMITMENT_SCHEMA, "record_schema_version": RECORD_SCHEMA,
               "canonicalization_version": CANONICALIZATION_VERSION,
               **{k: manifest[k] for k in IDENTITY_KEYS},
               "run_challenge": manifest["run_challenge"],
               "expected_inventory_digest": manifest["expected_inventory_digest"],
               "manifest_digest": manifest_digest(manifest), "record_count": count,
               "final_seq": count, "final_head": head, "closure_status": "CLOSED",
               "hash_algorithm": "SHA256", "signature_suite": SUITE,
               "signature_encoding": SIGNATURE_ENCODING, "signer_key_id": key_id}
    validate_permission_commitment(closure)
    return closure


def check_permission_commitment(manifest, entries, closure):
    validate_permission_commitment(closure)
    head = genesis(manifest)
    _require(entries[0]["event"]["body"]["manifest_digest"] == manifest_digest(manifest),
             "Permission start manifest digest mismatch")
    for entry in entries:
        _require(entry["event"]["prev_hash"] == head, "Permission predecessor discontinuity")
        head = event_hash(entry["event"])
        _require(entry["event_hash"] == head, "Permission event hash mismatch")
    _require(closure == make_permission_commitment(manifest, len(entries), head,
             closure["signer_key_id"]), "Permission count/head/manifest commitment mismatch")
    return head


def sign_permission_commitment(key, closure):
    _p256(key, private=True)
    validate_permission_commitment(closure)
    return base64.b64encode(key.sign(DOMAINS["COMMITMENT"] + encode(closure),
                                  ec.ECDSA(hashes.SHA256()))).decode("ascii")


def verify_permission_signature(key, closure, signature):
    _p256(key)
    validate_permission_commitment(closure)
    _require(type(signature) is str, "Permission signature must be base64 text")
    raw = base64.b64decode(signature, validate=True)
    _require(base64.b64encode(raw).decode("ascii") == signature, "Noncanonical permission signature")
    key.verify(raw, DOMAINS["COMMITMENT"] + encode(closure), ec.ECDSA(hashes.SHA256()))


def reproduce_permission_findings(manifest, records, lifecycle):
    """Evaluate trusted M2 code on the validated prior semantic facts only."""
    task, policy = manifest["task_id"], POLICY
    reference, streaming = B2Reference(task, policy), B2Streaming(task, policy)
    by_event = {}
    for fact in lifecycle.facts:
        by_event.setdefault(fact.event_id, []).append(fact)
    history, expected, seen = (), {}, set()
    proposals = reproduced = prefixes = 0
    for event in records:
        kind, body = event["event_type"], event["body"]
        if kind == "CALL_PROPOSAL":
            proposals += 1
            expected, seen = {}, set()
            current = Current(**{**body["current"],
                                 "sensitive_resources": tuple(body["current"]["sensitive_resources"])})
            if current.supported:
                proposal = event["event_id"]
                full = reference.evaluate(current, history, proposal)
                incremental = streaming.evaluate(current, proposal)
                _require(equivalent(full, incremental), "Offline permission B2 prefix disagreement")
                prefixes += 1
                findings = (replace(b0(current, policy), supporting_event_ids=(proposal,)),
                    attach_references(b1(current, project_b1(history, task), policy),
                                      proposal, current, history), full, incremental)
                expected = {f.detector_id: _finding_body(f, proposal) for f in findings}
                _require(tuple(expected) == DETECTOR_IDS, "Unsupported permission detector set")
        elif kind == "DETECTOR_FINDING":
            detector = body["detector_id"]
            _require(detector not in seen and expected.get(detector) == body,
                     "Permission finding differs from independent reproduction")
            seen.add(detector)
            reproduced += 1
        elif kind == "DISPATCH_DECISION":
            _require(seen == set(expected), "Missing permission detector finding")
        for fact in by_event.get(event["event_id"], ()):
            streaming.observe(fact)
            history += (fact,)
    return {"proposals": proposals, "findings_reproduced": reproduced,
            "b2_agreeing_prefixes": prefixes}


def _inspect_permission_session(package_bytes, inventory, expected_config, pinned_keys, singleton):
    report = {"mode": "INSPECT", "fresh_submission": "NOT_CHECKED", "inspection_passed": False,
              "dimensions": {name: {"status": "NOT_CHECKED", "reason": "Prerequisite unavailable"}
                             for name in PROFILE_DIMENSIONS}}
    def result(name, status, reason):
        report["dimensions"][name] = {"status": status, "reason": reason}
    try:
        package = decode(package_bytes)
        _require(type(package) is dict and set(package) ==
                 {"format_version", "manifest", "records", "commitment", "signature"},
                 "Invalid permission package fields")
        validate_profile_versions(PROFILE_VERSIONS)
        _require(package["format_version"] == PACKAGE_FORMAT, "Unsupported permission package format")
    except Exception as exc:
        result("schema_lifecycle", "FAIL", str(exc))
        return report
    manifest, entries, closure = package["manifest"], package["records"], package["commitment"]
    records = None
    try:
        records = validate_permission_structure(manifest, entries)
        result("schema_lifecycle", "PASS", "Permission schema, identity and sequence checked")
    except IncompleteEvidence as exc:
        result("schema_lifecycle", "INCOMPLETE", str(exc))
    except Exception as exc:
        result("schema_lifecycle", "FAIL", str(exc))
    if records is not None:
        try:
            if closure is None:
                raise IncompleteEvidence("Missing permission signed closure")
            check_permission_commitment(manifest, entries, closure)
            result("commitment_integrity", "PASS", "Permission manifest/count/chain head verified")
        except IncompleteEvidence as exc:
            result("commitment_integrity", "INCOMPLETE", str(exc))
        except Exception as exc:
            result("commitment_integrity", "FAIL", str(exc))
    try:
        if closure is None or package["signature"] is None:
            raise IncompleteEvidence("Missing permission closure/signature")
        validate_permission_commitment(closure)
        key = pinned_keys.get(closure["signer_key_id"])
        _require(key is not None, "Unknown externally pinned permission signer")
        verify_permission_signature(key, closure, package["signature"])
        result("trusted_signature", "PASS", "P-256/SHA-256 permission closure verified")
    except IncompleteEvidence as exc:
        result("trusted_signature", "INCOMPLETE", str(exc))
    except Exception as exc:
        result("trusted_signature", "FAIL", str(exc) or type(exc).__name__)
    bound = False
    try:
        validate_inventory(inventory)
        validate_permission_configuration(expected_config)
        _require(manifest["run_id"] == inventory["run_id"]
                 and manifest["run_challenge"] == inventory["run_challenge"], "Wrong permission run/challenge")
        _require({k: manifest[k] for k in IDENTITY_KEYS[1:]} in inventory["sessions"],
                 "Wrong permission task/session/monitor")
        _require(manifest["expected_inventory_digest"] == inventory_digest(inventory),
                 "Wrong permission expected inventory")
        _require(encode(manifest["configuration"]) == encode(expected_config),
                 "Permission manifest differs from external configuration")
        if closure is not None:
            _require(all(closure[k] == manifest[k] for k in (*IDENTITY_KEYS,
                     "run_challenge", "expected_inventory_digest")), "Permission closure context mismatch")
        result("expected_binding", "PASS", "External inventory and installed configuration matched")
        bound = True
    except Exception as exc:
        result("expected_binding", "FAIL", str(exc))
    if records is not None:
        try:
            if closure is None:
                raise IncompleteEvidence("Missing permission signed closure")
            validate_permission_commitment(closure)
            if len(entries) < closure["record_count"]:
                raise IncompleteEvidence("Truncated permission records")
            _require(len(entries) == closure["record_count"] == closure["final_seq"],
                     "Permission closure count mismatch")
            if not bound:
                result("inventory_completeness", "NOT_CHECKED", "External binding failed")
            elif singleton and len(inventory["sessions"]) != 1:
                raise IncompleteEvidence("Other expected permission sessions missing")
            else:
                result("inventory_completeness", "PASS", "Signed permission session count complete")
        except IncompleteEvidence as exc:
            result("inventory_completeness", "INCOMPLETE", str(exc))
        except Exception as exc:
            result("inventory_completeness", "FAIL", str(exc))
    elif bound and report["dimensions"]["schema_lifecycle"]["status"] == "INCOMPLETE":
        result("inventory_completeness", "INCOMPLETE", "Missing permission records")
    lifecycle = None
    if (records is not None and bound and report["dimensions"]["commitment_integrity"]["status"] == "PASS"
            and report["dimensions"]["trusted_signature"]["status"] == "PASS"):
        try:
            lifecycle = reconstruct_lifecycle(records, POLICY, manifest["execution_profile"],
                synthetic_experiment=expected_config["synthetic_experiment"],
                synthetic_sink=expected_config["synthetic_sink"],
                enforcement_detector=expected_config["enforcement_detector"])
            result("lifecycle_semantics", "PASS", "Permission grant/intent/outcome lifecycle reconstructed")
        except Exception as exc:
            result("lifecycle_semantics", "FAIL", str(exc))
    if lifecycle is not None:
        try:
            report["reproduction"] = reproduce_permission_findings(manifest, records, lifecycle)
            result("finding_reproduction", "PASS", "Permission findings independently reproduced")
        except Exception as exc:
            result("finding_reproduction", "FAIL", str(exc))
    report["inspection_passed"] = all(d["status"] == "PASS" for d in report["dimensions"].values())
    return report


def inspect_permission_package(package_bytes, inventory, expected_config, pinned_keys):
    return _inspect_permission_session(package_bytes, inventory, expected_config, pinned_keys, True)


def inspect_permission_run(package_snapshots, inventory, expected_config, pinned_keys):
    snapshots = tuple(package_snapshots)
    validate_inventory(inventory)
    reports = [_inspect_permission_session(data, inventory, expected_config, pinned_keys, False)
               for data in snapshots]
    associations = []
    for data in snapshots:
        try:
            manifest = decode(data)["manifest"]
            association = tuple(manifest[k] for k in IDENTITY_KEYS[1:])
            _require(all(type(v) is str for v in association), "Invalid permission session association")
            associations.append(association)
        except Exception:
            associations.append(None)
    required = {tuple(entry[k] for k in IDENTITY_KEYS[1:]) for entry in inventory["sessions"]}
    present = set(associations)
    if None in present or len(present) != len(associations) or present - required:
        completeness = {"status": "FAIL", "reason": "Invalid/duplicate/extra permission session"}
    elif required - present:
        completeness = {"status": "INCOMPLETE", "reason": "Missing independently expected permission session"}
    else:
        completeness = {"status": "PASS", "reason": "Every expected permission session present exactly once"}
    dimensions = {}
    for name in PROFILE_DIMENSIONS:
        values = [r["dimensions"][name]["status"] for r in reports]
        if name == "inventory_completeness":
            values.append(completeness["status"])
        status = next((s for s in ("FAIL", "INCOMPLETE", "NOT_CHECKED") if s in values),
                      "PASS" if values else "NOT_CHECKED")
        dimensions[name] = {"status": status,
                            "reason": completeness["reason"] if name == "inventory_completeness"
                            else "Aggregated permission session checks"}
    return {"mode": "INSPECT_RUN", "fresh_submission": "NOT_CHECKED", "sessions": reports,
            "dimensions": dimensions,
            "inspection_passed": all(d["status"] == "PASS" for d in dimensions.values())}
