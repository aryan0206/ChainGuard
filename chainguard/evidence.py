"""M4 signed chains for new non-release streams; no permission lifecycle.

SQLite is storage. Only confirmed commits advance the process-owned head.
M3 records are never migrated or reclassified as cryptographic evidence.
"""

import base64
from copy import deepcopy
from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import subprocess

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from chainguard import PROTOCOL_VERSION
from chainguard.audit import (AuditError, AuditSession, BODY_KEYS, ContinuityState, PROFILE,
                              _empty_phases, _phases, _require, _text, _validate_record, draft)
from chainguard.canonical import CANONICALIZATION_VERSION, MAX_INTEGER, decode, encode
from chainguard.detectors import ARTIFACT_DIGEST
from chainguard.semantics import EXTRACTION_VERSION, POLICY_VERSION, Policy


ROOT = Path(__file__).resolve().parent.parent
RECORD_SCHEMA = "m4-record-v1"
RECORD_CLASS = "M4_CHAINED_UNSEALED"
MANIFEST_SCHEMA = "m4-manifest-v1"
COMMITMENT_SCHEMA = "m4-commitment-v1"
PACKAGE_FORMAT = "m4-evidence-v1"
INVENTORY_SCHEMA = "m4-expected-inventory-v1"
SUITE = "ECDSA-P256-SHA256-DER-v1"
SIGNATURE_ENCODING = "DER-base64"
DOMAINS = {name: f"CHAIN GUARD {name}-v1".encode("ascii") + b"\0"
           for name in ("MANIFEST", "GENESIS", "EVENT", "COMMITMENT")}
IDENTITY_KEYS = ("run_id", "task_id", "session_id", "monitor_instance_id")
DETECTOR_IDS = ("B0", "B1", "B2-R", "B2-S")
ARTIFACT_NAMES = ("__init__.py", "audit.py", "canonical.py", "controlled_server.py",
                  "detectors.py", "evidence.py", "m3.py", "m4.py", "proxy.py",
                  "semantics.py", "verifier.py")
MANIFEST_KEYS = {"schema_version", "record_schema_version", "canonicalization_version",
                 "protocol_version", "observation_scope", "mode", "execution_profile",
                 "run_challenge", "expected_inventory_digest", "configuration"} | set(IDENTITY_KEYS)
COMMITMENT_KEYS = {"schema_version", "record_schema_version", "canonicalization_version",
                   "run_challenge", "expected_inventory_digest", "manifest_digest",
                   "record_count", "final_seq", "final_head", "closure_status", "hash_algorithm",
                   "signature_suite", "signature_encoding", "signer_key_id"} | set(IDENTITY_KEYS)
OBSERVATION_SCOPE = "supported-M1-tool-calls/non-release/sequential-stdio"


class IncompleteEvidence(ValueError):
    """Missing closure or unresolved work, distinct from verified completeness."""


def is_digest(value):
    return type(value) is str and len(value) == 64 and all(c in "0123456789abcdef" for c in value)


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def manifest_digest(manifest):
    return sha256(DOMAINS["MANIFEST"] + encode(manifest))


def genesis(manifest):
    return sha256(DOMAINS["GENESIS"] + bytes.fromhex(manifest_digest(manifest)))


def event_hash(event):
    # No current hash field exists in this typed event; prev_hash is inside it.
    return sha256(DOMAINS["EVENT"] + encode(event))


def configuration():
    """Assessor/installed-code configuration, never loaded from bundle code."""
    from chainguard.controlled_server import INPUT_SCHEMA

    policy = Policy(())
    registry = {"server": "chainguard-controlled-m1", "tools": sorted(PROFILE["supported_tools"]),
                "input_schema": INPUT_SCHEMA, "operation": "echo", "sensitivity": "public",
                "transformation": "none", "release_calls_enabled": False}
    artifacts = [{"name": name, "digest": sha256((ROOT / "chainguard" / name).read_bytes())}
                 for name in sorted(ARTIFACT_NAMES)]
    revision = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, check=True,
                              capture_output=True, text=True).stdout.strip()
    return {"schema_version": "m4-configuration-v1", "code_revision": revision, "artifacts": artifacts,
            "policy": {"version": POLICY_VERSION, "digest": policy.digest,
                       "resources": [], "destinations": list(policy.destinations),
                       "max_payload_bytes": policy.max_payload_bytes},
            "tool_registry": {"version": "m1-non-release-registry-v1", "digest": sha256(encode(registry)),
                              "definition": registry},
            "normalizer": {"version": "m3-non-release-v1", "extraction_version": EXTRACTION_VERSION,
                           "digest": sha256(b"non-release-normalizer\0" + (ROOT / "chainguard/audit.py").read_bytes())},
            "detectors": [{"id": name, "version": "m2-v1", "digest": ARTIFACT_DIGEST}
                          for name in DETECTOR_IDS]}


def validate_inventory(inventory):
    _require(type(inventory) is dict and set(inventory) == {"schema_version", "run_id", "run_challenge", "sessions"},
             "Invalid expected inventory fields")
    _require(inventory["schema_version"] == INVENTORY_SCHEMA and _text(inventory["run_id"])
             and is_digest(inventory["run_challenge"]), "Invalid expected run/challenge")
    sessions = inventory["sessions"]
    _require(type(sessions) is list and bool(sessions), "Empty expected inventory")
    for entry in sessions:
        _require(type(entry) is dict and set(entry) == {"task_id", "session_id", "monitor_instance_id"}
                 and all(_text(v) for v in entry.values()), "Invalid expected session association")
    _require(sessions == sorted(sessions, key=lambda s: (s["task_id"], s["session_id"], s["monitor_instance_id"])),
             "Unsorted expected inventory")
    _require(len({s["session_id"] for s in sessions}) == len(sessions)
             and len({s["task_id"] for s in sessions}) == len(sessions), "Duplicate expected session/task")
    encode(inventory)


def inventory_digest(inventory):
    validate_inventory(inventory)
    # Section 19.3 specifies canonical SHA-256; this is not the manifest domain.
    return sha256(encode(inventory))


def validate_configuration(config):
    _require(type(config) is dict and set(config) == {"schema_version", "code_revision", "artifacts", "policy",
             "tool_registry", "normalizer", "detectors"}, "Invalid configuration fields")
    _require(config["schema_version"] == "m4-configuration-v1", "Unknown configuration version")
    revision = config["code_revision"]
    _require(type(revision) is str and len(revision) == 40 and all(c in "0123456789abcdef" for c in revision),
             "Invalid code revision")
    artifacts = config["artifacts"]
    _require(type(artifacts) is list and len(artifacts) == len(ARTIFACT_NAMES), "Missing artifact references")
    for entry in artifacts:
        _require(type(entry) is dict and set(entry) == {"name", "digest"}
                 and entry["name"] in ARTIFACT_NAMES and is_digest(entry["digest"]), "Invalid artifact reference")
    _require([a["name"] for a in artifacts] == sorted(ARTIFACT_NAMES), "Unsorted/duplicate artifact references")
    policy = config["policy"]
    _require(type(policy) is dict and set(policy) == {"version", "digest", "resources", "destinations", "max_payload_bytes"}
             and policy["version"] == POLICY_VERSION and policy["digest"] == Policy(()).digest
             and policy["resources"] == [] and policy["destinations"] == ["sink"]
             and type(policy["max_payload_bytes"]) is int and policy["max_payload_bytes"] == 65536, "Unsupported policy configuration")
    registry = config["tool_registry"]
    _require(type(registry) is dict and set(registry) == {"version", "digest", "definition"}
             and registry["version"] == "m1-non-release-registry-v1" and is_digest(registry["digest"])
             and type(registry["definition"]) is dict and registry["digest"] == sha256(encode(registry["definition"])),
             "Invalid tool registry configuration")
    normalizer = config["normalizer"]
    _require(type(normalizer) is dict and set(normalizer) == {"version", "extraction_version", "digest"}
             and normalizer["version"] == "m3-non-release-v1" and normalizer["extraction_version"] == EXTRACTION_VERSION
             and is_digest(normalizer["digest"]), "Unsupported normalizer configuration")
    detectors = config["detectors"]
    _require(type(detectors) is list and len(detectors) == len(DETECTOR_IDS), "Invalid detector inventory")
    for detector, name in zip(detectors, DETECTOR_IDS, strict=True):
        _require(type(detector) is dict and set(detector) == {"id", "version", "digest"}
                 and detector["id"] == name and detector["version"] == "m2-v1" and is_digest(detector["digest"]),
                 "Unknown detector configuration")
    encode(config)


def validate_manifest(manifest):
    _require(type(manifest) is dict and set(manifest) == MANIFEST_KEYS, "Invalid manifest fields")
    _require(manifest["schema_version"] == MANIFEST_SCHEMA
             and manifest["record_schema_version"] == RECORD_SCHEMA
             and manifest["canonicalization_version"] == CANONICALIZATION_VERSION
             and manifest["protocol_version"] == PROTOCOL_VERSION, "Unsupported manifest versions")
    _require(all(_text(manifest[k]) for k in IDENTITY_KEYS), "Invalid manifest identity")
    _require(is_digest(manifest["run_challenge"]) and is_digest(manifest["expected_inventory_digest"]),
             "Invalid manifest challenge/inventory digest")
    _require(manifest["mode"] == "observation" and manifest["observation_scope"] == OBSERVATION_SCOPE
             and encode(manifest["execution_profile"]) == encode(PROFILE), "Unsupported execution scope")
    validate_configuration(manifest["configuration"])
    encode(manifest)


def make_manifest(inventory, config, task_id, session_id, monitor_instance_id):
    association = {"task_id": task_id, "session_id": session_id, "monitor_instance_id": monitor_instance_id}
    validate_inventory(inventory)
    _require(association in inventory["sessions"], "Monitor must be registered before task execution")
    manifest = {"schema_version": MANIFEST_SCHEMA, "record_schema_version": RECORD_SCHEMA,
                "canonicalization_version": CANONICALIZATION_VERSION, "protocol_version": PROTOCOL_VERSION,
                "observation_scope": OBSERVATION_SCOPE, "mode": "observation", "execution_profile": deepcopy(PROFILE),
                "run_id": inventory["run_id"], **association, "run_challenge": inventory["run_challenge"],
                "expected_inventory_digest": inventory_digest(inventory), "configuration": deepcopy(config)}
    validate_manifest(manifest)
    return manifest


def validate_record(record):
    """Exact M4 envelope, with the approved M3 non-release body semantics."""
    _validate_record(record, RECORD_SCHEMA, {"prev_hash"}, BODY_KEYS["SESSION_START"] | {"manifest_digest"},
        lambda body: (body["record_class"] == RECORD_CLASS and is_digest(body["run_challenge"])
                      and is_digest(body["manifest_digest"])
                      and encode(body["execution_profile"]) == encode(PROFILE)), "CLOSED")
    _require(is_digest(record["prev_hash"]), "Invalid prev_hash")


def validate_structure(manifest, entries, require_closed=False):
    validate_manifest(manifest)
    _require(type(entries) is list, "Records must be an ordered array")
    if not entries:
        raise IncompleteEvidence("Missing session records")
    records = []
    for seq, entry in enumerate(entries, 1):
        _require(type(entry) is dict and set(entry) == {"event", "event_hash"}, "Invalid record/hash wrapper")
        event = entry["event"]
        validate_record(event)
        _require(is_digest(entry["event_hash"]), "Invalid event hash")
        _require(event["seq"] == seq and all(event[k] == manifest[k] for k in IDENTITY_KEYS),
                 "Noncontiguous sequence or stream identity")
        records.append(event)
    _require(records[0]["event_type"] == "SESSION_START", "Missing initial session-start record")
    start = records[0]["body"]
    _require(start["run_challenge"] == manifest["run_challenge"]
             and start["execution_profile"] == manifest["execution_profile"], "Session/manifest mismatch")
    phase = _phases(records, _empty_phases(), validate_record)
    if require_closed and (not phase["closed"] or phase["unknown"] or phase["pending"] is not None):
        raise IncompleteEvidence("Missing clean close or unresolved outcome")
    return phase


def recompute_chain(manifest, entries):
    head = genesis(manifest)
    _require(entries[0]["event"]["body"]["manifest_digest"] == manifest_digest(manifest), "Start manifest digest mismatch")
    for entry in entries:
        event = entry["event"]
        _require(event["prev_hash"] == head, "Previous-hash discontinuity")
        head = event_hash(event)
        _require(entry["event_hash"] == head, "Event hash mismatch")
    return head


def validate_commitment(closure):
    _require(type(closure) is dict and set(closure) == COMMITMENT_KEYS, "Invalid commitment fields")
    _require(closure["schema_version"] == COMMITMENT_SCHEMA
             and closure["record_schema_version"] == RECORD_SCHEMA
             and closure["canonicalization_version"] == CANONICALIZATION_VERSION, "Unsupported commitment versions")
    _require(closure["hash_algorithm"] == "SHA256" and closure["signature_suite"] == SUITE
             and closure["signature_encoding"] == SIGNATURE_ENCODING, "Unsupported algorithm/encoding")
    _require(closure["closure_status"] == "CLOSED", "No clean closure")
    _require(all(_text(closure[k]) for k in (*IDENTITY_KEYS, "signer_key_id")), "Missing commitment identity/key")
    _require(all(is_digest(closure[k]) for k in ("manifest_digest", "final_head", "run_challenge", "expected_inventory_digest")),
             "Invalid commitment digest/challenge")
    _require(all(type(closure[k]) is int and 2 <= closure[k] <= MAX_INTEGER for k in ("record_count", "final_seq")),
             "Invalid commitment count/sequence")
    encode(closure)


def make_commitment(manifest, count, head, key_id):
    result = {"schema_version": COMMITMENT_SCHEMA, "record_schema_version": RECORD_SCHEMA,
              "canonicalization_version": CANONICALIZATION_VERSION,
              **{k: manifest[k] for k in IDENTITY_KEYS}, "run_challenge": manifest["run_challenge"],
              "expected_inventory_digest": manifest["expected_inventory_digest"],
              "manifest_digest": manifest_digest(manifest), "record_count": count, "final_seq": count,
              "final_head": head, "closure_status": "CLOSED", "hash_algorithm": "SHA256",
              "signature_suite": SUITE, "signature_encoding": SIGNATURE_ENCODING, "signer_key_id": key_id}
    validate_commitment(result)
    return result


def check_commitment(manifest, entries, closure):
    validate_commitment(closure)
    head = recompute_chain(manifest, entries)
    _require(closure == make_commitment(manifest, len(entries), head, closure["signer_key_id"]),
             "Commitment does not match manifest/records/count/head")
    return head


def _p256(key, private=False):
    required = ec.EllipticCurvePrivateKey if private else ec.EllipticCurvePublicKey
    _require(isinstance(key, required) and isinstance(key.curve, ec.SECP256R1), "Pinned suite requires P-256 key")


def sign_commitment(key, closure):
    _p256(key, private=True)
    validate_commitment(closure)
    signature = key.sign(DOMAINS["COMMITMENT"] + encode(closure), ec.ECDSA(hashes.SHA256()))
    return base64.b64encode(signature).decode("ascii")


def verify_signature(key, closure, signature):
    _p256(key)
    validate_commitment(closure)
    _require(type(signature) is str, "Signature must be base64 text")
    raw = base64.b64decode(signature, validate=True)
    _require(base64.b64encode(raw).decode("ascii") == signature, "Noncanonical base64 signature")
    key.verify(raw, DOMAINS["COMMITMENT"] + encode(closure), ec.ECDSA(hashes.SHA256()))


def load_private(path, password=None):
    resolved = Path(path).resolve()
    _require(not resolved.is_relative_to(ROOT), "Private key must be outside repository")
    key = serialization.load_pem_private_key(resolved.read_bytes(), password=password)
    _p256(key, private=True)
    return key


def load_public(path):
    key = serialization.load_pem_public_key(Path(path).read_bytes())
    _p256(key)
    return key


@dataclass(frozen=True)
class CryptographicState(ContinuityState):
    manifest_digest: str = ""
    cryptographic_head: str = ""


class ChainedAuditSession(AuditSession):
    """New M4 context; confirmed state owns head, not SQLite reconstruction."""

    database_version = 4
    record_schema = RECORD_SCHEMA
    end_status = "CLOSED"
    record_extra_sql = ", event_hash TEXT NOT NULL CHECK(length(event_hash)=64)"
    insert_sql = "INSERT INTO audit_records VALUES (?,?,?,?,?,?,?,?,?,?)"

    def __init__(self, path, manifest, inventory, observer=None):
        validate_manifest(manifest)
        validate_inventory(inventory)
        expected = make_manifest(inventory, configuration(), *(manifest[k] for k in IDENTITY_KEYS[1:]))
        _require(manifest == expected, "Manifest must match independently registered expected configuration/context")
        self._manifest_bytes = encode(manifest)
        self._inventory_bytes = encode(inventory)
        self._progress = {"durability": "COMMITTED", "sealing": "UNSEALED",
                          "signature": "NOT_SIGNED", "verification": "NOT_CHECKED"}
        self._seal_started = False
        super().__init__(path, *(manifest[k] for k in IDENTITY_KEYS[:3]), manifest["run_challenge"], observer)

    @property
    def manifest(self):
        return decode(self._manifest_bytes)

    @property
    def progress(self):
        return dict(self._progress)

    def _identity(self, run_id, task_id, session_id):
        return {key: self.manifest[key] for key in IDENTITY_KEYS}

    def _initial_state(self):
        return CryptographicState(manifest_digest=manifest_digest(self.manifest), cryptographic_head=genesis(self.manifest))

    def _create_extra_tables(self):
        self._connection.execute("""CREATE TABLE IF NOT EXISTS audit_manifests (
            session_id TEXT PRIMARY KEY, manifest_bytes BLOB NOT NULL, manifest_digest TEXT NOT NULL)""")

    def _start_draft(self, challenge):
        return draft("SESSION_START", {"record_class": RECORD_CLASS, "run_challenge": challenge,
                     "execution_profile": deepcopy(PROFILE), "manifest_digest": self.state.manifest_digest})

    def _prepare_records(self, records):
        head = self.state.cryptographic_head
        for record in records:
            record["prev_hash"] = head
            head = event_hash(record)
        return records

    def _validate_batch(self, records, phase):
        return _phases(records, phase, validate_record)

    def _candidate_state(self, records, phase):
        state = super()._candidate_state(records, phase)
        return CryptographicState(state.count, state.last_event_id, state.lifecycle, state.failure,
                                  self.state.manifest_digest, event_hash(records[-1]))

    def _storage_rows(self, records, encoded):
        rows = super()._storage_rows(records, encoded)
        return [(*row, event_hash(record)) for row, record in zip(rows, records, strict=True)]

    def _insert_prepared(self, rows):
        if self.state.count == 0:
            self._connection.execute("INSERT INTO audit_manifests VALUES (?,?,?)",
                                     (self.identity["session_id"], self._manifest_bytes, self.state.manifest_digest))
        super()._insert_prepared(rows)

    def _snapshot(self):
        # Explicit read transaction freezes manifest and records together.
        self._connection.execute("BEGIN")
        try:
            stored = self._connection.execute("SELECT manifest_bytes,manifest_digest FROM audit_manifests WHERE session_id=?",
                                               (self.identity["session_id"],)).fetchone()
            rows = self._connection.execute("SELECT * FROM audit_records WHERE session_id=? ORDER BY seq",
                                             (self.identity["session_id"],)).fetchall()
        finally:
            self._connection.rollback()  # Read-only snapshot, not an ambiguous write commit.
        _require(stored == (self._manifest_bytes, self.state.manifest_digest), "Stored manifest differs from trusted manifest")
        entries = []
        for row in rows:
            event = decode(row[8])
            _require(row[:8] == (event["session_id"], event["seq"], event["event_id"], event["event_type"],
                                 event.get("call_id"), event["run_id"], event["task_id"], event["monitor_instance_id"]),
                     "SQLite metadata/canonical event mismatch")
            entries.append({"event": event, "event_hash": row[9]})
        return entries

    def seal(self, private_key, key_id, pins, output=None):
        """Sign/export the reconciled snapshot once, then self-inspect offline."""
        from chainguard.verifier import inspect_package

        with self._lock:
            if self._seal_started:
                raise AuditError("Sealing already attempted")
            self._seal_started = True
            try:
                if self.state.lifecycle == "ACTIVE":
                    self.finish()
                _require(self.state.lifecycle == "CLOSED" and not self.state.failure, "Incomplete context cannot seal")
                frozen = self.state
                entries = self._snapshot()
                manifest = self.manifest
                validate_structure(manifest, entries, require_closed=True)
                head = recompute_chain(manifest, entries)
                _require((manifest_digest(manifest), len(entries), head) ==
                         (frozen.manifest_digest, frozen.count, frozen.cryptographic_head),
                         "Export snapshot differs from frozen trusted count/head")
                self._progress["sealing"] = "SEALED"
                closure = make_commitment(manifest, frozen.count, frozen.cryptographic_head, key_id)
                signature = sign_commitment(private_key, closure)
                self._progress["signature"] = "SIGNED"
                package = encode({"format_version": PACKAGE_FORMAT, "manifest": manifest, "records": entries,
                                  "commitment": closure, "signature": signature})
                report = inspect_package(package, decode(self._inventory_bytes), manifest["configuration"], pins)
                _require(report["inspection_passed"], "Package self-verification failed")
                self._progress["verification"] = "VERIFIED"
                if output is not None:
                    with Path(output).open("xb") as stream:
                        stream.write(package)
                        stream.flush()
                        os.fsync(stream.fileno())
                return package
            except Exception as exc:
                self._progress["sealing"] = "INCOMPLETE"
                self.halt(self.state.failure or "SEAL_OR_EXPORT_FAILED")
                raise AuditError("M4 sealing/export failed; evidence incomplete") from exc
