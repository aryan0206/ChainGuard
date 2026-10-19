"""Canonical, live-profile evidence contract (M6.4 Gate 1).

These checks establish only structure and field agreement. In particular, a
well-formed signature string is not a verified signature, and agreement with
supplied record hashes is not independent authentication or lifecycle proof.
No exporter, signer, verifier, or acceptance decision is provided here.
"""

import base64
import binascii

from chainguard.canonical import CANONICALIZATION_VERSION, MAX_INTEGER, decode, encode
from chainguard.evidence import (COMMITMENT_KEYS, DETECTOR_IDS, DOMAINS, IDENTITY_KEYS,
                                 SIGNATURE_ENCODING, SUITE, is_digest,
                                 manifest_digest, sha256)
from chainguard.m6_live_audit import validate_live_record
from chainguard.m6_live_profile import (COMMITMENT_SCHEMA, CONFIGURATION_SCHEMA,
    EXECUTION_PROFILE, IMPLEMENTATION_STAGE, MANIFEST_KEYS, MANIFEST_SCHEMA,
    OBSERVATION_SCOPE, PACKAGE_FORMAT)
from chainguard.permission_evidence import RECORD_SCHEMA
from chainguard.semantics import EXTRACTION_VERSION, POLICY_VERSION
from chainguard import PROTOCOL_VERSION


PACKAGE_KEYS = frozenset({"format_version", "manifest", "records", "commitment", "signature"})
ENTRY_KEYS = frozenset({"event", "event_hash"})
CONFIGURATION_KEYS = frozenset({"schema_version", "implementation_stage",
    "code_revision", "artifacts", "policy", "tool_registry", "normalizer",
    "detectors", "controller_profile", "synthetic_experiment", "synthetic_sink",
    "enforcement_detector"})
POLICY_KEYS = frozenset({"version", "digest", "resources", "destinations",
                         "max_payload_bytes"})
REGISTRY_KEYS = frozenset({"version", "digest", "definition"})
TOOL_KEYS = frozenset({"name", "operation", "resource", "destination",
                       "input_schema", "result_contract"})
NORMALIZER_KEYS = frozenset({"version", "extraction_version", "digest"})


def _require(condition, message):
    if not condition:
        raise ValueError(message)


def _canonical(value):
    try:
        return encode(value)
    except (RecursionError, UnicodeError) as exc:
        raise ValueError("Invalid or excessively nested live evidence") from exc


def validate_live_commitment(closure):
    """Validate the live closure schema, without authenticating its claims."""
    _require(type(closure) is dict and set(closure) == COMMITMENT_KEYS,
             "Invalid live commitment fields")
    _require((closure["schema_version"], closure["record_schema_version"],
              closure["canonicalization_version"]) ==
             (COMMITMENT_SCHEMA, RECORD_SCHEMA, CANONICALIZATION_VERSION),
             "Mixed or unsupported live commitment versions")
    _require((closure["hash_algorithm"], closure["signature_suite"],
              closure["signature_encoding"], closure["closure_status"]) ==
             ("SHA256", SUITE, SIGNATURE_ENCODING, "CLOSED"),
             "Unsupported live commitment suite or closure status")
    _require(all(type(closure[k]) is str and bool(closure[k])
                 for k in (*IDENTITY_KEYS, "signer_key_id")),
             "Invalid live commitment identity or signer")
    _require(all(is_digest(closure[k]) for k in
                 ("manifest_digest", "final_head", "run_challenge", "expected_inventory_digest")),
             "Invalid live commitment digest")
    _require(all(type(closure[k]) is int and 2 <= closure[k] <= MAX_INTEGER
                 for k in ("record_count", "final_seq")) and
             closure["record_count"] == closure["final_seq"],
             "Invalid live commitment count or final sequence")
    _canonical(closure)


def live_commitment_signing_input(closure):
    """Return the domain-separated bytes reserved for a future live signer."""
    validate_live_commitment(closure)
    return DOMAINS["COMMITMENT"] + _canonical(closure)


def live_commitment_digest(closure):
    """Digest signing input for reproducibility; this is not authentication."""
    return sha256(live_commitment_signing_input(closure))


def _validate_configuration_shape(config):
    """Check the versioned nested shape, not installed-code or assessor trust."""
    _require(type(config) is dict and set(config) == CONFIGURATION_KEYS and
             config["schema_version"] == CONFIGURATION_SCHEMA and
             config["implementation_stage"] == IMPLEMENTATION_STAGE and
             type(config["code_revision"]) is str and
             len(config["code_revision"]) == 40 and
             all(c in "0123456789abcdef" for c in config["code_revision"]) and
             config["synthetic_experiment"] is False and
             config["synthetic_sink"] == "sink" and
             config["enforcement_detector"] == "B2-S",
             "Invalid live configuration fields or profile")
    artifacts = config["artifacts"]
    _require(type(artifacts) is list and bool(artifacts), "Invalid live artifacts")
    for item in artifacts:
        _require(type(item) is dict and set(item) == {"name", "digest"} and
                 type(item["name"]) is str and bool(item["name"]) and
                 is_digest(item["digest"]), "Invalid live artifact reference")
    names = [item["name"] for item in artifacts]
    _require(names == sorted(set(names)) and "m6_live_evidence.py" in names,
             "Unsorted, duplicate, or missing live artifacts")
    policy = config["policy"]
    _require(type(policy) is dict and set(policy) == POLICY_KEYS and
             policy["version"] == POLICY_VERSION and is_digest(policy["digest"]) and
             type(policy["max_payload_bytes"]) is int and
             1 <= policy["max_payload_bytes"] <= MAX_INTEGER,
             "Invalid live policy fields")
    resources = policy["resources"]
    _require(type(resources) is list and bool(resources), "Invalid live policy resources")
    for pair in resources:
        _require(type(pair) is list and len(pair) == 2 and
                 all(type(value) is str and bool(value) for value in pair),
                 "Invalid live policy resource")
    _require(resources == sorted(resources) and
             len({pair[0] for pair in resources}) == len(resources),
             "Unsorted or duplicate live policy resources")
    destinations = policy["destinations"]
    _require(type(destinations) is list and bool(destinations) and
             all(type(value) is str and bool(value) for value in destinations) and
             len(destinations) == len(set(destinations)),
             "Invalid live policy destinations")
    registry = config["tool_registry"]
    _require(type(registry) is dict and set(registry) == REGISTRY_KEYS and
             registry["version"] == "m6-live-synthetic-fixed-v1" and
             is_digest(registry["digest"]), "Invalid live tool registry fields")
    definition = registry["definition"]
    _require(type(definition) is dict and set(definition) == {"server", "tools"} and
             type(definition["server"]) is str and bool(definition["server"]) and
             type(definition["tools"]) is list and bool(definition["tools"]),
             "Invalid live tool registry definition")
    for tool in definition["tools"]:
        _require(type(tool) is dict and set(tool) == TOOL_KEYS and
                 all(type(tool[key]) is str for key in
                     ("name", "operation", "resource", "destination")) and
                 bool(tool["name"]) and bool(tool["operation"]) and
                 type(tool["input_schema"]) is dict and
                 type(tool["result_contract"]) is dict,
                 "Invalid live tool definition")
    tool_names = [tool["name"] for tool in definition["tools"]]
    _require(tool_names == sorted(set(tool_names)) and
             registry["digest"] == sha256(_canonical(definition)),
             "Invalid live tool ordering or definition digest")
    normalizer = config["normalizer"]
    _require(type(normalizer) is dict and set(normalizer) == NORMALIZER_KEYS and
             normalizer["version"] == "m6-live-gated-v1" and
             normalizer["extraction_version"] == EXTRACTION_VERSION and
             is_digest(normalizer["digest"]), "Invalid live normalizer")
    detectors = config["detectors"]
    _require(type(detectors) is list and len(detectors) == len(DETECTOR_IDS),
             "Invalid live detector inventory")
    for detector, detector_id in zip(detectors, DETECTOR_IDS, strict=True):
        _require(type(detector) is dict and
                 set(detector) == {"id", "version", "digest"} and
                 detector["id"] == detector_id and
                 detector["version"] == "m2-v1" and
                 is_digest(detector["digest"]), "Invalid live detector reference")


def _validate_manifest_shape(manifest):
    _require(type(manifest) is dict and set(manifest) == MANIFEST_KEYS,
             "Invalid live manifest fields")
    config = manifest["configuration"]
    _validate_configuration_shape(config)
    _require((manifest["schema_version"], manifest["record_schema_version"],
              manifest["canonicalization_version"], manifest["protocol_version"],
              manifest["observation_scope"], manifest["mode"]) ==
             (MANIFEST_SCHEMA, RECORD_SCHEMA, CANONICALIZATION_VERSION,
              PROTOCOL_VERSION, OBSERVATION_SCOPE, EXECUTION_PROFILE["mode"]),
             "Mixed or unsupported live manifest versions or scope")
    _require(all(type(manifest[k]) is str and bool(manifest[k]) for k in IDENTITY_KEYS),
             "Invalid live manifest identity")
    _require(is_digest(manifest["run_challenge"]) and
             is_digest(manifest["expected_inventory_digest"]),
             "Invalid live manifest challenge or inventory digest")
    _require(type(manifest["execution_profile"]) is dict and
             type(config["controller_profile"]) is dict and
             _canonical(manifest["execution_profile"]) == _canonical(EXECUTION_PROFILE) and
             _canonical(config["controller_profile"]) == _canonical(EXECUTION_PROFILE),
             "Invalid live execution profile")
    _canonical(manifest)


def _validate_signature_encoding(signature):
    _require(type(signature) is str and bool(signature), "Missing live signature text")
    try:
        raw = base64.b64decode(signature, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ValueError("Invalid live signature encoding") from exc
    _require(bool(raw) and base64.b64encode(raw).decode("ascii") == signature,
             "Noncanonical live signature encoding")


def validate_live_package_structure(package_bytes):
    """Decode a canonical live package and check structural field agreement.

    The signature is only checked as canonical base64. Event hashes and the
    closure head are compared as supplied values, never recomputed here.
    An assessor must compare the complete canonical configuration to an
    independently trusted expected configuration before using its semantics.
    External inventory binding, chain authentication, signature verification,
    and authorization lifecycle reconstruction are later gates.
    """
    try:
        package = decode(package_bytes)
    except (RecursionError, UnicodeError) as exc:
        raise ValueError("Invalid or excessively nested live package") from exc
    _require(type(package) is dict and set(package) == PACKAGE_KEYS,
             "Invalid live package fields")
    _require(package["format_version"] == PACKAGE_FORMAT, "Unsupported live package format")
    manifest = package["manifest"]
    _validate_manifest_shape(manifest)
    closure = package["commitment"]
    validate_live_commitment(closure)
    _validate_signature_encoding(package["signature"])
    _require(all(closure[k] == manifest[k] for k in IDENTITY_KEYS) and
             closure["run_challenge"] == manifest["run_challenge"] and
             closure["expected_inventory_digest"] == manifest["expected_inventory_digest"] and
             closure["manifest_digest"] == manifest_digest(manifest),
             "Live commitment does not bind manifest fields")
    entries = package["records"]
    _require(type(entries) is list and len(entries) == closure["record_count"],
             "Live record count mismatch")
    for seq, entry in enumerate(entries, 1):
        _require(type(entry) is dict and set(entry) == ENTRY_KEYS,
                 "Invalid live record/hash wrapper")
        event = entry["event"]
        validate_live_record(event, manifest)
        _require(event["seq"] == seq and is_digest(entry["event_hash"]),
                 "Invalid live sequence or supplied hash")
    _require(closure["final_seq"] == len(entries) and
             closure["final_head"] == entries[-1]["event_hash"],
             "Live commitment count or supplied final head mismatch")
    return package
