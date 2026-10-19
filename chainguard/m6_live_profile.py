"""Installed contract for the isolated synthetic M6 gated runtime.

This module binds the fixed tool/server contract and manifest context. It does
not sign evidence or accept packages. The installed artifact inventory covers
the live writer, authority, runtime, and controlled tool surface.
"""

from copy import deepcopy
from dataclasses import dataclass
import subprocess
from types import MappingProxyType

from chainguard import PROTOCOL_VERSION
from chainguard.canonical import CANONICALIZATION_VERSION, encode
from chainguard.detectors import ARTIFACT_DIGEST
from chainguard.evidence import (DETECTOR_IDS, IDENTITY_KEYS, ROOT, inventory_digest,
                                 is_digest, sha256, validate_inventory)
from chainguard.permission_evidence import RECORD_SCHEMA
from chainguard.semantics import EXTRACTION_VERSION, POLICY_VERSION, Policy


PACKAGE_FORMAT = "m6-live-evidence-v1"
MANIFEST_SCHEMA = "m6-live-manifest-v1"
COMMITMENT_SCHEMA = "m6-live-commitment-v1"
CONFIGURATION_SCHEMA = "m6-live-configuration-v1"
PROFILE_VERSIONS = (PACKAGE_FORMAT, MANIFEST_SCHEMA, RECORD_SCHEMA,
                    COMMITMENT_SCHEMA, CONFIGURATION_SCHEMA)
OBSERVATION_SCOPE = "synthetic-live-permission-lifecycle/sequential-stdio"
SERVER_ID = "chainguard-m6-synthetic"
IMPLEMENTATION_STAGE = "GATED_RUNTIME"

POLICY = Policy((("secret-a", "SYNTHETIC_CANARY_A"),
                 ("secret-b", "SYNTHETIC_CANARY_B")),
                destinations=("sink", "other-sink"))
PUBLIC_RESULT = "SYNTHETIC_PUBLIC_TEXT"
SINK_ACK = "captured by local sink"


@dataclass(frozen=True)
class ToolContract:
    operation: str
    resource: str
    destination: str
    argument: str
    argument_limit: int
    argument_unit: str
    result: str


# Client tool names are lookup keys only. These definitions, not arguments,
# establish operation, source resource, destination, and result semantics.
TOOL_CONTRACTS = MappingProxyType({
    "controlled_failure": ToolContract("echo", "", "", "token", 256, "characters",
                                       "m1-controlled-failure-v1"),
    "echo": ToolContract("echo", "", "", "token", 256, "characters", "m1-echo-exact-v1"),
    "read_public": ToolContract("read", "public", "", "", 0, "none", "synthetic-read-exact-v1"),
    "read_secret_a": ToolContract("read", "secret-a", "", "", 0, "none", "synthetic-read-exact-v1"),
    "read_secret_b": ToolContract("read", "secret-b", "", "", 0, "none", "synthetic-read-exact-v1"),
    "send_other_sink": ToolContract("send", "", "other-sink", "payload",
                                    POLICY.max_payload_bytes, "utf8_bytes", "local-capture-ack-v1"),
    "send_sink": ToolContract("send", "", "sink", "payload",
                              POLICY.max_payload_bytes, "utf8_bytes", "local-capture-ack-v1"),
})
EXECUTION_PROFILE = {"mode": "observation", "supported_tools": sorted(TOOL_CONTRACTS),
                     "synthetic_local_sink_override": False, "release_calls_enabled": True}
ARTIFACT_NAMES = tuple(sorted(("__init__.py", "authorization.py", "canonical.py",
    "detectors.py", "evidence.py", "m6_controlled_server.py", "m6_live_audit.py",
    "m6_live_evidence.py",
    "m6_live_authorization.py", "m6_live_profile.py", "m6_live_runtime.py",
    "m6_live_seal.py",
    "permission_evidence.py", "semantics.py")))
MANIFEST_KEYS = {"schema_version", "record_schema_version", "canonicalization_version",
                 "protocol_version", "observation_scope", "mode", "execution_profile",
                 "run_challenge", "expected_inventory_digest", "configuration"} | set(IDENTITY_KEYS)


def _require(condition, message):
    if not condition:
        raise ValueError(message)


def validate_profile_versions(versions):
    _require(type(versions) is tuple and versions == PROFILE_VERSIONS,
             "Unknown or mixed live profile versions")


def tool_contract(name):
    _require(type(name) is str and name in TOOL_CONTRACTS, "Unknown M6 synthetic tool")
    return TOOL_CONTRACTS[name]


def input_schema(name):
    contract = tool_contract(name)
    if contract.argument == "":
        return {"type": "object", "properties": {}, "required": [], "additionalProperties": False}
    value_schema = {"type": "string", "maxLength": contract.argument_limit}
    if contract.argument_unit == "utf8_bytes":
        # Standard JSON Schema maxLength counts characters. This explicit
        # extension states the additional byte bound enforced by this server.
        value_schema.update({"minLength": 1,
                             "x-chainguard-maxUtf8Bytes": contract.argument_limit})
    return {"type": "object", "properties": {contract.argument: value_schema},
            "required": [contract.argument], "additionalProperties": False}


def validate_tool_arguments(name, arguments):
    """Validate input shape without accepting client-defined security semantics."""
    contract = tool_contract(name)
    if contract.argument == "" and arguments is None:
        arguments = {}
    _require(type(arguments) is dict and set(arguments) ==
             ({contract.argument} if contract.argument else set()), "Invalid M6 tool arguments")
    if contract.argument:
        value = arguments[contract.argument]
        _require(type(value) is str, "M6 tool argument must be text")
        try:
            size = len(value.encode("utf-8", errors="strict"))
        except UnicodeError as exc:
            raise ValueError("Invalid M6 tool argument text") from exc
        length = len(value) if contract.argument_unit == "characters" else size
        _require(length <= contract.argument_limit and
                 (contract.argument != "payload" or bool(value)),
                 "M6 tool argument exceeds supported payload shape")
    return contract


def result_contract(name):
    """Complete deterministic result and local-arrival contract for one tool."""
    contract = tool_contract(name)
    if contract.operation == "read":
        value = PUBLIC_RESULT if contract.resource == "public" else dict(POLICY.resources)[contract.resource]
        return {"version": contract.result, "kind": "exact_text", "text": value,
                "is_error": False}
    if contract.operation == "send":
        return {"version": contract.result, "kind": "exact_text", "text": SINK_ACK,
                "is_error": False,
                "arrival": {"component": "m6_local_sink", "phase": "sink_arrival",
                            "destination": contract.destination, "request_id": "sdk_request_id",
                            "tool": name, "payload_byte_count": "utf8_bytes",
                            "before_response": True}}
    if name == "controlled_failure":
        return {"version": contract.result, "kind": "argument_prefix", "argument": "token",
                "prefix": "controlled failure: ", "is_error": True}
    return {"version": contract.result, "kind": "argument_exact", "argument": "token",
            "is_error": False}


def registry_definition():
    return {"server": SERVER_ID, "tools": [
        {"name": name, "operation": contract.operation, "resource": contract.resource,
         "destination": contract.destination, "input_schema": input_schema(name),
         "result_contract": result_contract(name)}
        for name, contract in TOOL_CONTRACTS.items()]}


def live_configuration():
    """Bind current installed runtime code; no package supplies its authority."""
    revision = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, check=True,
                              capture_output=True, text=True).stdout.strip()
    registry = registry_definition()
    source = (ROOT / "chainguard/m6_live_profile.py").read_bytes()
    return {"schema_version": CONFIGURATION_SCHEMA, "implementation_stage": IMPLEMENTATION_STAGE,
            "code_revision": revision,
            "artifacts": [{"name": name, "digest": sha256((ROOT / "chainguard" / name).read_bytes())}
                          for name in ARTIFACT_NAMES],
            "policy": {"version": POLICY_VERSION, "digest": POLICY.digest,
                       "resources": [list(pair) for pair in POLICY.resources],
                       "destinations": list(POLICY.destinations),
                       "max_payload_bytes": POLICY.max_payload_bytes},
            "tool_registry": {"version": "m6-live-synthetic-fixed-v1",
                              "digest": sha256(encode(registry)), "definition": registry},
            "normalizer": {"version": "m6-live-gated-v1",
                           "extraction_version": EXTRACTION_VERSION,
                           "digest": sha256(b"m6-live-gated\0" + source +
                                            (ROOT / "chainguard/semantics.py").read_bytes())},
            "detectors": [{"id": name, "version": "m2-v1", "digest": ARTIFACT_DIGEST}
                          for name in DETECTOR_IDS],
            "controller_profile": deepcopy(EXECUTION_PROFILE),
            "synthetic_experiment": False, "synthetic_sink": "sink",
            "enforcement_detector": "B2-S"}


def validate_live_configuration(config):
    expected = live_configuration()
    _require(type(config) is dict and set(config) == set(expected),
             "Invalid live configuration fields")
    _require(config["schema_version"] == CONFIGURATION_SCHEMA,
             "Unknown live configuration")
    _require(_encode_live(config) == encode(expected),
             "Live configuration differs from approved installed contract")


def _encode_live(value):
    """Turn excessive nesting/cycles in untrusted live data into validation errors."""
    try:
        return encode(value)
    except RecursionError as exc:
        raise ValueError("Live value exceeds canonical nesting limit") from exc


def make_live_manifest(inventory, config, task_id, session_id, monitor_instance_id):
    validate_inventory(inventory)
    validate_live_configuration(config)
    association = {"task_id": task_id, "session_id": session_id,
                   "monitor_instance_id": monitor_instance_id}
    _require(association in inventory["sessions"], "Unregistered live session")
    manifest = {"schema_version": MANIFEST_SCHEMA, "record_schema_version": RECORD_SCHEMA,
                "canonicalization_version": CANONICALIZATION_VERSION,
                "protocol_version": PROTOCOL_VERSION, "observation_scope": OBSERVATION_SCOPE,
                "mode": EXECUTION_PROFILE["mode"], "execution_profile": deepcopy(EXECUTION_PROFILE),
                "run_id": inventory["run_id"], **association,
                "run_challenge": inventory["run_challenge"],
                "expected_inventory_digest": inventory_digest(inventory),
                "configuration": deepcopy(config)}
    validate_live_manifest(manifest, inventory)
    return manifest


def validate_live_manifest(manifest, inventory):
    """Validate against external inventory and installed contract-only config."""
    validate_inventory(inventory)
    _require(type(manifest) is dict and set(manifest) == MANIFEST_KEYS,
             "Invalid live manifest fields")
    _encode_live(manifest)
    _require(type(manifest["configuration"]) is dict and
             (manifest["schema_version"], manifest["record_schema_version"],
              manifest["configuration"].get("schema_version")) ==
             (MANIFEST_SCHEMA, RECORD_SCHEMA, CONFIGURATION_SCHEMA),
             "Mixed live profile versions")
    _require(manifest["canonicalization_version"] == CANONICALIZATION_VERSION and
             manifest["protocol_version"] == PROTOCOL_VERSION and
             manifest["observation_scope"] == OBSERVATION_SCOPE,
             "Unsupported live manifest scope or versions")
    _require(all(type(manifest[k]) is str and bool(manifest[k]) for k in IDENTITY_KEYS),
             "Invalid live manifest identity")
    _require(is_digest(manifest["run_challenge"]) and
             is_digest(manifest["expected_inventory_digest"]),
             "Invalid live challenge or inventory digest")
    validate_live_configuration(manifest["configuration"])
    _require(manifest["mode"] == EXECUTION_PROFILE["mode"] and
             manifest["execution_profile"] == EXECUTION_PROFILE and
             manifest["execution_profile"] == manifest["configuration"]["controller_profile"],
             "Live execution profile mismatch")
    _require(manifest["run_id"] == inventory["run_id"] and
             manifest["run_challenge"] == inventory["run_challenge"] and
             manifest["expected_inventory_digest"] == inventory_digest(inventory) and
             {k: manifest[k] for k in IDENTITY_KEYS[1:]} in inventory["sessions"],
             "Live manifest differs from expected inventory")
