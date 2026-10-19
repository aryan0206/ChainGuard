"""Installed M6 live profile validation, independent of package acceptance."""

from copy import deepcopy
import unittest
from unittest.mock import patch

from chainguard.canonical import encode
from chainguard.evidence import INVENTORY_SCHEMA, ROOT, sha256
from chainguard.m6_live_profile import (ARTIFACT_NAMES, CONFIGURATION_SCHEMA,
    MANIFEST_SCHEMA, PACKAGE_FORMAT, POLICY, PROFILE_VERSIONS, TOOL_CONTRACTS,
    input_schema, live_configuration, make_live_manifest, registry_definition,
    validate_live_configuration, validate_live_manifest, validate_profile_versions)
from chainguard.permission_evidence import RECORD_SCHEMA
from chainguard.permission_profile import PROFILE_VERSIONS as OFFLINE_VERSIONS


def inventory():
    association = {"task_id": "task-1", "session_id": "session-1",
                   "monitor_instance_id": "monitor-1"}
    return {"schema_version": INVENTORY_SCHEMA, "run_id": "run-1",
            "run_challenge": "ab" * 32, "sessions": [association]}


class LiveProfileTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.config = live_configuration()
        cls.expected = inventory()
        cls.manifest = make_live_manifest(cls.expected, cls.config,
                                          **cls.expected["sessions"][0])

    def test_exact_distinct_profile_versions_and_installed_binding(self):
        self.assertEqual(PROFILE_VERSIONS, ("m6-live-evidence-v1", "m6-live-manifest-v1",
            "m6-record-v1", "m6-live-commitment-v1", "m6-live-configuration-v1"))
        self.assertNotEqual(PROFILE_VERSIONS, OFFLINE_VERSIONS)
        self.assertEqual((PACKAGE_FORMAT, MANIFEST_SCHEMA, RECORD_SCHEMA,
                          CONFIGURATION_SCHEMA), (PROFILE_VERSIONS[0], PROFILE_VERSIONS[1],
                                                  PROFILE_VERSIONS[2], PROFILE_VERSIONS[4]))
        validate_profile_versions(PROFILE_VERSIONS)
        validate_live_configuration(self.config)
        validate_live_manifest(self.manifest, self.expected)
        self.assertEqual(self.config["implementation_stage"], "GATED_RUNTIME")
        for name in ("m6_controlled_server.py", "m6_live_audit.py",
                     "m6_live_authorization.py", "m6_live_evidence.py",
                     "m6_live_runtime.py", "m6_live_seal.py"):
            self.assertIn(name, ARTIFACT_NAMES)
            digest = next(row["digest"] for row in self.config["artifacts"]
                          if row["name"] == name)
            self.assertEqual(digest, sha256((ROOT / "chainguard" / name).read_bytes()))
            changed = deepcopy(self.config)
            changed["artifacts"] = [row for row in changed["artifacts"]
                                     if row["name"] != name]
            with self.assertRaises(ValueError):
                validate_live_configuration(changed)

    def test_mixed_and_wrong_type_profile_versions_fail(self):
        for versions in (OFFLINE_VERSIONS, tuple(PROFILE_VERSIONS[:-1]) + ("m6-configuration-v1",),
                         list(PROFILE_VERSIONS), None):
            with self.subTest(versions=versions), self.assertRaises(ValueError):
                validate_profile_versions(versions)

    def test_configuration_missing_extra_and_wrong_type_fields_fail(self):
        for mutate in (lambda x: x.pop("tool_registry"),
                       lambda x: x.update(extra=True),
                       lambda x: x.update(implementation_stage=1),
                       lambda x: x.update(artifacts={}),
                       lambda x: x.update(schema_version="m6-configuration-v1")):
            changed = deepcopy(self.config)
            mutate(changed)
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                validate_live_configuration(changed)
        with self.assertRaises(ValueError):
            validate_live_configuration([])

    def test_registry_and_artifact_tampering_fail_even_with_recomputed_digest(self):
        changed = deepcopy(self.config)
        changed["tool_registry"]["definition"]["tools"][-1]["destination"] = "other-sink"
        changed["tool_registry"]["digest"] = sha256(encode(
            changed["tool_registry"]["definition"]))
        with self.assertRaises(ValueError):
            validate_live_configuration(changed)
        changed = deepcopy(self.config)
        changed["artifacts"][0]["digest"] = "00" * 32
        with self.assertRaises(ValueError):
            validate_live_configuration(changed)
        self.assertEqual(self.config["tool_registry"]["definition"], registry_definition())

    def test_manifest_exact_fields_types_versions_and_external_inventory(self):
        for mutate in (lambda x: x.pop("configuration"),
                       lambda x: x.update(extra=True),
                       lambda x: x.update(record_schema_version="m5-record-v1"),
                       lambda x: x.update(schema_version="m6-manifest-v1"),
                       lambda x: x.update(task_id=1),
                       lambda x: x.update(execution_profile=[]),
                       lambda x: x.update(expected_inventory_digest="00" * 32),
                       lambda x: x["configuration"].update(controller_profile={})):
            changed = deepcopy(self.manifest)
            mutate(changed)
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                validate_live_manifest(changed, self.expected)
        with self.assertRaises(ValueError):
            validate_live_manifest([], self.expected)
        other = inventory()
        other["sessions"] = [{"task_id": "other", "session_id": "session-1",
                              "monitor_instance_id": "monitor-1"}]
        with self.assertRaises(ValueError):
            validate_live_manifest(self.manifest, other)

    def test_registry_binds_each_tool_to_fixed_semantics(self):
        expected = {"controlled_failure": ("echo", "", ""), "echo": ("echo", "", ""),
                    "read_public": ("read", "public", ""),
                    "read_secret_a": ("read", "secret-a", ""),
                    "read_secret_b": ("read", "secret-b", ""),
                    "send_sink": ("send", "", "sink"),
                    "send_other_sink": ("send", "", "other-sink")}
        self.assertEqual({name: (c.operation, c.resource, c.destination)
                          for name, c in TOOL_CONTRACTS.items()}, expected)
        self.assertEqual(self.config["tool_registry"]["definition"]["server"],
                         "chainguard-m6-synthetic")

    def test_every_result_field_and_security_field_affects_registry_digest(self):
        original = registry_definition()
        original_digest = sha256(encode(original))

        def changed_leaves(value):
            if type(value) is dict:
                for key, child in value.items():
                    for altered in changed_leaves(child):
                        copy = deepcopy(value)
                        copy[key] = altered
                        yield copy
            elif type(value) is list:
                for index, child in enumerate(value):
                    for altered in changed_leaves(child):
                        copy = deepcopy(value)
                        copy[index] = altered
                        yield copy
            elif type(value) is bool:
                yield not value
            elif type(value) is int:
                yield value + 1
            elif type(value) is str:
                yield value + "-changed"

        for index, tool in enumerate(original["tools"]):
            for field in ("name", "operation", "resource", "destination", "input_schema",
                          "result_contract"):
                for altered in changed_leaves(tool[field]):
                    changed = deepcopy(original)
                    changed["tools"][index][field] = altered
                    with self.subTest(tool=tool["name"], field=field):
                        self.assertNotEqual(sha256(encode(changed)), original_digest)

    def test_public_result_and_sink_acknowledgement_affect_registry_digest(self):
        original = sha256(encode(registry_definition()))
        with patch("chainguard.m6_live_profile.PUBLIC_RESULT", "different public text"):
            self.assertNotEqual(sha256(encode(registry_definition())), original)
        with patch("chainguard.m6_live_profile.SINK_ACK", "different acknowledgement"):
            self.assertNotEqual(sha256(encode(registry_definition())), original)

    def test_declared_utf8_byte_contract_and_empty_payload(self):
        schema = input_schema("send_sink")["properties"]["payload"]
        self.assertEqual(schema["minLength"], 1)
        self.assertEqual(schema["x-chainguard-maxUtf8Bytes"], POLICY.max_payload_bytes)
        self.assertEqual(schema["maxLength"], POLICY.max_payload_bytes)
        token = input_schema("echo")["properties"]["token"]
        self.assertEqual(token["maxLength"], 256)
        self.assertNotIn("x-chainguard-maxUtf8Bytes", token)

    def test_cycles_and_excessive_nesting_raise_value_error(self):
        cyclic = deepcopy(self.config)
        cyclic["artifacts"].append(cyclic["artifacts"])
        with self.assertRaises(ValueError):
            validate_live_configuration(cyclic)
        nested = []
        for _ in range(1200):
            nested = [nested]
        deep = deepcopy(self.config)
        deep["artifacts"].append(nested)
        with self.assertRaises(ValueError):
            validate_live_configuration(deep)
        manifest = deepcopy(self.manifest)
        manifest["configuration"]["artifacts"].append(
            manifest["configuration"]["artifacts"])
        with self.assertRaises(ValueError):
            validate_live_manifest(manifest, self.expected)


if __name__ == "__main__":
    unittest.main()
