"""Fixed synthetic M6 workflow using the public host and MCP stream interfaces.

No browser-provided controls, grants, destinations or arguments enter this file.
The assessor creates expectations and signer pins before the live task opens.
"""

from contextlib import closing
import json
import os
from pathlib import Path
import secrets
from threading import Thread
from uuid import uuid4


class StreamClient:
    """One serialized MCP stream; all frames enter HostTask.serve_client."""

    def __init__(self, task):
        client_read, host_write = os.pipe()
        host_read, client_write = os.pipe()
        self.reader = os.fdopen(client_read, "rb")
        self.writer = os.fdopen(client_write, "wb")
        host_input = os.fdopen(host_read, "rb")
        host_output = os.fdopen(host_write, "wb")

        def serve():
            with host_input, host_output:
                task.serve_client(host_input, host_output)

        self.thread = Thread(target=serve, name="frontend-m6-client", daemon=True)
        self.thread.start()

    def exchange(self, request):
        self.writer.write(json.dumps(request, ensure_ascii=True).encode() + b"\n")
        self.writer.flush()
        response = json.loads(self.reader.readline(128 * 1024 + 1))
        if response.get("id") != request["id"]:
            raise RuntimeError("Live response correlation failed")
        return response

    def close(self):
        if self.writer.closed:
            return
        self.writer.close()  # EOF drains the public stream and closes the task.
        self.thread.join(timeout=20)
        self.reader.close()
        if self.thread.is_alive():
            raise RuntimeError("Live client failed to close")


def execute(directory):
    from frontend_api.runtime_context import REVISION_ENV, checkout_revision
    # Provisioned by trusted local host code, never by scenario/browser input.
    os.environ[REVISION_ENV] = checkout_revision()
    from cryptography.hazmat.primitives.asymmetric import ec

    from chainguard import PROTOCOL_VERSION
    from chainguard.acceptance import AcceptanceRegistry
    from chainguard.canonical import decode
    from chainguard.evidence import INVENTORY_SCHEMA, ROOT, SUITE
    from chainguard.m6_live_profile import PROFILE_VERSIONS, live_configuration
    from chainguard.m6_live_runtime import M6Host
    from chainguard.m6_live_verifier import inspect_live_run
    from chainguard.semantics import Scope

    directory = Path(directory).resolve()
    if directory.is_relative_to(ROOT):
        raise ValueError("Live demo artifacts must stay outside the repository")
    identity = {name: str(uuid4()) for name in ("task_id", "session_id", "monitor_instance_id")}
    inventory = {"schema_version": INVENTORY_SCHEMA, "run_id": str(uuid4()),
                 "run_challenge": secrets.token_hex(32), "sessions": [identity]}
    config = live_configuration()
    key_id = "frontend-synthetic-live-signer"
    key = ec.generate_private_key(ec.SECP256R1())
    pins = {key_id: key.public_key()}
    registry_path = directory / "acceptance.sqlite"

    # Durably register and read back the exact assessor-owned expectations before
    # opening the task. This is the existing Gate 4 contract, not a new bypass.
    with closing(AcceptanceRegistry.create(registry_path)) as registry:
        registered = registry.register(inventory, config, pins)
    with closing(AcceptanceRegistry(registry_path)) as registry:
        if registry.expected(inventory["run_id"]) != registered:
            raise RuntimeError("Expected-run registration readback failed")

    requests, responses, controls = [], [], []
    meta = {"io.modelcontextprotocol/protocolVersion": PROTOCOL_VERSION,
            "io.modelcontextprotocol/clientCapabilities": {}}
    witness_dir = directory / "witness"
    task = M6Host().open_task(db_path=directory / "audit.sqlite", trusted_inventory=inventory,
                             witness_dir=witness_dir, **identity)
    with closing(StreamClient(task)) as client:
        def exchange(request_id, method, **params):
            request = {"jsonrpc": "2.0", "id": request_id, "method": method,
                       "params": {"_meta": meta, **params}}
            requests.append(request)
            response = client.exchange(request)
            responses.append(response)
            return response

        def call(request_id, tool, arguments, *, denied=False, failed=False):
            response = exchange(request_id, "tools/call", name=tool, arguments=arguments)
            if denied:
                if response.get("error", {}).get("code") != -32003:
                    raise RuntimeError("Expected live policy denial did not occur")
            elif "result" not in response or response["result"].get("isError", False) is not failed:
                raise RuntimeError("Unexpected live tool outcome")
            return response

        exchange("discovery", "server/discover")
        exchange("tools", "tools/list")
        call("read", "read_secret_a", {})
        payload = {"payload": "SYNTHETIC_CANARY_A"}
        call("denied-before-grant", "send_sink", payload, denied=True)
        scope = Scope(identity["task_id"], "secret-a", "sink")

        def grant(grant_id):
            task.grant(grant_id, scope).result(timeout=15)
            controls.append({"kind": "GRANT", "grant_id": grant_id,
                             "scope": {"task_id": scope.task_id, "resource": scope.resource,
                                       "destination": scope.destination, "release": scope.release},
                             "status": "committed"})

        grant("demo-grant-1")
        call("allowed-once", "send_sink", payload)
        call("denied-consumed", "send_sink", payload, denied=True)
        grant("demo-grant-2")
        task.revoke(scope).result(timeout=15)
        controls.append({"kind": "REVOKE_SCOPE", "status": "committed",
                         "scope": {"task_id": scope.task_id, "resource": scope.resource,
                                   "destination": scope.destination, "release": scope.release}})
        call("denied-revoked", "send_sink", payload, denied=True)
        grant("demo-grant-3")
        call("allowed-new-grant", "send_sink", payload)
        call("tool-error", "controlled_failure", {"token": "m6-demo-failure"}, failed=True)

    # Stream EOF has closed the task and stopped its downstream tool process.
    task.shutdown().result(timeout=15)
    package_bytes = task.export_live_evidence(expected_inventory=inventory,
        expected_configuration=config, private_key=key, signer_key_id=key_id,
        pinned_public_keys=pins, output_path=directory / "evidence.json")
    verification = inspect_live_run([package_bytes], expected_inventory=inventory,
        expected_configuration=config, trusted_signer_key_id=key_id,
        pinned_public_key=pins[key_id], accepted_versions=PROFILE_VERSIONS, accepted_suite=SUITE)
    if not verification["inspection_passed"]:
        raise RuntimeError("Live offline inspection failed")
    with closing(AcceptanceRegistry(registry_path)) as registry:
        acceptance = registry.submit(inventory["run_id"], [package_bytes])
    with closing(AcceptanceRegistry(registry_path)) as registry:
        duplicate = registry.submit(inventory["run_id"], [package_bytes])
    if acceptance["status"] != "ACCEPTED" or duplicate["reason"] != "ALREADY_ACCEPTED":
        raise RuntimeError("Live acceptance demonstration did not meet its contract")

    package = decode(package_bytes)
    # Only a bounded synthetic scenario reaches these files. Keep transport
    # frames/payload copies out of the web report; preserve observed metadata.
    omitted = {"raw_base64", "raw_sha256", "payload_base64", "payload_sha256", "wire_sha256"}
    def observations(name):
        return [{key: value for key, value in json.loads(line).items() if key not in omitted}
                for line in (witness_dir / name).read_text().splitlines()]

    return {"report": {
        "milestone": "M6.4", "protocol_version": PROTOCOL_VERSION,
        "record_count": len(package["records"]), "final_head": package["commitment"]["final_head"],
        "assessor_journal": {"issued_requests": requests, "responses": responses,
                             "host_controls": controls, "runtime_observations": list(task.child_events)},
        "registration": {"status": "COMMITTED", "read_back_before_task_open": True},
        "duplicate_submission": duplicate,
        "observations": {"host": observations("host.jsonl"), "child": observations("child.jsonl"),
                         "basis": "Assessor-held local observations, separate from signed audit; not proof against a dishonest host.",
                         "external_sink_capture": False},
        "limits": ["Synthetic local sink only; no external release.",
                   "Acceptance registry is a temporary demo fixture, deleted after this run.",
                   "Offline inspection reproduces recorded facts; it does not prove observation truth."]},
        "evidence": {"package": package, "verification": verification, "acceptance": acceptance}}
