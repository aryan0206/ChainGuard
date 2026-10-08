"""Declared attack labels, independent of verifier/detector verdicts.

Multi-session packages are synthetic, independently signed M4-format fixtures;
they are not produced by a new live exporter. Private keys exist only in memory.
"""

from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path
import secrets
from uuid import uuid4

from cryptography.hazmat.primitives.asymmetric import ec

from chainguard.audit import LiveAudit
from chainguard.canonical import decode, encode
from chainguard.evidence import (ChainedAuditSession, INVENTORY_SCHEMA, PACKAGE_FORMAT,
    event_hash, genesis, make_commitment, make_manifest,
    recompute_chain, sign_commitment, validate_structure)
from chainguard.m3 import shadows
from chainguard.m4 import KEY_ID


def context(count=1):
    return {"schema_version": INVENTORY_SCHEMA, "run_id": str(uuid4()),
        "run_challenge": secrets.token_hex(32), "sessions": sorted([
            {"task_id": str(uuid4()), "session_id": str(uuid4()), "monitor_instance_id": str(uuid4())}
            for _ in range(count)], key=lambda e: (e["task_id"], e["session_id"], e["monitor_instance_id"]))}


def packages(directory, inventory, config, key):
    result = []
    for entry in inventory["sessions"]:
        manifest = make_manifest(inventory, config, **entry)
        session = ChainedAuditSession(Path(directory) / (entry["session_id"] + ".sqlite"), manifest, inventory)
        try:
            gate = LiveAudit(session, shadows)
            request = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {
                "name": "echo", "arguments": {"token": "m5-public-fixture"}, "_meta": {
                "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                "io.modelcontextprotocol/clientCapabilities": {}}}}
            gate.after(gate.before(request), {"result": {"isError": False,
                "content": [{"type": "text", "text": "m5-public-fixture"}]}})
            if len(inventory["sessions"]) == 1:
                result.append(session.seal(key, KEY_ID, {KEY_ID: key.public_key()}))
            else:
                session.finish()
                entries = session._snapshot()
                validate_structure(manifest, entries, require_closed=True)
                head = recompute_chain(manifest, entries)
                assert head == session.state.cryptographic_head and len(entries) == session.state.count
                closure = make_commitment(manifest, len(entries), head, KEY_ID)
                result.append(encode({"format_version": PACKAGE_FORMAT, "manifest": manifest,
                    "records": entries, "commitment": closure, "signature": sign_commitment(key, closure)}))
        finally:
            session.close()
    return tuple(result)


def rechain(package, key=None):
    head = genesis(package["manifest"])
    for entry in package["records"]:
        entry["event"]["prev_hash"] = head
        head = event_hash(entry["event"])
        entry["event_hash"] = head
    package["commitment"] = make_commitment(package["manifest"], len(package["records"]), head, KEY_ID)
    if key is not None:
        package["signature"] = sign_commitment(key, package["commitment"])


@dataclass(frozen=True)
class Case:
    name: str
    data: bytes
    expected: str


def attacks(data, key):
    """Labels describe eligibility of transformations, not outputs of inspection."""
    original = decode(data)
    cases = [Case("valid-fresh-sealed", data, "ACCEPTED")]
    def add(name, change, expected="REJECTED", rebuild=False, signer=None):
        package = deepcopy(original)
        change(package)
        if rebuild:
            rechain(package, signer)
        cases.append(Case(name, encode(package), expected))
    for field in ("task_id", "run_id", "session_id", "monitor_instance_id", "run_challenge", "expected_inventory_digest"):
        add("wrong-" + field, lambda p, f=field: p["manifest"].__setitem__(f, "cd" * 32 if f in {
            "run_challenge", "expected_inventory_digest"} else "wrong-identity"))
    add("wrong-configuration-digest", lambda p: p["manifest"]["configuration"]["normalizer"].__setitem__("digest", "cd" * 32))
    add("record-mutation", lambda p: p["records"][0]["event"].__setitem__("observed_at_utc", "2026-10-09T00:00:00.000000Z"))
    add("manifest-mutation", lambda p: p["manifest"].__setitem__("observation_scope", "wrong"))
    add("closure-mutation", lambda p: p["commitment"].__setitem__("final_head", "cd" * 32))
    add("signature-mutation", lambda p: p.__setitem__("signature", "AAAA"))
    add("unknown-signer", lambda p: p["commitment"].__setitem__("signer_key_id", "attacker"))
    add("recomputed-old-signature", lambda p: p["records"][0]["event"].__setitem__("observed_at_utc", "2026-10-09T00:00:00.000000Z"), rebuild=True)
    stranger = ec.generate_private_key(ec.SECP256R1())
    add("recomputed-untrusted-signature", lambda p: p["records"][0]["event"].__setitem__("observed_at_utc", "2026-10-09T00:00:00.000000Z"), rebuild=True, signer=stranger)
    # The original signed count/head also fails: FAIL takes precedence over INCOMPLETE.
    add("truncated-final-record", lambda p: p["records"].pop())
    add("missing-closure", lambda p: p.__setitem__("commitment", None), "INCOMPLETE")
    add("missing-signature", lambda p: p.__setitem__("signature", None), "INCOMPLETE")
    add("missing-required-record", lambda p: p["records"].pop(3))
    add("insert-record", lambda p: p["records"].insert(3, deepcopy(p["records"][3])))
    add("reorder-records", lambda p: p["records"].reverse())
    add("alter-sequence", lambda p: p["records"][1]["event"].__setitem__("seq", 99))
    add("alter-predecessor", lambda p: p["records"][1]["event"].__setitem__("prev_hash", "cd" * 32))
    add("alter-event-hash", lambda p: p["records"][1].__setitem__("event_hash", "cd" * 32))
    add("incomplete-export", lambda p: p.__setitem__("records", []), "INCOMPLETE")
    add("unknown-format", lambda p: p.__setitem__("format_version", "unknown"))
    add("unknown-record-schema", lambda p: p["records"][0]["event"].__setitem__("schema_version", "unknown"))
    add("malformed-association", lambda p: p["manifest"].__setitem__("task_id", []))
    def false_finding(package):
        next(r["event"]["body"] for r in package["records"] if r["event"]["event_type"] == "DETECTOR_FINDING")["explanation"] = "authentic but incorrect finding"
    add("trusted-signed-incorrect-finding", false_finding, rebuild=True, signer=key)
    cases.extend([Case("noncanonical", b" " + data, "REJECTED"), Case("malformed-json", b"{", "REJECTED"),
                  Case("deeply-nested-json", b"[" * 2000 + b"0" + b"]" * 2000, "REJECTED")])
    return tuple(cases)
