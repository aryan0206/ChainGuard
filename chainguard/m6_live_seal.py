"""Host-side M6 live sealing from a reconciled, trusted clean-close snapshot.

This local self-check is not an independent evidence verifier or acceptance.
The caller must supply independently trusted inventory, configuration, and
public-key pins; none may be learned from the package being produced.
"""

import base64
import os
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from chainguard.canonical import CANONICALIZATION_VERSION, encode
from chainguard.evidence import (IDENTITY_KEYS, SIGNATURE_ENCODING, SUITE,
                                 _p256, manifest_digest)
from chainguard.m6_live_evidence import (live_commitment_signing_input,
    validate_live_commitment, validate_live_package_structure)
from chainguard.m6_live_profile import COMMITMENT_SCHEMA, PACKAGE_FORMAT
from chainguard.permission_evidence import RECORD_SCHEMA


def _require(condition, message):
    if not condition:
        raise ValueError(message)


def make_live_commitment(manifest, count, head, signer_key_id):
    """Bind trusted writer continuity and the exact live manifest."""
    closure = {"schema_version": COMMITMENT_SCHEMA,
               "record_schema_version": RECORD_SCHEMA,
               "canonicalization_version": CANONICALIZATION_VERSION,
               **{key: manifest[key] for key in IDENTITY_KEYS},
               "run_challenge": manifest["run_challenge"],
               "expected_inventory_digest": manifest["expected_inventory_digest"],
               "manifest_digest": manifest_digest(manifest),
               "record_count": count, "final_seq": count, "final_head": head,
               "closure_status": "CLOSED", "hash_algorithm": "SHA256",
               "signature_suite": SUITE, "signature_encoding": SIGNATURE_ENCODING,
               "signer_key_id": signer_key_id}
    validate_live_commitment(closure)
    return closure


def sign_live_commitment(private_key, closure):
    """Use the approved P-256 library convention on live-domain signing bytes."""
    _p256(private_key, private=True)
    signature = private_key.sign(live_commitment_signing_input(closure),
                                 ec.ECDSA(hashes.SHA256()))
    return base64.b64encode(signature).decode("ascii")


def verify_live_signature(public_key, closure, signature):
    """Local signature self-check only; no chain or lifecycle verification."""
    _p256(public_key)
    _require(type(signature) is str, "Invalid live signature text")
    raw = base64.b64decode(signature, validate=True)
    _require(base64.b64encode(raw).decode("ascii") == signature,
             "Noncanonical live signature")
    public_key.verify(raw, live_commitment_signing_input(closure),
                      ec.ECDSA(hashes.SHA256()))


def _seal_live_snapshot(manifest, entries, frozen, *, private_key, signer_key_id,
                        pinned_public_keys, output_path):
    """Sign and persist only the already reconciled snapshot, once."""
    _require(type(pinned_public_keys) is dict and
             type(signer_key_id) is str and signer_key_id in pinned_public_keys,
             "Missing externally pinned live signer")
    closure = make_live_commitment(manifest, frozen.record_count,
                                   frozen.final_head, signer_key_id)
    signature = sign_live_commitment(private_key, closure)
    package = encode({"format_version": PACKAGE_FORMAT, "manifest": manifest,
                      "records": entries, "commitment": closure,
                      "signature": signature})
    inspected = validate_live_package_structure(package)
    _require(inspected["commitment"] == closure and
             inspected["records"] == entries and inspected["manifest"] == manifest,
             "Live package self-inspection mismatch")
    verify_live_signature(pinned_public_keys[signer_key_id], closure, signature)

    path = Path(output_path)
    created = False
    try:
        with path.open("xb") as stream:
            created = True
            stream.write(package)
            stream.flush()
            os.fsync(stream.fileno())
        _require(path.read_bytes() == package, "Live export readback differs")
    except Exception:
        if created:
            try:
                path.unlink()
            except OSError:
                pass
        raise
    return package
