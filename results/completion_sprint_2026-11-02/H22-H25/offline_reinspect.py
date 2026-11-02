"""Reinspect the final M6 package in a fresh process with assessor pins."""

import json
import os
from pathlib import Path

from cryptography.hazmat.primitives.serialization import load_pem_public_key

from chainguard.evidence import SUITE
from chainguard.m6_live_profile import PROFILE_VERSIONS, REVISION_ENV
from chainguard.m6_live_verifier import inspect_live_package


ROOT = Path(__file__).resolve().parent / "live_m6_sink_final"
context = json.loads((ROOT / "assessor_context.json").read_text(encoding="utf-8"))
if os.environ.get(REVISION_ENV) != context["revision_pin"]:
    raise RuntimeError("Independent revision pin mismatch")
inventory = json.loads((ROOT / "assessor_inventory.json").read_text(encoding="utf-8"))
public_key = load_pem_public_key((ROOT / "assessor_public_key.pem").read_bytes())
package = (ROOT / "signed_package.json").read_bytes()
report = inspect_live_package(package, expected_inventory=inventory,
    expected_configuration=context["configuration"],
    trusted_signer_key_id="h22-h25-ephemeral-assessor",
    pinned_public_key=public_key, accepted_versions=PROFILE_VERSIONS,
    accepted_suite=SUITE)
(ROOT / "offline_reinspection.json").write_text(json.dumps(report, indent=2) + "\n",
                                                 encoding="utf-8")
raise SystemExit(0 if report["inspection_passed"] else 1)
