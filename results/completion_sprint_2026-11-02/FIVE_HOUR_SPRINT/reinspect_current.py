"""Fresh-process offline reinspection of current-source M6Q package."""

import json
import os
from pathlib import Path

from cryptography.hazmat.primitives.serialization import load_pem_public_key

from chainguard.evidence import SUITE
from chainguard.m6_live_profile import PROFILE_VERSIONS, REVISION_ENV
from chainguard.m6_live_verifier import inspect_live_package

OUT = Path(__file__).resolve().parent / "live_m6_current"


def main():
    context = json.loads((OUT / "assessor_context.json").read_text(encoding="utf-8"))
    pin = os.environ.get("CHAINGUARD_ASSESSOR_REVISION_PIN")
    if pin != context["revision_pin"] or os.environ.get(REVISION_ENV) != pin:
        raise RuntimeError("Assessor and runtime revision pins differ")
    inventory = json.loads((OUT / "assessor_inventory.json").read_text(encoding="utf-8"))
    key = load_pem_public_key((OUT / "assessor_public_key.pem").read_bytes())
    package = (OUT / "signed_package.json").read_bytes()
    report = inspect_live_package(package, expected_inventory=inventory,
        expected_configuration=context["configuration"],
        trusted_signer_key_id="five-hour-ephemeral-assessor",
        pinned_public_key=key, accepted_versions=PROFILE_VERSIONS,
        accepted_suite=SUITE)
    path = OUT / "fresh_process_reinspection.json"
    with path.open("x", encoding="utf-8") as stream:
        json.dump(report, stream, indent=2)
        stream.write("\n")
    print(f"inspection_passed={report['inspection_passed']}")
    return 0 if report["inspection_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
