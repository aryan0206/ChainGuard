"""Fresh-process durable acceptance of a preregistered complete M6Q run."""

import json
import os
from pathlib import Path

from chainguard.acceptance import AcceptanceRegistry
from chainguard.m6_live_profile import REVISION_ENV

OUT = Path(__file__).resolve().parent / "live_m6_current"


def save(name, value):
    with (OUT / name).open("x", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2)
        stream.write("\n")


def main():
    context = json.loads((OUT / "assessor_context.json").read_text(encoding="utf-8"))
    pin = os.environ.get("CHAINGUARD_ASSESSOR_REVISION_PIN")
    if pin != context["revision_pin"] or os.environ.get(REVISION_ENV) != pin:
        raise RuntimeError("Assessor and runtime revision pins differ")
    inventory = json.loads((OUT / "assessor_inventory.json").read_text(encoding="utf-8"))
    package = (OUT / "signed_package.json").read_bytes()
    registry_path = OUT / "acceptance_registry.sqlite"
    registry = AcceptanceRegistry(registry_path)
    try:
        before = registry.expected(inventory["run_id"])
        if before is None or before.state != "ACTIVE":
            raise RuntimeError("Pre-execution expectation was not ACTIVE")
        result = registry.submit(inventory["run_id"], [package])
    finally:
        registry.close()
    save("fresh_submission.json", {"pre_submission_state": before.state, "result": result})
    registry = AcceptanceRegistry(registry_path)
    try:
        after = registry.expected(inventory["run_id"])
        duplicate = registry.submit(inventory["run_id"], [package]) if after and after.state == "ACCEPTED" else None
    finally:
        registry.close()
    save("fresh_submission_readback.json", {
        "post_restart_state": after.state if after else None,
        "duplicate_after_restart": duplicate,
        "note": "Evidence replay rejection does not prevent replay of tool execution"})
    passed = (result["status"] == "ACCEPTED" and result["registry_durability"] == "COMMITTED"
              and after is not None and after.state == "ACCEPTED" and duplicate is not None
              and duplicate["status"] == "REJECTED" and duplicate["reason"] == "ALREADY_ACCEPTED")
    print(f"fresh_submission={result['status']} readback={after.state if after else None} duplicate={duplicate['reason'] if duplicate else None}")
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
