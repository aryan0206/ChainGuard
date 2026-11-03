"""Bounded A3 engineering mutation ledger; seven-variant E09 remains unexecuted."""

from copy import deepcopy
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path

from cryptography.hazmat.primitives.serialization import load_pem_public_key

from chainguard.canonical import decode, encode
from chainguard.evidence import SUITE
from chainguard.m6_live_profile import PROFILE_VERSIONS
from chainguard.m6_live_verifier import inspect_live_package

HERE = Path(__file__).resolve().parent
SOURCE = HERE / "live_m6_current"
PLAN = HERE / "e09_variant_and_mutation_plan.json"
OUT = HERE / ("e09_mutants_revision" if os.environ.get("CHAINGUARD_ASSESSOR_REVISION_PIN") else "e09_mutants")


def digest(data):
    return hashlib.sha256(data).hexdigest()


def main():
    if OUT.exists():
        raise FileExistsError(OUT)
    OUT.mkdir()
    plan_bytes = PLAN.read_bytes()
    plan = json.loads(plan_bytes)
    context = json.loads((SOURCE / "assessor_context.json").read_text(encoding="utf-8"))
    inventory = json.loads((SOURCE / "assessor_inventory.json").read_text(encoding="utf-8"))
    public_key = load_pem_public_key((SOURCE / "assessor_public_key.pem").read_bytes())
    original = (SOURCE / "signed_package.json").read_bytes()
    cases = []
    for spec in plan["current_a3_development_subset"]:
        name = spec["mutation"]
        raw = original
        expected_config = deepcopy(context["configuration"])
        if name == "noncanonical-trailing-byte":
            raw = original + b" "
        elif name == "edit-first-event-sequence":
            package = decode(original)
            package["records"][0]["event"]["seq"] = 2
            raw = encode(package)
        elif name == "delete-last-record":
            package = decode(original)
            package["records"].pop()
            raw = encode(package)
        elif name == "wrong-assessor-configuration":
            expected_config["policy"]["max_payload_bytes"] += 1
        elif name != "none":
            raise ValueError(f"Unknown frozen mutation {name}")
        path = OUT / (spec["case_id"] + ".package.bin")
        path.write_bytes(raw)
        config_file = None
        if name == "wrong-assessor-configuration":
            config_file = spec["case_id"] + ".expected_config.json"
            (OUT / config_file).write_bytes(encode(expected_config))
        report = inspect_live_package(raw, expected_inventory=inventory,
            expected_configuration=expected_config,
            trusted_signer_key_id="five-hour-ephemeral-assessor",
            pinned_public_key=public_key, accepted_versions=PROFILE_VERSIONS,
            accepted_suite=SUITE)
        (OUT / (spec["case_id"] + ".verifier.json")).write_text(
            json.dumps(report, indent=2) + "\n", encoding="utf-8")
        observed = report["dimensions"][spec["expected"]["dimension"]]["status"]
        matches = report["inspection_passed"] == spec["expected"]["inspection_passed"] and observed == spec["expected"]["status"]
        cases.append({"case_id": spec["case_id"], "mutation": name,
                      "package_file": str(path.relative_to(HERE)), "package_sha256": digest(raw),
                      "expected_configuration_file": config_file,
                      "expected": spec["expected"],
                      "observed_dimension_status": observed,
                      "inspection_passed": report["inspection_passed"],
                      "predeclared_expectation_matched": matches})
    result = {"schema": "chainguard-e09-a3-development-mutations-v1",
              "classification": "ENGINEERING_DEVELOPMENT_ONLY; NOT SEVEN_VARIANT_E09_RESEARCH",
              "source_package_sha256": digest(original),
              "source_revision_pin": context["revision_pin"],
              "plan_sha256": digest(plan_bytes),
              "ended_local": datetime.now().astimezone().isoformat(),
              "cases": cases,
              "matched_expectations": sum(c["predeclared_expectation_matched"] for c in cases),
              "case_count": len(cases)}
    (OUT / "mutation_results.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(f"matched_expectations={result['matched_expectations']}/{result['case_count']} research_cells=0")
    return 0 if result["matched_expectations"] == result["case_count"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
