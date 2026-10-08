"""Local M5 expectation administration, frozen submission and controlled campaign."""

import argparse
import io
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
import unittest
from tempfile import TemporaryDirectory
from time import perf_counter

from chainguard.acceptance import AcceptanceRegistry, RegistryError, _result
from chainguard.canonical import decode
from chainguard.evidence import ROOT, load_public
from chainguard.m4 import KEY_ID, execute_demo


def submit_process(registry, run_id, paths):
    command = [sys.executable, "-B", "-m", "chainguard.m5", "accept", "--registry", str(registry), "--run-id", run_id]
    for path in paths:
        command.extend(["--package", str(path)])
    process = subprocess.run(command, cwd=ROOT, capture_output=True, timeout=60)
    report = json.loads(process.stdout)
    if process.returncode != (0 if report["status"] == "ACCEPTED" else 2):
        raise RuntimeError("Acceptance process/report mismatch")
    return report


def campaign(directory):
    """Real singleton M4 execution plus explicitly synthetic mutation fixtures."""
    from cryptography.hazmat.primitives.asymmetric import ec
    from tests.m5_fixtures import attacks, context, packages
    from chainguard.evidence import configuration

    directory = Path(directory).resolve()
    if directory.is_relative_to(ROOT):
        raise ValueError("Campaign artifacts/private key must be outside repository")
    directory.mkdir(parents=True, exist_ok=True)
    registry_path = directory / "acceptance.sqlite"
    registry = AcceptanceRegistry.create(registry_path)
    try:
        live = execute_demo(directory / "live", register_expected=registry.register)
        inventory = decode((directory / "live" / "expected.json").read_bytes())
    finally:
        registry.close()
    started = perf_counter()
    accepted = submit_process(registry_path, inventory["run_id"], [directory / "live" / "evidence.json"])
    duplicate = submit_process(registry_path, inventory["run_id"], [directory / "live" / "evidence.json"])
    results = []
    fixture_dir = directory / "synthetic"
    fixture_dir.mkdir()
    inv, config, key = context(), configuration(), ec.generate_private_key(ec.SECP256R1())
    data = packages(fixture_dir, inv, config, key)[0]
    for index, case in enumerate(attacks(data, key)):
        reg = AcceptanceRegistry.create(fixture_dir / (str(index) + ".sqlite"))
        try:
            reg.register(inv, config, {KEY_ID: key.public_key()})
            result = reg.submit(inv["run_id"], [case.data])
            results.append({"case": case.name, "expected": case.expected, "actual": result["status"],
                            "passed": result["status"] == case.expected})
        finally:
            reg.close()
    # Consolidated original matrix cases 28/29/35/36: run actual existing M4
    # lifecycle and forwarding experiments, rather than duplicate their assertions.
    operational_cases = (
        "test_sealing_reconciles_fixed_snapshot_against_trusted_head",
        "test_intent_with_unknown_outcome_cannot_seal",
        "test_required_m4_persistence_failure_blocks_real_forwarding",
        "test_ambiguous_m4_commit_blocks_real_forwarding",
        "test_export_failure_is_incomplete_and_not_retried",
        "test_no_append_after_close_and_no_permission_bearing_intents",
    )
    acceptance_cases = (
        "test_old_valid_evidence_against_new_context_rejected",
        "test_wrong_external_pin_rejected",
        "test_duplicate_signature_bytes_do_not_define_identity",
        "test_cancelled_and_failed_terminal_contexts_survive_restart",
        "test_missing_and_unreadable_registry_never_created_implicitly",
        "test_ambiguous_committed_ack_never_reports_acceptance_then_retry_reconciles",
        "test_ambiguous_uncommitted_ack_explicit_retry_can_accept",
        "test_concurrent_processes_accept_exactly_once",
    )
    names = (["tests.test_m4.M4Tests." + name for name in operational_cases]
             + ["tests.test_m5.AcceptanceTests." + name for name in acceptance_cases]
             + ["tests.test_m5.WholeRunTests.test_multi_session_full_inventory_atomic_acceptance_and_singleton_unchanged",
                "tests.test_m5.WholeRunTests.test_multi_session_failed_write_rolls_back_all_commitments"])
    suite = unittest.defaultTestLoader.loadTestsFromNames(names)
    output = io.StringIO()
    operational = unittest.TextTestRunner(stream=output, verbosity=2).run(suite)
    passed = (accepted["status"] == "ACCEPTED" and duplicate["reason"] == "ALREADY_ACCEPTED"
              and all(r["passed"] for r in results) and operational.wasSuccessful())
    return {"milestone": "M5", "live_M4": live, "fresh_acceptance": accepted,
        "duplicate_after_process_restart": duplicate, "synthetic_campaign": results,
        "operational_campaign": {"cases": names, "tests_run": operational.testsRun,
                                 "passed": operational.wasSuccessful(), "output": output.getvalue()},
        "false_acceptances": sum(r["actual"] == "ACCEPTED" and r["expected"] != "ACCEPTED" for r in results),
        "false_rejections": sum(r["actual"] != "ACCEPTED" and r["expected"] == "ACCEPTED" for r in results),
        "elapsed_seconds": round(perf_counter() - started, 3), "passed": passed}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("init", "register", "accept", "terminate"):
        command = commands.add_parser(name)
        command.add_argument("--registry", type=Path, required=True)
        if name in {"accept", "terminate"}:
            command.add_argument("--run-id", required=True)
        if name == "accept":
            command.add_argument("--package", type=Path, action="append", required=True)
        elif name == "register":
            for field in ("expected", "config", "public-key"):
                command.add_argument("--" + field, type=Path, required=True)
            command.add_argument("--key-id", required=True)
        elif name == "terminate":
            command.add_argument("--state", choices=("CANCELLED", "FAILED"), required=True)
    demo = commands.add_parser("campaign")
    demo.add_argument("--directory", type=Path)
    args = parser.parse_args()
    registry = None
    try:
        if args.command == "campaign":
            if args.directory:
                report = campaign(args.directory)
            else:
                with TemporaryDirectory(prefix="chainguard-m5-") as directory:
                    report = campaign(directory)
            code = 0 if report["passed"] else 2
        else:
            registry = AcceptanceRegistry.create(args.registry) if args.command == "init" else AcceptanceRegistry(args.registry)
            if args.command == "accept":
                # One read per input; subsequent verification/persistence use these bytes.
                snapshots = tuple(path.read_bytes() for path in args.package)
                report = registry.submit(args.run_id, snapshots)
                code = 0 if report["status"] == "ACCEPTED" else 2
            elif args.command == "register":
                expected = registry.register(decode(args.expected.read_bytes()), decode(args.config.read_bytes()),
                                             {args.key_id: load_public(args.public_key)})
                report, code = {"registered": True, "identity": expected.identity, "state": expected.state}, 0
            elif args.command == "terminate":
                registry.terminate(args.run_id, args.state)
                report, code = {"state": args.state}, 0
            else:
                report, code = {"initialized": True}, 0
    except (OSError, sqlite3.Error, RegistryError, ValueError, TypeError) as exc:
        report, code = _result("NOT_CHECKED", "UNAVAILABLE: " + str(exc)), 2
    finally:
        if registry is not None:
            registry.close()
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
