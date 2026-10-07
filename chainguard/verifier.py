"""Repeatable M4 offline inspection. Durable fresh submission remains M5.

Only external expectations, approved installed code/configuration and pinned
public keys are trust inputs. Inspection never executes or reconnects tools.
"""

import argparse
from dataclasses import replace
import json
from pathlib import Path

from chainguard.audit import _facts, _require
from chainguard.canonical import decode, encode
from chainguard.detectors import B2Reference, B2Streaming, b0, b1, equivalent
from chainguard.evidence import (DETECTOR_IDS, IDENTITY_KEYS, PACKAGE_FORMAT, IncompleteEvidence,
    check_commitment, configuration, inventory_digest, load_public, validate_commitment,
    validate_inventory, validate_structure, verify_signature)
from chainguard.semantics import Current, Policy, attach_references, project_b1


DIMENSIONS = ("schema_lifecycle", "commitment_integrity", "trusted_signature", "expected_binding",
              "inventory_completeness", "finding_reproduction")


def _finding_body(finding, proposal):
    return {"evaluated_event_id": proposal, "detector_id": finding.detector_id,
            "detector_version": finding.detector_version, "detector_digest": finding.artifact_digest,
            "policy_digest": finding.policy_digest, "extraction_version": finding.extraction_version,
            "behavioral_verdict": finding.behavior, "authorization_assessment": finding.authorization,
            "hypothetical_recommendation": finding.hypothetical_recommendation, "rule_id": finding.rule_id,
            "supporting_event_ids": list(finding.supporting_event_ids), "explanation": finding.explanation}


def reproduce_findings(manifest, entries):
    """Approved evaluators on eligible prefixes; no stored verdict is an input."""
    task = manifest["task_id"]
    policy = Policy(())  # Exact configured non-release slice, validated externally.
    reference, streaming = B2Reference(task, policy), B2Streaming(task, policy)
    history = ()
    expected, seen = {}, set()
    proposals = reproduced = prefixes = 0
    for entry in entries:
        event = entry["event"]
        kind, body = event["event_type"], event["body"]
        if kind == "CALL_PROPOSAL":
            proposals += 1
            expected, seen = {}, set()
            current = Current(**{**body["current"], "sensitive_resources": tuple(body["current"]["sensitive_resources"])})
            if current.supported:
                proposal = event["event_id"]
                full = reference.evaluate(current, history, proposal)
                incremental = streaming.evaluate(current, proposal)
                _require(equivalent(full, incremental), "Offline B2-R/B2-S prefix disagreement")
                prefixes += 1
                results = (replace(b0(current, policy), supporting_event_ids=(proposal,)),
                    attach_references(b1(current, project_b1(history, task), policy), proposal, current, history),
                    full, incremental)
                expected = {f.detector_id: _finding_body(f, proposal) for f in results}
                _require(tuple(expected) == DETECTOR_IDS, "Unsupported detector set")
        elif kind == "DETECTOR_FINDING":
            detector = body["detector_id"]
            _require(detector not in seen and expected.get(detector) == body,
                     "Stored finding differs from independent reproduction")
            seen.add(detector)
            reproduced += 1
        elif kind == "DISPATCH_DECISION":
            _require(seen == set(expected), "Missing required detector finding")
        for fact in _facts((event,)):
            streaming.observe(fact)
            history += (fact,)
    return {"proposals": proposals, "findings_reproduced": reproduced, "b2_agreeing_prefixes": prefixes}


def inspect_package(package_bytes, inventory, expected_config, pinned_keys):
    """Freeze bytes once and report dimensions independently, without accepting a run."""
    report = {"mode": "INSPECT", "fresh_submission": "NOT_IMPLEMENTED_M5",
              "inspection_passed": False,
              "dimensions": {name: {"status": "NOT_CHECKED", "reason": "Prerequisite unavailable"}
                             for name in DIMENSIONS}}

    def result(name, status, reason):
        report["dimensions"][name] = {"status": status, "reason": reason}

    try:
        package = decode(package_bytes)
        _require(type(package) is dict and set(package) == {"format_version", "manifest", "records", "commitment", "signature"},
                 "Invalid package fields")
        _require(package["format_version"] == PACKAGE_FORMAT, "Unsupported package format")
    except Exception as exc:
        result("schema_lifecycle", "FAIL", str(exc))
        return report
    manifest, entries, closure = package["manifest"], package["records"], package["commitment"]
    phase = None
    try:
        phase = validate_structure(manifest, entries)
        result("schema_lifecycle", "PASS", "Canonical schema, identities, sequence and call lifecycle checked")
    except IncompleteEvidence as exc:
        result("schema_lifecycle", "INCOMPLETE", str(exc))
    except Exception as exc:
        result("schema_lifecycle", "FAIL", str(exc))
    if phase is not None:
        try:
            if closure is None:
                raise IncompleteEvidence("Missing signed closure")
            check_commitment(manifest, entries, closure)
            result("commitment_integrity", "PASS", "Manifest/genesis/event hashes and closure/count/head reproduced")
        except IncompleteEvidence as exc:
            result("commitment_integrity", "INCOMPLETE", str(exc))
        except Exception as exc:
            result("commitment_integrity", "FAIL", str(exc))
    try:
        if closure is None or package["signature"] is None:
            raise IncompleteEvidence("Missing signed closure/signature")
        validate_commitment(closure)
        key = pinned_keys.get(closure["signer_key_id"])
        _require(key is not None, "Unknown externally pinned signer key ID")
        verify_signature(key, closure, package["signature"])
        result("trusted_signature", "PASS", "P-256/SHA-256 closure verified with external pinned key")
    except IncompleteEvidence as exc:
        result("trusted_signature", "INCOMPLETE", str(exc))
    except Exception as exc:
        result("trusted_signature", "FAIL", str(exc) or type(exc).__name__)
    bound = False
    try:
        validate_inventory(inventory)
        _require(encode(expected_config) == encode(configuration()), "Expected configuration differs from approved installed artifacts")
        _require(manifest["run_id"] == inventory["run_id"] and manifest["run_challenge"] == inventory["run_challenge"],
                 "Wrong expected run/challenge")
        association = {k: manifest[k] for k in IDENTITY_KEYS[1:]}
        _require(association in inventory["sessions"], "Wrong expected task/session/monitor")
        _require(manifest["expected_inventory_digest"] == inventory_digest(inventory), "Expected inventory digest mismatch")
        _require(encode(manifest["configuration"]) == encode(expected_config), "Expected configuration binding mismatch")
        if closure is not None:
            _require(all(closure[k] == manifest[k] for k in (*IDENTITY_KEYS, "run_challenge", "expected_inventory_digest")),
                     "Closure/manifest expected context mismatch")
        result("expected_binding", "PASS", "External run/challenge/session association, inventory and approved configuration matched")
        bound = True
    except Exception as exc:
        result("expected_binding", "FAIL", str(exc))
    if phase is not None:
        try:
            if closure is None:
                raise IncompleteEvidence("Missing signed closure")
            validate_commitment(closure)
            if not phase["closed"] or phase["unknown"] or phase["pending"] is not None:
                raise IncompleteEvidence("Missing clean close or unresolved call")
            if len(entries) < closure["record_count"]:
                raise IncompleteEvidence("Truncated relative to signed record count")
            _require(len(entries) == closure["record_count"] == closure["final_seq"], "Extra records or closure sequence/count mismatch")
            if not bound:
                result("inventory_completeness", "NOT_CHECKED", "External context binding failed")
            elif len(inventory["sessions"]) != 1:
                raise IncompleteEvidence("This session package does not contain every independently expected session")
            else:
                result("inventory_completeness", "PASS", "Complete signed stream and exact singleton expected inventory")
        except IncompleteEvidence as exc:
            result("inventory_completeness", "INCOMPLETE", str(exc))
        except Exception as exc:
            result("inventory_completeness", "FAIL", str(exc))
    elif bound and report["dimensions"]["schema_lifecycle"]["status"] == "INCOMPLETE":
        result("inventory_completeness", "INCOMPLETE", "Missing expected session records")
    if phase is not None and bound:
        try:
            report["reproduction"] = reproduce_findings(manifest, entries)
            result("finding_reproduction", "PASS", "Approved B0/B1/B2-R/B2-S findings reproduced from eligible prior facts")
        except Exception as exc:
            result("finding_reproduction", "FAIL", str(exc))
    report["inspection_passed"] = all(d["status"] == "PASS" for d in report["dimensions"].values())
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("package", "expected", "config", "public-key"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--key-id", required=True)
    args = parser.parse_args()
    try:
        report = inspect_package(args.package.read_bytes(), decode(args.expected.read_bytes()),
                                 decode(args.config.read_bytes()), {args.key_id: load_public(args.public_key)})
    except Exception as exc:
        print(json.dumps({"mode": "INSPECT", "inspection_passed": False, "error": str(exc)}))
        return 2
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if report["inspection_passed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
