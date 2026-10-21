"""Offline inspection of sealed M6 live evidence; never accepts a run.

The assessor supplies expected inventory/configuration and a signer pin outside
the submitted package. This API checks those inputs for consistency, but cannot
establish where the assessor obtained them. Recorded normalized facts can be
replayed; raw tool arguments and downstream effects cannot be recovered here.
"""

from dataclasses import replace

from chainguard.canonical import decode, encode
from chainguard.detectors import B2Reference, B2Streaming, b0, b1, equivalent
from chainguard.evidence import (DETECTOR_IDS, IDENTITY_KEYS, SUITE, _p256,
                                 event_hash, genesis, inventory_digest,
                                 validate_inventory)
from chainguard.m6_live_evidence import validate_live_package_structure
from chainguard.m6_live_profile import (POLICY, PROFILE_VERSIONS,
    result_contract, tool_contract, validate_live_configuration,
    validate_profile_versions)
from chainguard.m6_live_seal import make_live_commitment, verify_live_signature
from chainguard.permission_evidence import reconstruct_lifecycle
from chainguard.semantics import Current, attach_references, project_b1
from chainguard.verifier import _finding_body


DIMENSIONS = ("package_schema", "commitment_integrity", "trusted_signature",
              "expected_binding", "inventory_completeness", "lifecycle_semantics",
              "finding_reproduction")
_PREREQUISITE = {"status": "NOT_CHECKED", "reason": "PREREQUISITE_UNAVAILABLE"}


def _require(condition):
    if not condition:
        raise ValueError("Live evidence check failed")


def _report(mode):
    return {"mode": mode, "fresh_submission": "NOT_CHECKED",
            "inspection_passed": False,
            "dimensions": {name: dict(_PREREQUISITE) for name in DIMENSIONS}}


def _set(report, name, status, reason):
    report["dimensions"][name] = {"status": status, "reason": reason}


def _finish(report):
    report["inspection_passed"] = all(
        item["status"] == "PASS" for item in report["dimensions"].values())
    return report


def _freeze_expected(inventory, config):
    """Snapshot caller-owned trust data once; no package value replaces it."""
    return decode(encode(inventory)), decode(encode(config))


def _check_chain(manifest, entries, closure):
    head = genesis(manifest)
    for entry in entries:
        event = entry["event"]
        _require(event["prev_hash"] == head)
        head = event_hash(event)
        _require(entry["event_hash"] == head)
    _require(closure == make_live_commitment(
        manifest, len(entries), head, closure["signer_key_id"]))


def _check_live_contracts(records):
    """Check fixed tool semantics that are present in normalized records."""
    tool = current = None
    resources = {name for name, _ in POLICY.resources}
    for event in records:
        kind, body = event["event_type"], event["body"]
        if kind == "CALL_PROPOSAL":
            tool = body["tool"]
            contract = tool_contract(tool)
            current = body["current"]
            _require(current["supported"] is True and
                     current["operation"] == contract.operation and
                     current["resource"] == contract.resource and
                     current["destination"] == contract.destination and
                     current["transformation"] == "none" and
                     current["static_prohibition"] is
                     (contract.operation == "send" and
                      contract.destination not in POLICY.destinations))
            if contract.operation == "read":
                _require(current["sensitivity"] ==
                         ("sensitive" if contract.resource in resources else "public")
                         and current["sensitive_resources"] == [])
            elif contract.operation == "send":
                _require(current["sensitivity"] ==
                         ("sensitive" if current["sensitive_resources"] else "public"))
            else:
                _require(current["sensitivity"] == "public" and
                         current["sensitive_resources"] == [])
        elif kind == "DISPATCH_DECISION":
            reason = ("Confirmed task permission" if body["dispatch_decision"] == "ALLOW"
                      else "Required permission unavailable; observation override disabled"
                      if body["authorization_assessment"] == "UNAUTHORIZED" and
                      not current["static_prohibition"] else "Controller refusal")
            _require(body["reason"] == reason)
        elif kind == "TOOL_OUTCOME":
            if body["status"] in {"succeeded", "failed"}:
                expected = "failed" if result_contract(tool)["is_error"] else "succeeded"
                _require(body["status"] == expected)
            tool = current = None


def _reproduce_findings(records, lifecycle, task_id):
    """Reproduce findings from asserted Current values and validated prior facts."""
    reference = B2Reference(task_id, POLICY)
    streaming = B2Streaming(task_id, POLICY)
    by_event = {}
    for fact in lifecycle.facts:
        by_event.setdefault(fact.event_id, []).append(fact)
    history, expected, seen = (), {}, set()
    proposals = reproduced = prefixes = 0
    for event in records:
        kind, body = event["event_type"], event["body"]
        if kind == "CALL_PROPOSAL":
            proposals += 1
            seen = set()
            current = Current(**{**body["current"],
                "sensitive_resources": tuple(body["current"]["sensitive_resources"])})
            proposal_id = event["event_id"]
            full = reference.evaluate(current, history, proposal_id)
            incremental = streaming.evaluate(current, proposal_id)
            _require(equivalent(full, incremental))
            prefixes += 1
            findings = (replace(b0(current, POLICY), supporting_event_ids=(proposal_id,)),
                attach_references(b1(current, project_b1(history, task_id), POLICY),
                                  proposal_id, current, history), full, incremental)
            expected = {finding.detector_id: _finding_body(finding, proposal_id)
                        for finding in findings}
            _require(tuple(expected) == DETECTOR_IDS)
        elif kind == "DETECTOR_FINDING":
            detector = body["detector_id"]
            _require(detector not in seen and expected.get(detector) == body)
            seen.add(detector)
            reproduced += 1
        elif kind == "DISPATCH_DECISION":
            _require(seen == set(expected))
        for fact in by_event.get(event["event_id"], ()):
            streaming.observe(fact)
            history += (fact,)
    return {"proposals": proposals, "findings_reproduced": reproduced,
            "b2_agreeing_prefixes": prefixes,
            "basis": "recorded_normalized_facts_only"}


def _inspect_session(package_bytes, inventory, config, signer_id, public_key,
                     accepted_versions, accepted_suite, *, singleton):
    report = _report("INSPECT")
    try:
        validate_profile_versions(accepted_versions)
        _require(type(accepted_suite) is str and accepted_suite == SUITE)
        package = validate_live_package_structure(package_bytes)
    except Exception:
        _set(report, "package_schema", "FAIL", "INVALID_OR_UNSUPPORTED_PACKAGE")
        return report
    _set(report, "package_schema", "PASS", "CANONICAL_LIVE_PACKAGE")
    manifest, entries, closure = (package[name] for name in
                                  ("manifest", "records", "commitment"))
    try:
        _check_chain(manifest, entries, closure)
        _set(report, "commitment_integrity", "PASS", "CHAIN_AND_CLOSURE_MATCH")
    except Exception:
        _set(report, "commitment_integrity", "FAIL", "CHAIN_OR_CLOSURE_MISMATCH")
    try:
        _require(type(signer_id) is str and bool(signer_id) and
                 closure["signer_key_id"] == signer_id)
        _p256(public_key)
        verify_live_signature(public_key, closure, package["signature"])
        _set(report, "trusted_signature", "PASS", "PINNED_SIGNER_VERIFIED")
    except Exception:
        _set(report, "trusted_signature", "FAIL", "SIGNER_OR_SIGNATURE_MISMATCH")
    try:
        validate_inventory(inventory)
        validate_live_configuration(config)
        _require(encode(manifest["configuration"]) == encode(config) and
                 manifest["run_id"] == inventory["run_id"] and
                 manifest["run_challenge"] == inventory["run_challenge"] and
                 manifest["expected_inventory_digest"] == inventory_digest(inventory) and
                 {key: manifest[key] for key in IDENTITY_KEYS[1:]} in inventory["sessions"])
        _set(report, "expected_binding", "PASS", "ASSESSOR_CONTEXT_MATCH")
    except Exception:
        _set(report, "expected_binding", "FAIL", "ASSESSOR_CONTEXT_MISMATCH")
    if report["dimensions"]["expected_binding"]["status"] == "PASS":
        if singleton and len(inventory["sessions"]) != 1:
            _set(report, "inventory_completeness", "INCOMPLETE",
                 "OTHER_EXPECTED_SESSIONS_MISSING")
        else:
            _set(report, "inventory_completeness", "PASS", "SESSION_PRESENT")
    if all(report["dimensions"][name]["status"] == "PASS" for name in
           ("commitment_integrity", "trusted_signature", "expected_binding")):
        records = [entry["event"] for entry in entries]
        try:
            lifecycle = reconstruct_lifecycle(records, POLICY, manifest["execution_profile"],
                require_complete=False,
                synthetic_experiment=config["synthetic_experiment"],
                synthetic_sink=config["synthetic_sink"],
                enforcement_detector=config["enforcement_detector"])
            _check_live_contracts(records)
            if not lifecycle.closed or lifecycle.halted or lifecycle.pending_call_id:
                _set(report, "lifecycle_semantics", "INCOMPLETE", "CLEAN_CLOSE_MISSING")
            else:
                _set(report, "lifecycle_semantics", "PASS", "LIVE_LIFECYCLE_RECONSTRUCTED")
        except Exception:
            _set(report, "lifecycle_semantics", "FAIL", "INVALID_LIVE_LIFECYCLE")
        else:
            if report["dimensions"]["lifecycle_semantics"]["status"] == "PASS":
                try:
                    report["reproduction"] = _reproduce_findings(
                        records, lifecycle, manifest["task_id"])
                    _set(report, "finding_reproduction", "PASS", "NORMALIZED_FINDINGS_REPRODUCED")
                except Exception:
                    _set(report, "finding_reproduction", "FAIL", "FINDINGS_MISMATCH")
    return _finish(report)


def inspect_live_package(package_bytes, *, expected_inventory,
                         expected_configuration, trusted_signer_key_id,
                         pinned_public_key, accepted_versions, accepted_suite):
    """Inspect one session under frozen assessor inputs; never accept or execute."""
    try:
        inventory, config = _freeze_expected(expected_inventory, expected_configuration)
    except Exception:
        report = _report("INSPECT")
        _set(report, "expected_binding", "FAIL", "INVALID_ASSESSOR_INPUT")
        return report
    return _inspect_session(package_bytes, inventory, config, trusted_signer_key_id,
        pinned_public_key, accepted_versions, accepted_suite, singleton=True)


def inspect_live_run(package_snapshots, *, expected_inventory,
                     expected_configuration, trusted_signer_key_id,
                     pinned_public_key, accepted_versions, accepted_suite):
    """Inspect the exact full session inventory without consuming it."""
    report = _report("INSPECT_RUN")
    report["sessions"] = []
    try:
        snapshots = tuple(package_snapshots)
        inventory, config = _freeze_expected(expected_inventory, expected_configuration)
        validate_inventory(inventory)
    except Exception:
        _set(report, "expected_binding", "FAIL", "INVALID_ASSESSOR_INPUT")
        return report
    reports = [_inspect_session(data, inventory, config, trusted_signer_key_id,
        pinned_public_key, accepted_versions, accepted_suite, singleton=False)
        for data in snapshots]
    report["sessions"] = reports
    associations = []
    for data in snapshots:
        try:
            package = validate_live_package_structure(data)
            manifest = package["manifest"]
            associations.append(tuple(manifest[key] for key in IDENTITY_KEYS[1:]))
        except Exception:
            associations.append(None)
    required = {tuple(session[key] for key in IDENTITY_KEYS[1:])
                for session in inventory["sessions"]}
    present = set(associations)
    if None in present or len(present) != len(associations) or present - required:
        completeness = {"status": "FAIL", "reason": "INVALID_DUPLICATE_OR_EXTRA_SESSION"}
    elif required - present:
        completeness = {"status": "INCOMPLETE", "reason": "EXPECTED_SESSION_MISSING"}
    else:
        completeness = {"status": "PASS", "reason": "EXACT_EXPECTED_SESSIONS"}
    for name in DIMENSIONS:
        statuses = [item["dimensions"][name]["status"] for item in reports]
        if name == "inventory_completeness":
            statuses.append(completeness["status"])
        status = next((value for value in ("FAIL", "INCOMPLETE", "NOT_CHECKED")
                       if value in statuses), "PASS" if statuses else "NOT_CHECKED")
        _set(report, name, status, completeness["reason"] if name ==
             "inventory_completeness" else "AGGREGATED_SESSION_CHECKS")
    return _finish(report)
