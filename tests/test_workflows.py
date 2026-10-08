"""Phase 2 infrastructure qualification only, not E01-E13 execution."""

import ast
from dataclasses import replace
import inspect
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

from chainguard import workflows
from chainguard.oracle import Fixture, STAGED
from chainguard.workflows import (CallObservation, EnvironmentObservations, MatchedGroup,
                                 qualify, unordered_signature, validate_contract, validate_group)
from workflow_fixtures import BY_ID, CANARY_A, CONTRACTS, MATCHED_GROUPS


def target(report, call="release"):
    return next(r for r in report.calls if r.expected.call_id == call)


def environment(contract, *receipts, **kwargs):
    return EnvironmentObservations(contract.workflow_id, contract.task_id,
                                   "explicit unittest synthetic observations, not live receipts",
                                   tuple(receipts), **kwargs)


def change_entry(contract, kind, **updates):
    return replace(contract, journal=tuple(
        replace(e, body_json=json.dumps({**e.body, **updates})) if e.kind == kind else e
        for e in contract.journal))


class FoundationTests(unittest.TestCase):
    def test_all_predeclared_contracts_qualify(self):
        self.assertEqual(len(CONTRACTS), 9)
        self.assertEqual({c.stratum for c in CONTRACTS}, {f"S{i}" for i in range(1, 7)})
        for contract in CONTRACTS:
            with self.subTest(contract=contract.workflow_id):
                self.assertEqual(len(validate_contract(contract)), len(contract.calls))

    def test_labels_inspectable_without_detector_execution(self):
        code = """
import sys
sys.path.insert(0, 'tests')
from workflow_fixtures import CONTRACTS
from chainguard.workflows import validate_contract
for c in CONTRACTS:
    validate_contract(c)
assert not any(n in sys.modules for n in ('chainguard.detectors', 'chainguard.m2', 'chainguard.semantics', 'chainguard.proxy'))
print(len(CONTRACTS))
"""
        result = subprocess.run([sys.executable, "-B", "-c", code], cwd=Path(__file__).resolve().parents[1],
                                capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "9")

    def test_dependency_ast_has_no_detector_controller_imports(self):
        for module in (workflows, sys.modules["chainguard.oracle"]):
            tree = ast.parse(inspect.getsource(module))
            imports = [n.module for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)]
            imports += [a.name for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names]
            self.assertTrue(all(not n.startswith("chainguard.") or n == "chainguard.oracle" for n in imports))

    def test_detector_results_change_without_truth_change(self):
        from chainguard.m2 import run_fixture
        contract = BY_ID["matched-revoke-grant"]
        legacy = Fixture(contract.workflow_id, contract.journal, contract.resources, contract.expected_output, ())
        before = qualify(contract)
        normal = run_fixture(legacy)
        wrong = run_fixture(legacy, lambda f: replace(f, authorization="UNAUTHORIZED",
                                                     behavior="POLICY_VIOLATION", hypothetical_recommendation="DENY"))
        self.assertNotEqual(normal["rows"][-1]["findings"], wrong["rows"][-1]["findings"])
        self.assertEqual(before, qualify(contract))
        self.assertEqual(target(before).expected.authorization, "AUTHORIZED")

    def test_controller_decisions_are_excluded_inputs(self):
        contract = BY_ID["matched-revoke-grant"]
        before = qualify(contract)
        for decision in ("ALLOW", "DENY"):
            with self.assertRaises(TypeError):
                CallObservation("release", controller_decision=decision)
            with self.assertRaises(ValueError):
                validate_contract(change_entry(contract, "PROPOSAL", controller_decision=decision))
            self.assertEqual(before, qualify(contract))

    def test_wrong_findings_are_rejected_not_used_as_truth(self):
        contract = BY_ID["matched-grant-revoke"]
        for verdict in ("ALLOW", "POLICY_VIOLATION"):
            with self.assertRaises(ValueError):
                validate_contract(change_entry(contract, "PROPOSAL", detector_finding=verdict))
        self.assertEqual(target(qualify(contract)).expected.authorization, "UNAUTHORIZED")

    def test_poisoned_evaluators_cannot_affect_qualification(self):
        from chainguard.detectors import B2Reference, B2Streaming
        with patch.object(B2Reference, "evaluate", side_effect=AssertionError("detector called")), \
                patch.object(B2Streaming, "observe", side_effect=AssertionError("detector called")):
            for contract in CONTRACTS:
                validate_contract(contract)
                qualify(contract)

    def test_arrival_contradicting_denial_plan_is_actual_effect(self):
        contract = BY_ID["matched-grant-revoke"]
        row = target(qualify(contract, environment(contract, CallObservation("release", handler_arrival="CONFIRMED"))))
        self.assertEqual(row.expected.dispatch, "NOT_DISPATCHED")
        self.assertEqual(row.dispatch, "CONFIRMED")

    def test_sink_contradicting_denial_plan_is_actual_disclosure(self):
        contract = BY_ID["matched-grant-revoke"]
        row = target(qualify(contract, environment(contract,
                     CallObservation("release", sink_receipts=(("sink", CANARY_A.encode()),)))))
        self.assertEqual(row.disclosure_resources, ("secret-a",))
        self.assertIsNone(row.axes.unauthorized_disclosure)  # permission history not observed
        self.assertEqual(row.expected.disclosure_resources, ())

    def test_consumption_observation_is_independent(self):
        contract = BY_ID["matched-revoke-grant"]
        for state, grants, expected_match in (("NONE", (), "FAIL"), ("CONFIRMED", ("opaque-grant",), "PASS")):
            row = target(qualify(contract, environment(contract,
                         CallObservation("release", permission_consumption=state, consumed_grants=grants))))
            self.assertEqual(row.observation.consumed_grants, grants)
            self.assertEqual(row.consumption_matches_contract, expected_match)

    def test_missing_observations_remain_unknown(self):
        row = target(qualify(BY_ID["matched-grant-revoke"]))
        self.assertEqual(row.authorization, "INDETERMINATE")
        self.assertEqual(row.dispatch, "UNKNOWN")
        self.assertIsNone(row.disclosure_resources)
        self.assertEqual(row.observation.permission_consumption, "UNKNOWN")
        self.assertEqual(row.axes.legitimate_task_completion, "UNKNOWN")
        self.assertEqual(row.observation.audit_persistence, "NOT_CHECKED")

    def test_positive_absence_requires_explicit_observations(self):
        contract = BY_ID["matched-grant-revoke"]
        row = target(qualify(contract, environment(contract, CallObservation(
            "release", forwarding="NOT_DISPATCHED", handler_arrival="NOT_DISPATCHED", sink_receipts=()))))
        self.assertEqual(row.dispatch, "NOT_DISPATCHED")
        self.assertEqual(row.disclosure_resources, ())
        self.assertFalse(row.axes.unauthorized_disclosure)

    def test_attempt_without_handler_is_not_confirmed(self):
        contract = BY_ID["matched-revoke-grant"]
        row = target(qualify(contract, environment(contract, CallObservation("release", forwarding="ATTEMPTED"))))
        self.assertEqual(row.dispatch, "ATTEMPTED")

    def test_independent_staged_history_labels_not_contract_fallback(self):
        contract = BY_ID["matched-revoke-grant"]
        changed = change_entry(contract, "CONTROL_WITNESS", commit="failed")
        receipts = CallObservation("release", sink_receipts=(("sink", CANARY_A.encode()),))
        row = target(qualify(contract, environment(contract, receipts, staged_journal=changed.journal)))
        self.assertEqual(row.expected.authorization, "AUTHORIZED")
        self.assertEqual(row.authorization, "UNAUTHORIZED")
        self.assertTrue(row.axes.unauthorized_disclosure)
        self.assertEqual(row.authorization_evidence_class, STAGED)

    def test_five_axes_are_separate_not_security_score(self):
        contract = BY_ID["matched-revoke-grant"]
        row = target(qualify(contract, environment(contract, task_output=contract.expected_output,
                                                   task_observation_complete=True)))
        self.assertEqual((row.axes.authorization_correctness, row.axes.decision_coverage,
                          row.axes.unnecessary_denial), ("NOT_CHECKED",) * 3)
        self.assertEqual(row.axes.legitimate_task_completion, "COMPLETE")
        self.assertIsNone(row.axes.unauthorized_disclosure)

    def test_task_and_audit_closure_do_not_imply_capture(self):
        contract = BY_ID["matched-revoke-grant"]
        report = qualify(contract, environment(contract, task_output=contract.expected_output,
                         task_observation_complete=True, audit_closure="PASS"))
        self.assertEqual(report.audit_closure, "PASS")
        self.assertIsNone(target(report).disclosure_resources)

    def test_task_failure_and_returned_error_are_preserved(self):
        contract = BY_ID["failed-use-retry"]
        row = target(qualify(contract, environment(contract, CallObservation(
            "first", handler_arrival="CONFIRMED", result_status="failed", returned_bytes=b"error"),
            task_output="failure", task_observation_complete=True)), "first")
        self.assertEqual(row.observation.result_status, "failed")
        self.assertEqual(row.observation.returned_bytes, b"error")
        self.assertEqual(row.axes.legitimate_task_completion, "INCOMPLETE")

    def test_matched_labels_and_nonorder_semantics(self):
        validate_group(MATCHED_GROUPS[0])
        labels = [next(c.authorization for c in contract.calls if c.call_id == call)
                  for contract, call in MATCHED_GROUPS[0].members]
        self.assertEqual(labels, ["UNAUTHORIZED", "AUTHORIZED"])

    def test_actual_b1_input_equality_on_separate_representation_path(self):
        from chainguard.m2 import ReplayLedger
        from chainguard.semantics import Policy, b1_input_bytes, extract_current, project_b1
        encoded = []
        for contract, call in MATCHED_GROUPS[0].members:
            policy = Policy(contract.resources)
            ledger = ReplayLedger(policy)
            history = []
            for entry in contract.journal:
                if entry.kind == "PROPOSAL" and entry.call_id == call:
                    encoded.append(b1_input_bytes(extract_current(entry.body, policy), project_b1(tuple(history), contract.task_id)))
                    break
                history.extend(ledger.accept(entry))
        self.assertEqual(encoded[0], encoded[1])

    def test_identifier_renaming_preserves_contract_and_signature(self):
        contract = BY_ID["matched-revoke-grant"]
        journal = []
        for entry in contract.journal:
            body = entry.body
            if body.get("grant_id"):
                body["grant_id"] = "renamed-grant"
            for grant in body.get("selected_grants", []):
                grant["grant_id"] = "renamed-grant"
            journal.append(replace(entry, event_id="renamed-" + entry.event_id, body_json=json.dumps(body)))
        calls = tuple(replace(c, consumed_grants=("renamed-grant",)) if c.consumed_grants else c for c in contract.calls)
        renamed = replace(contract, journal=tuple(journal), calls=calls)
        self.assertEqual(unordered_signature(contract, "release"), unordered_signature(renamed, "release"))

    def test_matched_group_rejects_different_objective(self):
        left, right = MATCHED_GROUPS[0].members
        bad = replace(right[0], expected_output="other-objective")
        with self.assertRaises(ValueError):
            validate_group(MatchedGroup("bad", (left, (bad, right[1]))))

    def test_malformed_contracts_are_rejected(self):
        contract = BY_ID["matched-revoke-grant"]
        malformed = [replace(contract, stratum="S7"), replace(contract, task_id="wrong"),
                     replace(contract, split="held-out"), replace(contract, calls=()),
                     replace(contract, resources=contract.resources * 2),
                     replace(contract, calls=(contract.calls[0],) * 2),
                     change_entry(contract, "TASK_END", observations_complete="true"),
                     change_entry(contract, "CONTROL_WITNESS", commit="maybe")]
        for candidate in malformed:
            with self.subTest(candidate=candidate):
                with self.assertRaises(ValueError):
                    validate_contract(candidate)

    def test_wrong_predeclared_label_is_rejected(self):
        contract = BY_ID["matched-grant-revoke"]
        calls = tuple(replace(c, authorization="AUTHORIZED") if c.call_id == "release" else c for c in contract.calls)
        with self.assertRaises(ValueError):
            validate_contract(replace(contract, calls=calls))

    def test_malformed_receipts_are_rejected(self):
        contract = BY_ID["matched-revoke-grant"]
        for receipt in (CallObservation("absent"), CallObservation("release", permission_consumption="NONE", consumed_grants=("g",)),
                        CallObservation("release", handler_arrival="false"),
                        CallObservation("release", sink_receipts=(("external", b"x"),))):
            with self.subTest(receipt=receipt):
                with self.assertRaises(ValueError):
                    qualify(contract, environment(contract, receipt))
        with self.assertRaises(ValueError):
            qualify(contract, environment(contract, CallObservation("release"), CallObservation("release")))

    def test_ambiguous_commit_and_failed_use_remain_distinct(self):
        ambiguous = BY_ID["ambiguous-reservation"]
        expected = ambiguous.calls[0]
        self.assertEqual((expected.dispatch, expected.permission_consumption), ("UNKNOWN", "UNKNOWN"))
        self.assertEqual([e.kind for e in ambiguous.journal].count("FORWARD"), 0)
        failed = BY_ID["failed-use-retry"]
        self.assertEqual([c.permission_consumption for c in failed.calls], ["CONFIRMED", "NONE"])
        self.assertEqual([c.authorization for c in failed.calls], ["AUTHORIZED", "UNAUTHORIZED"])

    def test_different_sink_destination_cannot_borrow_authorization(self):
        contract = replace(BY_ID["matched-revoke-grant"], destinations=("sink", "other-sink"))
        row = target(qualify(contract, environment(contract, CallObservation(
            "release", sink_receipts=(("other-sink", CANARY_A.encode()),)), staged_journal=contract.journal)))
        self.assertEqual(row.disclosure_resources, ("secret-a",))
        self.assertIsNone(row.axes.unauthorized_disclosure)

    def test_unreadable_sink_bytes_are_unknown_not_absence(self):
        contract = BY_ID["matched-revoke-grant"]
        row = target(qualify(contract, environment(contract, CallObservation(
            "release", sink_receipts=(("sink", b"\xff"),)))))
        self.assertIsNone(row.disclosure_resources)
        self.assertIsNone(row.axes.unauthorized_disclosure)

    def test_live_evidence_class_cannot_be_invented_from_replay(self):
        contract = BY_ID["matched-revoke-grant"]
        fake_live = tuple(replace(e, evidence_class="REAL_DURABLE_COMMIT") for e in contract.journal)
        with self.assertRaises(ValueError):
            qualify(contract, environment(contract, staged_journal=fake_live))

    def test_observation_identity_and_payload_structure_rejected(self):
        contract = BY_ID["matched-revoke-grant"]
        for observations in (replace(environment(contract), task_id="wrong"),
                             replace(environment(contract), provenance=""),
                             replace(environment(contract), calls=(object(),)),
                             environment(contract, CallObservation("release", sink_receipts="missing"))):
            with self.subTest(observations=observations):
                with self.assertRaises(ValueError):
                    qualify(contract, observations)


if __name__ == "__main__":
    unittest.main()
