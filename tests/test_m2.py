"""M2 semantic and pipeline integration tests; all evidence is synthetic replay."""

import ast
import base64
from dataclasses import fields, replace
import inspect
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from chainguard import oracle
from chainguard.detectors import B2Reference, B2Streaming, b0, b1, equivalent
from chainguard.m2 import ReplayLedger, experiment, run_fixture, verify_expectations
from chainguard.oracle import Fixture, assess, record
from chainguard.semantics import (B0_OPERATING_POINT, Bucket, EVIDENCE_CLASS, Fact, Policy,
                                 Scope, b1_input_bytes, canonical, extract_current, project_b1)
from m2_fixtures import (A, U, I, ALLOW, SUS, VIOL, CANARY_A, CANARY_B,
                         FIXTURES, RESOURCES, Transcript)


POLICY = Policy(RESOURCES)
CASES = {f.name: f for f in FIXTURES}


def changed(entry, **updates):
    return replace(entry, body_json=canonical({**entry.body, **updates}))


def modify(fixture, kind, transform, call=None):
    return replace(fixture, journal=tuple(transform(e) if e.kind == kind and (call is None or e.call_id == call)
                                          else e for e in fixture.journal))


def target(result, call="send"):
    return next(r for r in result["rows"] if r["call_id"] == call)


def observed(fixture, call="send"):
    return next(o for o in assess(fixture) if o.call_id == call)


class B0Tests(unittest.TestCase):
    def test_frozen_operating_point_and_stateless_interface(self):
        self.assertEqual(tuple(inspect.signature(b0).parameters), ("current", "policy"))
        self.assertEqual(B0_OPERATING_POINT, "raw+strict-base64; current-warning-deny; otherwise-shadow-allow")
        for payload in (CANARY_A, base64.b64encode(CANARY_A.encode()).decode()):
            current = extract_current({"operation": "send", "destination": "sink", "payload": payload}, POLICY)
            self.assertEqual(current.sensitive_resources, ("secret-a",))
            result = b0(current, POLICY)
            self.assertEqual((result.authorization, result.behavior, result.hypothetical_recommendation), (I, SUS, "DENY"))
        current = extract_current({"operation": "send", "destination": "sink", "payload": CANARY_A.encode().hex()}, POLICY)
        self.assertEqual(current.sensitive_resources, ())
        result = b0(current, POLICY)
        self.assertEqual((result.authorization, result.behavior, result.hypothetical_recommendation), (I, ALLOW, "ALLOW"))

    def test_static_prohibition_nonrelease_and_unresolved_mapping(self):
        raw = {"operation": "send", "destination": "external", "payload": CANARY_A}
        self.assertEqual(b0(extract_current(raw, POLICY), POLICY).authorization, U)
        self.assertEqual(b0(extract_current({"operation": "echo", "payload": "x"}, POLICY), POLICY).authorization, A)
        raw = {"operation": "send", "destination": "sink", "payload": "unmapped", "sensitivity": "sensitive"}
        result = b0(extract_current(raw, POLICY), POLICY)
        self.assertEqual((result.authorization, result.rule_id, result.behavior), (I, "UNSUPPORTED", SUS))

    def test_no_tuning_after_comparison(self):
        raw = {"operation": "send", "destination": "sink", "payload": CANARY_A.encode().hex()}
        before = b0(extract_current(raw, POLICY), POLICY)
        experiment(FIXTURES)
        self.assertEqual(before, b0(extract_current(raw, POLICY), POLICY))


class B1Tests(unittest.TestCase):
    def test_exact_locked_allowlist_and_no_identifiers(self):
        self.assertEqual({f.name for f in fields(Bucket)},
                         {"category", "operation", "resource", "destination", "outcome", "sensitivity", "transformation", "scope"})
        scope = Scope("hidden-task-id", "secret-a", "sink")
        history = (Fact("GRANT", "hidden-event-id", scope=scope, grant_id="hidden-grant-id"),)
        current = extract_current({"operation": "send", "destination": "sink", "payload": CANARY_A}, POLICY)
        encoded = b1_input_bytes(current, project_b1(history, "hidden-task-id"))
        for forbidden in (b"hidden-task-id", b"hidden-event-id", b"hidden-grant-id", b"ordinal", b"timestamp",
                          b"active", b"prev_hash", b"finding", b"scenario", b"transition", b"explanation"):
            self.assertNotIn(forbidden, encoded)
        row = json.loads(encoded)["history"][0]
        self.assertEqual(set(row), {f.name for f in fields(Bucket)} | {"count"})
        self.assertEqual(row["scope"], ["secret-a", "sink", "release"])

    def test_counts_permutation_and_evidence_id_invariance(self):
        scope = Scope("task", "secret-a", "sink")
        history = (Fact("GRANT", "g1", scope=scope, grant_id="opaque1"),
                   Fact("GRANT", "g2", scope=scope, grant_id="opaque2"),
                   Fact("REVOKE_SCOPE", "r", scope=scope))
        projected = project_b1(history, "task")
        self.assertEqual(sorted(n for _, n in projected), [1, 2])
        self.assertEqual(projected, project_b1(tuple(reversed(history)), "task"))
        renamed = tuple(replace(f, event_id="other-" + f.event_id,
                                grant_id="other-" + f.grant_id if f.grant_id else "") for f in history)
        self.assertEqual(projected, project_b1(renamed, "task"))

    def test_all_predicate_branches_and_uncertainty_behavior(self):
        scope = Scope("task", "secret-a", "sink")
        grant = Fact("GRANT", "g", scope=scope, grant_id="opaque")
        use = Fact("USE", "u", scope=scope, grant_id="opaque")
        revoke = Fact("REVOKE_SCOPE", "r", scope=scope)
        current = extract_current({"operation": "send", "destination": "sink", "payload": CANARY_A}, POLICY)
        for history, expected in (((), U), ((grant,), A), ((grant, use), U), ((grant, revoke), I)):
            with self.subTest(expected=expected):
                result = b1(current, project_b1(history, "task"), POLICY)
                self.assertEqual(result.authorization, expected)
                if expected == I:
                    self.assertEqual((result.behavior, result.hypothetical_recommendation), (SUS, "DENY"))

    def test_matched_order_pair_is_byte_identical(self):
        left = target(run_fixture(CASES["order-grant-then-revoke"]))
        right = target(run_fixture(CASES["order-revoke-then-new-grant"]))
        self.assertEqual(left["b1_input"], right["b1_input"])
        self.assertEqual(left["findings"][1].authorization, I)
        self.assertEqual(right["findings"][1].authorization, I)
        self.assertEqual(left["findings"][3].authorization, U)
        self.assertEqual(right["findings"][3].authorization, A)

    def test_definite_failure_dominates_other_scope_uncertainty(self):
        result = run_fixture(CASES["multi-scope-absence-dominates-ambiguity"])
        self.assertEqual(target(result)["findings"][1].authorization, U)


class B2Tests(unittest.TestCase):
    def test_equivalence_at_every_valid_proposal_prefix(self):
        prefixes = 0
        for fixture in FIXTURES:
            result = run_fixture(fixture)
            verify_expectations(fixture, result)
            for row in result["rows"]:
                with self.subTest(fixture=fixture.name, call=row["call_id"]):
                    self.assertTrue(equivalent(row["findings"][2], row["findings"][3]))
                    prefixes += 1
        self.assertEqual(prefixes, sum(len(f.expectations) for f in FIXTURES))
        self.assertGreater(prefixes, len(FIXTURES))

    def test_reference_does_not_call_streaming_transitions(self):
        row = target(run_fixture(CASES["order-revoke-then-new-grant"]))
        current = extract_current({"operation": "send", "destination": "sink", "payload": CANARY_A}, POLICY)
        with patch.object(B2Streaming, "observe", side_effect=AssertionError("must be independent")):
            result = B2Reference("task", POLICY).evaluate(current, row["history"], "proposal")
        self.assertEqual(result.authorization, A)

    def test_deterministic_full_multi_scope_selection(self):
        result = target(run_fixture(CASES["multi-scope-complete"]))
        self.assertEqual(result["findings"][3].hypothetical_grants, ("a-a", "b-b"))

    def test_use_projected_once_not_from_outcome(self):
        fixture = CASES["consumed-failure"]
        ledger = ReplayLedger(POLICY)
        uses = []
        for entry in fixture.journal:
            generated = ledger.accept(entry)
            if entry.kind == "TOOL_OUTCOME":
                self.assertTrue(all(f.category != "USE" for f in generated))
            uses.extend(f for f in generated if f.category == "USE")
        self.assertEqual(len(uses), 1)
        self.assertEqual(uses[0].grant_id, "once")
        self.assertEqual(target(run_fixture(fixture), "second")["findings"][3].authorization, U)

    def test_unknown_outcome_preserves_consumption_and_halts(self):
        fixture = CASES["consumed-unknown-outcome"]
        ledger = ReplayLedger(POLICY)
        streaming = B2Streaming("task", POLICY)
        for entry in fixture.journal:
            for fact in ledger.accept(entry):
                streaming.observe(fact)
        self.assertNotIn("once", streaming.active)
        self.assertTrue(streaming.incomplete)
        current = extract_current({"operation": "send", "destination": "sink", "payload": CANARY_A}, POLICY)
        with self.assertRaises(ValueError):
            streaming.evaluate(current, "next")
        with self.assertRaises(ValueError):
            B2Reference("task", POLICY).evaluate(current, tuple(streaming.history), "next")

    def test_semantic_history_excludes_proposals_findings_and_bookkeeping(self):
        result = run_fixture(CASES["hard-benign-sticky-exposure"])
        for row in result["rows"]:
            self.assertTrue(all(f.category in {"TOOL_OUTCOME", "GRANT", "REVOKE_SCOPE", "USE"} for f in row["history"]))
            available = {f.event_id for f in row["history"]}
            for finding in row["findings"]:
                # Exactly one extra permitted reference: the current proposal.
                self.assertLessEqual(len(set(finding.supporting_event_ids) - available), 1)
        for category in ("PROPOSAL", "FINDING", "SHADOW_DECISION", "LIFECYCLE", "DISPATCH_INTENT"):
            with self.assertRaises(ValueError):
                Fact(category, "forbidden")

    def test_duplicate_inactive_and_cross_task_facts_rejected(self):
        scope = Scope("task", "secret-a", "sink")
        grant = Fact("GRANT", "g", scope=scope, grant_id="once")
        revoke = Fact("REVOKE_SCOPE", "r", scope=scope)
        use = Fact("USE", "u", scope=scope, grant_id="once")
        current = extract_current({"operation": "send", "destination": "sink", "payload": CANARY_A}, POLICY)
        histories = ((grant, grant), (grant, revoke, use), (grant, use, replace(use, event_id="u2")),
                     (replace(grant, scope=Scope("other", "secret-a", "sink")),))
        for history in histories:
            with self.subTest(history=history):
                with self.assertRaises(ValueError):
                    B2Reference("task", POLICY).evaluate(current, history, "p")
                incremental = B2Streaming("task", POLICY)
                with self.assertRaises(ValueError):
                    for fact in history:
                        incremental.observe(fact)


class OracleTests(unittest.TestCase):
    def test_oracle_imports_no_detector_or_normalizer(self):
        tree = ast.parse(Path(oracle.__file__).read_text())
        imports = [n.module for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)]
        self.assertFalse(any(m and m.startswith("chainguard") for m in imports))
        with patch.object(B2Reference, "evaluate", side_effect=AssertionError("oracle must be independent")), \
                patch.object(B2Streaming, "observe", side_effect=AssertionError("oracle must be independent")):
            self.assertEqual(observed(CASES["direct-authorized"]).authorization, A)

    def test_all_five_dimensions_and_pre_reservation_snapshot(self):
        observation = observed(CASES["direct-authorized"])
        self.assertEqual((observation.authorization, observation.dispatch, observation.permission_consumption,
                          observation.consumed_grants, observation.disclosure_resources,
                          observation.unauthorized_disclosure, observation.task_completion),
                         (A, "CONFIRMED", "CONFIRMED", ("grant-a",), ("secret-a",), False, "COMPLETE"))
        benign = observed(CASES["hard-benign-sticky-exposure"])
        self.assertEqual((benign.authorization, benign.disclosure_resources, benign.unauthorized_disclosure), (U, (), False))

    def test_denied_proposals_still_labeled(self):
        observation = observed(CASES["direct-raw-no-grant"])
        self.assertEqual((observation.authorization, observation.dispatch, observation.permission_consumption),
                         (U, "NOT_DISPATCHED", "NONE"))

    def test_missing_control_witness_is_indeterminate(self):
        fixture = CASES["direct-authorized"]
        missing = replace(fixture, journal=tuple(e for e in fixture.journal if e.kind != "CONTROL_WITNESS"))
        self.assertEqual(observed(missing).authorization, I)
        with self.assertRaises(ValueError):
            run_fixture(missing)  # Never silently project issued approval as permission.

    def test_missing_independent_source_observation_is_indeterminate(self):
        fixture = CASES["reconnect-preserves-exposure"]
        missing = replace(fixture, journal=tuple(e for e in fixture.journal if e.kind != "SOURCE"))
        self.assertEqual(observed(missing).authorization, I)

    def test_failed_later_control_cannot_clear_unknown_authority(self):
        fixture = CASES["direct-authorized"]
        entries = list(fixture.journal)
        witness = next(i for i, e in enumerate(entries) if e.kind == "CONTROL_WITNESS")
        entries[witness] = changed(entries[witness], commit="unknown")
        extra = [record("CONTROL_ISSUED", "extra-issued", call_id="extra", control="revoke",
                        resource="secret-a", destination="sink", release="release"),
                 record("CONTROL_ADMITTED", "extra-admitted", call_id="extra", admission_ordinal=2),
                 record("CONTROL_WITNESS", "extra-witness", call_id="extra", commit="failed")]
        entries[witness + 1:witness + 1] = extra
        entries = [changed(e, admission_ordinal=3) if e.kind == "PROPOSAL" else e for e in entries]
        self.assertEqual(observed(replace(fixture, journal=tuple(entries))).authorization, I)

    def test_missing_reservation_witness_keeps_consumption_unknown(self):
        fixture = CASES["direct-authorized"]
        missing = replace(fixture, journal=tuple(e for e in fixture.journal if e.kind != "RESERVATION_WITNESS"))
        observation = observed(missing)
        self.assertEqual(observation.permission_consumption, "UNKNOWN")
        self.assertEqual(observation.dispatch, "CONFIRMED")
        self.assertFalse(observation.unauthorized_disclosure)

    def test_attempted_dispatch_and_missing_sink_observation(self):
        fixture = CASES["direct-authorized"]
        missing_arrival = replace(fixture, journal=tuple(e for e in fixture.journal if e.kind != "ARRIVAL"))
        self.assertEqual(observed(missing_arrival).dispatch, "ATTEMPTED")
        unknown_sink = modify(fixture, "SINK", lambda e: changed(e, payload=None))
        observation = observed(unknown_sink)
        self.assertIsNone(observation.disclosure_resources)
        self.assertIsNone(observation.unauthorized_disclosure)

    def test_closure_without_observation_coverage_does_not_prove_no_disclosure(self):
        fixture = CASES["direct-authorized"]
        fixture = replace(fixture, journal=tuple(e for e in fixture.journal if e.kind != "SINK"))
        fixture = modify(fixture, "TASK_END", lambda e: changed(e, observations_complete=False))
        self.assertIsNone(observed(fixture).disclosure_resources)

    def test_unknown_permission_observations_do_not_prove_unauthorized_disclosure(self):
        fixture = CASES["direct-authorized"]
        fixture = replace(fixture, journal=tuple(e for e in fixture.journal if e.kind != "CONTROL_WITNESS"))
        result = observed(fixture)
        self.assertEqual(result.authorization, I)
        self.assertEqual(result.disclosure_resources, ("secret-a",))
        self.assertIsNone(result.unauthorized_disclosure)

    def test_full_reservation_checked_independently(self):
        fixture = CASES["multi-scope-complete"]
        partial = modify(fixture, "RESERVATION_WITNESS", lambda e: changed(e, selected_grants=e.body["selected_grants"][:1]))
        self.assertEqual(observed(partial).reservation_correctness, "INVALID")

    def test_override_empty_selection_and_separate_disclosure(self):
        fixture = CASES["partial-coverage-override"]
        first, later = assess(fixture)
        self.assertEqual((first.authorization, first.permission_consumption, first.consumed_grants,
                          first.disclosure_resources, first.unauthorized_disclosure),
                         (U, "NONE", (), ("secret-a", "secret-b"), True))
        self.assertEqual(later.consumed_grants, ("unconsumed-a",))

    def test_independent_hex_receipt_coverage(self):
        result = run_fixture(CASES["hex-history-benefit"])
        row = target(result)
        self.assertEqual(row["findings"][0].behavior, ALLOW)
        observation = observed(CASES["hex-history-benefit"])
        self.assertEqual((observation.disclosure_resources, observation.unauthorized_disclosure), (("secret-a",), True))


class SeparationAndIntegrationTests(unittest.TestCase):
    def test_all_predeclared_fixtures(self):
        for fixture in FIXTURES:
            with self.subTest(fixture=fixture.name):
                verify_expectations(fixture, run_fixture(fixture))

    def test_findings_cannot_change_history_or_oracle(self):
        fixture = CASES["direct-authorized"]
        original = run_fixture(fixture)
        corrupted = run_fixture(fixture, lambda f: replace(f, authorization=U, behavior=VIOL,
                                                          hypothetical_recommendation="DENY"))
        self.assertEqual(original["oracle"], corrupted["oracle"])
        self.assertEqual([r["history"] for r in original["rows"]], [r["history"] for r in corrupted["rows"]])
        self.assertEqual(original["oracle"][0].dispatch, "CONFIRMED")
        self.assertEqual(corrupted["rows"][0]["findings"][3].hypothetical_recommendation, "DENY")

    def test_journal_annotations_cannot_enter_detector_features(self):
        fixture = CASES["order-revoke-then-new-grant"]
        original = run_fixture(fixture)
        annotated = replace(fixture, journal=tuple(changed(e, finding="POLICY_VIOLATION",
                            controller_authorization="UNAUTHORIZED", timestamp="2099-01-01",
                            audit_hash="untrusted", scenario_label="misleading") for e in fixture.journal))
        result = run_fixture(annotated)
        self.assertEqual(original, result)

    def test_wrong_facts_and_omitted_source_do_not_become_oracle_truth(self):
        fixture = CASES["reconnect-preserves-exposure"]
        row = target(run_fixture(fixture))
        current = extract_current({"operation": "send", "destination": "sink", "payload": "public bytes"}, POLICY)
        for bad_history in (tuple(replace(f, sensitivity="public") for f in row["history"]), ()):
            reference = B2Reference("task", POLICY).evaluate(current, bad_history, "p")
            incremental = B2Streaming("task", POLICY)
            for fact in bad_history:
                incremental.observe(fact)
            self.assertTrue(equivalent(reference, incremental.evaluate(current, "p")))
            self.assertEqual(reference.authorization, A)
            self.assertEqual(observed(fixture).authorization, U)

    def test_repeatability_and_observed_ambiguity_bound(self):
        first = experiment(FIXTURES)
        self.assertEqual(canonical(first), canonical(experiment(FIXTURES)))
        self.assertGreaterEqual(first["mixed_b1_input_groups"], 1)
        self.assertGreaterEqual(first["observed_minimum_binary_errors"], 1)
        self.assertEqual(first["oracle_indeterminate_count"], 1)
        self.assertEqual(first["evidence_class"], EVIDENCE_CLASS)
        self.assertEqual(first["execution"], "REPLAY_ONLY_NO_TOOL_EXECUTION")
        for fixture in first["fixtures"]:
            for proposal in fixture["proposals"]:
                for finding in proposal["detectors"]:
                    self.assertEqual(len(finding["artifact_digest"]), 64)
                    self.assertEqual(len(finding["policy_digest"]), 64)

    def test_comparison_rejects_policy_changes_and_operational_denial_is_not_violation(self):
        changed_policy = replace(FIXTURES[0], destinations=("sink", "other-sink"))
        with self.assertRaises(ValueError):
            experiment((FIXTURES[0], changed_policy))
        result = run_fixture(CASES["unsupported-resource-mapping"])
        for finding in target(result)["findings"]:
            self.assertEqual((finding.authorization, finding.behavior, finding.rule_id), (I, SUS, "UNSUPPORTED"))
        self.assertEqual(result["oracle"][0].dispatch, "NOT_DISPATCHED")


class ReplayBoundaryTests(unittest.TestCase):
    def test_duplicate_intent_and_selected_ids_rejected(self):
        fixture = CASES["direct-authorized"]
        duplicated = []
        for entry in fixture.journal:
            duplicated.append(entry)
            if entry.kind == "RESERVATION_WITNESS":
                duplicated.append(replace(entry, event_id="duplicate-intent"))
        with self.assertRaises(ValueError):
            run_fixture(replace(fixture, journal=tuple(duplicated)))
        duplicate_selection = modify(fixture, "RESERVATION_WITNESS", lambda e: changed(e, selected_grants=e.body["selected_grants"] * 2))
        with self.assertRaises(ValueError):
            run_fixture(duplicate_selection)

    def test_duplicate_ambiguous_reservation_is_rejected(self):
        fixture = CASES["reservation-unknown"]
        entries = []
        for entry in fixture.journal:
            entries.append(entry)
            if entry.kind == "RESERVATION_WITNESS":
                entries.append(replace(entry, event_id="duplicate-ambiguous-intent"))
        duplicate = replace(fixture, journal=tuple(entries))
        with self.assertRaises(ValueError):
            run_fixture(duplicate)
        with self.assertRaises(ValueError):
            assess(duplicate)

    def test_partial_selection_and_disabled_override_rejected(self):
        fixture = CASES["multi-scope-complete"]
        partial = modify(fixture, "RESERVATION_WITNESS", lambda e: changed(e, selected_grants=e.body["selected_grants"][:1]))
        with self.assertRaises(ValueError):
            run_fixture(partial)
        fixture = CASES["hex-history-benefit"]
        disabled = modify(fixture, "TASK_START", lambda e: changed(e, synthetic_local_sink_override=False))
        with self.assertRaises(ValueError):
            run_fixture(disabled)

    def test_closed_unknown_restarted_contexts_and_task_isolation(self):
        ledger = ReplayLedger(POLICY)
        with self.assertRaises(ValueError):
            ledger.accept(record("PROPOSAL", "unknown", call_id="call", operation="echo", admission_ordinal=1))
        ledger.accept(record("TASK_START", "start"))
        ledger.accept(record("TASK_END", "end"))
        with self.assertRaises(ValueError):
            ledger.accept(record("TASK_START", "reopen"))
        ledger = ReplayLedger(POLICY)
        ledger.accept(record("TASK_START", "start"))
        ledger.accept(record("RESTART", "restart"))
        with self.assertRaises(ValueError):
            ledger.accept(record("PROPOSAL", "after-restart", call_id="call", operation="echo", admission_ordinal=1))
        first = Transcript("task-a-grant")
        first.control("grant", "isolated")
        first = first.finish()
        first = replace(first, journal=tuple(replace(e, task_id="task-a") for e in first.journal))
        second = CASES["direct-raw-no-grant"]
        combined = replace(second, journal=first.journal + second.journal)
        result = run_fixture(combined)
        self.assertEqual(target(result)["findings"][3].authorization, U)
        self.assertEqual(target(result)["history"], ())

    def test_partial_sensitive_result_halts_and_no_queued_control_interleaving(self):
        fixture = CASES["failed-read"]
        partial = modify(fixture, "TOOL_OUTCOME", lambda e: changed(e, payload=CANARY_A), "read-a")
        with self.assertRaises(ValueError):
            run_fixture(partial)
        ledger = ReplayLedger(POLICY)
        ledger.accept(record("TASK_START", "s"))
        ledger.accept(record("PROPOSAL", "p", call_id="c", operation="echo", admission_ordinal=1))
        ledger.accept(record("CONTROL_ISSUED", "i", call_id="g", control="grant", grant_id="g",
                             resource="secret-a", destination="sink", release="release"))
        with self.assertRaises(ValueError):
            ledger.accept(record("CONTROL_ADMITTED", "a", call_id="g", admission_ordinal=2))

    def test_failed_control_witness_leaves_no_semantic_grant(self):
        transcript = Transcript("failed-control")
        transcript.control("grant", "not-active", commit="failed")
        ledger = ReplayLedger(POLICY)
        for entry in transcript.entries:
            ledger.accept(entry)
        self.assertEqual(ledger.tasks["task"]["history"], [])
        self.assertEqual(ledger.tasks["task"]["active"], {})
        self.assertTrue(ledger.tasks["task"]["halted"])

    def test_fixture_witness_cannot_claim_real_commit_evidence(self):
        fixture = CASES["direct-authorized"]
        unmarked = replace(fixture, journal=tuple(replace(e, evidence_class="REAL_DURABLE_COMMIT") for e in fixture.journal))
        with self.assertRaises(ValueError):
            run_fixture(unmarked)
        with self.assertRaises(ValueError):
            assess(unmarked)


if __name__ == "__main__":
    unittest.main()
