"""Pure M6 reservation-planner tests; no live authorization or tool execution."""

from copy import deepcopy
from dataclasses import FrozenInstanceError
from itertools import permutations
from types import MappingProxyType
import unittest

from chainguard.authorization import plan_reservation
from chainguard.semantics import Scope


class RepeatedGrantItems(dict):
    """Deliberately malformed items() stream; normal dicts cannot repeat keys."""

    def __init__(self, first_scope, repeated_scope):
        super().__init__({"g": first_scope})
        self.repeated_scope = repeated_scope

    def items(self):
        return (("g", self["g"]), ("g", self.repeated_scope))


class ReservationPlanTests(unittest.TestCase):
    def setUp(self):
        self.scope_a = Scope("task", "secret-a", "sink")
        self.scope_b = Scope("task", "secret-b", "sink")

    def test_no_required_scopes(self):
        for grants in ({}, {"unused": self.scope_a}):
            with self.subTest(grants=grants):
                result = plan_reservation("task", (), grants)
                self.assertTrue(result.complete)
                self.assertEqual(result.selections, ())

    def test_one_scope_one_matching_grant(self):
        result = plan_reservation("task", (self.scope_a,), {"opaque": self.scope_a})
        self.assertTrue(result.complete)
        self.assertEqual(result.selections, ((self.scope_a, "opaque"),))

    def test_lexicographically_smallest_eligible_id(self):
        grants = {"g-2": self.scope_a, "g-10": self.scope_a, "a-wrong-scope": self.scope_b}
        result = plan_reservation("task", (self.scope_a,), grants)
        self.assertEqual(result.selections, ((self.scope_a, "g-10"),))

    def test_candidate_order_does_not_change_selection(self):
        candidates = (("z", self.scope_a), ("a", self.scope_a), ("b", self.scope_b))
        expected = ((self.scope_a, "a"), (self.scope_b, "b"))
        for order in permutations(candidates):
            with self.subTest(order=order):
                result = plan_reservation("task", (self.scope_a, self.scope_b), dict(order))
                self.assertTrue(result.complete)
                self.assertEqual(result.selections, expected)

    def test_output_follows_canonical_scope_order_not_grant_id_order(self):
        grants = {"a-id": self.scope_b, "z-id": self.scope_a}
        for required in ((self.scope_b, self.scope_a), (self.scope_a, self.scope_b)):
            with self.subTest(required=required):
                result = plan_reservation("task", required, grants)
                self.assertEqual(result.selections, ((self.scope_a, "z-id"), (self.scope_b, "a-id")))

    def test_scope_order_includes_destination(self):
        earlier = Scope("task", "secret-a", "a-sink")
        result = plan_reservation("task", (self.scope_a, earlier),
                                  {"a-id": self.scope_a, "z-id": earlier})
        self.assertEqual(result.selections, ((earlier, "z-id"), (self.scope_a, "a-id")))

    def test_missing_scope_refuses_entire_reservation(self):
        for grants in ({}, {"only-a": self.scope_a}, {"only-b": self.scope_b}):
            with self.subTest(grants=grants):
                result = plan_reservation("task", (self.scope_b, self.scope_a), grants)
                self.assertFalse(result.complete)
                self.assertEqual(result.selections, ())

    def test_duplicate_requirements_rejected(self):
        equal_scope = Scope("task", "secret-a", "sink")
        with self.assertRaisesRegex(ValueError, "Duplicate required scope"):
            plan_reservation("task", (self.scope_a, equal_scope), {"g": self.scope_a})

    def test_duplicate_grant_id_with_same_scope_rejected(self):
        grants = RepeatedGrantItems(self.scope_a, self.scope_a)
        for required in ((), (self.scope_a,)):
            with self.subTest(required=required):
                with self.assertRaisesRegex(ValueError, "Duplicate grant ID"):
                    plan_reservation("task", required, grants)

    def test_duplicate_grant_id_with_different_scopes_rejected(self):
        grants = RepeatedGrantItems(self.scope_a, self.scope_b)
        for required in ((), (self.scope_a,), (self.scope_a, self.scope_b)):
            with self.subTest(required=required):
                with self.assertRaisesRegex(ValueError, "Duplicate grant ID"):
                    plan_reservation("task", required, grants)

    def test_non_scope_inputs_rejected(self):
        for invalid in (None, "secret-a", ("task", "secret-a", "sink", "release"),
                        {"task_id": "task", "resource": "secret-a", "destination": "sink"}):
            with self.subTest(invalid=invalid):
                with self.assertRaises(ValueError):
                    plan_reservation("task", (invalid,), {})
                with self.assertRaises(ValueError):
                    plan_reservation("task", (), {"g": invalid})

    def test_scope_field_types_and_empty_identifiers_rejected(self):
        # Scope's constructor checks truthiness, so strict field validation is
        # needed here. Tampering simulates malformed supplied frozen instances.
        for field in ("task_id", "resource", "destination", "release"):
            for value in (None, "", 7, True, [], "\ud800"):
                malformed = Scope("task", "secret-a", "sink")
                object.__setattr__(malformed, field, value)
                with self.subTest(field=field, value=value):
                    with self.assertRaises(ValueError):
                        plan_reservation("task", (malformed,), {})
                    with self.assertRaises(ValueError):
                        plan_reservation("task", (), {"g": malformed})

    def test_incomplete_scopes_raise_value_error(self):
        incomplete = [object.__new__(Scope)]
        for field in ("task_id", "resource", "destination"):
            scope = Scope("task", "secret-a", "sink")
            object.__delattr__(scope, field)
            incomplete.append(scope)
        for scope in incomplete:
            with self.subTest(fields=vars(scope)):
                with self.assertRaisesRegex(ValueError, "Missing scope field"):
                    plan_reservation("task", (scope,), {})
                with self.assertRaisesRegex(ValueError, "Missing scope field"):
                    plan_reservation("task", (), {"g": scope})

    def test_invalid_grant_ids_rejected(self):
        for grant_id in (None, "", 7, True, b"g", "\ud800"):
            with self.subTest(grant_id=grant_id):
                with self.assertRaises(ValueError):
                    plan_reservation("task", (), {grant_id: self.scope_a})

    def test_invalid_task_ids_rejected(self):
        for task_id in (None, "", 7, True, b"task", "\ud800"):
            with self.subTest(task_id=task_id):
                with self.assertRaises(ValueError):
                    plan_reservation(task_id, (), {})

    def test_cross_task_requirements_rejected(self):
        other = Scope("other-task", "secret-a", "sink")
        with self.assertRaisesRegex(ValueError, "Cross-task scope"):
            plan_reservation("task", (other,), {})

    def test_cross_task_grants_rejected_even_if_unused(self):
        other = Scope("other-task", "secret-b", "sink")
        grants = {"valid": self.scope_a, "cross-task": other}
        for required in ((), (self.scope_a,)):
            with self.subTest(required=required):
                with self.assertRaisesRegex(ValueError, "Cross-task scope"):
                    plan_reservation("task", required, grants)

    def test_invalid_candidate_is_not_hidden_by_missing_coverage(self):
        with self.assertRaises(ValueError):
            plan_reservation("task", (self.scope_b,), {"": self.scope_a})

    def test_wrong_resource_or_destination_does_not_match(self):
        for wrong in (self.scope_b, Scope("task", "secret-a", "other-sink")):
            with self.subTest(wrong=wrong):
                result = plan_reservation("task", (self.scope_a,), {"g": wrong})
                self.assertFalse(result.complete)
                self.assertEqual(result.selections, ())

    def test_wrong_release_is_rejected_not_matched(self):
        wrong = Scope("task", "secret-a", "sink")
        object.__setattr__(wrong, "release", "read")
        with self.assertRaisesRegex(ValueError, "Only exact release scopes"):
            plan_reservation("task", (self.scope_a,), {"g": wrong})

    def test_inputs_unchanged_on_complete_and_refused_plans(self):
        required = [self.scope_b, self.scope_a]
        for grants in ({"z": self.scope_a, "a": self.scope_b}, {"z": self.scope_a}):
            before = deepcopy((required, grants))
            with self.subTest(grants=grants):
                plan_reservation("task", required, grants)
                self.assertEqual((required, grants), before)

    def test_inputs_unchanged_on_validation_failure(self):
        required = [self.scope_a, self.scope_a]
        grants = {"g": self.scope_a}
        before = deepcopy((required, grants))
        with self.assertRaises(ValueError):
            plan_reservation("task", required, grants)
        self.assertEqual((required, grants), before)

    def test_read_only_mapping_and_immutable_result(self):
        result = plan_reservation("task", (self.scope_a,), MappingProxyType({"g": self.scope_a}))
        self.assertEqual(result.selections, ((self.scope_a, "g"),))
        with self.assertRaises(FrozenInstanceError):
            result.complete = False

    def test_opaque_unicode_ids_preserved_without_normalization(self):
        scope = Scope("task", "resource-\u00e9", "sink")
        result = plan_reservation("task", (scope,), {"\u00e9": scope, "e\u0301": scope})
        self.assertEqual(result.selections, ((scope, "e\u0301"),))

    def test_invalid_collection_shapes_rejected(self):
        for required, grants in ((None, {}), (iter((self.scope_a,)), {}), ("", {}),
                                  ("scope", {}), (b"", {}), (bytearray(), {}),
                                  ((), None), ((), [("g", self.scope_a)])):
            with self.subTest(required=required, grants=grants):
                with self.assertRaises(ValueError):
                    plan_reservation("task", required, grants)


if __name__ == "__main__":
    unittest.main()
