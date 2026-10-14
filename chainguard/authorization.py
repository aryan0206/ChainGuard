"""Pure reservation planning from supplied scopes and candidate active grants.

This does not establish live/committed authority, consume permissions, or
serialize a dispatch intent. The caller must supply an authoritative snapshot.
"""

from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from chainguard.semantics import Scope


@dataclass(frozen=True)
class ReservationPlan:
    """Complete coverage or refusal; pairs are (scope, grant_id) in scope order."""

    complete: bool
    selections: tuple[tuple[Scope, str], ...]


def _validate_identifier(value, field):
    if type(value) is not str or not value:
        raise ValueError(f"{field} must be a nonempty string")
    try:
        value.encode("utf-8", errors="strict")
    except UnicodeError as exc:
        raise ValueError(f"{field} must be valid UTF-8 text") from exc


def _validate_scope(scope, task_id):
    if type(scope) is not Scope:
        raise ValueError("Expected an existing Scope instance")
    for field in ("task_id", "resource", "destination", "release"):
        try:
            value = getattr(scope, field)
        except AttributeError as exc:
            raise ValueError(f"Missing scope field: {field}") from exc
        _validate_identifier(value, field)
    if scope.release != "release":
        raise ValueError("Only exact release scopes are supported")
    if scope.task_id != task_id:
        raise ValueError("Cross-task scope")


def plan_reservation(
    task_id: str,
    required_scopes: Sequence[Scope],
    active_grants: Mapping[str, Scope],
) -> ReservationPlan:
    """Choose the smallest matching ID per scope without changing any input.

    Requirements must be unique; input order is immaterial. Every supplied
    scope/grant is validated, even when requirements are empty or incomplete.
    Malformed or cross-task input raises ValueError. Missing coverage returns
    ReservationPlan(False, ()); no requirements returns a complete empty plan.
    IDs are opaque nonempty strings, compared lexicographically without
    coercion or Unicode normalization. Output follows Scope field order, not
    the grant-ID order used by replay's dispatch-intent serialization.
    """
    _validate_identifier(task_id, "task_id")
    if (not isinstance(required_scopes, Sequence)
            or isinstance(required_scopes, (str, bytes, bytearray))):
        raise ValueError("required_scopes must be a sequence of Scope instances")
    if not isinstance(active_grants, Mapping):
        raise ValueError("active_grants must map grant IDs to Scope instances")

    required = tuple(required_scopes)
    for scope in required:
        _validate_scope(scope, task_id)
    if len(set(required)) != len(required):
        raise ValueError("Duplicate required scope")

    smallest = {}
    seen_grant_ids = set()
    for grant_id, scope in active_grants.items():
        _validate_identifier(grant_id, "grant_id")
        if grant_id in seen_grant_ids:
            raise ValueError("Duplicate grant ID")
        seen_grant_ids.add(grant_id)
        _validate_scope(scope, task_id)
        if scope not in smallest or grant_id < smallest[scope]:
            smallest[scope] = grant_id

    if any(scope not in smallest for scope in required):
        return ReservationPlan(False, ())
    return ReservationPlan(True, tuple((scope, smallest[scope]) for scope in sorted(required)))
