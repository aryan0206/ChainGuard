"""M2 shadows only. No evaluator forwards calls or mutates execution history."""

from collections import defaultdict
from dataclasses import replace
import hashlib
from pathlib import Path

from chainguard import semantics
from chainguard.semantics import Fact, attach_references, finding


ARTIFACT_DIGEST = hashlib.sha256(b"detectors\0" + Path(__file__).read_bytes()
                                 + b"\0shared-semantics\0" + Path(semantics.__file__).read_bytes()).hexdigest()


def identified(result):
    return replace(result, artifact_digest=ARTIFACT_DIGEST)


def immediate(detector, current, policy):
    if current.static_prohibition:
        return finding(detector, current, policy, "UNAUTHORIZED", "STATIC_PROHIBITION")
    if not current.supported:
        return finding(detector, current, policy, "INDETERMINATE", "UNSUPPORTED")
    if current.operation != "send":
        return finding(detector, current, policy, "AUTHORIZED", "NO_RELEASE_OBLIGATION")
    return None


def b0(current, policy):
    """Frozen operating point; signature deliberately has no historical input."""
    return identified(immediate("B0", current, policy) or
                      finding("B0", current, policy, "INDETERMINATE", "HISTORY_UNAVAILABLE"))


def b1(current, counts, policy):
    early = immediate("B1", current, policy)
    if early:
        return identified(early)
    exposed = set()
    control_counts = defaultdict(lambda: defaultdict(int))
    for row, count in counts:
        if type(count) is not int or count <= 0:
            raise ValueError("B1 requires positive integral counts")
        if (row.category == "TOOL_OUTCOME" and row.operation == "read"
                and row.outcome == "succeeded" and row.sensitivity == "sensitive"):
            exposed.add(row.resource)
        if row.category in {"GRANT", "REVOKE_SCOPE", "USE"}:
            control_counts[row.scope][row.category] += count
    required = exposed | set(current.sensitive_resources)
    if not required:
        return identified(finding("B1", current, policy, "AUTHORIZED", "NO_RELEASE_OBLIGATION"))
    statuses = []
    for resource in sorted(required):
        values = control_counts[(resource, current.destination, "release")]
        grants, uses, revokes = values["GRANT"], values["USE"], values["REVOKE_SCOPE"]
        statuses.append("UNAUTHORIZED" if grants <= uses else
                        "INDETERMINATE" if revokes else "AUTHORIZED")
    auth = "UNAUTHORIZED" if "UNAUTHORIZED" in statuses else (
        "INDETERMINATE" if "INDETERMINATE" in statuses else "AUTHORIZED")
    rule = {"UNAUTHORIZED": "PERMISSION_ABSENT", "INDETERMINATE": "UNORDERED_REVOKE_AMBIGUITY",
            "AUTHORIZED": "PERMISSION_PRESENT"}[auth]
    return identified(finding("B1", current, policy, auth, rule))


class B2Reference:
    """Full-prefix reconstruction by scanning each grant's subsequent facts.

    This never calls the streaming transition implementation. Quadratic work is
    intentional in this small reference; no scaling/performance claim is made.
    """

    def __init__(self, task_id, policy):
        self.task_id, self.policy = task_id, policy

    def evaluate(self, current, history, current_id):
        grants = {}
        seen_facts = set()
        for index, fact in enumerate(history):
            key = (fact.event_id, fact.grant_id if fact.category == "USE" else "")
            if key in seen_facts:
                raise ValueError("Duplicate semantic fact")
            seen_facts.add(key)
            if fact.scope and fact.scope.task_id != self.task_id:
                raise ValueError("Cross-task scope")
            if fact.category == "GRANT":
                if fact.grant_id in grants:
                    raise ValueError("Replayed grant ID")
                grants[fact.grant_id] = (index, fact.scope)
            if fact.category == "TOOL_OUTCOME" and fact.outcome == "unknown":
                raise ValueError("Unknown outcome makes prefix incomplete")
            if fact.category == "USE":
                if fact.grant_id not in grants:
                    raise ValueError("Use before grant")
                issued, scope = grants[fact.grant_id]
                if scope != fact.scope or any(
                    (p.category == "REVOKE_SCOPE" and p.scope == scope)
                    or (p.category == "USE" and p.grant_id == fact.grant_id)
                    for p in history[issued + 1:index]
                ):
                    raise ValueError("Use of inactive or mismatched grant")
        exposed = {f.resource for f in history if f.category == "TOOL_OUTCOME"
                   and f.operation == "read" and f.outcome == "succeeded" and f.sensitivity == "sensitive"}
        active = {}
        for grant_id, (issued, scope) in grants.items():
            if not any((f.category == "REVOKE_SCOPE" and f.scope == scope)
                       or (f.category == "USE" and f.grant_id == grant_id)
                       for f in history[issued + 1:]):
                active.setdefault(scope, []).append(grant_id)
        result = immediate("B2-R", current, self.policy)
        if result is None:
            required = exposed | set(current.sensitive_resources)
            selected = []
            missing = False
            for resource in sorted(required):
                candidates = [ids for scope, ids in active.items()
                              if scope.resource == resource and scope.destination == current.destination]
                if not candidates:
                    missing = True
                else:
                    selected.append(min(candidates[0]))
            auth = "UNAUTHORIZED" if missing else "AUTHORIZED"
            rule = "PERMISSION_ABSENT" if missing else (
                "PERMISSION_PRESENT" if required else "NO_RELEASE_OBLIGATION")
            result = finding("B2-R", current, self.policy, auth, rule,
                             selection=() if missing else tuple(sorted(selected)))
        return identified(attach_references(result, current_id, current, history))


class B2Streaming:
    """Independent incremental transitions; all state is private to this shadow."""

    def __init__(self, task_id, policy):
        self.task_id, self.policy = task_id, policy
        self.exposed = set()
        self.active = {}
        self.issued_ids = set()
        self.seen_facts = set()
        self.history = []  # Supporting-reference storage is explicitly retained.
        self.incomplete = False

    def observe(self, fact: Fact):
        if self.incomplete:
            raise ValueError("Cannot extend incomplete context")
        key = (fact.event_id, fact.grant_id if fact.category == "USE" else "")
        if key in self.seen_facts:
            raise ValueError("Duplicate semantic fact")
        if fact.scope and fact.scope.task_id != self.task_id:
            raise ValueError("Cross-task scope")
        if fact.category == "GRANT":
            if fact.grant_id in self.issued_ids:
                raise ValueError("Replayed grant ID")
            self.issued_ids.add(fact.grant_id)
            self.active[fact.grant_id] = fact.scope
        elif fact.category == "REVOKE_SCOPE":
            self.active = {g: s for g, s in self.active.items() if s != fact.scope}
        elif fact.category == "USE":
            if self.active.get(fact.grant_id) != fact.scope:
                raise ValueError("Use of inactive or mismatched grant")
            del self.active[fact.grant_id]
        elif fact.outcome == "unknown":
            self.incomplete = True
        elif fact.operation == "read" and fact.outcome == "succeeded" and fact.sensitivity == "sensitive":
            self.exposed.add(fact.resource)
        self.seen_facts.add(key)
        self.history.append(fact)

    def evaluate(self, current, current_id):
        if self.incomplete:
            raise ValueError("Unknown outcome makes prefix incomplete")
        result = immediate("B2-S", current, self.policy)
        if result is None:
            needed = self.exposed.union(current.sensitive_resources)
            selected = []
            for resource in sorted(needed):
                candidates = sorted(g for g, scope in self.active.items()
                                    if scope.resource == resource and scope.destination == current.destination)
                if not candidates:
                    result = finding("B2-S", current, self.policy, "UNAUTHORIZED", "PERMISSION_ABSENT")
                    break
                selected.append(candidates[0])
            if result is None:
                result = finding("B2-S", current, self.policy, "AUTHORIZED",
                                 "PERMISSION_PRESENT" if needed else "NO_RELEASE_OBLIGATION",
                                 selection=tuple(sorted(selected)))
        return identified(attach_references(result, current_id, current, tuple(self.history)))


def equivalent(reference, streaming):
    """Identity differs, policy results and all deterministic support must agree."""
    fields = ("authorization", "behavior", "hypothetical_recommendation", "rule_id",
              "supporting_event_ids", "explanation", "hypothetical_grants", "policy_digest")
    return all(getattr(reference, f) == getattr(streaming, f) for f in fields)
