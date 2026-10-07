"""Frozen M2 policy facts. Synthetic replay is not durable execution evidence.

B0 operating point frozen before fixture comparison, 8 October 2026:
exact registered synthetic canaries in raw UTF-8 or one strict base64 layer,
64 KiB input limit, local destination allowlist. No hex recognition, recursive
decoding, adaptive patterns, or fixture-dependent tuning. Architecture §§4/6/16
require meaningful bounded direct checks, not universal content recognition.
"""

import base64
from collections import Counter
from dataclasses import asdict, dataclass, replace
import hashlib
import json


EXTRACTION_VERSION = "m2-raw-base64-v1"
POLICY_VERSION = "m2-conservative-v1"
B0_OPERATING_POINT = "raw+strict-base64; current-warning-deny; otherwise-shadow-allow"
EVIDENCE_CLASS = "SYNTHETIC_REPLAY_NOT_DURABLE_COMMIT_PROOF"


def canonical(value) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


@dataclass(frozen=True, order=True)
class Scope:
    task_id: str
    resource: str
    destination: str
    release: str = "release"

    def __post_init__(self):
        if not all((self.task_id, self.resource, self.destination)) or self.release != "release":
            raise ValueError("Invalid exact release scope")


@dataclass(frozen=True)
class Policy:
    resources: tuple[tuple[str, str], ...]
    destinations: tuple[str, ...] = ("sink",)
    max_payload_bytes: int = 65536

    def __post_init__(self):
        if len(dict(self.resources)) != len(self.resources):
            raise ValueError("Duplicate registered resource")
        if any(not r or not c for r, c in self.resources):
            raise ValueError("Empty resource/canary")
        if len({c for _, c in self.resources}) != len(self.resources):
            raise ValueError("Canaries must map unambiguously")

    @property
    def digest(self):
        # Configuration identity only; neither evidence authentication nor secrecy.
        body = (POLICY_VERSION, EXTRACTION_VERSION, B0_OPERATING_POINT, asdict(self))
        return hashlib.sha256(canonical(body).encode()).hexdigest()


@dataclass(frozen=True)
class Current:
    operation: str
    resource: str = ""
    destination: str = ""
    sensitivity: str = "public"
    transformation: str = "none"
    sensitive_resources: tuple[str, ...] = ()
    supported: bool = True
    static_prohibition: bool = False


def extract_current(raw: dict, policy: Policy) -> Current:
    operation = raw.get("operation", "")
    resource = raw.get("resource", "")
    destination = raw.get("destination", "")
    payload = raw.get("payload", "")
    transformation = raw.get("transformation", "none")
    supported = (
        operation in {"read", "send", "transform", "echo"}
        and isinstance(payload, str)
        and len(payload.encode("utf-8")) <= policy.max_payload_bytes
        and transformation in {"none", "raw", "base64", "hex"}
        and (operation != "read" or resource in dict(policy.resources) or resource == "public")
    )
    bodies = [payload] if isinstance(payload, str) else []
    if supported and operation == "send":
        try:
            bodies.append(base64.b64decode(payload, validate=True).decode("utf-8"))
        except (ValueError, UnicodeError):
            pass
    recognized = tuple(sorted(r for r, c in policy.resources if any(c in b for b in bodies)))
    if raw.get("sensitivity") == "sensitive" and operation == "send" and not recognized:
        supported = False  # Explicit but unresolved resource mapping is unsupported.
    sensitivity = "sensitive" if resource in dict(policy.resources) or recognized else "public"
    return Current(operation, resource, destination, sensitivity, transformation,
                   recognized if operation == "send" else (), supported,
                   operation == "send" and destination not in policy.destinations)


@dataclass(frozen=True)
class Fact:
    """Only eligible semantics; reference/correlation IDs are B2/sideband data."""
    category: str
    event_id: str
    operation: str = ""
    resource: str = ""
    destination: str = ""
    outcome: str = ""
    sensitivity: str = ""
    transformation: str = ""
    scope: Scope | None = None
    grant_id: str = ""

    def __post_init__(self):
        if self.category not in {"TOOL_OUTCOME", "GRANT", "REVOKE_SCOPE", "USE"}:
            raise ValueError("Nonsemantic record cannot enter H_t")
        if not self.event_id:
            raise ValueError("Missing evidence reference")
        if self.category != "TOOL_OUTCOME" and self.scope is None:
            raise ValueError("Control/use needs exact scope")
        if self.category in {"GRANT", "USE"} and not self.grant_id:
            raise ValueError("Grant/use needs opaque ID")
        if self.category == "TOOL_OUTCOME":
            if self.scope is not None or self.grant_id or self.outcome not in {"succeeded", "failed", "denied", "unknown"}:
                raise ValueError("Invalid tool-outcome facts")
        elif any((self.operation, self.resource, self.destination, self.outcome, self.sensitivity, self.transformation)):
            raise ValueError("Control/use facts contain only their exact scope and grant correlation")
        if self.category == "REVOKE_SCOPE" and self.grant_id:
            raise ValueError("Revocation addresses scope, not a grant ID")


@dataclass(frozen=True, order=True)
class Bucket:
    """EXACT B1 allowlist (§16); task partitioning occurs before projection.

    scope is (resource, destination, release). Task identity is implicit in the
    already validated single-task input, never an additional B1 ID feature.
    """
    category: str
    operation: str
    resource: str
    destination: str
    outcome: str
    sensitivity: str
    transformation: str
    scope: tuple[str, ...]


def bucket(fact: Fact) -> Bucket:
    scope = () if fact.scope is None else (fact.scope.resource, fact.scope.destination, fact.scope.release)
    return Bucket(fact.category, fact.operation, fact.resource, fact.destination,
                  fact.outcome, fact.sensitivity, fact.transformation, scope)


def project_b1(history: tuple[Fact, ...], task_id: str) -> tuple[tuple[Bucket, int], ...]:
    if any(f.scope is not None and f.scope.task_id != task_id for f in history):
        raise ValueError("Cross-task scope in history")
    return tuple(sorted(Counter(bucket(f) for f in history).items()))


def b1_input_bytes(current: Current, counts: tuple[tuple[Bucket, int], ...]) -> bytes:
    return canonical({"current": asdict(current),
                      "history": [{**asdict(b), "count": n} for b, n in counts]}).encode()


@dataclass(frozen=True)
class Finding:
    detector_id: str
    authorization: str
    behavior: str
    hypothetical_recommendation: str
    rule_id: str
    supporting_event_ids: tuple[str, ...]
    explanation: str
    policy_digest: str
    detector_version: str = "m2-v1"
    extraction_version: str = EXTRACTION_VERSION
    artifact_digest: str = ""
    hypothetical_grants: tuple[str, ...] = ()


def finding(detector, current, policy, authorization, rule, references=(), selection=()):
    if rule == "STATIC_PROHIBITION":
        behavior = "POLICY_VIOLATION"
    elif authorization == "AUTHORIZED":
        behavior = "ALLOW"
    elif authorization == "UNAUTHORIZED" and current.sensitive_resources:
        behavior = "POLICY_VIOLATION"
    elif detector == "B0" and rule == "HISTORY_UNAVAILABLE" and not current.sensitive_resources:
        behavior = "ALLOW"
    else:
        behavior = "SUSPICIOUS"
    return Finding(detector, authorization, behavior,
                   "ALLOW" if behavior == "ALLOW" else "DENY", rule,
                   tuple(sorted(set(references))),
                   f"{rule}: {authorization}; behavior={behavior}; recommendation is hypothetical.",
                   policy.digest, hypothetical_grants=tuple(selection))


def attach_references(result, current_id, current, history):
    """One-way rendering: references never feed a B1 decision or count bucket."""
    refs = [current_id]
    if current.operation == "send" and result.rule_id not in {"STATIC_PROHIBITION", "UNSUPPORTED"}:
        exposed = {f.resource for f in history if f.category == "TOOL_OUTCOME"
                   and f.operation == "read" and f.outcome == "succeeded" and f.sensitivity == "sensitive"}
        relevant = exposed | set(current.sensitive_resources)
        for f in history:
            if (f.category == "TOOL_OUTCOME" and f.resource in relevant
                and f.operation == "read" and f.outcome == "succeeded" and f.sensitivity == "sensitive"):
                refs.append(f.event_id)
            elif f.scope and f.scope.resource in relevant and f.scope.destination == current.destination:
                refs.append(f.event_id)
    return replace(result, supporting_event_ids=tuple(sorted(set(refs))))
