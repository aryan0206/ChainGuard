"""Task-local live permission authority backed by confirmed M6 audit writes.

This module neither forwards tools nor restores authority from audit storage.
The trusted controller must own the audit session exclusively and supply real
detector findings and observed outcomes; MCP input has no control entry point.
"""

from copy import deepcopy
from dataclasses import asdict, dataclass, field
from threading import RLock, get_ident
from uuid import uuid4

from chainguard.authorization import plan_reservation
from chainguard.m6_live_audit import LiveAuditSession, live_draft
from chainguard.m6_live_profile import POLICY, SERVER_ID, validate_tool_arguments
from chainguard.permission_evidence import DETECTOR_IDS, LIFECYCLE_BODY_KEYS
from chainguard.semantics import Fact, Scope, extract_current


class AuthorizationError(RuntimeError):
    """Admission refused; a halted task cannot issue further permissions."""


@dataclass(frozen=True, eq=False)
class DispatchPermit:
    run_id: str
    task_id: str
    session_id: str
    monitor_instance_id: str
    call_id: str
    request_id: str | int
    intent_event_id: str
    _nonce: str = field(repr=False)


@dataclass(frozen=True)
class _Pending:
    permit: DispatchPermit
    tool: str
    current: object
    taken: bool = False


# A task identity may be claimed once during this monitor process. This does
# not coordinate separate monitor processes; restart requires fresh identities.
_claimed_tasks = set()
_claims_lock = RLock()


def _scope_body(scope):
    return {"resource": scope.resource, "destination": scope.destination,
            "release": scope.release}


def _outcome_body(tool, current, status):
    return {"server": SERVER_ID, "tool": tool, "operation": current.operation,
            "resource": current.resource, "destination": current.destination,
            "status": status, "sensitivity": current.sensitivity,
            "transformation": current.transformation}


class LiveAuthorizationTask:
    """One fresh task; all transitions are serialized through its audit writer."""

    def __init__(self, audit: LiveAuditSession):
        self._lock = RLock()
        self._usable = False
        if type(audit) is not LiveAuditSession or audit.state.lifecycle != "ACTIVE":
            raise ValueError("A confirmed, active live audit session is required")
        self._audit = audit
        # The existing SQLite connection uses check_same_thread=True. The
        # controller's FIFO owner thread is therefore the only admission thread.
        self._owner_thread = get_ident()
        self._identity = tuple(audit.identity[k] for k in
                               ("run_id", "task_id", "session_id", "monitor_instance_id"))
        self._manifest = deepcopy(audit.manifest)
        self._continuity = audit.state
        self._active = {}
        self._issued = set()
        self._exposed = set()
        self._facts = ()
        self._calls = set()
        self._ordinal = 0
        self._pending = None
        self._halted = False
        self._closed = False
        self._evaluating = False
        claim = self._identity[1]
        with _claims_lock:
            if claim in _claimed_tasks:
                raise ValueError("Trusted task identity already has an authority owner")
            _claimed_tasks.add(claim)
            self._usable = True

    def _ready(self):
        if not self._usable:
            raise AuthorizationError("Task authority was not initialized")
        if self._evaluating:
            raise AuthorizationError("Authority transition inside findings callback")
        if get_ident() != self._owner_thread:
            raise AuthorizationError("Admission must run on the audit owner's thread")
        if self._halted or self._closed:
            raise AuthorizationError("Task is not admitting work")
        if self._audit.state != self._continuity or self._audit.state.lifecycle != "ACTIVE":
            self._halted = True
            raise AuthorizationError("Audit continuity changed outside the task authority")

    def _append(self, drafts, lifecycle="ACTIVE"):
        before = self._continuity
        try:
            receipt = self._audit.append_batch(tuple(drafts))
        except Exception:
            self._halted = True
            raise
        expected_ids = tuple(d.event_id for d in drafts)
        expected_types = tuple(d.event_type for d in drafts)
        after = self._audit.state
        if (receipt.session_id != self._identity[2]
                or receipt.first_seq != before.record_count + 1
                or receipt.last_seq != before.record_count + len(drafts)
                or receipt.batch_count != len(drafts)
                or receipt.record_count != receipt.last_seq
                or receipt.event_ids != expected_ids
                or receipt.event_types != expected_types
                or receipt.final_head != after.final_head
                or after.record_count != receipt.record_count
                or after.lifecycle != lifecycle):
            self._halted = True
            raise AuthorizationError("Live audit receipt does not match committed batch")
        self._continuity = after
        return receipt

    def grant(self, grant_id: str, scope: Scope):
        """Trusted-host control only; no client-provided origin flag is accepted."""
        with self._lock:
            self._ready()
            if self._pending is not None:
                raise AuthorizationError("Host control must wait for the proposal turn")
            if (type(grant_id) is not str or not grant_id or grant_id in self._issued
                    or type(scope) is not Scope or scope.task_id != self._identity[1]):
                raise ValueError("Invalid, duplicate, or cross-task grant")
            body = {"grant_id": grant_id, "scope": _scope_body(scope),
                    "host_origin": "trusted_host", "admission_ordinal": self._ordinal + 1}
            control = live_draft("GRANT", body)
            fact = Fact("GRANT", control.event_id, scope=scope, grant_id=grant_id)
            self._append((control,))
            self._issued.add(grant_id)
            self._active[grant_id] = scope
            self._ordinal += 1
            self._facts += (fact,)

    def revoke(self, scope: Scope):
        with self._lock:
            self._ready()
            if self._pending is not None:
                raise AuthorizationError("Host control must wait for the proposal turn")
            if type(scope) is not Scope or scope.task_id != self._identity[1]:
                raise ValueError("Invalid or cross-task revocation")
            body = {"scope": _scope_body(scope), "host_origin": "trusted_host",
                    "admission_ordinal": self._ordinal + 1}
            control = live_draft("REVOKE_SCOPE", body)
            fact = Fact("REVOKE_SCOPE", control.event_id, scope=scope)
            self._append((control,))
            self._active = {g: s for g, s in self._active.items() if s != scope}
            self._ordinal += 1
            self._facts += (fact,)

    def admit_call(self, call_id, tool, request_id, arguments, findings=None, *,
                   findings_factory=None):
        """Commit a whole decision turn; return a permit only for confirmed intent."""
        with self._lock:
            self._ready()
            if self._pending is not None:
                raise AuthorizationError("Another proposal turn is pending")
            if type(call_id) is not str or not call_id or call_id in self._calls:
                raise ValueError("Invalid or repeated call ID")
            if type(request_id) not in (str, int):
                raise ValueError("Invalid request ID")
            contract = validate_tool_arguments(tool, arguments)
            raw = {"operation": contract.operation, "resource": contract.resource,
                   "destination": contract.destination,
                   "payload": arguments.get("payload", "") if arguments else ""}
            current = extract_current(raw, POLICY)
            if not current.supported:
                raise ValueError("Unsupported normalized M6 call")
            proposal = live_draft("CALL_PROPOSAL", {"server": SERVER_ID, "tool": tool,
                "request_id": request_id, "admission_ordinal": self._ordinal + 1,
                "current": {**asdict(current),
                            "sensitive_resources": list(current.sensitive_resources)}},
                call_id=call_id)
            if (findings is None) == (findings_factory is None):
                raise ValueError("Supply exactly one trusted findings source")
            if findings_factory is not None:
                if not callable(findings_factory):
                    raise ValueError("Invalid trusted findings factory")
                self._evaluating = True
                try:
                    findings = findings_factory(current, proposal.event_id, self._facts)
                except Exception:
                    self._halted = True
                    raise
                finally:
                    self._evaluating = False
            if type(findings) is not dict or set(findings) != set(DETECTOR_IDS):
                if findings_factory is not None:
                    self._halted = True
                raise ValueError("Expected all trusted detector findings")
            drafts = [proposal]
            for detector in DETECTOR_IDS:
                body = deepcopy(findings[detector])
                if (type(body) is not dict or set(body) != LIFECYCLE_BODY_KEYS["DETECTOR_FINDING"]
                        or body.get("detector_id") != detector):
                    if findings_factory is not None:
                        self._halted = True
                    raise ValueError("Invalid trusted detector finding")
                body["evaluated_event_id"] = proposal.event_id
                drafts.append(live_draft("DETECTOR_FINDING", body, call_id=call_id))

            resources = (self._exposed | set(current.sensitive_resources)
                         if current.operation == "send" else set())
            required = tuple(Scope(self._identity[1], r, current.destination)
                             for r in sorted(resources))
            plan = plan_reservation(self._identity[1], required, self._active)
            assessment = ("UNAUTHORIZED" if current.static_prohibition or not plan.complete
                          else "AUTHORIZED")
            profile = self._manifest["execution_profile"]
            config = self._manifest["configuration"]
            ready = not current.static_prohibition and (
                current.operation != "send" or profile["release_calls_enabled"])
            # No Step-2 predicate proves that an arbitrary payload is an approved
            # synthetic workflow. The default-disabled override remains unavailable.
            allow = ready and assessment == "AUTHORIZED"
            if profile["mode"] == "enforcement":
                chosen = config["enforcement_detector"]
                allow &= findings[chosen]["hypothetical_recommendation"] == "ALLOW"
            decision = "ALLOW" if allow else "DENY"
            reason = "Confirmed task permission" if allow else "Controller refusal"
            if (not allow and not plan.complete and not current.static_prohibition
                    and profile["mode"] == "observation"
                    and profile["synthetic_local_sink_override"] is False):
                reason = "Required permission unavailable; observation override disabled"
            drafts.append(live_draft("DISPATCH_DECISION", {
                "dispatch_decision": decision, "authorization_assessment": assessment,
                "reason": reason},
                call_id=call_id))
            if allow:
                status = "AUTHORIZED" if required else "NO_RELEASE_OBLIGATION"
                selected = sorted(({"grant_id": grant, **_scope_body(scope)}
                                   for scope, grant in plan.selections),
                                  key=lambda row: row["grant_id"])
                intent = live_draft("DISPATCH_INTENT", {
                    "call_id": call_id, "required_scopes": [_scope_body(s) for s in required],
                    "selected_grants": selected, "reservation_status": status},
                    call_id=call_id)
                drafts.append(intent)
                facts = tuple(Fact("USE", intent.event_id, scope=scope, grant_id=grant)
                              for scope, grant in plan.selections)
            else:
                outcome = live_draft("TOOL_OUTCOME", _outcome_body(tool, current, "denied"),
                                     call_id=call_id)
                drafts.append(outcome)
                facts = (Fact("TOOL_OUTCOME", outcome.event_id, current.operation,
                              current.resource, current.destination, "denied",
                              current.sensitivity, current.transformation),)
            self._append(drafts)
            self._ordinal += 1
            self._calls.add(call_id)
            self._facts += facts
            if not allow:
                return None
            for _, grant_id in plan.selections:
                del self._active[grant_id]
            permit = DispatchPermit(*self._identity, call_id, request_id,
                                    intent.event_id, uuid4().hex)
            self._pending = _Pending(permit, tool, current)
            return permit

    def take_dispatch(self, permit: DispatchPermit):
        """Consume the sole permit at the controller's actual dispatch boundary."""
        with self._lock:
            self._ready()
            if self._pending is None or self._pending.permit is not permit or self._pending.taken:
                raise AuthorizationError("Invalid or already used dispatch permit")
            self._pending = _Pending(permit, self._pending.tool, self._pending.current, True)

    def record_outcome(self, permit: DispatchPermit, status: str):
        with self._lock:
            self._ready()
            pending = self._pending
            if pending is None or pending.permit is not permit or not pending.taken:
                raise AuthorizationError("Outcome lacks a taken dispatch permit")
            if status not in {"succeeded", "failed", "unknown"}:
                self._halted = True
                raise AuthorizationError("Unrecognized dispatched outcome; task halted")
            outcome = live_draft("TOOL_OUTCOME", _outcome_body(
                pending.tool, pending.current, status), call_id=permit.call_id)
            fact = Fact("TOOL_OUTCOME", outcome.event_id, pending.current.operation,
                        pending.current.resource, pending.current.destination, status,
                        pending.current.sensitivity, pending.current.transformation)
            self._append((outcome,),
                "HALTED" if status == "unknown" else "ACTIVE")
            self._facts += (fact,)
            if status == "succeeded" and pending.current.operation == "read" and \
                    pending.current.sensitivity == "sensitive":
                self._exposed.add(pending.current.resource)
            self._pending = None
            if status == "unknown":
                self._halted = True

    def halt_uncertain(self):
        """Contain a committed intent with missing or uncertain dispatch evidence."""
        with self._lock:
            self._halted = True

    def close(self):
        with self._lock:
            self._ready()
            if self._pending is not None:
                raise AuthorizationError("Pending call prevents clean closure")
            self._append((live_draft("SESSION_END", {"closure_status": "CLOSED"}),),
                         "CLOSED_UNSEALED")
            self._active.clear()
            self._closed = True
