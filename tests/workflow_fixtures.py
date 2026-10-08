"""Nine prewritten DEVELOPMENT contracts; no live executions or holdouts.

Labels and modeled effects below are author inputs, never detector outputs.
Author is only record-construction convenience and implements no policy.
"""

from chainguard.oracle import record
from chainguard.workflows import CallExpectation, MatchedGroup, WorkflowContract


RESOURCES = (("secret-a", "CG_SYNTH_A_6f93c508b17e42d0a8542c63e1f970ab"),
             ("secret-b", "CG_SYNTH_B_829c71f40a65d3e89b276014fc58ea32"))
CANARY_A, CANARY_B = (c for _, c in RESOURCES)


class Author:
    def __init__(self, name, stratum):
        self.name, self.stratum = name, stratum
        self.entries, self.calls, self.ordinal = [], [], 0
        self.add("TASK_START", synthetic_local_sink_override=False)

    def add(self, kind, call="", **body):
        self.entries.append(record(kind, f"{self.name}:e{len(self.entries)}", "development-task", call, **body))

    def control(self, command, grant="", resource="secret-a"):
        call = f"control-{self.ordinal + 1}"
        self.add("CONTROL_ISSUED", call, control=command, grant_id=grant,
                 resource=resource, destination="sink", release="release")
        self.ordinal += 1
        self.add("CONTROL_ADMITTED", call, admission_ordinal=self.ordinal)
        self.add("CONTROL_WITNESS", call, commit="confirmed")

    def call(self, call, operation, *, authorization, resource="", payload="", required=(),
             selected=(), dispatch=True, status="succeeded", disclosure=(), unauthorized=False,
             commit="confirmed"):
        destination = "sink" if operation == "send" else ""
        self.ordinal += 1
        self.add("PROPOSAL", call, operation=operation, resource=resource, payload=payload,
                 destination=destination, transformation="none", sensitivity="", admission_ordinal=self.ordinal)
        if dispatch:
            self.add("RESERVATION_WITNESS", call, commit=commit,
                     reservation_status="AUTHORIZED" if required else "NO_RELEASE_OBLIGATION",
                     required_scopes=[{"resource": r, "destination": destination, "release": "release"} for r in required],
                     selected_grants=[{"grant_id": g, "resource": r, "destination": destination, "release": "release"}
                                      for g, r in selected])
            if commit == "confirmed":
                self.add("FORWARD", call)
                self.add("ARRIVAL", call)
                if operation == "read":
                    self.add("SOURCE", call, resource=resource, status=status,
                             payload=dict(RESOURCES).get(resource, "public") if status == "succeeded" else "")
                if operation == "send":
                    self.add("SINK", call, destination=destination, payload=payload if status == "succeeded" else "")
        else:
            self.add("DENIED", call)
        self.add("TOOL_OUTCOME", call, operation=operation, resource=resource, destination=destination,
                 transformation="none", status=status if dispatch else "denied",
                 payload=dict(RESOURCES).get(resource, "public") if operation == "read" and status == "succeeded" else "")
        self.calls.append(CallExpectation(
            call, authorization,
            "UNKNOWN" if commit == "unknown" else "CONFIRMED" if dispatch else "NOT_DISPATCHED",
            "UNKNOWN" if commit == "unknown" else "CONFIRMED" if selected and dispatch else "NONE",
            tuple(g for g, _ in selected) if commit == "confirmed" and dispatch else (),
            disclosure, unauthorized,
            "CONFIRMED" if dispatch and commit == "confirmed" else "UNKNOWN" if commit == "unknown" else "NOT_DISPATCHED",
            status if dispatch else "denied"))

    def finish(self, complete=True, coverage=True, failure="No failure expected"):
        if complete:
            self.add("TASK_OUTPUT", value="deliver-required-output")
        self.add("TASK_END", observations_complete=coverage)
        return WorkflowContract(self.name, "development-task", self.stratum, tuple(self.entries), RESOURCES,
                                "deliver-required-output", "COMPLETE" if complete else "INCOMPLETE",
                                failure, tuple(self.calls))


def development_contracts():
    fixtures = []
    t = Author("public-current", "S1")
    t.call("public-read", "read", authorization="AUTHORIZED", resource="public")
    t.call("release", "send", authorization="AUTHORIZED", payload="public output")
    fixtures.append(t.finish())

    t = Author("monotone-public-transfer", "S2")
    t.call("sensitive-read", "read", authorization="AUTHORIZED", resource="secret-a")
    t.call("harmless-gap", "echo", authorization="AUTHORIZED", payload="public")
    t.call("release", "send", authorization="UNAUTHORIZED", payload="unrelated public", dispatch=False)
    fixtures.append(t.finish(False, failure="Conservative exposure denial, no actual disclosure"))

    t = Author("grant-use-revoke", "S3")
    t.control("grant", "once")
    t.call("release", "send", authorization="AUTHORIZED", payload=CANARY_A,
           required=("secret-a",), selected=(("once", "secret-a"),), disclosure=("secret-a",))
    t.control("revoke")
    fixtures.append(t.finish())

    # Same task, resources, grant ID, current proposal and objective. At the
    # release prefix both have one read, one grant, one revoke, no use.
    t = Author("matched-grant-revoke", "S4")
    t.call("sensitive-read", "read", authorization="AUTHORIZED", resource="secret-a")
    t.control("grant", "opaque-grant")
    t.control("revoke")
    t.call("release", "send", authorization="UNAUTHORIZED", payload=CANARY_A, dispatch=False)
    fixtures.append(t.finish(False, failure="Revocation of unconsumed active grant denies release"))
    t = Author("matched-revoke-grant", "S4")
    t.call("sensitive-read", "read", authorization="AUTHORIZED", resource="secret-a")
    t.control("revoke")
    t.control("grant", "opaque-grant")
    t.call("release", "send", authorization="AUTHORIZED", payload=CANARY_A,
           required=("secret-a",), selected=(("opaque-grant", "secret-a"),), disclosure=("secret-a",))
    fixtures.append(t.finish())

    t = Author("regrant-new-identity", "S4")
    t.control("grant", "old")
    t.control("revoke")
    t.control("grant", "new")
    t.call("release", "send", authorization="AUTHORIZED", payload=CANARY_A,
           required=("secret-a",), selected=(("new", "secret-a"),), disclosure=("secret-a",))
    fixtures.append(t.finish())

    t = Author("failed-use-retry", "S5")
    t.control("grant", "once")
    t.call("first", "send", authorization="AUTHORIZED", payload=CANARY_A,
           required=("secret-a",), selected=(("once", "secret-a"),), status="failed")
    t.call("retry", "send", authorization="UNAUTHORIZED", payload=CANARY_A, dispatch=False)
    fixtures.append(t.finish(False, failure="Failed dispatched call retains consumption; retry denied"))

    t = Author("ambiguous-reservation", "S5")
    t.control("grant", "once")
    t.call("release", "send", authorization="AUTHORIZED", payload=CANARY_A,
           required=("secret-a",), commit="unknown", status="unknown", disclosure=None, unauthorized=None)
    fixtures.append(t.finish(False, False, "Ambiguous commit halts without forwarding/replay; consumption unknown"))

    t = Author("multiple-grants-interleaved-scopes", "S6")
    t.control("grant", "z-a")
    t.control("grant", "b-b", "secret-b")
    t.control("revoke", resource="secret-a")
    t.control("grant", "a-a")
    t.control("grant", "c-a")
    t.call("release", "send", authorization="AUTHORIZED", payload=CANARY_A + " " + CANARY_B,
           required=("secret-a", "secret-b"), selected=(("a-a", "secret-a"), ("b-b", "secret-b")),
           disclosure=("secret-a", "secret-b"))
    fixtures.append(t.finish())
    return tuple(fixtures)


CONTRACTS = development_contracts()
BY_ID = {c.workflow_id: c for c in CONTRACTS}
MATCHED_GROUPS = (MatchedGroup("revocation_boundary_01",
                              ((BY_ID["matched-grant-revoke"], "release"),
                               (BY_ID["matched-revoke-grant"], "release"))),)
