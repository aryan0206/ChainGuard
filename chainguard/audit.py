"""M3 durable records and trusted continuity; no cryptographic evidence.

The approved M3 head is (last_seq, last_event_id). It is not a hash commitment.
Reconstruction is inspection only and never restores execution authority.
"""

from copy import deepcopy
from dataclasses import asdict, dataclass, replace
from datetime import datetime, timezone
from pathlib import Path
import sqlite3
import threading
from uuid import uuid4

from chainguard.canonical import MAX_INTEGER, decode, encode
from chainguard.semantics import Current, Fact, Scope


SCHEMA_VERSION = "m3-record-v1"
RECORD_CLASS = "M3_DURABLE_UNSEALED_NO_CRYPTOGRAPHIC_COMMITMENT"
PROFILE = {"mode": "observation", "supported_tools": ["controlled_failure", "echo"],
           "synthetic_local_sink_override": False, "release_calls_enabled": False}
CALL_TYPES = {"CALL_PROPOSAL", "DETECTOR_FINDING", "DISPATCH_DECISION",
              "DISPATCH_INTENT", "TOOL_OUTCOME"}
BODY_KEYS = {
    "SESSION_START": {"record_class", "run_challenge", "execution_profile"},
    "SESSION_END": {"closure_status"},
    "CALL_PROPOSAL": {"server", "tool", "request_id", "admission_ordinal", "current"},
    "DETECTOR_FINDING": {"evaluated_event_id", "detector_id", "detector_version",
                         "detector_digest", "policy_digest", "extraction_version",
                         "behavioral_verdict", "authorization_assessment",
                         "hypothetical_recommendation", "rule_id",
                         "supporting_event_ids", "explanation"},
    "DISPATCH_DECISION": {"dispatch_decision", "authorization_assessment", "reason"},
    "DISPATCH_INTENT": {"call_id", "required_scopes", "selected_grants", "reservation_status"},
    "TOOL_OUTCOME": {"server", "tool", "operation", "resource", "destination",
                     "status", "sensitivity", "transformation"},
    "GRANT": {"grant_id", "scope", "host_origin"},
    "REVOKE_SCOPE": {"scope", "host_origin"},
}
COMMON = {"schema_version", "run_id", "task_id", "session_id", "monitor_instance_id",
          "event_id", "seq", "observed_at_utc", "event_type", "body"}


class AuditError(RuntimeError):
    """Operational audit error, never a detector threat verdict."""


class AmbiguousCommit(AuditError):
    pass


def _require(condition, message):
    if not condition:
        raise ValueError(message)


def _text(value):
    return type(value) is str and bool(value)


def _validate_record(record, schema_version, extra_fields, start_keys, start_check, end_status):
    """Shared typed bodies; format choices come from approved code, never evidence."""
    _require(type(record) is dict, "Record must be an object")
    kind = record.get("event_type")
    _require(kind in BODY_KEYS, "Unknown record type")
    keys = COMMON | extra_fields | ({"call_id"} if kind in CALL_TYPES else set())
    _require(set(record) == keys, "Unexpected or missing envelope fields")
    _require(record["schema_version"] == schema_version, "Unknown record schema version")
    for key in ("run_id", "task_id", "session_id", "monitor_instance_id", "event_id"):
        _require(_text(record[key]), "Missing stream identity")
    _require(type(record["seq"]) is int and 1 <= record["seq"] <= MAX_INTEGER, "Invalid seq")
    stamp = record["observed_at_utc"]
    _require(type(stamp) is str and stamp.endswith("Z"), "UTC display timestamp required")
    datetime.fromisoformat(stamp)
    if kind in CALL_TYPES:
        _require(_text(record["call_id"]), "Missing call correlation")
    body = record["body"]
    _require(type(body) is dict and set(body) == (start_keys if kind == "SESSION_START" else BODY_KEYS[kind]),
             "Invalid typed body fields")
    if kind == "SESSION_START":
        _require(start_check(body), "Unsupported session-start contract")
    elif kind == "SESSION_END":
        _require(body["closure_status"] == end_status, "Invalid closure status")
    elif kind == "CALL_PROPOSAL":
        _require(type(body["request_id"]) in (int, str), "Invalid protocol correlation ID")
        _require(type(body["admission_ordinal"]) is int and 1 <= body["admission_ordinal"] <= MAX_INTEGER,
                 "Invalid admission ordinal")
        _require(body["server"] == "chainguard-controlled-m1" and _text(body["tool"]), "Invalid tool")
        current = body["current"]
        _require(type(current) is dict and set(current) == set(Current.__dataclass_fields__), "Invalid current facts")
        for key in ("operation", "resource", "destination", "sensitivity", "transformation"):
            _require(type(current[key]) is str, "Invalid current field type")
        _require(type(current["supported"]) is bool and type(current["static_prohibition"]) is bool,
                 "Invalid current flags")
        resources = current["sensitive_resources"]
        _require(type(resources) is list and all(_text(v) for v in resources)
                 and resources == sorted(set(resources)), "Invalid recognized resources")
    elif kind == "DETECTOR_FINDING":
        for key in BODY_KEYS[kind] - {"supporting_event_ids"}:
            _require(_text(body[key]), "Invalid finding field type")
        _require(body["behavioral_verdict"] in {"ALLOW", "SUSPICIOUS", "POLICY_VIOLATION"}
                 and body["authorization_assessment"] in {"AUTHORIZED", "UNAUTHORIZED", "INDETERMINATE"}
                 and body["hypothetical_recommendation"] in {"ALLOW", "DENY"}, "Invalid shadow finding")
        refs = body["supporting_event_ids"]
        _require(type(refs) is list and all(_text(v) for v in refs)
                 and refs == sorted(set(refs)), "Invalid finding references")
        for key in ("detector_digest", "policy_digest"):
            value = body[key]
            _require(len(value) == 64 and all(c in "0123456789abcdef" for c in value), "Invalid artifact identity")
    elif kind == "DISPATCH_DECISION":
        _require((body["dispatch_decision"], body["authorization_assessment"], body["reason"]) in {
            ("ALLOW", "AUTHORIZED", "NON_RELEASE_M1"),
            ("DENY", "INDETERMINATE", "UNSUPPORTED_M3_CALL")}, "Invalid M3 controller decision")
    elif kind == "DISPATCH_INTENT":
        _require(body == {"call_id": record["call_id"], "required_scopes": [],
                         "selected_grants": [], "reservation_status": "NO_RELEASE_OBLIGATION"},
                 "M3 permits only non-release intents with empty selection")
    elif kind == "TOOL_OUTCOME":
        _require(body["server"] == "chainguard-controlled-m1" and _text(body["tool"]), "Invalid outcome tool")
        _require(body["status"] in {"succeeded", "failed", "denied", "unknown"}, "Invalid outcome status")
        _require(body["sensitivity"] in {"public", "sensitive"}, "Invalid sensitivity")
        _require(all(type(body[k]) is str for k in ("operation", "resource", "destination", "transformation")),
                 "Invalid semantic field type")
    elif kind in {"GRANT", "REVOKE_SCOPE"}:
        scope = body["scope"]
        _require(type(scope) is dict and set(scope) == {"resource", "destination", "release"}, "Invalid scope fields")
        _require(_text(scope["resource"]) and _text(scope["destination"]), "Invalid scope identity types")
        Scope(record["task_id"], **scope)
        _require(body["host_origin"] == "trusted_host", "Invalid control origin")
        if kind == "GRANT":
            _require(_text(body["grant_id"]), "Missing grant ID")
    encode(record)  # Also rejects invalid JSON types, integer ranges and Unicode.


def validate_record(record):
    """Exact M3 staging schema; M4 fields/versions remain rejected."""
    _validate_record(record, SCHEMA_VERSION, set(), BODY_KEYS["SESSION_START"],
        lambda body: (body["record_class"] == RECORD_CLASS and _text(body["run_challenge"])
                      and encode(body["execution_profile"]) == encode(PROFILE)), "CLOSED_UNSEALED")


@dataclass(frozen=True)
class Draft:
    event_type: str
    body_bytes: bytes
    event_id: str
    call_id: str = ""


def draft(kind, body, call_id="", event_id=None):
    return Draft(kind, encode(body), event_id or str(uuid4()), call_id)


@dataclass(frozen=True)
class ContinuityState:
    count: int = 0
    last_event_id: str = ""
    lifecycle: str = "CREATED"
    failure: str = ""

    @property
    def head(self):
        return self.count, self.last_event_id


@dataclass(frozen=True)
class CommitReceipt:
    session_id: str
    first_seq: int
    last_seq: int
    event_ids: tuple[str, ...]
    event_types: tuple[str, ...]
    call_ids: tuple[str, ...]


def _phases(records, phase, validator=validate_record):
    """Validate lifecycle/correlation, with no detector-based authority."""
    for record in records:
        validator(record)
        kind, body = record["event_type"], record["body"]
        _require(record["event_id"] not in phase["events"], "Duplicate event ID")
        if kind == "SESSION_START":
            _require(not phase["started"], "Repeated session start")
            phase["started"] = True
        else:
            _require(phase["started"] and not phase["closed"] and not phase["unknown"], "Inactive stream")
        if kind == "CALL_PROPOSAL":
            call = record["call_id"]
            _require(phase["pending"] is None and call not in phase["calls"], "Duplicate/concurrent call")
            _require(body["admission_ordinal"] == phase["ordinal"] + 1, "Noncontiguous FIFO admission")
            phase["ordinal"] += 1
            phase["calls"].add(call)
            phase["pending"] = {"call": call, "proposal": record["event_id"], "body": body,
                                "decision": None, "intent": False, "detectors": set()}
        elif kind in CALL_TYPES:
            pending = phase["pending"]
            _require(pending is not None and record["call_id"] == pending["call"], "Uncorrelated phase")
            if kind == "DETECTOR_FINDING":
                _require(not pending["intent"] and body["detector_id"] not in pending["detectors"], "Repeated/late finding")
                _require(body["evaluated_event_id"] == pending["proposal"]
                         and set(body["supporting_event_ids"]) <= phase["events"], "Unavailable finding reference")
                pending["detectors"].add(body["detector_id"])
            elif kind == "DISPATCH_DECISION":
                _require(pending["decision"] is None, "Repeated decision")
                pending["decision"] = body["dispatch_decision"]
            elif kind == "DISPATCH_INTENT":
                current = pending["body"]["current"]
                _require(pending["decision"] == "ALLOW" and not pending["intent"], "Invalid/repeated intent")
                _require(pending["body"]["tool"] in PROFILE["supported_tools"] and current == {
                    **asdict(Current("echo")), "sensitive_resources": []}, "M3 cannot authorize release calls")
                pending["intent"] = True
            elif kind == "TOOL_OUTCOME":
                _require(pending["decision"] is not None, "Outcome before decision")
                _require((body["status"] == "denied") == (pending["decision"] == "DENY"), "Denial mismatch")
                _require(body["status"] == "denied" or pending["intent"], "Outcome without committed intent")
                current = pending["body"]["current"]
                _require(body["tool"] == pending["body"]["tool"] and all(body[k] == current[k] for k in (
                    "operation", "resource", "destination", "sensitivity", "transformation")), "Outcome facts changed")
                phase["unknown"] |= body["status"] == "unknown"
                phase["pending"] = None
        elif kind in {"GRANT", "REVOKE_SCOPE"}:
            _require(phase["pending"] is None, "Control during a proposal turn")
            if kind == "GRANT":
                _require(body["grant_id"] not in phase["grants"], "Repeated grant ID")
                phase["grants"].add(body["grant_id"])
        elif kind == "SESSION_END":
            _require(phase["pending"] is None, "Unresolved call cannot close")
            phase["closed"] = True
        phase["events"].add(record["event_id"])
    return phase


def _empty_phases():
    return {"started": False, "closed": False, "unknown": False, "ordinal": 0, "events": set(),
            "calls": set(), "grants": set(), "pending": None}


def _facts(records):
    facts = []
    for r in records:
        b, kind = r["body"], r["event_type"]
        if kind == "TOOL_OUTCOME":
            facts.append(Fact(kind, r["event_id"], b["operation"], b["resource"], b["destination"],
                              b["status"], b["sensitivity"], b["transformation"]))
        elif kind in {"GRANT", "REVOKE_SCOPE"}:
            facts.append(Fact(kind, r["event_id"], scope=Scope(r["task_id"], **b["scope"]),
                              grant_id=b.get("grant_id", "")))
        # M3 intent selections are empty. No separately persisted USE is permitted.
    return tuple(facts)


class AuditSession:
    """One new M3 monitor/context; old SQLite rows cannot bootstrap authority."""

    database_version = 3
    record_schema = SCHEMA_VERSION
    end_status = "CLOSED_UNSEALED"
    record_extra_sql = ""
    insert_sql = "INSERT INTO audit_records VALUES (?,?,?,?,?,?,?,?,?)"

    def _schema_statements(self):
        return {
            "audit_records": f"""CREATE TABLE audit_records (
                session_id TEXT NOT NULL, seq INTEGER NOT NULL CHECK(seq BETWEEN 1 AND 9007199254740991),
                event_id TEXT NOT NULL, event_type TEXT NOT NULL, call_id TEXT,
                run_id TEXT NOT NULL, task_id TEXT NOT NULL, monitor_instance_id TEXT NOT NULL,
                record_bytes BLOB NOT NULL{self.record_extra_sql},
                PRIMARY KEY(session_id, seq), UNIQUE(session_id, event_id))""",
            "call_phases": """CREATE UNIQUE INDEX call_phases
                ON audit_records(session_id, call_id, event_type)
                WHERE event_type IN ('CALL_PROPOSAL','DISPATCH_DECISION','DISPATCH_INTENT','TOOL_OUTCOME')""",
        }

    def __init__(self, path, run_id, task_id, session_id, challenge, observer=None):
        self.identity = self._identity(run_id, task_id, session_id)
        self.state = self._initial_state()
        self.history = ()
        self._phase = _empty_phases()
        self._lock = threading.RLock()
        self._observer = observer
        self._connection = sqlite3.connect(path, isolation_level=None, timeout=5)
        try:
            self._connection.execute("PRAGMA journal_mode=DELETE")
            self._connection.execute("PRAGMA synchronous=FULL")
            version = self._connection.execute("PRAGMA user_version").fetchone()[0]
            _require(version in {0, self.database_version}, "Unknown database schema")
            for name in ("audit_records", "call_phases"):
                statement = self._schema_statements()[name]
                statement = statement.replace("CREATE TABLE ", "CREATE TABLE IF NOT EXISTS ", 1)
                statement = statement.replace("CREATE UNIQUE INDEX ", "CREATE UNIQUE INDEX IF NOT EXISTS ", 1)
                self._connection.execute(statement)
            self._create_extra_tables()
            self._connection.execute(f"PRAGMA user_version={self.database_version}")
            existing = self._connection.execute("""SELECT 1 FROM audit_records
                WHERE run_id=? OR task_id=? OR session_id=? LIMIT 1""", (run_id, task_id, session_id)).fetchone()
            _require(existing is None, "Restart requires a fresh singleton run/task/session; inspection only for old rows")
            self.append_batch((self._start_draft(challenge),))
        except Exception:
            self._connection.close()
            raise

    def _identity(self, run_id, task_id, session_id):
        return {"run_id": run_id, "task_id": task_id, "session_id": session_id,
                "monitor_instance_id": str(uuid4())}

    def _initial_state(self):
        return ContinuityState()

    def _create_extra_tables(self):
        pass

    def _start_draft(self, challenge):
        return draft("SESSION_START", {"record_class": RECORD_CLASS,
                     "run_challenge": challenge, "execution_profile": deepcopy(PROFILE)})

    def _prepare_records(self, records):
        return records

    def _validate_batch(self, records, phase):
        return _phases(records, phase)

    def _candidate_state(self, records, phase):
        lifecycle = "CLOSED" if phase["closed"] else "HALTED" if phase["unknown"] else "ACTIVE"
        return ContinuityState(records[-1]["seq"], records[-1]["event_id"], lifecycle,
                               "UNKNOWN_OUTCOME" if phase["unknown"] else "")

    def _storage_rows(self, records, encoded):
        return [(r["session_id"], r["seq"], r["event_id"], r["event_type"], r.get("call_id"),
                 r["run_id"], r["task_id"], r["monitor_instance_id"], data)
                for r, data in zip(records, encoded, strict=True)]

    def _insert_prepared(self, rows):
        for row in rows:
            self._connection.execute(self.insert_sql, row)

    def _validate_storage_schema(self):
        """Approve this dedicated audit DB under the BEGIN IMMEDIATE lock.

        Compare definitions to code, never to a baseline obtained from storage.
        Temp objects are forbidden so unqualified DML cannot be redirected.
        """
        _require(self._connection.in_transaction, "Schema validation requires a write transaction")
        _require(not self._connection.execute("SELECT 1 FROM temp.sqlite_schema LIMIT 1").fetchone(),
                 "Unexpected temporary audit schema")
        _require(self._connection.execute("PRAGMA main.user_version").fetchone()[0] == self.database_version,
                 "Unexpected audit database version")
        statements = self._schema_statements()
        expected = {
            ("table" if name.startswith("audit_") else "index", name,
             name if name.startswith("audit_") else "audit_records", " ".join(sql.split()))
            for name, sql in statements.items()
        }
        expected.update({("index", "sqlite_autoindex_audit_records_1", "audit_records", None),
                         ("index", "sqlite_autoindex_audit_records_2", "audit_records", None)})
        if "audit_manifests" in statements:
            expected.add(("index", "sqlite_autoindex_audit_manifests_1", "audit_manifests", None))
        actual = {(kind, name, table, " ".join(sql.split()) if sql is not None else None)
                  for kind, name, table, sql in self._connection.execute(
                      "SELECT type,name,tbl_name,sql FROM main.sqlite_schema").fetchall()}
        _require(actual == expected, "Unapproved audit schema (tables/indexes/triggers/views)")

    def _verify_stored_batch(self, rows):
        """Verify complete final materialization, not INSERT acknowledgements.

        Frozen tuples contain all metadata, canonical bytes and (in M4) hashes.
        Read after every DML in the batch; no database value becomes authority.
        """
        _require(self._connection.in_transaction, "Batch verification requires a write transaction")
        actual = self._connection.execute(
            "SELECT * FROM main.audit_records WHERE session_id=? AND seq BETWEEN ? AND ? ORDER BY seq",
            (self.identity["session_id"], rows[0][1], rows[-1][1])).fetchall()
        _require(actual == list(rows), "Stored audit batch differs from exact expected records")

    def halt(self, reason):
        self.state = replace(self.state, lifecycle="HALTED", failure=reason)

    @property
    def next_admission_ordinal(self):
        return self._phase["ordinal"] + 1

    def _commit(self):
        """Separated solely to inject loss of commit acknowledgement in tests."""
        self._connection.execute("COMMIT")

    def append_batch(self, drafts):
        with self._lock:
            if self.state.lifecycle not in {"CREATED", "ACTIVE"}:
                raise AuditError("Inactive audit context")
            records = []
            try:
                _require(bool(drafts), "Empty transaction")
                for n, item in enumerate(drafts, self.state.count + 1):
                    record = {"schema_version": self.record_schema, **self.identity,
                              "event_id": item.event_id, "seq": n, "event_type": item.event_type,
                              "observed_at_utc": datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z"),
                              "body": decode(item.body_bytes)}
                    if item.event_type in CALL_TYPES:
                        record["call_id"] = item.call_id
                    records.append(record)
                records = self._prepare_records(records)
                phase = self._validate_batch(records, deepcopy(self._phase))
                pending = phase["pending"]
                _require(pending is None or pending["intent"], "Proposal/decision/intent must commit together")
                history = self.history + _facts(records)
                encoded = [encode(r) for r in records]
                rows = tuple(self._storage_rows(records, encoded))
                state = self._candidate_state(records, phase)
                receipt = CommitReceipt(self.identity["session_id"], records[0]["seq"], records[-1]["seq"],
                                        tuple(r["event_id"] for r in records), tuple(r["event_type"] for r in records),
                                        tuple(r.get("call_id", "") for r in records))
            except (ValueError, TypeError, KeyError) as exc:
                self.halt("INVALID_RECORD")
                raise AuditError("Invalid audit transaction") from exc
            try:
                self._connection.execute("BEGIN IMMEDIATE")
                self._validate_storage_schema()
                self._insert_prepared(rows)
                self._verify_stored_batch(rows)
            except (sqlite3.Error, ValueError, TypeError, KeyError) as exc:
                try:
                    self._connection.rollback()
                    _require(not self._connection.in_transaction, "Audit rollback not confirmed")
                except (sqlite3.Error, ValueError):
                    self.halt("ROLLBACK_UNCONFIRMED")
                    raise AmbiguousCommit("Audit rollback could not be confirmed") from exc
                self.halt("ROLLED_BACK")
                raise AuditError("Audit transaction failed and rolled back") from exc
            try:
                self._commit()
            except Exception as exc:
                # Never query/adopt SQLite, retry, or claim rollback after COMMIT began.
                self.halt("AMBIGUOUS_COMMIT")
                raise AmbiguousCommit("Audit commit outcome unknown; task halted") from exc
            self._phase = phase
            self.history = history
            self.state = state
            if self._observer is not None:
                try:
                    self._observer(receipt)
                except Exception as exc:
                    self.halt("WITNESS_DELIVERY_FAILED")
                    raise AuditError("Committed audit write; witness delivery failed") from exc
            return receipt

    def finish(self):
        self.append_batch((draft("SESSION_END", {"closure_status": self.end_status}),))

    def close(self):
        if self.state.lifecycle in {"CREATED", "ACTIVE"}:
            self.halt("UNFINISHED_CONTEXT")
        self._connection.close()


def read_records(path, session_id):
    """Read-only audit inspection, without creating trusted running state."""
    uri = Path(path).resolve().as_uri() + "?mode=ro"
    connection = sqlite3.connect(uri, uri=True)
    try:
        rows = connection.execute("SELECT * FROM audit_records WHERE session_id=? ORDER BY seq", (session_id,)).fetchall()
    finally:
        connection.close()
    records = []
    for row in rows:
        record = decode(row[8])
        validate_record(record)
        expected = (record["session_id"], record["seq"], record["event_id"], record["event_type"],
                    record.get("call_id"), record["run_id"], record["task_id"], record["monitor_instance_id"])
        _require(row[:8] == expected, "SQLite metadata/canonical record mismatch")
        records.append(record)
    return tuple(records)


def reconstruct_history(records):
    """Validated committed-row projection for inspection; never restart recovery."""
    _require(bool(records), "Missing session")
    identity = {key: records[0][key] for key in ("run_id", "task_id", "session_id", "monitor_instance_id")}
    for seq, r in enumerate(records, 1):
        _require(r["seq"] == seq and all(r[k] == v for k, v in identity.items()), "Invalid stream sequence/identity")
    _phases(records, _empty_phases())
    return _facts(records)


class LiveAudit:
    """M3 non-release gate. Later enforcement remains governed by the lock.

    Only the trusted M1 registry/current validation authorizes this slice.
    A shadow callback can supply finding records but cannot supply outcomes.
    """

    def __init__(self, session, shadow=None):
        self.session = session
        self.shadow = shadow
        self._pending = None

    def before(self, request):
        params = request["params"]
        tool, args = params.get("name"), params.get("arguments")
        supported = (tool in PROFILE["supported_tools"] and type(args) is dict
                     and set(args) == {"token"} and type(args["token"]) is str and len(args["token"]) <= 256)
        current = Current("echo") if supported else Current("unsupported", supported=False)
        tool = tool if tool in PROFILE["supported_tools"] else "unsupported"
        call_id = str(uuid4())
        normalized = asdict(current)
        normalized["sensitive_resources"] = list(current.sensitive_resources)
        proposal = draft("CALL_PROPOSAL", {"server": "chainguard-controlled-m1", "tool": tool,
            "request_id": request["id"], "admission_ordinal": self.session.next_admission_ordinal,
            "current": normalized}, call_id)
        records = [proposal]
        if supported and self.shadow is not None:
            records.extend(draft("DETECTOR_FINDING", body, call_id) for body in
                           self.shadow(current, self.session.history, proposal.event_id, self.session.identity["task_id"]))
        records.append(draft("DISPATCH_DECISION", {"dispatch_decision": "ALLOW" if supported else "DENY",
            "authorization_assessment": "AUTHORIZED" if supported else "INDETERMINATE",
            "reason": "NON_RELEASE_M1" if supported else "UNSUPPORTED_M3_CALL"}, call_id))
        if supported:
            records.append(draft("DISPATCH_INTENT", {"call_id": call_id, "required_scopes": [],
                "selected_grants": [], "reservation_status": "NO_RELEASE_OBLIGATION"}, call_id))
        else:
            records.append(self._outcome(call_id, tool, current, "denied"))
        self.session.append_batch(tuple(records))
        if not supported:
            return None
        self._pending = (call_id, tool, current, args["token"])
        return call_id

    def _outcome(self, call_id, tool, current, status):
        return draft("TOOL_OUTCOME", {"server": "chainguard-controlled-m1", "tool": tool,
            "operation": current.operation, "resource": current.resource, "destination": current.destination,
            "status": status, "sensitivity": current.sensitivity, "transformation": current.transformation}, call_id)

    def after(self, call_id, response):
        _require(self._pending is not None and self._pending[0] == call_id, "Missing live call")
        _, tool, current, token = self._pending
        result = response.get("result")
        failed = tool == "controlled_failure"
        expected = f"controlled failure: {token}" if failed else token
        content = result.get("content") if type(result) is dict else None
        if (type(result) is not dict or result.get("isError", False) is not failed
                or type(content) is not list or len(content) != 1 or type(content[0]) is not dict
                or content[0].get("type") != "text" or content[0].get("text") != expected):
            self.unknown(call_id)
            raise AuditError("Unsupported terminal response; outcome unknown")
        self.session.append_batch((self._outcome(call_id, tool, current, "failed" if failed else "succeeded"),))
        self._pending = None

    def unknown(self, call_id):
        if self._pending is not None and self._pending[0] == call_id:
            _, tool, current, _ = self._pending
            self._pending = None
            self.session.append_batch((self._outcome(call_id, tool, current, "unknown"),))
        else:
            self.session.halt("UNKNOWN_OUTCOME")
