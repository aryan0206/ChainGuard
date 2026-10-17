"""Unsealed, live-profile M6 record writer; never a permission authority.

The live manifest is distinct from the M6.2 asserted-offline profile. The
shared m6-record-v1 *shape* fits these phases, but the offline profile
validator intentionally does not accept live manifests. This writer checks
live record shapes and ordering without granting, reserving, forwarding,
signing, sealing, or restoring execution state from SQLite.
"""

from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime, timezone
import sqlite3
import threading
from uuid import uuid4

from chainguard.canonical import MAX_INTEGER, decode, encode
from chainguard.evidence import IDENTITY_KEYS, event_hash, genesis, is_digest, manifest_digest
from chainguard.m6_live_profile import SERVER_ID, validate_live_manifest
from chainguard.permission_evidence import (DETECTOR_IDS, LIFECYCLE_BODY_KEYS,
    LIFECYCLE_CALL_TYPES, RECORD_CLASS, RECORD_SCHEMA, validate_intent_body)
from chainguard.semantics import Current, Scope


_ADMISSIONS = frozenset({"GRANT", "REVOKE_SCOPE", "CALL_PROPOSAL"})
_CALL_PHASES = frozenset(LIFECYCLE_CALL_TYPES)
_ENVELOPE = frozenset({"schema_version", *IDENTITY_KEYS, "event_id", "seq",
                       "observed_at_utc", "event_type", "body", "prev_hash"})
_TABLE = """CREATE TABLE m6_live_records (
    session_id TEXT NOT NULL, seq INTEGER NOT NULL CHECK(seq BETWEEN 1 AND 9007199254740991),
    event_id TEXT NOT NULL, event_type TEXT NOT NULL, call_id TEXT,
    run_id TEXT NOT NULL, task_id TEXT NOT NULL, monitor_instance_id TEXT NOT NULL,
    record_bytes BLOB NOT NULL, event_hash TEXT NOT NULL,
    PRIMARY KEY(session_id, seq), UNIQUE(session_id, event_id))"""
_INDEX = """CREATE UNIQUE INDEX m6_live_call_phases
    ON m6_live_records(session_id, call_id, event_type)
    WHERE event_type IN ('CALL_PROPOSAL','DISPATCH_DECISION','DISPATCH_INTENT','TOOL_OUTCOME')"""
_TASK_START_INDEX = """CREATE UNIQUE INDEX m6_live_task_start
    ON m6_live_records(task_id) WHERE event_type='SESSION_START'"""


class LiveAuditError(RuntimeError):
    """The task must not dispatch after a live audit failure."""


class LiveAmbiguousCommit(LiveAuditError):
    """Persistence might have committed; do not retry or adopt storage state."""


def _require(condition, message):
    if not condition:
        raise ValueError(message)


def _encode(value):
    try:
        return encode(value)
    except (RecursionError, UnicodeError) as exc:
        raise ValueError("Recursive, excessively nested, or invalid Unicode live record") from exc


def _object(value, keys, label):
    _require(type(value) is dict and set(value) == keys, f"Invalid {label} fields")
    _encode(value)


def _text(value, label, *, empty=False):
    _require(type(value) is str and (empty or bool(value)), f"Invalid {label}")
    _encode(value)


def _ordinal(value, label):
    _require(type(value) is int and 1 <= value <= MAX_INTEGER, f"Invalid {label}")


def _scope(value, task_id, *, selected=False):
    keys = {"resource", "destination", "release"} | ({"grant_id"} if selected else set())
    _object(value, keys, "scope")
    for key in keys:
        _text(value[key], key)
    Scope(task_id, value["resource"], value["destination"], value["release"])


def _current(value):
    _object(value, set(Current.__dataclass_fields__), "current")
    for key in ("operation", "resource", "destination", "sensitivity", "transformation"):
        _text(value[key], key, empty=True)
    _require(value["operation"] in {"read", "send", "transform", "echo"}
             or (value["operation"] == "unsupported" and value["supported"] is False),
             "Invalid current operation")
    _require(value["sensitivity"] in {"public", "sensitive"}
             and value["transformation"] in {"none", "raw", "base64", "hex"},
             "Invalid current classification")
    _require(type(value["supported"]) is bool and type(value["static_prohibition"]) is bool,
             "Invalid current flags")
    resources = value["sensitive_resources"]
    _require(type(resources) is list, "Invalid current resources")
    for resource in resources:
        _text(resource, "recognized resource")
    _require(resources == sorted(set(resources)), "Duplicate or unsorted current resources")


def validate_live_record(record, manifest):
    """Validate one m6-record-v1 shape against an already trusted live manifest.

    This is structural validation, not proof of host origin, detector findings,
    actual grant eligibility, or downstream effects.
    """
    _require(type(manifest) is dict, "Invalid live manifest")
    _require(type(record) is dict, "Record must be an object")
    kind = record.get("event_type")
    _text(kind, "event type")
    _require(kind in LIFECYCLE_BODY_KEYS, "Unknown live record type")
    _object(record, _ENVELOPE | ({"call_id"} if kind in _CALL_PHASES else set()), "record")
    _require(record["schema_version"] == RECORD_SCHEMA, "Wrong live record schema")
    for key in IDENTITY_KEYS:
        _text(record[key], key)
        _require(record[key] == manifest[key], "Live record identity mismatch")
    _text(record["event_id"], "event ID")
    _ordinal(record["seq"], "sequence")
    _require(is_digest(record["prev_hash"]), "Invalid previous hash")
    stamp = record["observed_at_utc"]
    _require(type(stamp) is str and stamp.endswith("Z"), "Invalid UTC timestamp")
    try:
        datetime.fromisoformat(stamp)
    except ValueError as exc:
        raise ValueError("Invalid UTC timestamp") from exc
    if kind in _CALL_PHASES:
        _text(record["call_id"], "call ID")
    body = record["body"]
    _object(body, LIFECYCLE_BODY_KEYS[kind], "body")
    if kind == "SESSION_START":
        _require(body["record_class"] == RECORD_CLASS
                 and body["run_challenge"] == manifest["run_challenge"]
                 and body["execution_profile"] == manifest["execution_profile"]
                 and body["manifest_digest"] == manifest_digest(manifest),
                 "Live start does not bind manifest")
    elif kind in {"GRANT", "REVOKE_SCOPE"}:
        _scope(body["scope"], record["task_id"])
        _require(body["host_origin"] == "trusted_host", "Invalid host origin classification")
        _ordinal(body["admission_ordinal"], "admission ordinal")
        if kind == "GRANT":
            _text(body["grant_id"], "grant ID")
    elif kind == "CALL_PROPOSAL":
        _require(body["server"] == SERVER_ID, "Wrong live server")
        _text(body["tool"], "tool")
        _require(type(body["request_id"]) in (str, int), "Invalid request ID")
        _ordinal(body["admission_ordinal"], "admission ordinal")
        _current(body["current"])
    elif kind == "DETECTOR_FINDING":
        for key in body.keys() - {"supporting_event_ids"}:
            _text(body[key], key)
        _require(body["detector_id"] in DETECTOR_IDS
                 and is_digest(body["detector_digest"])
                 and is_digest(body["policy_digest"]), "Invalid finding identity")
        _require(body["behavioral_verdict"] in {"ALLOW", "SUSPICIOUS", "POLICY_VIOLATION"}
                 and body["authorization_assessment"] in
                 {"AUTHORIZED", "UNAUTHORIZED", "INDETERMINATE"}, "Invalid finding verdict")
        _require(body["hypothetical_recommendation"] ==
                 ("ALLOW" if body["behavioral_verdict"] == "ALLOW" else "DENY"),
                 "Invalid finding recommendation")
        refs = body["supporting_event_ids"]
        _require(type(refs) is list, "Invalid finding references")
        for ref in refs:
            _text(ref, "finding reference")
        _require(refs == sorted(set(refs)), "Duplicate or unsorted finding references")
    elif kind == "DISPATCH_DECISION":
        for key in body:
            _text(body[key], key)
        _require(body["dispatch_decision"] in {"ALLOW", "DENY"}
                 and body["authorization_assessment"] in
                 {"AUTHORIZED", "UNAUTHORIZED", "INDETERMINATE"}, "Invalid live decision")
    elif kind == "DISPATCH_INTENT":
        validate_intent_body(body, record["task_id"], record["call_id"])
    elif kind == "TOOL_OUTCOME":
        for key in body:
            _require(type(body[key]) is str, f"Invalid outcome {key}")
        _require(body["server"] == SERVER_ID and bool(body["tool"])
                 and body["status"] in {"succeeded", "failed", "denied", "unknown"}
                 and body["sensitivity"] in {"public", "sensitive"}, "Invalid live outcome")
    elif kind == "SESSION_END":
        _require(body["closure_status"] == "CLOSED", "Invalid live end status")


@dataclass(frozen=True)
class LiveDraft:
    event_type: str
    body_bytes: bytes
    call_id: str = ""
    event_id: str = ""


def live_draft(event_type, body, *, call_id="", event_id=None):
    """Freeze caller-owned body before a transaction can be attempted."""
    _text(event_type, "event type")
    _require(event_type in LIFECYCLE_BODY_KEYS, "Unknown live record type")
    _require(type(call_id) is str, "Invalid call ID")
    _require((event_type in _CALL_PHASES) == bool(call_id), "Call ID/phase mismatch")
    if event_id is None:
        event_id = str(uuid4())
    _text(event_id, "event ID")
    return LiveDraft(event_type, _encode(body), call_id, event_id)


@dataclass(frozen=True)
class LiveCommitReceipt:
    session_id: str
    first_seq: int
    last_seq: int
    batch_count: int
    record_count: int
    final_head: str
    event_ids: tuple[str, ...]
    event_types: tuple[str, ...]


@dataclass(frozen=True)
class LiveContinuity:
    record_count: int
    final_head: str
    lifecycle: str
    failure: str = ""


def _initial_phase():
    return {"started": False, "closed": False, "unknown": False, "ordinal": 0,
            "events": set(), "calls": set(), "issued": set(), "pending": None}


def _phases(records, phase, manifest):
    """Check record order only; the later controller owns permission semantics."""
    admissions = 0
    new_proposal = False
    dispatched_outcome = False
    for record in records:
        kind, body = record["event_type"], record["body"]
        _require(record["event_id"] not in phase["events"], "Duplicate event ID")
        if kind == "SESSION_START":
            _require(not phase["started"], "Repeated session start")
            phase["started"] = True
        else:
            _require(phase["started"] and not phase["closed"] and not phase["unknown"],
                     "Inactive live stream")
        if kind in _ADMISSIONS:
            admissions += 1
            _require(body["admission_ordinal"] == phase["ordinal"] + 1,
                     "Noncontiguous admission order")
            phase["ordinal"] += 1
        if kind in {"GRANT", "REVOKE_SCOPE"}:
            _require(phase["pending"] is None, "Control inside proposal turn")
            if kind == "GRANT":
                _require(body["grant_id"] not in phase["issued"], "Reissued grant ID")
                phase["issued"].add(body["grant_id"])
        elif kind == "CALL_PROPOSAL":
            call_id = record["call_id"]
            _require(phase["pending"] is None and call_id not in phase["calls"],
                     "Duplicate or concurrent call")
            phase["calls"].add(call_id)
            phase["pending"] = {"call": call_id, "proposal": record["event_id"],
                                "body": body, "decision": None, "intent": False,
                                "detectors": set()}
            new_proposal = True
        elif kind in _CALL_PHASES:
            pending = phase["pending"]
            _require(pending is not None and record["call_id"] == pending["call"],
                     "Uncorrelated call phase")
            if kind == "DETECTOR_FINDING":
                _require(pending["decision"] is None and body["detector_id"] not in
                         pending["detectors"] and pending["body"]["current"]["supported"],
                         "Repeated, late, or unsupported finding")
                _require(body["evaluated_event_id"] == pending["proposal"]
                         and set(body["supporting_event_ids"]) <= phase["events"],
                         "Unavailable finding reference")
                pending["detectors"].add(body["detector_id"])
            elif kind == "DISPATCH_DECISION":
                _require(pending["decision"] is None, "Repeated decision")
                expected = set(DETECTOR_IDS) if pending["body"]["current"]["supported"] else set()
                _require(pending["detectors"] == expected, "Missing or unexpected findings")
                if body["dispatch_decision"] == "ALLOW":
                    _require(pending["body"]["current"]["supported"]
                             and not pending["body"]["current"]["static_prohibition"],
                             "Unsupported or prohibited dispatch")
                pending["decision"] = body["dispatch_decision"]
            elif kind == "DISPATCH_INTENT":
                _require(pending["decision"] == "ALLOW" and not pending["intent"],
                         "Early, denied, or duplicate intent")
                if body["reservation_status"] == "OBSERVATION_OVERRIDE":
                    profile = manifest["execution_profile"]
                    config = manifest["configuration"]
                    current = pending["body"]["current"]
                    _require(profile["mode"] == "observation" and
                             profile["synthetic_local_sink_override"] is True and
                             config["controller_profile"]["synthetic_local_sink_override"] is True and
                             config["synthetic_experiment"] is True and
                             current["operation"] == "send" and
                             current["destination"] == config["synthetic_sink"],
                             "Observation override disabled or outside configured local sink")
                pending["intent"] = True
            elif kind == "TOOL_OUTCOME":
                _require(pending["decision"] is not None, "Outcome before decision")
                denied = pending["decision"] == "DENY"
                _require((body["status"] == "denied") == denied
                         and (denied or pending["intent"]), "Outcome/intent mismatch")
                current = pending["body"]["current"]
                _require(body["server"] == pending["body"]["server"]
                         and body["tool"] == pending["body"]["tool"]
                         and all(body[key] == current[key] for key in
                                 ("operation", "resource", "destination", "sensitivity",
                                  "transformation")), "Outcome facts changed")
                dispatched_outcome |= not denied
                phase["unknown"] |= body["status"] == "unknown"
                phase["pending"] = None
        elif kind == "SESSION_END":
            _require(phase["pending"] is None, "Pending call cannot end")
            phase["closed"] = True
        phase["events"].add(record["event_id"])
    _require(admissions <= 1, "Multiple admissions in one transaction")
    _require(not new_proposal or not dispatched_outcome,
             "Dispatched outcome cannot share its pre-dispatch transaction")
    pending = phase["pending"]
    _require(pending is None or pending["intent"],
             "Proposal, findings, decision and intent must commit together")
    if any(record["event_type"] in {"GRANT", "REVOKE_SCOPE", "SESSION_START", "SESSION_END"}
           for record in records):
        _require(len(records) == 1, "Control or session boundary must commit alone")
    return phase


class LiveAuditSession:
    """One fresh live stream; SQLite is output storage, never restart authority."""

    database_version = 6

    def __init__(self, path, manifest, inventory):
        try:
            validate_live_manifest(manifest, inventory)
            _encode(manifest)
            self.manifest = deepcopy(manifest)
            self.identity = {key: self.manifest[key] for key in IDENTITY_KEYS}
            self.state = LiveContinuity(0, genesis(self.manifest), "CREATED")
        except (ValueError, TypeError, KeyError, RecursionError, UnicodeError) as exc:
            raise LiveAuditError("Invalid live manifest or inventory") from exc
        self._phase = _initial_phase()
        self._lock = threading.RLock()
        try:
            self._connection = sqlite3.connect(path, isolation_level=None, timeout=5)
        except sqlite3.Error as exc:
            raise LiveAuditError("Cannot open live audit storage") from exc
        try:
            self._connection.execute("PRAGMA journal_mode=DELETE")
            self._connection.execute("PRAGMA synchronous=FULL")
            self._initialize_storage()
            self.append_batch((live_draft("SESSION_START", {
                "record_class": RECORD_CLASS,
                "run_challenge": self.manifest["run_challenge"],
                "execution_profile": self.manifest["execution_profile"],
                "manifest_digest": manifest_digest(self.manifest)}),))
        except Exception:
            if self.state.lifecycle in {"CREATED", "ACTIVE"}:
                self._halt("INITIALIZATION_FAILED")
            try:
                self._connection.close()
            except Exception:
                pass  # Preserve the initialization error, especially ambiguous persistence.
            raise

    def _initialize_storage(self):
        commit_attempted = False
        try:
            self._connection.execute("BEGIN IMMEDIATE")
            version = self._connection.execute("PRAGMA main.user_version").fetchone()[0]
            if version == 0:
                _require(not self._connection.execute(
                    "SELECT 1 FROM main.sqlite_schema LIMIT 1").fetchone(),
                    "Database already has an unrelated schema")
                self._connection.execute(_TABLE)
                self._connection.execute(_INDEX)
                self._connection.execute(_TASK_START_INDEX)
                self._connection.execute(f"PRAGMA main.user_version={self.database_version}")
            self._validate_storage_schema()
            collision = self._connection.execute("""SELECT 1 FROM main.m6_live_records
                WHERE session_id=? OR task_id=? LIMIT 1""",
                (self.identity["session_id"], self.identity["task_id"])).fetchone()
            _require(collision is None, "Existing rows cannot restore a live task")
            commit_attempted = True
            self._connection.execute("COMMIT")
            _require(not self._transaction_open(), "Storage initialization commit unconfirmed")
        except Exception as exc:
            if isinstance(exc, LiveAmbiguousCommit):
                raise
            if self._transaction_open():
                try:
                    self._connection.rollback()
                    _require(not self._transaction_open(),
                             "Storage initialization rollback unconfirmed")
                except LiveAmbiguousCommit:
                    raise
                except Exception:
                    self._halt("ROLLBACK_UNCONFIRMED")
                    raise LiveAmbiguousCommit("Storage initialization rollback unconfirmed") from exc
                raise LiveAuditError("Live storage initialization failed; rollback confirmed") from exc
            if commit_attempted:
                self._halt("AMBIGUOUS_COMMIT")
                raise LiveAmbiguousCommit("Storage initialization commit acknowledgement ambiguous") from exc
            raise LiveAuditError("Live storage initialization failed") from exc

    def _validate_storage_schema(self):
        _require(self._transaction_open(), "Schema check requires transaction")
        _require(not self._connection.execute("SELECT 1 FROM temp.sqlite_schema LIMIT 1").fetchone(),
                 "Unexpected temporary schema")
        _require(self._connection.execute("PRAGMA main.user_version").fetchone()[0] ==
                 self.database_version, "Wrong live database version")
        normalized = lambda sql: " ".join(sql.split()) if sql is not None else None
        expected = {
            ("table", "m6_live_records", "m6_live_records", normalized(_TABLE)),
            ("index", "m6_live_call_phases", "m6_live_records", normalized(_INDEX)),
            ("index", "m6_live_task_start", "m6_live_records", normalized(_TASK_START_INDEX)),
            ("index", "sqlite_autoindex_m6_live_records_1", "m6_live_records", None),
            ("index", "sqlite_autoindex_m6_live_records_2", "m6_live_records", None),
        }
        actual = {(kind, name, table, normalized(sql)) for kind, name, table, sql in
                  self._connection.execute(
                      "SELECT type,name,tbl_name,sql FROM main.sqlite_schema").fetchall()}
        _require(actual == expected, "Unapproved live database schema")

    def _insert_prepared(self, rows):
        for row in rows:
            self._connection.execute("""INSERT INTO main.m6_live_records
                (session_id,seq,event_id,event_type,call_id,run_id,task_id,
                 monitor_instance_id,record_bytes,event_hash) VALUES (?,?,?,?,?,?,?,?,?,?)""", row)

    def _verify_stored_batch(self, rows):
        actual = self._connection.execute("""SELECT session_id,seq,event_id,event_type,
            call_id,run_id,task_id,monitor_instance_id,record_bytes,event_hash
            FROM main.m6_live_records WHERE session_id=? AND seq BETWEEN ? AND ?
            ORDER BY seq""", (self.identity["session_id"], rows[0][1], rows[-1][1])).fetchall()
        _require(actual == list(rows), "Stored live batch differs from prepared rows")

    def _commit(self):
        self._connection.execute("COMMIT")

    def _halt(self, reason):
        self.state = LiveContinuity(self.state.record_count, self.state.final_head,
                                    "HALTED", reason)

    def _transaction_open(self):
        try:
            return self._connection.in_transaction
        except Exception as exc:
            self._halt("TRANSACTION_STATE_UNKNOWN")
            raise LiveAmbiguousCommit("Live transaction state unknown") from exc

    def append_batch(self, drafts):
        """Return a receipt only after exact readback and confirmed COMMIT."""
        with self._lock:
            if self.state.lifecycle not in {"CREATED", "ACTIVE"}:
                raise LiveAuditError("Inactive live audit context")
            try:
                _require(type(drafts) in (list, tuple) and bool(drafts), "Invalid live batch")
                records, rows = [], []
                head = self.state.final_head
                for seq, item in enumerate(drafts, self.state.record_count + 1):
                    _require(type(item) is LiveDraft and type(item.body_bytes) is bytes,
                             "Invalid live draft")
                    body = decode(item.body_bytes)
                    record = {"schema_version": RECORD_SCHEMA, **self.identity,
                              "event_id": item.event_id, "seq": seq,
                              "observed_at_utc": datetime.now(timezone.utc).isoformat(
                                  timespec="microseconds").replace("+00:00", "Z"),
                              "event_type": item.event_type, "body": body, "prev_hash": head}
                    if item.event_type in _CALL_PHASES:
                        record["call_id"] = item.call_id
                    validate_live_record(record, self.manifest)
                    head = event_hash(record)
                    encoded = _encode(record)
                    records.append(record)
                    rows.append((record["session_id"], seq, record["event_id"],
                                 record["event_type"], record.get("call_id"),
                                 record["run_id"], record["task_id"],
                                 record["monitor_instance_id"], encoded, head))
                phase = _phases(records, deepcopy(self._phase), self.manifest)
                receipt = LiveCommitReceipt(self.identity["session_id"], records[0]["seq"],
                                            records[-1]["seq"], len(records), records[-1]["seq"],
                                            head, tuple(r["event_id"] for r in records),
                                            tuple(r["event_type"] for r in records))
            except (ValueError, TypeError, KeyError, RecursionError, UnicodeError) as exc:
                self._halt("INVALID_RECORD")
                raise LiveAuditError("Invalid live audit batch") from exc
            try:
                self._connection.execute("BEGIN IMMEDIATE")
                self._validate_storage_schema()
                self._insert_prepared(rows)
                self._verify_stored_batch(rows)
            except LiveAmbiguousCommit:
                raise
            except Exception as exc:
                try:
                    self._connection.rollback()
                    _require(not self._transaction_open(), "Rollback unconfirmed")
                except LiveAmbiguousCommit:
                    raise
                except Exception:
                    self._halt("ROLLBACK_UNCONFIRMED")
                    raise LiveAmbiguousCommit("Live rollback outcome unknown") from exc
                self._halt("ROLLED_BACK")
                raise LiveAuditError("Live batch failed; rollback confirmed") from exc
            try:
                self._commit()
                _require(not self._transaction_open(),
                         "Live commit returned with an open transaction")
            except Exception as exc:
                if isinstance(exc, LiveAmbiguousCommit):
                    raise
                if self._transaction_open():
                    try:
                        self._connection.rollback()
                        _require(not self._transaction_open(), "Rollback unconfirmed")
                    except LiveAmbiguousCommit:
                        raise
                    except Exception:
                        self._halt("ROLLBACK_UNCONFIRMED")
                        raise LiveAmbiguousCommit("Live commit/rollback outcome unknown") from exc
                    self._halt("ROLLED_BACK")
                    raise LiveAuditError("Live commit failed; rollback confirmed") from exc
                self._halt("AMBIGUOUS_COMMIT")
                raise LiveAmbiguousCommit("Live commit acknowledgement ambiguous") from exc
            self._phase = phase
            self.state = LiveContinuity(receipt.record_count, receipt.final_head,
                "CLOSED_UNSEALED" if phase["closed"] else
                "HALTED" if phase["unknown"] else "ACTIVE",
                "UNKNOWN_OUTCOME" if phase["unknown"] else "")
            return receipt

    def close(self):
        """Release the connection; never recover authority or seal records."""
        with self._lock:
            if self.state.lifecycle in {"CREATED", "ACTIVE"}:
                self._halt("UNFINISHED_CONTEXT")
            self._connection.close()
