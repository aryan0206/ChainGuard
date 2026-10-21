"""M5 local trusted expectation registry. Never executes tools or restores authority.

Registry rollback/tampering is outside the audit-storage attack boundary.
Unlike execution commits, ambiguous registry commits reconcile on explicit retry.
For live evidence, the one registered signer pin identifies the trusted signer;
the registry enforces supplied trust inputs, not how the assessor obtained them.
"""

from dataclasses import dataclass, replace
from pathlib import Path
import sqlite3

from cryptography.hazmat.primitives import serialization

from chainguard.audit import _require
from chainguard.canonical import decode, encode
from chainguard.evidence import (DETECTOR_IDS, DOMAINS, _p256, inventory_digest, sha256,
                                validate_commitment, validate_configuration, validate_inventory)
from chainguard.verifier import inspect_run


SCHEMA = {
    "expected_runs": """CREATE TABLE expected_runs (
        run_id TEXT PRIMARY KEY, challenge TEXT NOT NULL UNIQUE,
        inventory_bytes BLOB NOT NULL, inventory_digest TEXT NOT NULL,
        config_bytes BLOB NOT NULL, pins_bytes BLOB NOT NULL,
        state TEXT NOT NULL CHECK(state IN ('ACTIVE','ACCEPTED','CANCELLED','FAILED')))""",
    "accepted_sessions": """CREATE TABLE accepted_sessions (
        run_id TEXT NOT NULL REFERENCES expected_runs(run_id), session_id TEXT NOT NULL,
        commitment_bytes BLOB NOT NULL, commitment_digest TEXT NOT NULL,
        PRIMARY KEY(run_id,session_id))""",
}


class RegistryError(RuntimeError):
    pass


class RegistryAmbiguous(RegistryError):
    pass


def commitment_digest(closure):
    """Digest of the profile's ECDSA-SHA256 signing input."""
    _require(type(closure) is dict, "Invalid commitment")
    if closure.get("schema_version") == "m6-live-commitment-v1":
        from chainguard.m6_live_evidence import live_commitment_digest
        return live_commitment_digest(closure)
    if closure.get("schema_version") == "m6-commitment-v1":
        from chainguard.permission_profile import validate_permission_commitment
        validate_permission_commitment(closure)
    elif closure.get("schema_version") == "m4-commitment-v1":
        validate_commitment(closure)
    else:
        raise ValueError("Unknown commitment profile")
    return sha256(DOMAINS["COMMITMENT"] + encode(closure))


def _validate_expected_configuration(config):
    _require(type(config) is dict, "Invalid expected configuration")
    if config.get("schema_version") == "m6-live-configuration-v1":
        from chainguard.m6_live_profile import validate_live_configuration
        validate_live_configuration(config)
    elif config.get("schema_version") == "m6-configuration-v1":
        from chainguard.permission_profile import validate_permission_configuration
        validate_permission_configuration(config)
    elif config.get("schema_version") == "m4-configuration-v1":
        validate_configuration(config)
    else:
        raise ValueError("Unknown expected configuration profile")


def _inspect_expected_run(snapshots, inventory, config, pins):
    if config["schema_version"] == "m6-live-configuration-v1":
        from chainguard.evidence import SUITE
        from chainguard.m6_live_profile import PROFILE_VERSIONS
        from chainguard.m6_live_verifier import inspect_live_run
        signer_id, public_key = _live_pin(pins)
        return inspect_live_run(snapshots, expected_inventory=inventory,
            expected_configuration=config, trusted_signer_key_id=signer_id,
            pinned_public_key=public_key, accepted_versions=PROFILE_VERSIONS,
            accepted_suite=SUITE)
    if config["schema_version"] == "m6-configuration-v1":
        from chainguard.permission_profile import inspect_permission_run
        return inspect_permission_run(snapshots, inventory, config, pins)
    if config["schema_version"] == "m4-configuration-v1":
        return inspect_run(snapshots, inventory, config, pins)
    raise ValueError("Unknown expected configuration profile")


def _live_pin(pins):
    _require(type(pins) is dict and len(pins) == 1,
             "Live expectation requires exactly one assessor-registered signer pin")
    return next(iter(pins.items()))


def _live_result_statuses(report, snapshots):
    """Check the live inspector's result shape before it can gate a commit."""
    from chainguard.m6_live_verifier import DIMENSIONS

    session_reasons = {
        "package_schema": {"PASS": "CANONICAL_LIVE_PACKAGE",
                           "FAIL": "INVALID_OR_UNSUPPORTED_PACKAGE"},
        "commitment_integrity": {"PASS": "CHAIN_AND_CLOSURE_MATCH",
                                 "FAIL": "CHAIN_OR_CLOSURE_MISMATCH"},
        "trusted_signature": {"PASS": "PINNED_SIGNER_VERIFIED",
                              "FAIL": "SIGNER_OR_SIGNATURE_MISMATCH"},
        "expected_binding": {"PASS": "ASSESSOR_CONTEXT_MATCH",
                             "FAIL": "ASSESSOR_CONTEXT_MISMATCH"},
        "inventory_completeness": {"PASS": "SESSION_PRESENT"},
        "lifecycle_semantics": {"PASS": "LIVE_LIFECYCLE_RECONSTRUCTED",
                                "FAIL": "INVALID_LIVE_LIFECYCLE",
                                "INCOMPLETE": "CLEAN_CLOSE_MISSING"},
        "finding_reproduction": {"PASS": "NORMALIZED_FINDINGS_REPRODUCED",
                                 "FAIL": "FINDINGS_MISMATCH"},
    }
    if set(session_reasons) != set(DIMENSIONS):
        return None

    def dimensions(value, *, session):
        if type(value) is not dict or set(value) != set(DIMENSIONS):
            return None
        for name, item in value.items():
            if (type(item) is not dict or set(item) != {"status", "reason"}
                    or type(item["status"]) is not str
                    or item["status"] not in {"PASS", "FAIL", "INCOMPLETE", "NOT_CHECKED"}
                    or type(item["reason"]) is not str or not item["reason"]):
                return None
            status, reason = item["status"], item["reason"]
            if session:
                allowed = ("PREREQUISITE_UNAVAILABLE" if status == "NOT_CHECKED"
                           else session_reasons[name].get(status))
                if reason != allowed:
                    return None
            elif status == "PASS":
                if reason != ("EXACT_EXPECTED_SESSIONS" if name == "inventory_completeness"
                              else "AGGREGATED_SESSION_CHECKS"):
                    return None
            elif name == "inventory_completeness":
                if reason not in {"PREREQUISITE_UNAVAILABLE", "EXACT_EXPECTED_SESSIONS",
                                  "EXPECTED_SESSION_MISSING", "INVALID_DUPLICATE_OR_EXTRA_SESSION"} or (
                        reason == "PREREQUISITE_UNAVAILABLE" and status != "NOT_CHECKED"):
                    return None
            elif not (reason == "AGGREGATED_SESSION_CHECKS" or
                    reason == "PREREQUISITE_UNAVAILABLE" and status == "NOT_CHECKED" or
                    name == "expected_binding" and status == "FAIL" and
                    reason == "INVALID_ASSESSOR_INPUT"):
                return None
        return {item["status"] for item in value.values()}

    def valid_reproduction(value):
        if type(value) is not dict or set(value) != {
                "proposals", "findings_reproduced", "b2_agreeing_prefixes", "basis"}:
            return False
        proposals = value["proposals"]
        return (type(proposals) is int and proposals >= 0
                and type(value["findings_reproduced"]) is int
                and value["findings_reproduced"] == proposals * len(DETECTOR_IDS)
                and type(value["b2_agreeing_prefixes"]) is int
                and value["b2_agreeing_prefixes"] == proposals
                and type(value["basis"]) is str
                and value["basis"] == "recorded_normalized_facts_only")

    if (type(report) is not dict or set(report) !=
            {"mode", "fresh_submission", "inspection_passed", "dimensions", "sessions"}
            or type(report["mode"]) is not str or report["mode"] != "INSPECT_RUN"
            or type(report["fresh_submission"]) is not str
            or report["fresh_submission"] != "NOT_CHECKED"
            or type(report["inspection_passed"]) is not bool
            or type(report["sessions"]) is not list
            or len(report["sessions"]) != len(snapshots)):
        return None
    statuses = dimensions(report["dimensions"], session=False)
    if statuses is None or report["inspection_passed"] is not (statuses == {"PASS"}):
        return None
    for session in report["sessions"]:
        if (type(session) is not dict or not
                {"mode", "fresh_submission", "inspection_passed", "dimensions"} <= set(session)
                or set(session) - {"mode", "fresh_submission", "inspection_passed",
                                   "dimensions", "reproduction"}
                or type(session["mode"]) is not str or session["mode"] != "INSPECT"
                or type(session["fresh_submission"]) is not str
                or session["fresh_submission"] != "NOT_CHECKED"
                or type(session["inspection_passed"]) is not bool):
            return None
        session_statuses = dimensions(session["dimensions"], session=True)
        if (session_statuses is None or
                session["inspection_passed"] is not (session_statuses == {"PASS"})):
            return None
        reproduced = session["dimensions"]["finding_reproduction"]["status"] == "PASS"
        if (('reproduction' in session) != reproduced or
                reproduced and not valid_reproduction(session["reproduction"])):
            return None
        if report["inspection_passed"] and (session["inspection_passed"] is not True
                or session_statuses != {"PASS"}):
            return None
    if report["inspection_passed"] and statuses != {"PASS"}:
        return None
    return statuses


def _encode_pins(pins):
    _require(type(pins) is dict and bool(pins), "Missing external public-key pins")
    encoded = {}
    for key_id, key in pins.items():
        _require(type(key_id) is str and bool(key_id), "Invalid trusted key ID")
        _p256(key)
        encoded[key_id] = key.public_bytes(serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo).decode("ascii")
    return encode(encoded)


def _decode_pins(data):
    values = decode(data)
    _require(type(values) is dict and bool(values), "Invalid stored pins")
    pins = {key_id: serialization.load_pem_public_key(pem.encode("ascii")) for key_id, pem in values.items()}
    _require(_encode_pins(pins) == data, "Noncanonical stored pins")
    return pins


@dataclass(frozen=True)
class ExpectedRun:
    run_id: str
    challenge: str
    inventory_bytes: bytes
    inventory_digest: str
    config_bytes: bytes
    pins_bytes: bytes
    state: str

    @property
    def identity(self):
        return {"run_id": self.run_id, "run_challenge": self.challenge,
                "expected_inventory_digest": self.inventory_digest}


def _result(status, reason, expectation=None, verification=None, commitments=(), durability="NOT_CHECKED"):
    return {"mode": "FRESH_SUBMISSION", "status": status, "reason": reason,
            "identity": expectation.identity if expectation else None,
            "verification": verification, "commitments": list(commitments), "registry_durability": durability}


class AcceptanceRegistry:
    """Explicit create; opening a missing registry MUST NOT erase replay history."""

    @classmethod
    def create(cls, path):
        path = Path(path).resolve()
        path.touch(exist_ok=False)
        connection = sqlite3.connect(path, isolation_level=None)
        try:
            connection.execute("PRAGMA journal_mode=DELETE")
            connection.execute("PRAGMA synchronous=FULL")
            connection.execute("BEGIN IMMEDIATE")
            for sql in SCHEMA.values():
                connection.execute(sql)
            connection.execute("PRAGMA user_version=1")
            connection.execute("COMMIT")
        finally:
            connection.close()
        return cls(path)

    def __init__(self, path):
        self.path = Path(path).resolve()
        self._connection = sqlite3.connect(self.path.as_uri() + "?mode=rw", uri=True,
                                          isolation_level=None, timeout=5)
        try:
            self._connection.execute("PRAGMA journal_mode=DELETE")
            self._connection.execute("PRAGMA synchronous=FULL")
            self._connection.execute("PRAGMA foreign_keys=ON")
            self._begin()
            _require(self._connection.execute("PRAGMA quick_check").fetchall() == [("ok",)], "Corrupt registry")
            _require(not self._connection.execute("PRAGMA foreign_key_check").fetchall(), "Orphan accepted commitment")
            for (run_id,) in self._connection.execute("SELECT run_id FROM expected_runs").fetchall():
                self._load(run_id)
            self._connection.rollback()
        except Exception as exc:
            self._connection.close()
            raise RegistryError("Registry unavailable or inconsistent") from exc

    def close(self):
        self._connection.close()

    def _check_schema(self):
        _require(self._connection.in_transaction, "Registry schema check outside transaction")
        _require(self._connection.execute("PRAGMA journal_mode").fetchone() == ("delete",)
                 and self._connection.execute("PRAGMA synchronous").fetchone() == (2,)
                 and self._connection.execute("PRAGMA foreign_keys").fetchone() == (1,), "Unsafe registry transaction settings")
        _require(self._connection.execute("PRAGMA main.user_version").fetchone() == (1,), "Unknown registry schema")
        _require(not self._connection.execute("SELECT 1 FROM temp.sqlite_schema LIMIT 1").fetchone(), "Temporary registry schema")
        expected = {("table", name, name, " ".join(sql.split())) for name, sql in SCHEMA.items()}
        expected.update({("index", "sqlite_autoindex_expected_runs_1", "expected_runs", None),
                         ("index", "sqlite_autoindex_expected_runs_2", "expected_runs", None),
                         ("index", "sqlite_autoindex_accepted_sessions_1", "accepted_sessions", None)})
        actual = {(t, n, table, " ".join(sql.split()) if sql else None)
                  for t, n, table, sql in self._connection.execute("SELECT type,name,tbl_name,sql FROM main.sqlite_schema")}
        _require(actual == expected, "Unapproved registry schema")

    def _begin(self):
        self._connection.execute("BEGIN IMMEDIATE")
        self._check_schema()

    def _rollback(self):
        try:
            self._connection.rollback()
            _require(not self._connection.in_transaction, "Registry rollback unconfirmed")
        except Exception as exc:
            raise RegistryAmbiguous("REGISTRY_ROLLBACK_UNCONFIRMED") from exc

    def _commit(self):
        self._connection.execute("COMMIT")

    def _confirm(self):
        try:
            self._commit()
            _require(not self._connection.in_transaction, "Registry commit not confirmed")
        except Exception as exc:
            # No guessed success or rollback claim. Reopen/reconcile on retry.
            self._connection.close()
            raise RegistryAmbiguous("REGISTRY_COMMIT_AMBIGUOUS") from exc

    def _load(self, run_id):
        row = self._connection.execute("SELECT * FROM main.expected_runs WHERE run_id=?", (run_id,)).fetchone()
        if row is None:
            return None
        expectation = ExpectedRun(*row)
        inventory = decode(expectation.inventory_bytes)
        validate_inventory(inventory)
        config = decode(expectation.config_bytes)
        _validate_expected_configuration(config)
        pins = _decode_pins(expectation.pins_bytes)
        if config["schema_version"] == "m6-live-configuration-v1":
            _live_pin(pins)
        _require(inventory["run_id"] == run_id and inventory["run_challenge"] == expectation.challenge
                 and inventory_digest(inventory) == expectation.inventory_digest, "Inconsistent expected identity")
        rows = self._connection.execute("SELECT session_id,commitment_bytes,commitment_digest FROM main.accepted_sessions WHERE run_id=? ORDER BY session_id", (run_id,)).fetchall()
        if expectation.state == "ACCEPTED":
            required = {entry["session_id"]: entry for entry in inventory["sessions"]}
            _require({r[0] for r in rows} == set(required), "Incomplete accepted inventory")
            for session_id, data, digest in rows:
                closure = decode(data)
                if config["schema_version"] == "m6-live-configuration-v1":
                    _require(closure["schema_version"] == "m6-live-commitment-v1",
                             "Accepted live commitment profile mismatch")
                _require(commitment_digest(closure) == digest and closure["run_id"] == run_id
                         and closure["run_challenge"] == expectation.challenge
                         and closure["expected_inventory_digest"] == expectation.inventory_digest
                         and all(closure[k] == v for k, v in required[session_id].items()), "Inconsistent accepted commitment")
        else:
            _require(expectation.state in {"ACTIVE", "CANCELLED", "FAILED"} and not rows, "Partial registry acceptance")
        return expectation

    def expected(self, run_id):
        try:
            self._begin()
            result = self._load(run_id)
            self._connection.rollback()
            return result
        except Exception:
            self._rollback()
            raise

    def register(self, inventory, config, pins):
        validate_inventory(inventory)
        _validate_expected_configuration(config)
        if config["schema_version"] == "m6-live-configuration-v1":
            _live_pin(pins)
        row = (inventory["run_id"], inventory["run_challenge"], encode(inventory), inventory_digest(inventory),
               encode(config), _encode_pins(pins), "ACTIVE")
        try:
            self._begin()
            _require(self._load(row[0]) is None, "Expected run already registered")
            self._connection.execute("INSERT INTO main.expected_runs VALUES (?,?,?,?,?,?,?)", row)
            _require(self._load(row[0]) == ExpectedRun(*row), "Expected registration not materialized")
        except Exception:
            self._rollback()
            raise
        self._confirm()
        return ExpectedRun(*row)

    def terminate(self, run_id, state):
        _require(state in {"CANCELLED", "FAILED"}, "Invalid trusted lifecycle transition")
        try:
            self._begin()
            current = self._load(run_id)
            _require(current is not None and current.state == "ACTIVE", "Expectation is not ACTIVE")
            self._connection.execute("UPDATE main.expected_runs SET state=? WHERE run_id=?", (state, run_id))
            intended = replace(current, state=state)
            _require(self._load(run_id) == intended, "Lifecycle transition not materialized")
        except Exception:
            self._rollback()
            raise
        self._confirm()

    def _store_acceptance(self, expectation, rows):
        self._connection.executemany("INSERT INTO main.accepted_sessions VALUES (?,?,?,?)", rows)
        self._connection.execute("UPDATE main.expected_runs SET state='ACCEPTED' WHERE run_id=? AND state='ACTIVE'",
                                 (expectation.run_id,))

    def submit(self, run_id, package_snapshots):
        expectation = None
        verification = None
        try:
            snapshots = tuple(package_snapshots)
            if not all(type(data) is bytes for data in snapshots):
                return _result("REJECTED", "MALFORMED_SUBMISSION")
            expectation = self.expected(run_id)
            if expectation is None:
                return _result("REJECTED", "UNKNOWN_EXPECTATION")
            if expectation.state != "ACTIVE":
                return _result("REJECTED", "ALREADY_ACCEPTED" if expectation.state == "ACCEPTED" else "EXPECTATION_" + expectation.state, expectation)
            config = decode(expectation.config_bytes)
            if config["schema_version"] == "m6-live-configuration-v1":
                try:
                    verification = _inspect_expected_run(snapshots, decode(expectation.inventory_bytes),
                        config, _decode_pins(expectation.pins_bytes))
                except Exception:
                    return _result("NOT_CHECKED", "VERIFICATION_NOT_CHECKED", expectation)
                statuses = _live_result_statuses(verification, snapshots)
                if statuses is None:
                    return _result("NOT_CHECKED", "VERIFICATION_NOT_CHECKED", expectation, verification)
            else:
                verification = _inspect_expected_run(snapshots, decode(expectation.inventory_bytes),
                    config, _decode_pins(expectation.pins_bytes))
                statuses = {d["status"] for d in verification["dimensions"].values()}
            if verification["inspection_passed"] is not True:
                status = "REJECTED" if "FAIL" in statuses else "INCOMPLETE" if "INCOMPLETE" in statuses else "NOT_CHECKED"
                return _result(status, "VERIFICATION_" + status, expectation, verification)
            closures = sorted((decode(data)["commitment"] for data in snapshots), key=lambda c: c["session_id"])
            rows = tuple((run_id, c["session_id"], encode(c), commitment_digest(c)) for c in closures)
            try:
                self._begin()
                current = self._load(run_id)
                if current != expectation:
                    self._connection.rollback()
                    return _result("REJECTED", "EXPECTATION_CHANGED", expectation, verification)
                self._store_acceptance(expectation, rows)
                accepted = self._load(run_id)
                actual = self._connection.execute("SELECT * FROM main.accepted_sessions WHERE run_id=? ORDER BY session_id", (run_id,)).fetchall()
                _require(accepted == replace(expectation, state="ACCEPTED")
                         and actual == list(rows), "Exact registry acceptance not materialized")
            except Exception:
                self._rollback()
                raise
            self._confirm()
            commitments = [{"session_id": row[1], "commitment_digest": row[3]} for row in rows]
            return _result("ACCEPTED", "FRESH_COMPLETE_RUN", expectation, verification, commitments, "COMMITTED")
        except RegistryAmbiguous as exc:
            return _result("NOT_CHECKED", str(exc), expectation, verification, durability="UNKNOWN")
        except (sqlite3.Error, RegistryError, ValueError, TypeError, KeyError) as exc:
            return _result("NOT_CHECKED", "REGISTRY_OR_INPUT_ERROR: " + str(exc), expectation, verification)
