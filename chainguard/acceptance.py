"""M5 local trusted expectation registry. Never executes tools or restores authority.

Registry rollback/tampering is outside the audit-storage attack boundary.
Unlike execution commits, ambiguous registry commits reconcile on explicit retry.
"""

from dataclasses import dataclass, replace
from pathlib import Path
import sqlite3

from cryptography.hazmat.primitives import serialization

from chainguard.audit import _require
from chainguard.canonical import decode, encode
from chainguard.evidence import (DOMAINS, _p256, inventory_digest, sha256,
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
    """Digest of the EXISTING M4 ECDSA-SHA256 signing input, not new crypto."""
    validate_commitment(closure)
    return sha256(DOMAINS["COMMITMENT"] + encode(closure))


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
        validate_configuration(decode(expectation.config_bytes))
        _decode_pins(expectation.pins_bytes)
        _require(inventory["run_id"] == run_id and inventory["run_challenge"] == expectation.challenge
                 and inventory_digest(inventory) == expectation.inventory_digest, "Inconsistent expected identity")
        rows = self._connection.execute("SELECT session_id,commitment_bytes,commitment_digest FROM main.accepted_sessions WHERE run_id=? ORDER BY session_id", (run_id,)).fetchall()
        if expectation.state == "ACCEPTED":
            required = {entry["session_id"]: entry for entry in inventory["sessions"]}
            _require({r[0] for r in rows} == set(required), "Incomplete accepted inventory")
            for session_id, data, digest in rows:
                closure = decode(data)
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
        validate_configuration(config)
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
            verification = inspect_run(snapshots, decode(expectation.inventory_bytes),
                decode(expectation.config_bytes), _decode_pins(expectation.pins_bytes))
            statuses = {d["status"] for d in verification["dimensions"].values()}
            if not verification["inspection_passed"]:
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
