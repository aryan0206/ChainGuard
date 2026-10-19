"""Host-owned, single-worker M6 gateway for the fixed synthetic tool surface.

The MCP stream has no grant/revoke entry point. Only trusted in-process host
code receives HostTask; this module does not coordinate separate processes.
"""

from concurrent.futures import Future, TimeoutError as FutureTimeout
from copy import deepcopy
from dataclasses import dataclass
import json
import os
from pathlib import Path
import queue
import subprocess
import sys
from threading import Lock, Thread, get_ident
from typing import BinaryIO
from uuid import uuid4

from chainguard import PROTOCOL_VERSION
from chainguard.detectors import B2Reference, B2Streaming, b0, b1, equivalent
from chainguard.m6_live_audit import LiveAuditSession
from chainguard.m6_live_authorization import DispatchPermit, LiveAuthorizationTask
from chainguard.m6_live_profile import (POLICY, TOOL_CONTRACTS, live_configuration,
                                        make_live_manifest, result_contract,
                                        validate_tool_arguments)
from chainguard.semantics import Scope, attach_references, project_b1


ROOT = Path(__file__).resolve().parent.parent
MAX_FRAME_BYTES = 128 * 1024
RESPONSE_TIMEOUT_SECONDS = 30
_HANDSHAKE_TIMEOUT_SECONDS = 15
_claimed_tasks = set()
_claimed_sessions = set()
_claims_lock = Lock()
_HOST_TOKEN = object()


class LiveRuntimeError(RuntimeError):
    """The task cannot safely continue through the controlled gateway."""


class _ClientRequestError(ValueError):
    def __init__(self, request_id, code, message, fatal=False):
        super().__init__(message)
        self.request_id, self.code, self.fatal = request_id, code, fatal


@dataclass(frozen=True)
class _Auxiliary:
    method: str
    request_id: str | int
    params_bytes: bytes
    output: BinaryIO | None
    done: Future | None


@dataclass(frozen=True)
class _Proposal:
    ticket: int
    request_id: str | int
    call_id: str
    tool: str
    arguments_bytes: bytes
    params_bytes: bytes
    output: BinaryIO
    done: Future


@dataclass(frozen=True)
class _Control:
    ticket: int
    kind: str
    scope: Scope
    grant_id: str
    done: Future


@dataclass(frozen=True)
class _Stop:
    done: Future


def _reject_constant(value):
    raise ValueError("Non-JSON numeric constant: " + value)


def _canonical_bytes(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def _frame(value):
    raw = _canonical_bytes(value) + b"\n"
    if len(raw) > MAX_FRAME_BYTES:
        raise ValueError("M6 frame exceeds supported size")
    return raw


def _decode(frame):
    if type(frame) is not bytes or not frame.endswith(b"\n") or len(frame) > MAX_FRAME_BYTES:
        raise ValueError("Invalid M6 frame boundary")
    value = json.loads(frame.decode("utf-8"), parse_constant=_reject_constant)
    if type(value) is not dict or value.get("jsonrpc") != "2.0":
        raise ValueError("Expected one JSON-RPC 2.0 object")
    return value


def _snapshot(raw):
    """Decode an immutable canonical parameter snapshot; never use it as a frame."""
    try:
        if type(raw) is not bytes:
            raise ValueError("Invalid parameter snapshot")
        value = json.loads(raw.decode("utf-8"), parse_constant=_reject_constant)
        if _canonical_bytes(value) != raw:
            raise ValueError("Noncanonical parameter snapshot")
        return value
    except (ValueError, TypeError, UnicodeError, RecursionError) as exc:
        raise LiveRuntimeError("Invalid queued parameter snapshot") from exc


def _valid_meta(meta):
    return (type(meta) is dict and
            type(meta.get("io.modelcontextprotocol/clientCapabilities")) is dict and
            meta.get("io.modelcontextprotocol/protocolVersion") == PROTOCOL_VERSION)


def _error(request_id, code, message):
    return _frame({"jsonrpc": "2.0", "id": request_id,
                   "error": {"code": code, "message": message}})


def _finding_body(finding, proposal_id):
    return {"evaluated_event_id": proposal_id, "detector_id": finding.detector_id,
        "detector_version": finding.detector_version,
        "detector_digest": finding.artifact_digest,
        "policy_digest": finding.policy_digest,
        "extraction_version": finding.extraction_version,
        "behavioral_verdict": finding.behavior,
        "authorization_assessment": finding.authorization,
        "hypothetical_recommendation": finding.hypothetical_recommendation,
        "rule_id": finding.rule_id,
        "supporting_event_ids": list(finding.supporting_event_ids),
        "explanation": finding.explanation}


class M6Host:
    """Trusted in-process control ingress; the client sees only stdio."""

    def open_task(self, *, db_path, trusted_inventory, task_id, session_id,
                  monitor_instance_id):
        inventory = deepcopy(trusted_inventory)
        manifest = make_live_manifest(inventory, live_configuration(), task_id,
                                      session_id, monitor_instance_id)
        # Retain attempted identities even if start or child readiness fails.
        with _claims_lock:
            if task_id in _claimed_tasks or session_id in _claimed_sessions:
                raise LiveRuntimeError("Task or session identity already attempted in this process")
            _claimed_tasks.add(task_id)
            _claimed_sessions.add(session_id)
        return HostTask(Path(db_path), inventory, manifest, _HOST_TOKEN)


class HostTask:
    """Opaque host handle; one worker exclusively owns all live authority."""

    def __init__(self, db_path, inventory, manifest, host_token):
        if host_token is not _HOST_TOKEN:
            raise LiveRuntimeError("Only the trusted host may create a task handle")
        self._db_path, self._inventory, self._manifest = db_path, inventory, manifest
        self._identity = tuple(manifest[key] for key in
                               ("run_id", "task_id", "session_id", "monitor_instance_id"))
        self._lock = Lock()
        self._state = "STARTING"
        self._ticket = 0
        self._seen_requests = set()
        self._admissions = []
        self._events_lock = Lock()
        self._child_events = []
        self._queue = queue.Queue()
        self._responses = queue.Queue(maxsize=1)
        self._ready = Future()
        self._abort_startup = False
        self._audit = None
        self._authority = None
        self._child = None
        self._worker_ident = None
        self._stdout_reader = None
        self._stderr_reader = None
        self._shadow = B2Streaming(self._identity[1], POLICY)
        self._shadow_count = 0
        self._thread = Thread(target=self._work, name="m6-task-" + self._identity[1],
                              daemon=True)
        self._thread.start()
        try:
            self._ready.result(timeout=2 * _HANDSHAKE_TIMEOUT_SECONDS + 5)
        except FutureTimeout as exc:
            with self._lock:
                if self._ready.done():
                    self._ready.result()
                    return
                self._abort_startup = True
            raise LiveRuntimeError("M6 task did not become ready") from exc
        except Exception as exc:
            with self._lock:
                self._abort_startup = True
            raise LiveRuntimeError("M6 task did not become ready") from exc

    @property
    def admissions(self):
        with self._lock:
            return tuple(self._admissions)

    @property
    def child_events(self):
        with self._events_lock:
            return tuple(deepcopy(self._child_events))

    def _enqueue_control(self, kind, scope, grant_id=""):
        done = Future()
        with self._lock:
            if self._state != "ACTIVE":
                raise LiveRuntimeError("Task is not admitting controls")
            self._ticket += 1
            ticket = self._ticket
            self._queue.put_nowait(_Control(ticket, kind, scope, grant_id, done))
            self._admissions.append((ticket, kind, grant_id))
        return done

    def grant(self, grant_id: str, scope: Scope) -> Future:
        return self._enqueue_control("GRANT", scope, grant_id)

    def revoke(self, scope: Scope) -> Future:
        return self._enqueue_control("REVOKE_SCOPE", scope)

    def _submit_client_frame(self, frame: bytes, output: BinaryIO) -> Future:
        try:
            request = _decode(frame)
        except (ValueError, UnicodeError, TypeError) as exc:
            raise _ClientRequestError(None, -32700, "Malformed M6 JSON frame", True) from exc
        request_id = request.get("id")
        if type(request_id) not in (str, int):
            raise _ClientRequestError(None, -32600, "M6 requires a string or integer request ID")
        method = request.get("method")
        if type(method) is not str or method not in {
                "server/discover", "tools/list", "tools/call"}:
            raise _ClientRequestError(request_id, -32601, "Method outside the M6 subset")
        params = request.get("params")
        meta = params.get("_meta") if type(params) is dict else None
        if not _valid_meta(meta):
            raise _ClientRequestError(request_id, -32602, "Invalid per-request MCP metadata")
        arguments = None
        tool = None
        if method == "tools/call":
            if set(params) != {"_meta", "name", "arguments"}:
                raise _ClientRequestError(request_id, -32602, "Invalid M6 call parameters")
            tool, arguments = params["name"], params["arguments"]
            try:
                validate_tool_arguments(tool, arguments)
            except (ValueError, TypeError) as exc:
                raise _ClientRequestError(request_id, -32602, "Invalid M6 tool call") from exc
            if arguments is None:
                arguments = {}
            params = {"_meta": meta, "name": tool, "arguments": deepcopy(arguments)}
        elif set(params) != {"_meta"}:
            raise _ClientRequestError(request_id, -32602, "Invalid M6 auxiliary parameters")
        clean = {"jsonrpc": "2.0", "id": request_id, "method": method,
                 "params": params}
        try:
            _frame(clean)  # Enforce the complete frame size before admission.
            params_bytes = _canonical_bytes(params)
            arguments_bytes = _canonical_bytes(arguments) if method == "tools/call" else None
        except (ValueError, UnicodeError, TypeError) as exc:
            raise _ClientRequestError(request_id, -32602, "Invalid M6 request encoding") from exc
        done = Future()
        with self._lock:
            if self._state != "ACTIVE":
                raise LiveRuntimeError("Task is not admitting client requests")
            request_key = (type(request_id), request_id)
            if request_key in self._seen_requests:
                raise _ClientRequestError(request_id, -32600, "Duplicate request ID")
            self._seen_requests.add(request_key)
            if method == "tools/call":
                self._ticket += 1
                ticket = self._ticket
                item = _Proposal(ticket, request_id, uuid4().hex, tool, arguments_bytes,
                                 params_bytes, output, done)
                self._admissions.append((ticket, "CALL_PROPOSAL", request_id))
            else:
                item = _Auxiliary(method, request_id, params_bytes, output, done)
            self._queue.put_nowait(item)
        return done

    def serve_client(self, input_stream: BinaryIO, output_stream: BinaryIO) -> None:
        """Read only MCP frames; host controls never come from this stream."""
        try:
            while frame := input_stream.readline(MAX_FRAME_BYTES + 1):
                try:
                    self._submit_client_frame(frame, output_stream).result()
                except _ClientRequestError as exc:
                    output_stream.write(_error(exc.request_id, exc.code, str(exc)))
                    output_stream.flush()
                    if exc.fatal:
                        break
                except Exception:
                    break  # Worker has halted; never retry the request.
        finally:
            try:
                self.shutdown().result(timeout=10)
            except Exception:
                pass

    def shutdown(self) -> Future:
        done = Future()
        with self._lock:
            if self._state == "ACTIVE":
                self._state = "CLOSING"
                self._queue.put_nowait(_Stop(done))
            elif self._state == "CLOSED":
                done.set_result(None)
            else:
                done.set_exception(LiveRuntimeError("Task cannot close cleanly"))
        return done

    def _read_stdout(self):
        while True:
            frame = self._child.stdout.readline(MAX_FRAME_BYTES + 1)
            while True:
                try:
                    self._responses.put(frame, timeout=0.1)
                    break
                except queue.Full:
                    with self._lock:
                        if self._state in {"CLOSING", "HALTED", "CLOSED"}:
                            return
            if not frame or len(frame) > MAX_FRAME_BYTES:
                return

    def _read_stderr(self):
        for line in self._child.stderr:
            try:
                event = json.loads(line)
            except (ValueError, UnicodeError):
                continue
            if type(event) is dict and event.get("component") in {
                    "m6_controlled_server", "m6_local_sink"}:
                with self._events_lock:
                    self._child_events.append(event)

    def _await_response(self, request_id, timeout=RESPONSE_TIMEOUT_SECONDS):
        frame = self._responses.get(timeout=timeout)
        response = _decode(frame)
        if (type(response.get("id")) is not type(request_id) or
                response.get("id") != request_id or
                ("result" in response) == ("error" in response) or
                "method" in response):
            raise LiveRuntimeError("Downstream response does not match request")
        return response

    def _write_downstream(self, item, permit=None):
        """The sole downstream stdin write; calls require a consumed permit."""
        if get_ident() != self._worker_ident:
            raise LiveRuntimeError("Only the task worker may write downstream")
        if type(item.request_id) not in (str, int):
            raise LiveRuntimeError("Invalid queued request ID")
        params = _snapshot(item.params_bytes)
        if type(params) is not dict or not _valid_meta(params.get("_meta")):
            raise LiveRuntimeError("Invalid queued MCP metadata")
        if type(item) is _Proposal:
            arguments = _snapshot(item.arguments_bytes)
            if (set(params) != {"_meta", "name", "arguments"} or
                    params["name"] != item.tool or params["arguments"] != arguments):
                raise LiveRuntimeError("Queued call differs from admitted proposal")
            try:
                validate_tool_arguments(item.tool, arguments)
            except (ValueError, TypeError) as exc:
                raise LiveRuntimeError("Invalid queued tool call") from exc
            method = "tools/call"
            expected = (*self._identity, item.call_id, item.request_id)
            if (type(permit) is not DispatchPermit or
                    (permit.run_id, permit.task_id, permit.session_id,
                     permit.monitor_instance_id, permit.call_id,
                     permit.request_id) != expected or not permit.intent_event_id):
                raise LiveRuntimeError("Permit does not bind the in-flight request")
        elif type(item) is _Auxiliary:
            if (item.method not in {"server/discover", "tools/list"} or
                    set(params) != {"_meta"} or permit is not None):
                raise LiveRuntimeError("Auxiliary request cannot dispatch a tool")
            method = item.method
        else:
            raise LiveRuntimeError("Unknown downstream request type")
        wire = _frame({"jsonrpc": "2.0", "id": item.request_id,
                       "method": method, "params": params})
        if type(item) is _Proposal:
            self._authority.take_dispatch(permit)
        written = self._child.stdin.write(wire)
        if written != len(wire):
            raise LiveRuntimeError("Incomplete downstream write")
        self._child.stdin.flush()

    def _startup(self):
        self._audit = LiveAuditSession(self._db_path, self._manifest, self._inventory)
        self._authority = LiveAuthorizationTask(self._audit)
        self._child = subprocess.Popen(
            [sys.executable, "-u", "-m", "chainguard.m6_controlled_server"],
            cwd=ROOT, env={**os.environ, "PYTHONUTF8": "1"}, stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self._stdout_reader = Thread(target=self._read_stdout, daemon=True)
        self._stderr_reader = Thread(target=self._read_stderr, daemon=True)
        self._stdout_reader.start()
        self._stderr_reader.start()
        meta = {"io.modelcontextprotocol/protocolVersion": PROTOCOL_VERSION,
                "io.modelcontextprotocol/clientCapabilities": {}}
        for method in ("server/discover", "tools/list"):
            request_id = "m6-host-ready-" + method
            self._write_downstream(_Auxiliary(method, request_id,
                _canonical_bytes({"_meta": meta}), None, None))
            response = self._await_response(request_id, _HANDSHAKE_TIMEOUT_SECONDS)
            result = response.get("result")
            if type(result) is not dict:
                raise LiveRuntimeError("Controlled child did not become ready")
            if method == "server/discover":
                if result.get("supportedVersions") != [PROTOCOL_VERSION]:
                    raise LiveRuntimeError("Controlled child has wrong protocol")
            elif (sorted(tool.get("name") for tool in result.get("tools", [])) !=
                  sorted(TOOL_CONTRACTS) or result.get("nextCursor") is not None):
                raise LiveRuntimeError("Controlled child has wrong tool registry")

    def _findings(self, current, proposal_id, facts):
        for fact in facts[self._shadow_count:]:
            self._shadow.observe(fact)
        self._shadow_count = len(facts)
        reference = B2Reference(self._identity[1], POLICY).evaluate(
            current, facts, proposal_id)
        streaming = self._shadow.evaluate(current, proposal_id)
        if not equivalent(reference, streaming):
            raise LiveRuntimeError("M6 B2 prefix mismatch")
        findings = (b0(current, POLICY),
            attach_references(b1(current, project_b1(facts, self._identity[1]), POLICY),
                              proposal_id, current, facts), reference, streaming)
        from dataclasses import replace
        findings = (replace(findings[0], supporting_event_ids=(proposal_id,)),
                    *findings[1:])
        return {finding.detector_id: _finding_body(finding, proposal_id)
                for finding in findings}

    def _deliver(self, item, response):
        item.output.write(_frame(response))
        item.output.flush()

    def _handle_auxiliary(self, item):
        self._write_downstream(item)
        self._deliver(item, self._await_response(item.request_id))

    def _handle_proposal(self, item):
        arguments = _snapshot(item.arguments_bytes)
        params = _snapshot(item.params_bytes)
        if (type(item.request_id) not in (str, int) or
                type(params) is not dict or not _valid_meta(params.get("_meta")) or
                set(params) != {"_meta", "name", "arguments"} or
                params["name"] != item.tool or params["arguments"] != arguments):
            raise LiveRuntimeError("Queued call differs from admitted proposal")
        try:
            validate_tool_arguments(item.tool, arguments)
            _frame({"jsonrpc": "2.0", "id": item.request_id,
                    "method": "tools/call", "params": params})
        except (ValueError, TypeError) as exc:
            raise LiveRuntimeError("Invalid queued tool call") from exc
        permit = self._authority.admit_call(item.call_id, item.tool, item.request_id,
                                             arguments,
                                             findings_factory=self._findings)
        if permit is None:
            self._deliver(item, {"jsonrpc": "2.0", "id": item.request_id,
                                 "error": {"code": -32003,
                                           "message": "M6 authorization denied"}})
            return
        self._write_downstream(item, permit)
        try:
            response = self._await_response(item.request_id)
            result = response.get("result")
            rule = result_contract(item.tool)
            if rule["kind"] == "exact_text":
                expected = rule["text"]
            elif rule["kind"] == "argument_prefix":
                expected = rule["prefix"] + arguments[rule["argument"]]
            else:
                expected = arguments[rule["argument"]]
            content = result.get("content") if type(result) is dict else None
            if (type(result) is not dict or type(content) is not list or len(content) != 1 or
                    type(content[0]) is not dict or content[0].get("type") != "text" or
                    content[0].get("text") != expected or
                    result.get("isError", False) is not rule["is_error"]):
                raise LiveRuntimeError("Unrecognized downstream tool result")
        except Exception:
            self._authority.record_outcome(permit, "unknown")
            raise
        self._authority.record_outcome(permit, "failed" if rule["is_error"] else "succeeded")
        self._deliver(item, response)

    def _work(self):
        stop = None
        self._worker_ident = get_ident()
        try:
            self._startup()
            with self._lock:
                if self._abort_startup:
                    raise LiveRuntimeError("Host abandoned task initialization")
                self._state = "ACTIVE"
                self._ready.set_result(None)
            while True:
                item = self._queue.get()
                if type(item) is _Stop:
                    stop = item.done
                    self._authority.close()
                    break
                try:
                    if type(item) is _Control:
                        if item.kind == "GRANT":
                            self._authority.grant(item.grant_id, item.scope)
                        else:
                            self._authority.revoke(item.scope)
                    elif type(item) is _Proposal:
                        self._handle_proposal(item)
                    else:
                        self._handle_auxiliary(item)
                except Exception as exc:
                    self._authority.halt_uncertain()
                    if type(item) in {_Proposal, _Auxiliary}:
                        try:
                            self._deliver(item, {"jsonrpc": "2.0", "id": item.request_id,
                                "error": {"code": -32603, "message": "M6 task halted"}})
                        except Exception:
                            pass
                    item.done.set_exception(exc)
                    with self._lock:
                        self._state = "HALTED"
                    break
                item.done.set_result(None)
        except Exception as exc:
            if not self._ready.done():
                self._ready.set_exception(exc)
            if stop is not None:
                stop.set_exception(exc)
            with self._lock:
                self._state = "HALTED"
        finally:
            if self._authority is not None and self._state == "HALTED":
                self._authority.halt_uncertain()
            cleanup_error = None
            if self._audit is not None:
                try:
                    self._audit.close()
                except Exception as exc:
                    cleanup_error = exc
            if self._child is not None:
                try:
                    self._child.stdin.close()
                    self._child.wait(timeout=5)
                except (OSError, subprocess.TimeoutExpired):
                    self._child.kill()
                    self._child.wait(timeout=5)
            if self._stdout_reader is not None:
                self._stdout_reader.join(timeout=1)
            if self._stderr_reader is not None:
                self._stderr_reader.join(timeout=1)
            if self._child is not None:
                self._child.stdout.close()
                self._child.stderr.close()
            with self._lock:
                if cleanup_error is not None:
                    self._state = "HALTED"
                elif self._state != "HALTED":
                    self._state = "CLOSED"
            if stop is not None and not stop.done():
                if cleanup_error is None:
                    stop.set_result(None)
                else:
                    stop.set_exception(cleanup_error)
            failure = LiveRuntimeError("M6 task halted before queued admission")
            while True:
                try:
                    pending = self._queue.get_nowait()
                except queue.Empty:
                    break
                if not pending.done.done():
                    pending.done.set_exception(failure)
