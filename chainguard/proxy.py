"""Sequential M1 stdio relay; protocol checks only, no security policy."""

import json
import os
from pathlib import Path
import queue
import subprocess
import sys
import threading
from typing import BinaryIO

from chainguard import PROTOCOL_VERSION


ROOT = Path(__file__).resolve().parent.parent
METHODS = {"server/discover", "tools/list", "tools/call"}
MAX_FRAME_BYTES = 64 * 1024
RESPONSE_TIMEOUT_SECONDS = 30


def diagnostic(phase: str, **fields: object) -> None:
    """Transient transport diagnostics contain no arguments or result content."""
    sys.stderr.write(json.dumps({"component": "proxy", "phase": phase, "pid": os.getpid(), **fields}) + "\n")
    sys.stderr.flush()


def reject_constant(value: str) -> None:
    raise ValueError(f"Non-JSON numeric constant: {value}")


def decode_frame(frame: bytes) -> dict:
    if len(frame) > MAX_FRAME_BYTES or not frame.endswith(b"\n"):
        raise ValueError("Expected a newline-terminated JSON frame of at most 64 KiB")
    message = json.loads(frame.decode("utf-8"), parse_constant=reject_constant)
    if not isinstance(message, dict) or message.get("jsonrpc") != "2.0":
        raise ValueError("Expected one JSON-RPC 2.0 object; batches are unsupported")
    return message


def write_error(output: BinaryIO, request_id: object, code: int, message: str, **extra: object) -> None:
    error = {"code": code, "message": message, **extra}
    response = {"jsonrpc": "2.0", "id": request_id, "error": error}
    output.write(json.dumps(response, ensure_ascii=False).encode("utf-8") + b"\n")
    output.flush()


def read_responses(stream: BinaryIO, responses: queue.Queue) -> None:
    while True:
        frame = stream.readline(MAX_FRAME_BYTES + 1)
        responses.put(frame)
        if not frame or len(frame) > MAX_FRAME_BYTES:
            return


def run(input_stream: BinaryIO, output_stream: BinaryIO, audit=None) -> int:
    """The downstream command is fixed; the client can only launch this proxy."""
    environment = {**os.environ, "PYTHONUTF8": "1"}
    with subprocess.Popen(
        [sys.executable, "-u", "-m", "chainguard.controlled_server"],
        cwd=ROOT,
        env=environment,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        # Inherit stderr separately from the protocol stream.
    ) as downstream:
        assert downstream.stdin is not None and downstream.stdout is not None
        responses: queue.Queue = queue.Queue(maxsize=1)
        reader = threading.Thread(target=read_responses, args=(downstream.stdout, responses), daemon=True)
        reader.start()
        diagnostic("started", downstream_pid=downstream.pid)
        status = 0
        try:
            while frame := input_stream.readline(MAX_FRAME_BYTES + 1):
                try:
                    request = decode_frame(frame)
                except (ValueError, UnicodeError):
                    write_error(output_stream, None, -32700, "Malformed or unsupported M1 JSON frame")
                    diagnostic("rejected", reason="invalid_frame")
                    status = 2
                    break
                request_id = request.get("id")
                if type(request_id) not in (str, int):
                    # Never answer a notification. M1 has no notification channel.
                    if "id" in request:
                        write_error(output_stream, None, -32600, "M1 requires a string or integer request ID")
                    diagnostic("rejected", reason="unsupported_envelope")
                    status = 2
                    break
                method = request.get("method")
                if not isinstance(method, str) or method not in METHODS:
                    write_error(output_stream, request_id, -32601, "Method outside the M1 subset")
                    diagnostic("rejected", request_id=request_id, reason="unsupported_method")
                    continue
                params = request.get("params")
                meta = params.get("_meta") if isinstance(params, dict) else None
                if not isinstance(meta, dict) or not isinstance(meta.get("io.modelcontextprotocol/clientCapabilities"), dict):
                    write_error(output_stream, request_id, -32602, "Required per-request MCP metadata missing or invalid")
                    diagnostic("rejected", request_id=request_id, reason="invalid_metadata")
                    continue
                version = meta.get("io.modelcontextprotocol/protocolVersion")
                if not isinstance(version, str):
                    write_error(output_stream, request_id, -32602, "Required protocolVersion metadata missing or invalid")
                    diagnostic("rejected", request_id=request_id, reason="invalid_metadata")
                    continue
                if version != PROTOCOL_VERSION:
                    write_error(
                        output_stream, request_id, -32022, "Protocol version outside the M1 subset",
                        data={"supportedVersions": [PROTOCOL_VERSION]},
                    )
                    diagnostic("rejected", request_id=request_id, reason="unsupported_version")
                    continue
                fields = {"request_id": request_id, "method": method, "downstream_pid": downstream.pid}
                diagnostic("received", **fields, protocol_version=version, required_metadata=True)
                call_id = None
                terminal_recorded = False
                if audit is not None and method == "tools/call":
                    from chainguard.audit import AuditError
                    try:
                        # M3 proposal + decision + intent commit and trusted
                        # continuity advance must finish before this relay writes.
                        call_id = audit.before(request)
                    except (AuditError, ValueError, TypeError, KeyError):
                        audit.session.halt(audit.session.state.failure or "AUDIT_PREPARATION_FAILED")
                        write_error(output_stream, request_id, -32603, "Audit persistence failed; task halted")
                        diagnostic("audit_failure", **fields, failure=audit.session.state.failure)
                        status = 2
                        break
                    if call_id is None:
                        write_error(output_stream, request_id, -32602, "Call outside the M3 non-release subset")
                        diagnostic("rejected", request_id=request_id, reason="unsupported_m3_call")
                        continue
                try:
                    downstream.stdin.write(frame)
                    downstream.stdin.flush()
                    diagnostic("forwarded", **fields)
                    response_frame = responses.get(timeout=RESPONSE_TIMEOUT_SECONDS)
                    response = decode_frame(response_frame)
                    if (
                        type(response.get("id")) is not type(request_id)
                        or response.get("id") != request_id
                        or ("result" in response) == ("error" in response)
                        or "method" in response
                    ):
                        raise ValueError("Downstream response does not correlate with the request")
                    diagnostic("response_received", **fields)
                    if call_id is not None:
                        try:
                            audit.after(call_id, response)
                        except (AuditError, ValueError):
                            audit.session.halt(audit.session.state.failure or "AUDIT_OUTCOME_FAILED")
                            write_error(output_stream, request_id, -32603, "Audit outcome incomplete; task halted")
                            diagnostic("audit_failure", **fields, failure=audit.session.state.failure)
                            status = 2
                            break
                        terminal_recorded = True
                    output_stream.write(response_frame)
                    output_stream.flush()
                    diagnostic("returned", **fields)
                except (OSError, ValueError, UnicodeError, queue.Empty):
                    if call_id is not None:
                        if terminal_recorded:
                            audit.session.halt("CLIENT_RESPONSE_DELIVERY_FAILED")
                        else:
                            try:
                                audit.unknown(call_id)
                            except (AuditError, ValueError):
                                audit.session.halt(audit.session.state.failure or "AUDIT_OUTCOME_FAILED")
                    message = ("Client response delivery failed; recorded tool outcome retained" if terminal_recorded
                               else "Downstream transport failed; call outcome unknown")
                    diagnostic("client_delivery_failure" if terminal_recorded else "transport_failure", **fields)
                    write_error(output_stream, request_id, -32603, message)
                    status = 2
                    break
        finally:
            downstream.stdin.close()
            try:
                downstream.wait(timeout=5)
            except subprocess.TimeoutExpired:
                downstream.terminate()
                try:
                    downstream.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    downstream.kill()
                    downstream.wait(timeout=5)
            reader.join(timeout=1)
            diagnostic("stopped", downstream_pid=downstream.pid, downstream_exit_code=downstream.returncode)
            if downstream.returncode != 0:
                status = 2
        return status


def main() -> int:
    try:
        return run(sys.stdin.buffer, sys.stdout.buffer)
    except (OSError, BrokenPipeError):
        diagnostic("transport_failure", reason="process_or_pipe_failure")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
