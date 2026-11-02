"""Isolated synthetic M6 tool server; no authorization is enforced here yet."""

import asyncio
import base64
import hashlib
import json
import os
import socket
import sys

from mcp import types
from mcp.server import Server, ServerRequestContext
from mcp.server.stdio import stdio_server
from mcp.shared.exceptions import MCPError

from chainguard import __version__
from chainguard.m6_live_profile import (SERVER_ID, TOOL_CONTRACTS, input_schema,
                                        result_contract, validate_tool_arguments)


TOOLS = [types.Tool(name=name, description="Fixed synthetic M6 tool.",
                    input_schema=input_schema(name)) for name in sorted(TOOL_CONTRACTS)]
def _emit(event, *, stderr=True, assessor_event=None):
    line = json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n"
    path = os.environ.get("CHAINGUARD_ASSESSOR_CHILD_WITNESS")
    if path:
        capture = assessor_event if assessor_event is not None else event
        capture_line = json.dumps(capture, sort_keys=True, separators=(",", ":")) + "\n"
        descriptor = os.open(path, os.O_WRONLY | os.O_APPEND)
        try:
            raw = capture_line.encode("utf-8")
            if os.write(descriptor, raw) != len(raw):
                raise OSError("Incomplete assessor child witness write")
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    if stderr:
        sys.stderr.write(line)
        sys.stderr.flush()


def _send_to_assessor_sink(request_id, tool, destination, payload_bytes):
    endpoint = os.environ.get("CHAINGUARD_ASSESSOR_SINK_ENDPOINT")
    if not endpoint:
        return
    host, port_text = endpoint.split(":", 1)
    if host != "127.0.0.1":
        raise RuntimeError("Assessor sink must be local")
    header = json.dumps({"request_id": request_id, "tool": tool,
        "destination": destination, "length": len(payload_bytes)},
        sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"
    with socket.create_connection((host, int(port_text)), timeout=5) as connection:
        connection.sendall(header + payload_bytes)
        connection.shutdown(socket.SHUT_WR)
        response = connection.recv(32)
        if response != b"OK\n":
            raise RuntimeError("Assessor sink did not acknowledge exact capture")


async def list_tools(ctx: ServerRequestContext,
                     params: types.PaginatedRequestParams | None) -> types.ListToolsResult:
    if params is not None and params.cursor is not None:
        raise MCPError(code=-32602, message="This fixed tool list has no next page")
    return types.ListToolsResult(tools=TOOLS)


async def call_tool(ctx: ServerRequestContext,
                    params: types.CallToolRequestParams) -> types.CallToolResult:
    try:
        contract = validate_tool_arguments(params.name, params.arguments)
    except ValueError as exc:
        raise MCPError(code=-32602, message=str(exc)) from exc

    _emit({"component": "m6_controlled_server", "phase": "tool_received",
           "request_id": ctx.request_id, "tool": params.name,
           "pid": os.getpid(), "parent_pid": os.getppid()})

    result_rule = result_contract(params.name)
    if contract.operation == "send":
        payload = params.arguments["payload"]
        payload_bytes = payload.encode("utf-8")
        # Emitted by the server before constructing the client response. Tests
        # can observe this arrival independently of the returned result.
        arrival = result_rule["arrival"]
        _send_to_assessor_sink(ctx.request_id, params.name,
                               arrival["destination"], payload_bytes)
        metadata = {"component": arrival["component"], "phase": arrival["phase"],
               "request_id": ctx.request_id, "tool": params.name,
               "destination": arrival["destination"],
               "payload_byte_count": len(payload_bytes)}
        _emit(metadata, assessor_event={**metadata,
               "payload_sha256": hashlib.sha256(payload_bytes).hexdigest(),
               "payload_base64": base64.b64encode(payload_bytes).decode("ascii")})

    if result_rule["kind"] == "exact_text":
        result = result_rule["text"]
    elif result_rule["kind"] == "argument_prefix":
        result = result_rule["prefix"] + params.arguments[result_rule["argument"]]
    else:
        result = params.arguments[result_rule["argument"]]

    return types.CallToolResult(
        content=[types.TextContent(type="text", text=result)],
        is_error=result_rule["is_error"])


async def main() -> None:
    _emit({"component": "m6_controlled_server", "phase": "child_started",
           "pid": os.getpid(), "parent_pid": os.getppid()}, stderr=False)
    server = Server(SERVER_ID, version=__version__, on_list_tools=list_tools,
                    on_call_tool=call_tool,
                    get_tool_input_schema=lambda name: input_schema(name)
                    if name in TOOL_CONTRACTS else None)
    try:
        async with stdio_server() as (read_stream, write_stream):
            await server.run(read_stream, write_stream,
                             server.create_initialization_options())
    finally:
        _emit({"component": "m6_controlled_server", "phase": "child_exiting",
               "pid": os.getpid()}, stderr=False)


if __name__ == "__main__":
    asyncio.run(main())
