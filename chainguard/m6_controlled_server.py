"""Isolated synthetic M6 tool server; no authorization is enforced here yet."""

import asyncio
import json
import os
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
def _emit(event):
    sys.stderr.write(json.dumps(event, sort_keys=True) + "\n")
    sys.stderr.flush()


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
        # Emitted by the server before constructing the client response. Tests
        # can observe this arrival independently of the returned result.
        arrival = result_rule["arrival"]
        _emit({"component": arrival["component"], "phase": arrival["phase"],
               "request_id": ctx.request_id, "tool": params.name,
               "destination": arrival["destination"],
               "payload_byte_count": len(payload.encode("utf-8"))})

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
    server = Server(SERVER_ID, version=__version__, on_list_tools=list_tools,
                    on_call_tool=call_tool,
                    get_tool_input_schema=lambda name: input_schema(name)
                    if name in TOOL_CONTRACTS else None)
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream,
                         server.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())
