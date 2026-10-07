"""Deterministic, harmless tools served by the approved MCP Python SDK."""

import asyncio
import json
import os
import sys

from mcp import types
from mcp.server import Server, ServerRequestContext
from mcp.server.stdio import stdio_server
from mcp.shared.exceptions import MCPError

from chainguard import __version__


INPUT_SCHEMA = {
    "type": "object",
    "properties": {"token": {"type": "string", "maxLength": 256}},
    "required": ["token"],
    "additionalProperties": False,
}
TOOLS = [
    types.Tool(
        name="echo",
        description="Return a supplied synthetic test token unchanged.",
        input_schema=INPUT_SCHEMA,
    ),
    types.Tool(
        name="controlled_failure",
        description="Return a deterministic tool-execution error for a test token.",
        input_schema=INPUT_SCHEMA,
    ),
]


async def list_tools(
    ctx: ServerRequestContext, params: types.PaginatedRequestParams | None
) -> types.ListToolsResult:
    if params is not None and params.cursor is not None:
        raise MCPError(code=-32602, message="This fixed tool list has no next page")
    return types.ListToolsResult(tools=TOOLS)


async def call_tool(
    ctx: ServerRequestContext, params: types.CallToolRequestParams
) -> types.CallToolResult:
    if params.name not in {tool.name for tool in TOOLS}:
        raise MCPError(code=-32602, message="Unknown M1 tool")
    arguments = params.arguments or {}
    if (
        set(arguments) != {"token"}
        or not isinstance(arguments.get("token"), str)
        or len(arguments["token"]) > 256
    ):
        raise MCPError(code=-32602, message="Expected exactly one string token of at most 256 characters")
    sys.stderr.write(
        json.dumps({
            "component": "controlled_server",
            "phase": "tool_received",
            "request_id": ctx.request_id,
            "tool": params.name,
            "pid": os.getpid(),
            "parent_pid": os.getppid(),
        }) + "\n"
    )
    sys.stderr.flush()
    failed = params.name == "controlled_failure"
    text = f"controlled failure: {arguments['token']}" if failed else arguments["token"]
    return types.CallToolResult(
        content=[types.TextContent(type="text", text=text)],
        is_error=failed,
    )


async def main() -> None:
    server = Server(
        "chainguard-controlled-m1",
        version=__version__,
        on_list_tools=list_tools,
        on_call_tool=call_tool,
        get_tool_input_schema=lambda name: INPUT_SCHEMA if name in {tool.name for tool in TOOLS} else None,
    )
    async with stdio_server() as (read_stream, write_stream):
        # This SDK option object also configures modern stdio serving. Creating
        # it does not send or require an initialize handshake.
        await server.run(read_stream, write_stream, server.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())
