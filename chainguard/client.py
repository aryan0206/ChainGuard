"""Scripted SDK client exercising only the controlled M1 proxy path."""

import asyncio
import json
from pathlib import Path
import sys

from mcp import Client, types
from mcp.client.stdio import StdioServerParameters

from chainguard import PROTOCOL_VERSION, __version__


ROOT = Path(__file__).resolve().parent.parent


def verify_result(result: types.CallToolResult, expected: str, failed: bool) -> dict:
    if result.is_error is not failed:
        raise RuntimeError("Unexpected tool error status")
    if len(result.content) != 1 or not isinstance(result.content[0], types.TextContent):
        raise RuntimeError("Expected exactly one text result")
    if result.content[0].text != expected:
        raise RuntimeError("Result does not match its originating call's synthetic token")
    return {"isError": result.is_error, "text": result.content[0].text}


async def exercise() -> dict:
    target = StdioServerParameters(
        command=sys.executable,
        args=["-u", "-m", "chainguard.proxy"],
        cwd=str(ROOT),
        env={"PYTHONUTF8": "1"},
    )
    async with Client(
        target,
        mode=PROTOCOL_VERSION,
        cache=None,
        read_timeout_seconds=35,
        client_info=types.Implementation(name="chainguard-m1-client", version=__version__),
    ) as client:
        # A pinned Client initially synthesizes discovery state. Explicitly
        # probe the real server, then adopt its answer; never use auto fallback.
        discovery = types.DiscoverResult.model_validate(await client.session.send_discover(PROTOCOL_VERSION))
        if discovery.supported_versions != [PROTOCOL_VERSION]:
            raise RuntimeError("Controlled server did not advertise exactly the locked modern version")
        client.session.adopt(discovery)
        if client.protocol_version != PROTOCOL_VERSION or discovery.capabilities.tools is None:
            raise RuntimeError("Locked protocol/tools capability missing")
        tools = await client.list_tools()
        names = sorted(tool.name for tool in tools.tools)
        if names != ["controlled_failure", "echo"] or tools.next_cursor is not None:
            raise RuntimeError("Unexpected controlled tool discovery")
        successful = verify_result(await client.call_tool("echo", {"token": "m1-success-A"}), "m1-success-A", False)
        failed = verify_result(
            await client.call_tool("controlled_failure", {"token": "m1-failure-B"}),
            "controlled failure: m1-failure-B", True,
        )
        after_error = verify_result(
            await client.call_tool("echo", {"token": "m1-success-C"}), "m1-success-C", False,
        )
        server = client.server_info
        if server is None or server.name != "chainguard-controlled-m1":
            raise RuntimeError("Unexpected controlled server identity")
        report = {
            "protocol_version": client.protocol_version,
            "server": server.name,
            "tools": names,
            "success": successful,
            "controlled_error": failed,
            "success_after_error": after_error,
        }
    return report


def main() -> None:
    print(json.dumps(asyncio.run(exercise()), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
