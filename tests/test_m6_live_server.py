"""Isolated M6 server contracts and server-side local sink witness."""

import asyncio
from contextlib import redirect_stderr
from io import StringIO
import json
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from mcp.shared.exceptions import MCPError

from chainguard.m6_controlled_server import TOOLS, call_tool, list_tools
from chainguard.m6_live_profile import PUBLIC_RESULT, POLICY, TOOL_CONTRACTS
from tests.test_m1 import launch, request


def invoke(name, arguments):
    capture = StringIO()
    with redirect_stderr(capture):
        result = asyncio.run(call_tool(SimpleNamespace(request_id="request-1"),
                                       SimpleNamespace(name=name, arguments=arguments)))
    return result, [json.loads(line) for line in capture.getvalue().splitlines()]


class LiveServerTests(unittest.TestCase):
    def wire(self, frames):
        process = launch("chainguard.m6_controlled_server", frames)
        responses = [json.loads(line) for line in process.stdout.splitlines()]
        events = []
        for line in process.stderr.splitlines():
            try:
                item = json.loads(line)
            except ValueError:
                continue
            if isinstance(item, dict) and item.get("component") in {
                    "m6_controlled_server", "m6_local_sink"}:
                events.append(item)
        return process, responses, events

    def test_only_fixed_tools_are_advertised(self):
        listed = asyncio.run(list_tools(None, None))
        self.assertEqual([tool.name for tool in listed.tools], sorted(TOOL_CONTRACTS))
        self.assertEqual([tool.name for tool in TOOLS], sorted(TOOL_CONTRACTS))
        with self.assertRaises(MCPError):
            asyncio.run(list_tools(None, SimpleNamespace(cursor="next")))

    def test_all_read_and_non_release_results_are_fixed(self):
        cases = [("read_public", {}, PUBLIC_RESULT, False),
                 ("read_secret_a", {}, dict(POLICY.resources)["secret-a"], False),
                 ("read_secret_b", {}, dict(POLICY.resources)["secret-b"], False),
                 ("echo", {"token": "hello"}, "hello", False),
                 ("controlled_failure", {"token": "hello"},
                  "controlled failure: hello", True)]
        for name, args, expected, failed in cases:
            with self.subTest(name=name):
                result, events = invoke(name, args)
                self.assertEqual(result.content[0].text, expected)
                self.assertEqual(result.is_error, failed)
                self.assertEqual([(e["phase"], e["tool"]) for e in events],
                                 [("tool_received", name)])

    def test_both_sink_destinations_are_fixed_and_arrivals_server_side(self):
        for name, destination in (("send_sink", "sink"),
                                  ("send_other_sink", "other-sink")):
            with self.subTest(name=name):
                result, events = invoke(name, {"payload": "synthetic β"})
                self.assertEqual(result.content[0].text, "captured by local sink")
                self.assertFalse(result.is_error)
                self.assertEqual([event["phase"] for event in events],
                                 ["tool_received", "sink_arrival"])
                self.assertEqual(events[1]["component"], "m6_local_sink")
                self.assertEqual(events[1]["destination"], destination)
                self.assertEqual(events[1]["payload_byte_count"],
                                 len("synthetic β".encode("utf-8")))
                self.assertNotIn("payload", events[1])

    def test_arrival_is_emitted_before_response_construction(self):
        capture = StringIO()
        with patch("chainguard.m6_controlled_server.types.CallToolResult",
                   side_effect=RuntimeError("response unavailable")):
            with redirect_stderr(capture), self.assertRaisesRegex(RuntimeError,
                                                                    "response unavailable"):
                asyncio.run(call_tool(SimpleNamespace(request_id="request-1"),
                    SimpleNamespace(name="send_sink", arguments={"payload": "synthetic"})))
        events = [json.loads(line) for line in capture.getvalue().splitlines()]
        self.assertEqual(events[-1]["phase"], "sink_arrival")

    def test_unknown_malformed_and_control_shaped_input_has_zero_arrivals(self):
        cases = [("grant", {"task_id": "task-1"}),
                 ("send_sink", {"payload": "synthetic", "destination": "other-sink"}),
                 ("send_sink", {"payload": "synthetic", "operation": "read"}),
                 ("send_sink", {"payload": "synthetic", "grant_id": "g1"}),
                 ("send_sink", {"payload": "synthetic", "resource": "secret-a"}),
                 ("send_sink", {"payload": ""}), ("send_sink", {"payload": 1}),
                 ("send_sink", {"payload": "x" * (POLICY.max_payload_bytes + 1)}),
                 ("read_secret_a", {"task_id": "task-1"}),
                 ("read_public", {"resource": "secret-a"}),
                 ("echo", {}), ("echo", {"token": "x" * 257}),
                 ("send_sink", ["synthetic"]), ("send_sink", None)]
        for name, args in cases:
            capture = StringIO()
            with self.subTest(name=name, args=str(args)[:70]):
                with redirect_stderr(capture), self.assertRaises(MCPError):
                    asyncio.run(call_tool(SimpleNamespace(request_id="request-1"),
                                            SimpleNamespace(name=name, arguments=args)))
                self.assertEqual(capture.getvalue(), "")

    def test_client_cannot_supply_host_control_through_other_tools(self):
        for name in TOOL_CONTRACTS:
            capture = StringIO()
            with self.subTest(name=name):
                with redirect_stderr(capture), self.assertRaises(MCPError):
                    asyncio.run(call_tool(SimpleNamespace(request_id="request-1"),
                        SimpleNamespace(name=name, arguments={"grant": {"scope": "*"}})))
                self.assertEqual(capture.getvalue(), "")

    def test_multibyte_payload_byte_boundary_and_empty_payload(self):
        limit = POLICY.max_payload_bytes
        self.assertEqual(limit % len("β".encode("utf-8")), 0)
        _, events = invoke("send_sink", {"payload": "β" * (limit // 2)})
        self.assertEqual(events[-1]["payload_byte_count"], limit)
        for payload in ("", "β" * (limit // 2 + 1)):
            capture = StringIO()
            with self.subTest(byte_length=len(payload.encode("utf-8"))):
                with redirect_stderr(capture), self.assertRaises(MCPError):
                    asyncio.run(call_tool(SimpleNamespace(request_id="request-1"),
                        SimpleNamespace(name="send_sink", arguments={"payload": payload})))
                self.assertEqual(capture.getvalue(), "")

    def test_real_stdio_send_has_server_side_arrival(self):
        frame = json.dumps(request(41, "tools/call", name="send_sink",
                                   arguments={"payload": "synthetic-wire"})).encode("utf-8") + b"\n"
        process, responses, events = self.wire(frame)
        self.assertEqual(process.returncode, 0, process.stderr.decode("utf-8"))
        self.assertEqual(responses[0]["id"], 41)
        self.assertEqual(responses[0]["result"]["content"][0]["text"],
                         "captured by local sink")
        arrivals = [event for event in events if event["phase"] == "sink_arrival"]
        self.assertEqual(len(arrivals), 1)
        self.assertEqual(arrivals[0]["request_id"], 41)
        self.assertEqual(arrivals[0]["destination"], "sink")
        self.assertEqual(arrivals[0]["payload_byte_count"], len("synthetic-wire"))
        self.assertNotIn("payload", arrivals[0])

    def test_real_stdio_valid_mcp_rejections_have_zero_arrivals(self):
        calls = [(51, "grant", {"task_id": "task-1"}),
                 (52, "send_sink", {"payload": "synthetic", "destination": "other-sink"}),
                 (53, "send_sink", {"grant": {"scope": "*"}}),
                 (54, "send_sink", {"payload": ""}),
                 (55, "send_sink", {"payload": 1})]
        for number, name, args in calls:
            frame = json.dumps(request(number, "tools/call", name=name,
                                       arguments=args)).encode("utf-8") + b"\n"
            with self.subTest(number=number, name=name):
                process, responses, events = self.wire(frame)
                self.assertEqual(process.returncode, 0, process.stderr.decode("utf-8"))
                self.assertEqual(len(responses), 1)
                self.assertEqual(responses[0]["id"], number)
                self.assertIn("error", responses[0])
                self.assertFalse(events)

    def test_real_stdio_multibyte_byte_boundary(self):
        limit = POLICY.max_payload_bytes
        for number, payload, accepted in ((71, "β" * (limit // 2), True),
                                          (72, "β" * (limit // 2 + 1), False)):
            frame = json.dumps(request(number, "tools/call", name="send_sink",
                                       arguments={"payload": payload})).encode("utf-8") + b"\n"
            with self.subTest(number=number):
                process, responses, events = self.wire(frame)
                self.assertEqual(process.returncode, 0, process.stderr.decode("utf-8"))
                self.assertEqual(len(responses), 1)
                self.assertEqual(responses[0]["id"], number)
                arrivals = [event for event in events if event["phase"] == "sink_arrival"]
                if accepted:
                    self.assertIn("result", responses[0])
                    self.assertEqual(arrivals[0]["payload_byte_count"], limit)
                    self.assertEqual(len(arrivals), 1)
                else:
                    self.assertIn("M6 tool argument exceeds", json.dumps(responses[0]["error"]))
                    self.assertFalse(events)

    def test_malformed_protocol_frame_is_distinct_from_rejected_tool_call(self):
        process, responses, events = self.wire(b"{not-json}\n")
        self.assertFalse(events)
        self.assertFalse(any(response.get("id") == 61 for response in responses))
        # This is valid JSON and passes JSON Schema maxLength (characters),
        # then fails the server's declared UTF-8 byte limit in the handler.
        over_limit = "β" * (POLICY.max_payload_bytes // 2 + 1)
        valid_frame = json.dumps(request(61, "tools/call", name="send_sink",
                                         arguments={"payload": over_limit})).encode("utf-8") + b"\n"
        valid_process, rejected, valid_events = self.wire(valid_frame)
        self.assertEqual(valid_process.returncode, 0, valid_process.stderr.decode("utf-8"))
        self.assertEqual(len(rejected), 1)
        self.assertEqual(rejected[0]["id"], 61)
        self.assertIn("error", rejected[0])
        self.assertIn("M6 tool argument exceeds", json.dumps(rejected[0]["error"]))
        self.assertFalse(valid_events)


if __name__ == "__main__":
    unittest.main()
