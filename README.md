# ChainGuard

ChainGuard investigates explainable security analysis of MCP tool-call sequences and independently verifiable evidence of the monitor's observations and decisions. It is an Information Security course project intended to support a reproducible IEEE-style study.

**Status, 7 October 2026:** **ARCHITECTURE LOCKED — ChainGuard Architecture v1.1**. The owner subsequently authorized M1 implementation and the exact dependency set in `requirements-m1.txt`. M1 transport tests and the standalone client -> proxy -> controlled server flow pass. M2 and later milestones remain unimplemented; this is not yet a working security detector or audit-evidence system. No commit or push was made.

The locked final architecture specifies a local Python MCP stdio proxy, task-scoped events, B0/B1/B2, core grant/revoke/one-use consumption, SQLite, trusted running SHA-256 commitments, ECDSA P-256 signatures, offline verification and independent evaluation. The final study includes B2-R/B2-S checks, the pinned sensitivity-policy reference adaptation and signed-transcript comparison. A minimal report will separate behavioral findings, oracle labels and evidence status.

Normal observation mode MUST NOT bypass authorization. Unauthorized forwarding is possible ONLY through the explicitly configured synthetic local-sink observation override. Evaluation 1 targets M1–M5; M6 is optional for that evaluation and mandatory for the final project. Missing M6 cannot weaken or redefine core scope.

The research contribution is a controlled study of event ordering and task-bound verifiable findings. Session monitoring, sequence rules, hashing, and signing are established techniques; their inclusion alone is not a novelty claim. Cryptographic verification authenticates committed evidence under the threat model and does not establish that a detector's judgment is correct.

## Project controls

| Document | Responsibility |
| --- | --- |
| [Architecture Lock](docs/ARCHITECTURE_LOCK.md) | Authoritative approved components, contracts, algorithms, scope and acceptance criteria |
| [Project Charter](docs/PROJECT_CHARTER.md) | Research questions, contribution limits, syllabus mapping and experimental methodology |
| [Threat Model](docs/THREAT_MODEL.md) | Assets, adversaries, trust boundaries, assumptions and security limits |
| [Engineering Playbook](ENGINEERING_PLAYBOOK.md) | Approval gates, milestones, verification and student understanding |
| [Agent Instructions](AGENTS.md) | Operating rules for contributors and coding agents |
| [Historical amendment](ARCHITECTURE_AMENDMENTS_V1.md) | Supporting record only; contracts are incorporated into the sole authoritative Architecture Lock |

ML, periodic signed checkpoints, additional transports, real LLM studies, and cryptographic payload storage are extensions. Sensitive payload encryption becomes a requirement if a later approved change retains sensitive payloads; the core stores redacted, policy-sufficient observations.

## M1 execution path

```text
Scripted MCP SDK client --stdio--> ChainGuard proxy --stdio--> Controlled MCP SDK server
                       <--stdio--                  <--stdio--
```

| Component | Responsibility and choice |
| --- | --- |
| `chainguard/client.py` | Launch only the proxy; explicitly discover the modern protocol, list tools, and check a success/error/success sequence. The official SDK supplies client semantics and schema validation. |
| `chainguard/proxy.py` | Launch the fixed controlled server and relay one request/result at a time, preserving supported frames byte for byte. A small standard-library relay makes transport mediation visible without adding a framework. |
| `chainguard/controlled_server.py` | Use the official low-level SDK server to advertise only tools. `echo` returns a synthetic token; `controlled_failure` intentionally returns a tool error. Neither operation uses external services or performs releases. |
| `tests/test_m1.py` | Exercise the real SDK subprocess path, raw request IDs, process relationships, protocol errors and injected downstream wire faults. Expected values are specified in the tests before execution. |

Alternatives considered were a raw JSON-RPC scripted client, the SDK's higher-level `MCPServer`, and a proxy built as separate SDK server/client endpoints. The SDK client retains supported protocol handling; the low-level server advertises only the intended tools; the byte relay keeps original correlation IDs and frames directly inspectable.

The protocol target is **MCP 2026-07-28**. The client pins that version, sends a real `server/discover` request, validates the response and adopts it. It does not use the SDK's automatic legacy fallback. Each supported request must carry `io.modelcontextprotocol/protocolVersion` and `io.modelcontextprotocol/clientCapabilities` in `params._meta`. Client identity metadata is not an authenticated identity or task context.

The supported proxy subset is `server/discover`, `tools/list`, and `tools/call`, with one JSON-RPC object per UTF-8 newline-delimited frame, string/integer request IDs, sequential calls and a 64 KiB frame limit. The controlled tools accept exactly one string `token` of at most 256 characters. Discovery advertises only the tools capability, with no list-change subscription. Other methods, versions, legacy initialization, batching, notifications, subscriptions, multi-round-trip interactions and other transports are outside M1. No full-MCP-compliance claim is made.

`controlled_failure` returns a JSON-RPC **result** with `isError: true`; it is a tool-execution error. Invalid metadata, unknown tools or invalid arguments produce JSON-RPC **errors**. Downstream EOF, timeout or a mismatched response produces a correlated transport error, marks the call outcome unknown and stops the proxy without retrying it.

Proxy stderr diagnostics record request IDs and receive/forward/response/return phases. The tool's independent handler receipt records its PID, parent PID and request ID. They contain no arguments or result content and are transient transport diagnostics, not persisted audit events or authenticated evidence. On Windows, the virtual-environment Python launcher can add a process between the proxy and the tool interpreter; the mediation test checks that observed parent chain.

## Run M1

Tested on Windows x64 with CPython **3.14.3**, pip **25.3**, and the owner-approved **`mcp==2.3.0`**. All 29 installed distributions match the exact pins in [requirements-m1.txt](requirements-m1.txt); those pins were unchanged after approval. SDK-imposed transitives include HTTP/ASGI, OAuth/cryptography, OpenTelemetry API and Windows support packages. M1 uses only local stdio, adds no CLI extras or test framework, and implements no cryptographic evidence functionality.

Run from the repository root in PowerShell; activating the existing `.venv` is unnecessary:

```powershell
.\.venv\Scripts\python.exe -m pip install --only-binary=:all: -r requirements-m1.txt
.\.venv\Scripts\python.exe -m pip check
.\.venv\Scripts\python.exe -m compileall -q chainguard tests
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
.\.venv\Scripts\python.exe -m chainguard.client
```

The client launches both downstream processes itself. Its JSON summary appears on stdout; payload-free transport diagnostics appear on stderr. A failed client assertion or test exits unsuccessfully. The proxy is not a production security control and exposes no task/grant/authorization interface at M1.

## Actual M1 results — 7 October 2026

Installation succeeded, `pip check` reported **No broken requirements found**, and an installed-version check matched all **29** approved pins. Syntax compilation and imports of all four application modules passed.

The first test execution passed 11 of 12 tests and exposed an incorrect test assumption that the Windows venv launcher PID equaled the tool interpreter PID. The test was corrected to validate the launcher's parent relationship; no dependency or architecture change was needed. The final full execution reported **Ran 12 tests in 21.915s — OK**, exit code **0**. This duration is a test-run observation, not a performance benchmark. Nine tests cover real SDK/raw subprocess integration and three inject local downstream frames/EOF to check relay behavior.

| Required check | Actual passing evidence |
| --- | --- |
| M1-T1 — Discovery | SDK client discovered `chainguard-controlled-m1`, protocol `2026-07-28`, and exactly `echo` / `controlled_failure` through the proxy. |
| M1-T2 — Success | `echo` returned `m1-success-A`; a later call returned `m1-success-C` after the intervening error. |
| M1-T3 — Controlled error | `controlled_failure` returned `isError: true` and `controlled failure: m1-failure-B`. |
| M1-T4 — Correlation | Raw calls with integer `7`, string `"7"`, and Unicode ID `"unicode-\u03bb"` retained their ID types and matching success/error results. SDK diagnostics also correlated all five requests across four proxy phases. |
| M1-T5 — Mediation | The client launched the proxy; its diagnostics showed five forwarded/returned requests and three matching tool-handler arrivals beneath the launched downstream process. Frame-preservation tests also compared actual pipe bytes. |

The separate end-to-end command exited **0** and produced:

```json
{
  "protocol_version": "2026-07-28",
  "server": "chainguard-controlled-m1",
  "tools": ["controlled_failure", "echo"],
  "success": {"isError": false, "text": "m1-success-A"},
  "controlled_error": {"isError": true, "text": "controlled failure: m1-failure-B"},
  "success_after_error": {"isError": false, "text": "m1-success-C"}
}
```

In that run the proxy PID was **26488**, the downstream launcher PID **37012**, and the tool-handler PID **23284** with parent PID **37012**. Requests **1–5** traversed the proxy, including tool calls **3–5**; downstream shutdown reported exit code **0**. These PIDs are run-specific and are not reproducibility inputs.

Additional passing checks cover required per-request metadata, refusal to forward missing metadata/unsupported versions, rejection of legacy and unsupported methods, distinction between protocol errors and tool errors, exact request/response frame preservation, and stopping on mismatched response IDs or downstream EOF without retries.

M1 proves the configured local execution path and correlated success/error behavior. It does not detect attacks, authenticate diagnostics, prevent arbitrary host-side bypasses, track sensitive data, implement an oracle, persist audits, produce hashes/signatures, or manage grants/revocation/consumption. M2–M6 were not implemented. Protocol conformance beyond this subset, other operating systems, concurrent calls and exhaustive timeout/resource-failure behavior have not been demonstrated. Student verification remains pending; subsequent milestone work requires a new instruction.

For the viva: the SDK client/server provide protocol semantics, the relay proves where supported traffic flows, and the deterministic tools isolate success/error behavior. A tool error is a valid correlated protocol result, while a transport error can leave the execution outcome unknown. Passing M1 establishes transport progress, not detector correctness.

The supplied paper is a proposal/literature baseline and needs alignment with this design before reporting implementation or results. The final marking rubric and evaluation date still need confirmation. The existing LICENSE contains only a placeholder heading; release readiness requires resolving it separately.
