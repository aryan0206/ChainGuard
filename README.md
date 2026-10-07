# ChainGuard

ChainGuard investigates explainable security analysis of MCP tool-call sequences and independently verifiable evidence of the monitor's observations and decisions. It is an Information Security course project intended to support a reproducible IEEE-style study.

**Status, 8 October 2026:** **ARCHITECTURE LOCKED — ChainGuard Architecture v1.1**. M1 and M2 were accepted, committed and pushed (`3e7f6e8`, `5515b05`, confirmed in the local/remote main history). M2 remains replay-only. The owner approved M3 with a continuity head `(last_seq, last_event_id)` and canonical typed records, explicitly deferring cryptographic chaining/head semantics to M4. M3 now implements real SQLite persistence and a live audited non-release M1 path; its implementation/results await owner review. M4–M6 remain unimplemented. There is no live grant/revoke/one-use manager or cryptographically verifiable audit evidence. No M3 commit or push has been made.

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

M1 proves the configured local execution path and correlated success/error behavior. It does not detect attacks, authenticate diagnostics, prevent arbitrary host-side bypasses, track sensitive data, implement an oracle, persist audits, produce hashes/signatures, or manage grants/revocation/consumption. M2–M6 were not implemented at M1 completion. Protocol conformance beyond this subset, other operating systems, concurrent calls and exhaustive timeout/resource-failure behavior have not been demonstrated. The owner subsequently accepted M1; the separately approved M2 work is described below.

For the viva: the SDK client/server provide protocol semantics, the relay proves where supported traffic flows, and the deterministic tools isolate success/error behavior. A tool error is a valid correlated protocol result, while a transport error can leave the execution outcome unknown. Passing M1 establishes transport progress, not detector correctness.

## M2 replay-only semantics

All M2 evidence is labeled **SYNTHETIC_REPLAY_NOT_DURABLE_COMMIT_PROOF**. The harness executes no tools, writes no database, and introduces no live grant/revoke interface. A fixture's `commit: confirmed` is a staged input assumption, never proof of a real durable commit. Real transaction witnesses and live permission-bearing execution were deferred to M3/M6. M1 client, proxy, controlled server and tests were unchanged during M2.

| File | Responsibility and locked contract |
| --- | --- |
| `chainguard/semantics.py` | Frozen current extraction, immutable semantic facts/scopes, exact B1 count projection and findings (§§6, 15.3, 16). |
| `chainguard/detectors.py` | Stateless B0, conservative B1, independently implemented full-prefix B2-R and incremental B2-S. They output shadows and cannot execute tools. |
| `chainguard/oracle.py` | Independently reconstruct raw fixture observations and assess authorization, dispatch, consumption, disclosure and task completion (§18). Imports no detector or normalizer. |
| `chainguard/m2.py` | Validate staged admission/call phases, project one shared history independently of shadows, compare every proposal prefix, check prewritten expectations and report observed B1 ambiguity. |
| `tests/m2_fixtures.py` | Explicit synthetic journals, public synthetic canaries, expected contract labels, side effects and detector operating-point expectations. |
| `tests/test_m2.py` | Semantic unit tests, fault/uncertainty tests and integration of the complete replay pipeline. |

**B0 was frozen before the first fixture comparison on 8 October 2026.** Its fixed operating point recognizes exact registered synthetic canaries in raw UTF-8 or one strict base64 layer, with a 64 KiB input bound and static local-destination restrictions. This implements the bounded direct-content checks required by Architecture Lock §§6/16. There is no recursive decoding, hex recognition or tuning from B1/B2 results. Missing historical permission is `INDETERMINATE`: current warnings recommend hypothetical denial; an outgoing call without warnings can recommend hypothetical allowance without establishing task authorization. The comparison rejects changes to the static policy across fixtures.

B1 receives only counts by category, operation, resource, destination, outcome, sensitivity, transformation category and exact scope. Task identity is implicit in prior validation/partitioning; event/grant IDs, order, ordinals, timestamps, active-state flags, transition features, scenario labels and findings are absent. Evidence references are attached after evaluation through a separate mapping. Permission is established only when `G_s > U_s AND R_s = 0`; `G_s <= U_s` is definite absence under validated lifecycle, while remaining revoke ambiguity is `INDETERMINATE` with `SUSPICIOUS` and hypothetical denial.

B2-R reconstructs state by independently examining each grant and later eligible facts; B2-S incrementally updates private exposure/grant/revoke/use state. Both see only prior `TOOL_OUTCOME`, `GRANT`, `REVOKE_SCOPE` and once-only projected `USE` facts. Current proposals and lifecycle/admission bookkeeping are outside history features. `USE` comes from selected grants in a staged reservation witness; outcomes never consume again. Failed reads create no exposure; failed dispatched releases do not refund consumption; unknown outcomes halt subsequent proposal evaluation. Supporting-reference storage and grant-ID tombstones are retained: no constant-memory claim is made.

The oracle separately consumes the raw assessor journal: controls/witnesses, proposals/order, source observations, forwarding attempts, handler arrivals, destination-tagged sink bytes and task outputs. It uses its own raw/base64/hex canary checks and pre-reservation permission snapshots. Its five dimensions remain separate from detector authorization, behavior and hypothetical recommendations. Incomplete observations preserve `INDETERMINATE` or `UNKNOWN`; task closure alone does not establish absence of disclosure. The replay ledger validates transcript execution choices without reading shadow findings. Neither it nor the oracle is a live controller.

There are 23 prewritten research transcripts, covering public/failed/denied reads, sticky exposure and unrelated public transfer, raw/base64 recognition, authorized release, revoke/new-grant ordering, consumption after success/failure/unknown outcome, wrong scopes, multi-resource coverage, static prohibitions, unsupported mappings, empty-selection synthetic override, hex disclosure, reconnect and ambiguous reservation. Additional tests exercise missing witnesses, task isolation, restart/closure validation, malformed reservations and incorrect/omitted normalized observations. Replay integration was chosen to validate policy semantics within the owner-approved M2 boundary; implementing a durable live controller here would cross into later milestones.

## Run M2 and regress M1

No dependencies were added or installed; `requirements-m1.txt` and its approved pins are unchanged. Use the existing Windows CPython 3.14.3 environment from the repository root:

```powershell
.\.venv\Scripts\python.exe -B -m unittest discover -s tests -p test_m2.py -v
.\.venv\Scripts\python.exe -B -m unittest discover -s tests -p test_m1.py -v
.\.venv\Scripts\python.exe -B -m chainguard.m2
.\.venv\Scripts\python.exe -B -m chainguard.client
git diff --check
git diff
git status --short --untracked-files=all
```

The replay command emits deterministic JSON with the staging label, frozen B0 point, findings and five-dimensional oracle observations for each proposal. It fails if a prewritten expectation or B2 prefix-equivalence check fails. Its repository-local fixture source is `tests/m2_fixtures.py`. The M1 command separately runs real MCP subprocesses.

## Actual M2 validation — 8 October 2026

- Complete M2 suite: **41 tests in 0.184s — OK**, exit 0.
- Complete unchanged M1 regression: **12 tests in 23.188s — OK**, exit 0.
- Standalone M1 flow: exit 0; discovery and success/error/success retained their expected correlated results.
- Replay harness: exit 0; **23 fixtures / 37 valid proposal prefixes**, all prewritten expectations passed, and B2-R/B2-S agreed at **every** prefix on authorization, behavior, recommendation, rules, explanations, supporting references and hypothetical selection.
- Matched order pair: byte-identical B1 input, B1 `INDETERMINATE` in both cases; B2 `UNAUTHORIZED` after grant→revoke and `AUTHORIZED` after revoke→NEW grant.
- Observed ambiguity analysis: **one mixed-label B1 input group**, minimum binary error count **1** for that observed group; **one oracle-INDETERMINATE proposal**, excluded from the binary grouping counts. This is not a population result or an accuracy benchmark.

The first M2 run reported four failures caused by one oracle bug: task closure incorrectly implied no disclosure despite incomplete observation coverage. The oracle was corrected to preserve unknown disclosure, with regression cases for missing coverage and uncertain permissions. Diff review added regressions for missing independent source observations, persistent unknown authority and duplicate ambiguous reservation records. Golden expectations and B0 content coverage were unchanged. Test durations are observations, not a performance study.

The hex case illustrates bounded history benefit over frozen B0 coverage using independently covered synthetic sink bytes. B1 also represents sticky exposure; this case does not establish an ordering advantage over B1. The matched grant/revoke pair provides the ordering distinction. Hard benign public-transfer and failed-read controls accompany those interpretations.

For the viva: B1 loses order while retaining counts; B2-R/B2-S agreement tests two implementations of one policy, while the independent oracle checks that policy against raw fixture observations. An unrelated public transfer can violate the conservative authorization contract without leaking a canary. Hypothetical detector denial cannot be credited with preventing a staged dispatch. Source/configuration digests identify frozen artifacts; they do not authenticate these transcripts. Live prevention, durable witnesses, evidence integrity, scaling, held-out accuracy and publication-level claims remain untested in M2.

## M3 durable persistence and live non-release staging

The owner approved this milestone interpretation on 8 October 2026. M3's trusted head is **continuity state `(last_seq, last_event_id)`**, maintained in memory with the record count and task/call lifecycle independently of SQLite. It does not commit the complete transcript cryptographically or detect arbitrary earlier-record mutation. `schema_version = m3-record-v1` and the stored class **M3_DURABLE_UNSEALED_NO_CRYPTOGRAPHIC_COMMITMENT** distinguish these developmental records from later M4 evidence. M3 records cannot be retroactively presented as M4-compliant signed evidence. SHA-256 `prev_hash` chaining, a cryptographic trusted head, signatures, keys, offline verification and evidence packages remain M4 work.

The live surface is deliberately restricted to M1's `echo` and `controlled_failure`, with their existing single synthetic string-token contract. Both are normalized as local, public, non-release operations; server/tool identity and succeeded/failed status distinguish them. The trusted gate rejects other tool names and invalid arguments before dispatch. It commits the default-disabled override and disabled release surface in the session-start execution profile. No observation setting or stored grant record enables a release call. For these non-release M3 calls, detector recommendations do not determine forwarding. Later enforcement behavior remains governed by the Architecture Lock; this slice does not establish a general detector non-enforcement rule.

| File | Responsibility |
| --- | --- |
| `chainguard/canonical.py` | Restricted deterministic UTF-8 JSON bytes; sorted keys, compact separators, preserved Unicode, bounded integers, strict decoding and duplicate-key/type rejection. No cryptographic operations. |
| `chainguard/audit.py` | Exact M3 envelope/body schemas, transactional appends, independent continuity/call state, a non-release gate, and read-only committed-history inspection. |
| `chainguard/proxy.py` | Optional internal audit hook used by the explicit M3 launch path. Required audit persistence precedes each M3 tool forwarding; result persistence precedes return to the client. The M1 entry point remains the transport demonstration. |
| `chainguard/m3.py` | Trusted singleton-run harness with fresh context/challenge, real scripted raw MCP client, the accepted relay/SDK server, shadow evaluations and independently retained runtime journal. |
| `tests/test_m3.py` | Canonical byte vectors, real temporary SQLite transactions, interruption/ambiguity tests, context isolation and real forwarding/outcome integration checks. |

### Record and transaction contracts

The single `audit_records` table stores `session_id`, `seq`, `event_id`, `event_type`, optional `call_id`, `run_id`, `task_id`, `monitor_instance_id` and `record_bytes` (canonical typed event BLOB). The primary key is `(session_id, seq)`; `(session_id, event_id)` is unique. A partial unique index rejects duplicate proposal/decision/intent/outcome phases for a call. Reads check indexed metadata against canonical bytes. The application inserts records and provides no replace/update path; this does not prevent a storage attacker modifying SQLite directly.

Every staged envelope carries schema/stream/monitor/event identity, contiguous `seq`, display-only UTC timestamp, event type and its exact body; call phases also carry `call_id`. Proposal admission ordinals are contiguous FIFO bookkeeping and never enter behavioral history. Exact body fields are declared in `audit.BODY_KEYS` and validated before persistence. Fixed generic, typed session-end and empty-intent byte vectors are checked in `tests/test_m3.py`. Canonicalization is deterministic for a fixed record; fresh live identities and timestamps are expected to vary between executions.

SQLite uses `journal_mode=DELETE`, `synchronous=FULL` and explicit `BEGIN IMMEDIATE`/`COMMIT` transactions. The required live boundary is:

```text
proposal + B0/B1/B2-R/B2-S shadow findings + controller decision + dispatch intent
  -> ONE confirmed SQLite commit
  -> advance trusted count/continuity/call state
  -> emit the observed transaction receipt
  -> permit forwarding
terminal handler result -> separate confirmed outcome transaction -> return response
```

Prepared rows or an in-memory draft do not enable dispatch. A known insertion failure rolls back the entire batch, leaves trusted count/head unchanged and halts the context. An exception once `COMMIT` begins is conservatively classified `AMBIGUOUS_COMMIT`: no automatic retry, database adoption, forwarding or claim of rollback. A result-write failure after tool execution cannot undo the effect and leaves the stream incomplete. A lost/unsupported downstream result is recorded as unknown where possible and stops later calls. If an already known, durably recorded result cannot be delivered to the client, that result stays known while the context halts. A halted/unresolved stream has no clean closing event; successful closure is explicitly `CLOSED_UNSEALED`.

Only execution-derived committed outcomes and storage-level grant/revocation primitives project semantic facts. Findings, proposals, decisions, IDs used for ordering, timestamps and continuity bookkeeping cannot create semantic facts. Grant/revocation storage tests do not activate permissions. M3 rejects nonempty dispatch selections and has no live grant/revoke interface. Its intents generate no `USE`; `USE` is never a separate stored consumption event. Grant-bearing once-only projection/consumption remains M6 work. M2's independent oracle and fixtures are unchanged and still reject claims of real commit evidence.

The parent harness retains issued raw synthetic requests, correlated responses, admission/forwarding diagnostics, transaction receipts emitted at the successful commit boundary, and independent tool-handler receipts outside SQLite. These observations assume the trusted runtime/fault-injection boundary and are not cryptographic proof against a dishonest monitor. They support M3 transaction/mediation checks; no full live five-dimensional oracle evaluation is claimed here.

On a fresh monitor launch, the harness creates a fresh run/task/session/challenge and starts a fresh controlled process context; the audit session creates a new monitor instance ID. This bounded slice uses one session per run. Reusing stored run/task/session identities is refused, and old rows can only be inspected. No SQLite reconstruction restores exposure, active grants, pending calls or client variables. A failed proxy invocation ends the controlled client/server context, with no automatic reconnect/replay. The trusted launch configuration establishes context; MCP client metadata does not authenticate it.

### Run M3

No dependencies were installed or changed. Validated with Windows x64, CPython **3.14.3**, SQLite **3.50.4**, and the existing approved `mcp==2.3.0` environment:

```powershell
.\.venv\Scripts\python.exe -B -m unittest discover -s tests -p test_m3.py -v
.\.venv\Scripts\python.exe -B -m unittest discover -s tests -p test_m1.py -v
.\.venv\Scripts\python.exe -B -m unittest discover -s tests -p test_m2.py -v
.\.venv\Scripts\python.exe -B -m chainguard.m3
git diff --check
git diff
git status --short --untracked-files=all
```

The demonstration uses a temporary SQLite file, inspects its committed records, returns the independently retained journal and removes the temporary directory. `demo --db <path>` can instead retain the audit file at an explicitly chosen local path. Keep generated databases/journals outside tracked/public artifacts. Discovery and tool listing retain the accepted M1 protocol path; typed per-call audit transactions cover the three supported tool calls.

### Actual M3 validation — 8 October 2026

| Executed check | Actual result |
| --- | --- |
| Complete M3 suite | **35 tests in 27.163s — OK**, exit 0 |
| Complete M1 regression | **12 tests in 27.548s — OK**, exit 0 |
| Complete M2 regression | **41 tests in 0.500s — OK**, exit 0 |
| Standalone real audited flow | Exit 0; modern discovery; success/error/success; **26 records / 8 confirmed transactions**; independent handler request IDs **3, 4, 5**; `CLOSED_UNSEALED` |
| Diff/status inspection | `git diff --check` and new-file whitespace checks passed; full tracked/new-file diffs and final unstaged status inspected |

Test durations are observations, including overlapping suite execution, not benchmarks. M3 covers successful durable append, rollback with no partial proposal/decision records, prepared/uncommitted rows, a child exiting inside an unfinished SQLite transaction, both committed and uncommitted loss-of-acknowledgement cases, real refusal to forward after write failure/ambiguity, outcome-write failure after an observed effect, unknown results, duplicate records/phases, closure, restart/reopen inspection, continuity agreement, immutable bytes, redaction and finding/semantic-history separation.

The first M3 run completed **31 tests with three teardown errors**: trigger-installation test connections were not explicitly closed, which kept temporary SQLite files open on Windows. Behavioral assertions passed; the cleanup failed. The tests were fixed to close these connections explicitly. Added byte-vector/unknown-outcome coverage then passed 34 tests. Full diff review added a regression ensuring client response delivery failure preserves an already committed known tool outcome; the final complete M3 and M1 suites passed as recorded above. No architecture, dependency, B0 coverage or golden M2 expectation changed.

For the viva: SQLite supplies atomic durable appends under its local filesystem assumptions; the process owns continuity and phase authority; canonical bytes make record representation reproducible; the later signature authenticates a cryptographic commitment. A database commit and a tool effect are separate operations, so an interrupted intent/outcome interval cannot justify replay or a clean close. Inspection of old rows is useful for audit reconstruction but cannot restore execution authority. JSON-line files were an alternative, but SQLite supplies explicit transaction/rollback behavior without a new dependency. M3 does not establish arbitrary MCP protection, storage tamper detection, trusted timestamps, power-failure correctness on arbitrary hardware, live permission lifecycle or M4 evidence acceptance.

M3 code and README changes remain unstaged for owner/student review. No commit or push is authorized by passing these checks. The Architecture Lock, Charter, Threat Model, Engineering Playbook and AGENTS remain unchanged.

The supplied paper is a proposal/literature baseline and needs alignment with this design before reporting implementation or results. The final marking rubric and evaluation date still need confirmation. The existing LICENSE contains only a placeholder heading; release readiness requires resolving it separately.
