# ChainGuard

ChainGuard investigates explainable security analysis of MCP tool-call sequences and independently verifiable evidence of the monitor's observations and decisions. It is an Information Security course project intended to support a reproducible IEEE-style study.

**Status, 8 October 2026:** **ARCHITECTURE LOCKED — ChainGuard Architecture v1.1**. M1, M2 and M3 were accepted, committed and pushed (`3e7f6e8`, `5515b05`, `21d655b`, confirmed in main's history). M2 remains replay-only; M3 implements durable SQLite records and a noncryptographic continuity head. The owner approved the M4 design and implementation. M4 now adds new SHA-256 chained streams, ECDSA P-256 closures and pinned-key offline inspection with deterministic finding reproduction. M4 changes/results await student review and remain uncommitted. M5 durable fresh submission/adversarial evaluation and M6 live grant/revoke/one-use execution remain unimplemented.

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

The owner approved this milestone interpretation on 8 October 2026. M3's trusted head is **continuity state `(last_seq, last_event_id)`**, maintained in memory with the record count and task/call lifecycle independently of SQLite. It does not commit the complete transcript cryptographically or detect arbitrary earlier-record mutation. `schema_version = m3-record-v1` and the stored class **M3_DURABLE_UNSEALED_NO_CRYPTOGRAPHIC_COMMITMENT** distinguish these developmental records from M4 evidence. M3 records cannot be retroactively presented as M4-compliant signed evidence. The separate M4 implementation below creates new chained streams; the M3 entry point still produces its original unsealed format.

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

The owner subsequently reviewed M3 and authorized its commit/push (`21d655b`). M4's shared writer extension retains M3's record schema, noncryptographic state, failure semantics and entry point. The Architecture Lock, Charter, Threat Model, Engineering Playbook and AGENTS remain unchanged.

## M4 cryptographically verifiable committed evidence

M4 implements the approved A3 chain/signature slice and repeatable **INSPECT** verification. It extends the durable writer rather than reconstructing trusted running state from SQLite. It introduces no live release capability, grants, revocation, permission consumption or enforcement policy. The supported live calls remain M1's public, non-release `echo` and `controlled_failure`; their authorization gate remains independent of observation-mode shadows. The existing M2 oracle and detector semantics are unchanged.

| File | Responsibility and choice |
| --- | --- |
| `chainguard/audit.py` | Small internal format hooks reuse typed validation, explicit transactions and confirmed state advancement. M3 defaults and its public schema validator remain strict. |
| `chainguard/canonical.py` | Unchanged encoding algorithm, now named `chainguard-json-v1`; no cryptographic operations. |
| `chainguard/evidence.py` | Exact M4 schemas, manifest/genesis/event commitments, process-owned cryptographic head, snapshot reconciliation, library signing and key loading. |
| `chainguard/verifier.py` | Offline inspection with external expectations/pins, independently recomputed hashes and approved detector reproduction. |
| `chainguard/m4.py` | Fresh trusted launch/bootstrap, independent parent journal, fixture key provisioning and separate-process verification after monitor exit. |
| `tests/test_m4.py` | Fixed byte/hash vectors, focused mutations, transaction/head checks, sealing failures and real integration. |

### Canonical bytes, chain and persistence

The restricted JSON encoder preserves Unicode, emits UTF-8 with sorted keys and compact separators, and accepts explicit strings/booleans/null and integers within ±(2^53−1). Floats, non-finite values, duplicate keys, invalid Unicode, unknown schemas, extra typed fields and noncanonical bytes are rejected. This project format does not claim RFC 8785 compliance.

The exact construction from Architecture Lock §8 is:

```text
D_M = ASCII("CHAIN GUARD MANIFEST-v1")   || 0x00
D_G = ASCII("CHAIN GUARD GENESIS-v1")    || 0x00
D_E = ASCII("CHAIN GUARD EVENT-v1")      || 0x00
D_C = ASCII("CHAIN GUARD COMMITMENT-v1") || 0x00

M   = SHA256(D_M || canonical(manifest))
H_0 = SHA256(D_G || raw_32_bytes(M))
event_i.prev_hash = lowercase_hex(H_(i-1))
H_i = SHA256(D_E || canonical(event_i))
signing_input = D_C || canonical(commitment)
```

Identity, `seq` and `prev_hash` are inside the canonical event. Its current hash is outside the event in the storage/export wrapper. Digests are exactly 64 lowercase hexadecimal characters. The canonical expected inventory uses `SHA256(canonical(inventory))` as specified in §19.3. Source-artifact/configuration digests identify approved inputs; they do not themselves authenticate those inputs.

M4 uses a fresh `user_version=4` database. `audit_records` retains M3's identity/correlation columns and constraints and adds `event_hash`; `record_bytes` holds the complete canonical M4 event including `prev_hash`. `audit_manifests(session_id, manifest_bytes, manifest_digest)` stores the canonical manifest. Manifest and initial record commit together. No M3 database migration or retrospective signature is provided.

The process maintains immutable count/continuity state plus `manifest_digest` and `cryptographic_head`. Proposed hashes and complete candidate state are prepared before the transaction; neither becomes authoritative until commit confirmation. Under the existing task gate:

```text
proposal + four shadows + controller decision + empty-selection intent
  -> one SQLite transaction containing complete records/hashes
  -> confirmed COMMIT
  -> advance trusted continuity, cryptographic and semantic state
  -> observed commit receipt
  -> forwarding
terminal outcome -> separate confirmed transaction -> client response
```

Rollback leaves both heads and semantic history unchanged. An exception after COMMIT begins halts as ambiguous, with no adoption, retry, forwarding or claim of rollback. Prepared SQLite rows do not authorize dispatch. A later result-write failure cannot undo execution. Restart requires fresh monitor/client/run/task/session/challenge; stored records never restore execution authority. This remains local SQLite durability under the stated filesystem/runtime assumptions, not a power-loss certification.

### Manifest, closure and signing

`m4-manifest-v1` binds record/canonical/protocol versions, observation scope, run/task/session/monitor identities, mode, the disabled-release/default-disabled-override profile, a fresh assessor-issued 32-byte random hexadecimal challenge, expected-inventory digest, policy/registry/normalizer/detector versions and digests, code revision and source-artifact digests. References use fixed module names; machine paths, PIDs and environment values are absent. Required display timestamps stay in events and are not freshness authorities.

At launch the monitor emits its new instance ID. The parent registers it in the external expected inventory and fixes configuration before sending trusted bootstrap and any MCP requests. This bootstrap is an internal controlled-host channel; ordinary MCP metadata cannot establish context. The independent parent journal retains prewritten requests, responses, transaction receipts and tool-handler observations outside SQLite. These witnesses assume the trusted runtime; they are not proofs of monitor honesty or a full new live oracle.

`m4-commitment-v1` has exactly: `schema_version`, `record_schema_version`, `canonicalization_version`, `run_id`, `task_id`, `session_id`, `monitor_instance_id`, `run_challenge`, `expected_inventory_digest`, `manifest_digest`, `record_count`, `final_seq`, `final_head`, `closure_status`, `hash_algorithm`, `signature_suite`, `signature_encoding`, `signer_key_id`. Contiguous sequence makes count and final sequence equal; both are bound explicitly. Algorithm/encoding values are `SHA256`, `ECDSA-P256-SHA256-DER-v1`, `DER-base64`.

Sealing stops admissions, requires terminal known outcomes, durably appends `SESSION_END` with `CLOSED`, freezes trusted manifest/count/head, then reads one explicit SQLite snapshot. Schema/lifecycle/sequence and all hashes must reconcile with the frozen process values. Signing/export uses that exact snapshot without rereading storage. Self-verification must pass before output success. The output uses exclusive file creation and is flushed/fsynced; failure reports incomplete and does not replace an existing file. No executed effect is rolled back.

Signing uses `private_key.sign(signing_input, ec.ECDSA(hashes.SHA256()))` with P-256. SHA-256 runs inside the library API once; no preliminary commitment hash is passed to that API. DER signature bytes are transported as strict base64. ECDSA nonce generation is delegated to the library; signatures need not have identical bytes when the same commitment is signed again.

Progress separately reports prefix `durability`, `sealing`, `signature` and `verification`. A committed `CLOSED` event alone is not a signature or verified package. Failed reconciliation/signing/export marks sealing `INCOMPLETE`; a signature already produced before export failure can remain `SIGNED` while export is unsuccessful. Halted contexts cannot resume appending or automatically retry sealing.

Private keys are outside the repository and SQLite. The fixture provisions a key before execution and pins its public key independently for that evidence configuration. Repeated verifier processes reuse that pin; they never generate keys or trust a key embedded in evidence. The explicit `keygen --private-key <external-path> --public-key <trusted-path>` command refuses existing files and repository private-key paths. Generated fixture PEM private keys are unencrypted demonstration artifacts; production key custody is not implemented. Separate files on this host do not establish OS privilege isolation: simulated storage mutation is restricted to the audit database/package, excluding keys, expected configuration and assessor journals.

### Package and offline inspection

The canonical package has exactly `format_version = m4-evidence-v1`, `manifest`, ordered `records` containing `{event, event_hash}`, `commitment`, and `signature`. Approved configuration definitions and artifact references are in the manifest. No executable artifact selected by evidence is run.

Inspection freezes package bytes and reports six dimensions independently as `PASS`, `FAIL`, `INCOMPLETE` or `NOT_CHECKED`: schema/lifecycle/sequence, recomputed commitment/link integrity, trusted signature, external expected-context/configuration binding, signed/inventory completeness, and deterministic finding reproduction. `inspection_passed` is only an all-dimensions summary; the individual results remain available. A valid old signature can pass origin while failing the expected challenge/context. An altered record can fail its chain while the original unchanged closure signature still passes.

Reproduction uses approved installed B0/B1/B2-R/B2-S code. B0 sees only current facts; B1 receives the exact unordered projection; B2-S incrementally observes eligible facts and is compared with full-prefix B2-R. Only prior committed outcomes and existing storage-level control facts enter history. Findings, controller conclusions, lifecycle, sequence, timestamps and hashes are excluded from behavioral features. Required findings must be present and match versions/digests, authorization, behavior, hypothetical recommendation, rule, references and explanation. The independent oracle remains unchanged and is not called for cryptographic inspection.

This reference verifier requires matching approved source artifacts, Git revision and external configuration. It performs no MCP calls, needs no SQLite database or monitor process, and requires no private key. It currently inspects one session package against an exact singleton inventory; a larger expected inventory cannot pass on one session alone. Repeated inspection is allowed. **Durable fresh complete-run acceptance, duplicate rejection after restart and the full adversarial campaign remain M5. M6 live permission lifecycle and final-study A3T/A4T comparisons remain pending.**

### Run M4

No dependencies were installed or changed. M4 uses the already approved/installed `cryptography==50.0.2` plus standard-library SHA-256/SQLite/JSON/unittest. The owner approved unittest commands because pytest is absent. Runtime remains Windows x64 / CPython 3.14.3 / SQLite 3.50.4 / MCP 2.3.0.

```powershell
.\.venv\Scripts\python.exe -B -m unittest discover -s tests -p test_m4.py -v
.\.venv\Scripts\python.exe -B -m unittest discover -s tests -p test_m3.py -v
.\.venv\Scripts\python.exe -B -m unittest discover -s tests -p test_m2.py -v
.\.venv\Scripts\python.exe -B -m unittest discover -s tests -p test_m1.py -v
.\.venv\Scripts\python.exe -B -m chainguard.client
.\.venv\Scripts\python.exe -B -m chainguard.m3
.\.venv\Scripts\python.exe -B -m chainguard.m4
git diff --check
git diff
git status --short --untracked-files=all
```

The default M4 demonstration removes its external temporary fixture directory after printing the result. To retain a fresh fixture and repeat inspection in another process:

```powershell
$taskM4Directory = Join-Path $env:TEMP ("chainguard-m4-review-" + [guid]::NewGuid())
.\.venv\Scripts\python.exe -B -m chainguard.m4 demo --directory $taskM4Directory
.\.venv\Scripts\python.exe -B -m chainguard.verifier --package "$taskM4Directory\evidence.json" --expected "$taskM4Directory\expected.json" --config "$taskM4Directory\configuration.json" --public-key "$taskM4Directory\fixture-public.pem" --key-id chainguard-m4-fixture-key
```

### Actual M4 validation — 8 October 2026

| Executed check | Actual result |
| --- | --- |
| Complete final M4 suite | **45 tests in 35.993s — OK**, exit 0 |
| Complete M3 regression | **35 tests in 26.312s — OK**, exit 0 |
| Complete M2 regression | **41 tests in 0.368s — OK**, exit 0 |
| Complete M1 regression | **12 tests in 20.287s — OK**, exit 0 |
| Standalone M1 flow | Exit 0; modern discovery and correlated success/error/success |
| Standalone M3 flow | Exit 0; 26 records / 8 transactions; `CLOSED_UNSEALED`, original noncryptographic class |
| Standalone M4 flow | Exit 0; request IDs 3/4/5 returned `m4-success-A`, `controlled failure: m4-failure-B`, `m4-success-C`; 26 records / 8 confirmed transactions |
| Separate-process offline verifier | Exit 0 after monitor termination; all six dimensions PASS; 12 findings reproduced at 3 B2-agreeing prefixes |
| Diff/status inspection | `git diff --check` and all new-file whitespace checks passed; complete tracked/new-file diffs inspected; three modified and four new files remain unstaged |

The first smoke flow and initial complete suite passed; the initial suite had **42 tests in 43.784s — OK**. There were no failed-first-run tests. Review added actual ambiguous-commit forwarding refusal, empty-stream/noncanonical-package checks and explicit INCOMPLETE reporting for missing closure/signature/records, bringing the suite to 45. That run passed in 43.713s. Final diff review strengthened reconciliation to use a structurally valid, fully recomputed SQLite chain; the complete final suite passed in 35.993s. Fixed vectors were independently calculated with literal domain bytes and standard-library JSON/hashlib, then retained as test constants. Earlier checks overlapped; durations are test observations, not benchmarks.

Tests distinguish changed records, recomputed chains against an old signature, incorrect authentic findings, absent required findings, wrong key/curve/suite, external context mismatch, unsealed/truncated evidence and snapshot/sign/export failure. They verify both heads remain unchanged on rollback/ambiguity and that required failures block actual forwarding. The full M5 campaign is not implemented or claimed complete.

For the viva: the chain commits ordered canonical facts; the process-owned head prevents replacing live authority with attacker-recomputed SQLite; the final signature authenticates the stated closure under an independently pinned key. Reproduction checks consistency with approved rules, not raw observation truth. Signatures do not prove monitor honesty, complete capture, correct tool behavior, detector correctness, trusted time, universal tamper resistance or novel cryptography. M3 records remain unsealed developmental records. M4 is pending student review; no commit or push has been made.

The supplied paper is a proposal/literature baseline and needs alignment with this design before reporting implementation or results. The final marking rubric and evaluation date still need confirmation. The existing LICENSE contains only a placeholder heading; release readiness requires resolving it separately.
