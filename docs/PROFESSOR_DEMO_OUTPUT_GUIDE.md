# ChainGuard professor demonstration: output guide

## 1. Purpose and boundaries

This is a suite of bounded, synthetic demonstrations. M1 shows controlled MCP transport; M2 compares representations on prewritten replay fixtures; M3 records a live non-release sequence; M4 signs and independently inspects that kind of sequence; M5 pre-registers and accepts a separate signed run. The retained M6Q records show an engineering qualification of the trusted-host permission path. They are **not** a completed research evaluation.

M1–M5 are separate processes and histories, not one continuous MCP conversation. M5 calls the M4 demonstration itself because its expectation must be registered **before** that run executes. The standalone M4 package from the previous step is not submitted to M5. M6Q is read from the retained `live_m6_current` tree: its historical harness uses a fixed output location and must **not be rerun** during this presentation.

These steps establish that specific controlled flows and checks worked in the owner's environment when freshly run. They do not establish general MCP coverage, arbitrary information-flow tracking, detector superiority, trusted time, or completed E01–E13 research measurements. The controlled surface is local stdio MCP plus the M6 synthetic source and local sink.

## 2. Before starting

From the repository root in ordinary Windows PowerShell, run:

```powershell
.\scripts\demo\Run-ProfessorDemo.ps1
```

The runner resolves the repository from its own location and uses the existing `.venv\Scripts\python.exe`. It checks that the interpreter runs, the required Python modules import, and the named M6Q historical files exist. It does not create an environment or install anything. M4/M5 may perform their already established internal revision lookup; the runner performs no separate Git command.

A new `chainguard-professor-<GUID>` directory is made under the user's `$env:TEMP`, outside the repository. The runner refuses an existing run path. Its `logs/` directory holds each Python child's raw stdout and stderr separately. It retains M3's SQLite database, M4's database, signed package, expected inventory, configuration and fixture keys, plus M5's separate registry, live package, keys and synthetic campaign artifacts. `run-manifest.json` records status and paths. Failed runs keep their partial artifacts.

**Keep the whole run directory private.** `m4/fixture-private.pem` and `m5/live/fixture-private.pem` are unencrypted synthetic signing keys. Do not display, paste, publish or commit them. Do not delete the evidence before reviewing a failed run. Share only selected logs or redacted reports after checking their contents. The historical M6Q tree and acceptance registry must remain untouched.

## 3. Reading the console and manifest

Each header identifies a step. The runner prints the exact child command, UTC start/end times, process exit code, and a short output preview; full bytes stay in separate log files. A `PASS` summary is a runner check of the parsed output and expected artifacts. The final manifest gives every step's command array, timestamps, exit code, raw log paths, artifact paths and verification fields. A successful run ends with suite status `PASSED` and the manifest path. If it stops, read `failed_step`, the two raw logs for that step, and the preserved partial artifacts. Do not simply rerun into the same directory; a new launch gets a new GUID directory.

An exit code describes a **process**, while `isError`, `authorization_assessment`, `status` and `reason` describe tool or security outcomes inside a successful process. The M1/M3/M4 controlled tool error is intentional. M5's campaign process exits 0 only when its first `ACCEPTED` and later `REJECTED`/`ALREADY_ACCEPTED` both match expectations. A manually repeated `m5 accept` CLI call would exit 2 for that expected rejection; this runner does not issue an extra manual call.

### Successful run used below

I identified `C:\Users\Laptop\AppData\Local\Temp\chainguard-professor-7a5207b6676c45cfb0d952f264dad748` from its own `run-manifest.json`: all nine steps have status `PASSED`. The other inspected professor-run manifest stopped at `preflight-imports`. In the successful run, `<run>/logs/<step>.stdout.log` contains full JSON, stderr has separate diagnostics, and the manifest names every log and artifact. The run reports Python 3.14.3, M2 23 fixtures/37 valid proposal prefixes, M3 and M4 26 records each, and M5 32 synthetic cases/16 engineering tests. Those are observed engineering run values, not fixed promises or completed research measurements. GUIDs, timestamps, hashes, process IDs, paths and signatures vary. The historical M6Q tree under `results/` is separate from this new run.

## 4. M1 — MCP transport

`chainguard.client` uses the MCP SDK to contact the stdio proxy and its controlled server. It explicitly discovers the pinned protocol and two tools, sends `echo`, sends `controlled_failure`, then sends `echo` again. The output fields appear as `protocol_version`, `server`, `tools`, `success`, `controlled_error`, `success_after_error`. Each result object has `isError` and `text`. In the source, the three tokens are `m1-success-A`, `m1-failure-B` (returned as `controlled failure: m1-failure-B`), and `m1-success-C`. The middle result's `isError` is true; the last false result shows the transport and correlation continued after the error. Protocol version and server identity are checked, not free-form labels.

### A. Exact inputs

The runner (`scripts/demo/Run-ProfessorDemo.ps1`) invokes the existing Python with `-B -m chainguard.client`, repository working directory and `PYTHONUTF8=1`. `chainguard/client.py:exercise` constructs discovery and tool-list requests, then SDK calls `echo` with `{"token":"m1-success-A"}`, `controlled_failure` with `{"token":"m1-failure-B"}`, and `echo` with `{"token":"m1-success-C"}`. These are code-defined synthetic values, **not** a separate fixture file. The SDK supplies runtime JSON-RPC IDs and per-request metadata. `chainguard/__init__.py` defines the pinned protocol version; `chainguard/controlled_server.py` defines the two tools and the one-string-token schema. No database, registry, key, oracle or operator-provided payload is read.

### B. What each input represents

The first and third calls are ordinary successful requests. The middle call deliberately produces a tool-level error, not a policy denial or crashed process. Discovery/listing establish the expected server and bounded tool surface. The third call tests whether a later request still correlates correctly after an error.

### C. Exact source file

Request construction is in `chainguard/client.py`; transport validation is in `chainguard/proxy.py`; the fixed handlers are in `chainguard/controlled_server.py`. These files contain code that constructs or handles inputs, not a separate M1 fixture.

### D. Processing path

`chainguard/client.py:exercise` starts `chainguard.proxy` through the SDK. `chainguard/proxy.py:run` validates JSON-RPC framing, IDs, method, metadata and protocol version, then forwards to `chainguard.controlled_server`. Its `call_tool` handler validates the token, returns it unchanged for `echo`, or prefixes `controlled failure: ` and sets `is_error=True`. The proxy checks the response ID before relaying it. `chainguard/client.py:verify_result` checks the returned `isError` and text against each originating call. No M3/M4 audit state changes here.

### E. Output and location

The client JSON is printed to `<run>/logs/M1-client.stdout.log`; stderr is separate. `run-manifest.json` records command, log paths, exit code and checked protocol/server/error/recovery fields. The successful run prints `protocol_version=2026-07-28`, `server=chainguard-controlled-m1`, the two tool names, and `success.isError=false`, `controlled_error.isError=true`, `success_after_error.isError=false` with the exact texts above.

### F. Input → processing → decision/state change → output

`echo(m1-success-A)` → validated relay/handler → success → `success.text=m1-success-A`. `controlled_failure(m1-failure-B)` → deliberate handler error → `controlled_error.text=controlled failure: m1-failure-B`. `echo(m1-success-C)` → next valid request → `success_after_error.text=m1-success-C`. The final result shows transport/error handling continued; it is not M4/M6 audit evidence.

**Say:** “I gave the controlled server two echo tokens with a deliberate failure between them. The client checked each response and still received the last echo. The evidence is in `M1-client.stdout.log`.”

## 5. M2 — B0/B1/B2 replay

`chainguard.m2` loads staged fixtures and prewritten expectations. It executes **no live tool** and makes no durable audit commit. Its admission ledger projects a common history into B0 current-event, B1 conservative unordered-prefix, and B2 ordered-state forms. B2-R is the full-prefix reference; B2-S is incremental state. The fixture oracle independently assesses authorization, dispatch, permission consumption, disclosure and task completion from staged observations, rather than reading detector verdicts as truth.

The top-level JSON order is `evidence_class`, `execution` (`REPLAY_ONLY_NO_TOOL_EXECUTION`), `b0_operating_point`, `extraction_version`, `fixture_count`, `valid_proposal_prefixes`, `b2_equivalence` (`PASS_AT_EVERY_VALID_PROPOSAL_PREFIX`), `mixed_b1_input_groups`, `observed_minimum_binary_errors`, `oracle_indeterminate_count`, and `fixtures`. Each fixture has `name` and `proposals`; each proposal has `call_id`, four `detectors`, and an `oracle`. A detector finding has its identity/version/digest fields and separate `behavior`, `authorization`, `hypothetical_recommendation`, rule, supporting IDs and explanation. The oracle describes independently specified effects. Counts depend on the committed fixtures; the runner reports the actual values. Mixed B1 input groups indicate identical unordered inputs with both authorized and unauthorized oracle labels. The minimum binary error count is a representational ambiguity observation, not a final held-out performance score. A B2 equivalence pass proves the two implementations agreed on these valid prefixes, not that their policy is correct.

### A. Exact inputs

The runner calls `-B -m chainguard.m2`, with no live MCP connection, database or key. `tests/m2_fixtures.py:research_fixtures` **constructs** `FIXTURES` as Python data; it contains the synthetic resources/canaries, staged journal instructions and prewritten `Expected` labels. `chainguard/oracle.py` defines the `Fixture`, `JournalRecord`, `Expected` structures and independent assessor. `chainguard/semantics.py` defines the policy, current extraction and unordered projection; `chainguard/detectors.py` defines the four evaluators. The fixture's resource registry and `sink` destination become a runtime `Policy`.

### B. What each input represents

Use the exact fixtures `order-grant-then-revoke` and `order-revoke-then-new-grant` in `tests/m2_fixtures.py`. Both stage a successful sensitive `read-a` of `secret-a`, then a `send`. In the first, grant precedes revoke; in the second, revoke precedes a **new** grant. The current send and unordered prior fact counts match, but active permission differs. The first `send` is prewritten as unauthorized/not dispatched; the second as authorized/confirmed. These are fixture expectations, not detector-generated truth. `chainguard/oracle.py:assess` derives observations from staged controls, proposals, reservation/arrival/source/sink witnesses and task output.

### C. Exact source file

The authored fixture and expected labels are in `tests/m2_fixtures.py`. `chainguard/oracle.py` defines the independent assessor; `chainguard/m2.py`, `chainguard/semantics.py` and `chainguard/detectors.py` load and evaluate the staged data.

### D. Processing path

`chainguard/m2.py:load_fixtures` loads `tests/m2_fixtures.py`. `experiment` and `run_fixture` pass its journal entries to `ReplayLedger.accept`, which validates admission order and assembles eligible history facts. At each `PROPOSAL`, `extract_current` gives B0 only current-call facts; `project_b1` gives B1 current facts plus unordered scoped counts; `B2Reference.evaluate` receives ordered prior facts; `B2Streaming.evaluate` uses its incrementally updated ordered state. `equivalent` compares B2-R/B2-S at every valid proposal. `chainguard/oracle.py:assess` runs separately, and `verify_expectations` checks the independently specified labels. Staged records are replayed deterministically; no child tool executes and no SQLite transaction occurs.

### E. Output and location

`<run>/logs/M2-replay.stdout.log` contains `fixtures[].name`, then `proposals[].call_id`, four `detectors[]` in B0/B1/B2-R/B2-S order, and the independent `oracle`; the manifest records fixture count, valid prefixes and equivalence. The successful run has 23 fixtures, 37 prefixes, `b2_equivalence=PASS_AT_EVERY_VALID_PROPOSAL_PREFIX`, one mixed B1 input group and one observed minimum binary error. In the named pair's `send`, the first oracle says `authorization=UNAUTHORIZED`, `dispatch=NOT_DISPATCHED`; B2-R/B2-S agree on unauthorized. The second oracle says `AUTHORIZED`, `CONFIRMED`; B2-R/B2-S agree on authorized. B0/B1 report `INDETERMINATE` authorization in both sends. These are staged engineering observations, not held-out performance results.

### F. Input → processing → decision/state change → output

`read → grant → revoke → send` → ordered B2 has no active grant → unauthorized send. `read → revoke → new grant → send` → B2 has an active grant → authorized send. B1's unordered counts cannot distinguish their order; B0 only sees the current send. The oracle fields record the separately staged dispatch/effect, while `b2_equivalence` reports implementation agreement, not oracle correctness.

**Say:** “These two staged histories differ only in the order of grant and revoke. I gave the same current send to each representation; B2 distinguishes the permission state, while B0 and B1 cannot. The paired results are under their fixture names in `M2-replay.stdout.log`.”

## 6. M3 — durable event recording

`chainguard.m3 demo --db` sends discovery, tool listing, then echo/failure/echo requests with tool request IDs 3, 4 and 5. The live proxy appends typed events in a fresh SQLite database and emits commit receipts; the controlled handler provides arrival observations. Output fields are `record_class`, `protocol_version`, `expected_context`, `monitor_instance_id`, `record_count`, `continuity_head`, `closure`, `tool_outcomes`, `handler_request_ids`, `confirmed_transactions`, `commit_witnesses`, `assessor_journal`, and `crypto_evidence_implemented`. `expected_context` contains fresh run/task/session/challenge identifiers. `continuity_head` is the final sequence and event ID; `tool_outcomes` should be `succeeded`, `failed`, `succeeded`. `commit_witnesses` are transaction receipts. `assessor_journal` retains issued requests, runtime observations and responses. The source checks handler arrivals and reconstructed history. `crypto_evidence_implemented` is false: M3 is durable recording without a signed closure.

The M3 `closure` value is `CLOSED_UNSEALED`, which is a clean unsealed close, not a signature. To inspect safely, use a read-only SQLite viewer on the **new** `m3/audit.sqlite`, or inspect the M3 stdout log and manifest. Avoid editing the database or opening the historical registry as a writable database. A database row is a recorded observation, not independent proof that every external event was captured.

### A. Exact inputs

The runner passes `-B -m chainguard.m3 demo --db <run>/m3/audit.sqlite`; that database path is fresh and external. `chainguard/m3.py:execute_demo` **constructs** newline-delimited JSON-RPC frames in code: IDs 1/2 are discovery/listing, and IDs 3/4/5 call `echo(m3-success-A)`, `controlled_failure(m3-failure-B)`, `echo(m3-success-C)`. Each includes pinned protocol metadata. `execute_demo` generates UUID run/task/session/challenge values; `AuditSession` generates monitor/event/call IDs. `chainguard/audit.py:PROFILE` fixes the non-release observation policy. `chainguard/m3.py:shadows` supplies B0/B1/B2 finding bodies for public echo. No existing registry, key or independent oracle fixture is supplied.

### B. What each input represents

The fixed success/error/success calls exercise live handling and outcome recording. The generated identities bind one fresh session and its requests; the challenge is context, not an M3 signature. The failed tool call is a controlled tool outcome, while the overall M3 process should still succeed. No sensitive release or grant is attempted.

### C. Exact source file

`chainguard/m3.py` constructs the frames and generated context. `chainguard/proxy.py`, `chainguard/audit.py` and `chainguard/controlled_server.py` process them; no separate M3 request fixture file is loaded.

### D. Processing path

`chainguard/m3.py:execute_demo` sends the frames to `chainguard.m3 proxy`. `chainguard/proxy.py:run` validates and calls `chainguard/audit.py:LiveAudit.before` for tools. `before` normalizes the call, gets shadow findings, and commits `CALL_PROPOSAL`, four `DETECTOR_FINDING` records, `DISPATCH_DECISION` and `DISPATCH_INTENT` before forwarding. `chainguard/controlled_server.py:call_tool` handles the request. `LiveAudit.after` commits `TOOL_OUTCOME` as succeeded or failed; `AuditSession.finish` writes `SESSION_END`. `m3.execute_demo` calls `read_records` and `reconstruct_history` on the stored rows to derive `tool_outcomes`. This inspection never restores execution authority.

### E. Output and location

`<run>/m3/audit.sqlite` has `audit_records` with canonical `record_bytes` and metadata, plus `call_phases`, a unique **index**, both defined in `chainguard/audit.py:AuditSession._schema_statements`. `append_batch` returns transaction `CommitReceipt` values; the nested proxy emits `audit_committed` diagnostics captured in `assessor_journal.runtime_observations` and `commit_witnesses`. Handler `tool_received` diagnostics supply `handler_request_ids`. The outer report is `<run>/logs/M3-durable.stdout.log`, named by the manifest. The successful run shows 26 records, eight confirmed transactions, handler IDs `[3,4,5]`, `tool_outcomes=[succeeded,failed,succeeded]`, and `closure=CLOSED_UNSEALED`. Generated IDs, timestamps and receipts vary.

### F. Input → processing → decision/state change → output

Request 3 → proposal/decision/intent commit → echo handler → persisted `TOOL_OUTCOME=succeeded`. Request 4 follows the same audit path, but the handler returns its deliberate error → `TOOL_OUTCOME=failed`. Request 5 succeeds afterward. The process exit code 0 and the failed middle **tool** outcome answer different questions.

**Say:** “I sent three live tool calls with a deliberate failure in the middle. The audit committed the decisions before forwarding, then recorded all three outcomes in SQLite. I can show the reconstructed sequence in `M3-durable.stdout.log` and its database path in the manifest.”

## 7. M4 — signed evidence

M4 runs a new non-release echo/failure/echo sequence. The monitor records normalized events and transaction receipts, reconciles the event-chain head at clean closure, signs the closure with ECDSA P-256/SHA-256, exports `evidence.json`, exits, then launches a separate offline verifier. The stdout report fields appear as `milestone`, `protocol_version`, `live_results`, `record_count`, `final_head`, `confirmed_transactions`, `handler_request_ids`, `monitor_exited_before_verification`, `monitor_launch_pid`, `progress`, `offline_verifier_exit_code`, `offline_verification`, `assessor_journal`, `M5_fresh_submission_implemented`, and `M6_permission_lifecycle_implemented`. The last two fields describe **this M4 fixture's scope**, not the current repository's overall implementation. The source expects 26 committed records in this fixture, eight receipts, and handler IDs 3–5; the runner reads the actual report.

The M4 verifier reports six dimensions, in order: `schema_lifecycle` checks canonical structure and call lifecycle; `commitment_integrity` recomputes manifest/genesis/event hashes and signed closure count/head; `trusted_signature` checks P-256/SHA-256 against the externally supplied public key; `expected_binding` matches the independent run challenge/session inventory and approved configuration; `inventory_completeness` checks clean closed singleton evidence against the expected inventory; `finding_reproduction` recomputes B0/B1/B2 findings from eligible recorded facts. `inspection_passed` requires all six to pass. Signing authenticates a commitment by the pinned key. Reproduction checks consistency with the frozen detector and policy. Neither proves that a recorded external event actually happened, that behavior was benign, or that the local time was trusted.

The `m4/` artifacts are `audit.sqlite`, `evidence.json`, `expected.json`, `configuration.json`, `fixture-public.pem`, and **private** `fixture-private.pem`. Keep the independently supplied expectations/configuration/public key apart from the submitted package when explaining the trust contract; their being in one temporary demo directory is a convenience, not a strong OS trust boundary.

### A. Exact inputs

The runner invokes `-B -m chainguard.m4 demo --directory <run>/m4`; `chainguard/m4.py:execute_demo` constructs discovery/listing and three tool-call frames with IDs 3–5 and fixed synthetic tokens `m4-success-A`, `m4-failure-B`, `m4-success-C`. It generates fresh run/task/session UUIDs and a random run challenge. `chainguard/evidence.py:configuration` builds the non-release tool registry, policy, normalizer/detector identities, source digests and approved code revision from installed source; `chainguard/audit.py:PROFILE` and `chainguard/controlled_server.py:INPUT_SCHEMA` are inputs to that configuration. This is code-generated configuration, not a pre-existing JSON file. `chainguard/m4.py:provision_key` generates a new P-256 fixture keypair outside the repository. No old database or registry is reused.

### B. What each input represents

The calls are the same bounded live non-release success/error/success pattern as M3, with a new session. The expected inventory describes **which** run, challenge, task, session and launched monitor must appear. The configuration freezes **which** code/policy/tool definitions the verifier should approve. The private key signs a clean closure; its matching public key is a verifier trust input. The caller does not learn trust by reading a key from the evidence package itself.

### C. Exact source file

`chainguard/m4.py` constructs requests, inventory and keys. `chainguard/evidence.py` creates configuration, chain and signature; `chainguard/audit.py` handles audited calls; `chainguard/verifier.py` inspects the package.

### D. Processing path

`chainguard/m4.py:execute_demo` starts `m4.proxy` and waits for its `m4_monitor_ready` diagnostic so the actual monitor ID can be included in the inventory. It writes generated `expected.json` and `configuration.json` **before** sending the trusted bootstrap manifest/inventory and MCP frames. `chainguard/evidence.py:make_manifest` binds inventory/configuration to the session. `chainguard/proxy.py:run` and `chainguard/audit.py:LiveAudit` process the calls. `chainguard/evidence.py:ChainedAuditSession` stores the manifest in `audit_manifests`, records in `audit_records`, and an event hash with each record. Starting from a manifest-derived genesis hash, each event includes `prev_hash` and yields the next `event_hash`. On clean close, `seal` freezes the stored snapshot, reconciles count/head against trusted writer state, makes the commitment, signs it and exports the package. `chainguard/m4.py` then starts `chainguard.verifier` in another process.

The four layers are distinct: **audited data** are normalized proposals, findings, decisions, intents, outcomes and closure; **chained data** are the canonical events linked by `prev_hash` and event hashes; **signed data** are the domain-separated canonical commitment containing identities, challenge, inventory/manifest digests, record count, final sequence/head, closure status, algorithms and signer key ID; **independently checked data** are the exported package against separately supplied inventory, installed configuration and public key. A signature does not directly sign every raw MCP byte or independently attest that observations were true.

### E. Output and location

`<run>/m4/audit.sqlite` stores `audit_records` and `audit_manifests`; `call_phases` is an index. `<run>/m4/evidence.json` has `format_version`, `manifest`, ordered `records` (each `event` plus `event_hash`), `commitment` and `signature`. `<run>/m4/expected.json`, `configuration.json`, `fixture-public.pem` and **private** `fixture-private.pem` are generated by this M4 run. The report is `<run>/logs/M4-signed.stdout.log`; `run-manifest.json` lists all artifacts and checks its internal `offline_verification.inspection_passed`. The successful run shows 26 records, eight receipts, IDs 3–5, verifier exit 0 and `monitor_exited_before_verification=true`. All hashes, IDs, timestamps and signature bytes vary.

### F. Input → processing → decision/state change → output

The `m4-failure-B` call → audited `CALL_PROPOSAL`/findings/allow/intent → controlled error response → `TOOL_OUTCOME=failed` in the chain, followed by successful final echo. Clean session closure → reconciled 26-record final head in the observed run → P-256 signed commitment in `evidence.json`. External inventory/configuration/public key → offline inspection → six PASS dimensions in the successful run. The signing step authenticates the commitment; it does not make the handler observation independently true.

**Say:** “I gave M4 a fresh expected run and three controlled calls. It chained the resulting records, signed the clean final count and head, and another process checked the package against the expected inventory and pinned public key. I can show the package and verifier report, without opening the private PEM.”

## 8. Standalone M4 verification

The runner invokes `chainguard.verifier` as a separate Python process using the current M4 `evidence.json`, `expected.json`, `configuration.json`, `fixture-public.pem`, and key ID `chainguard-m4-fixture-key`. The package is the submitted evidence; the expected inventory, approved configuration and pinned public key are external trust inputs. The command does not execute tools or consume an acceptance registry entry. It repeats the M4 internal inspection deliberately after the monitor has exited.

Output begins with `mode: INSPECT`, `fresh_submission: NOT_CHECKED`, `inspection_passed`, then `dimensions`, with per-dimension `status` and `reason`; on eligible records it also contains `reproduction` counts. `PASS` means that dimension's check succeeded. `FAIL` means a checked contract was violated. `INCOMPLETE` is used for missing clean closure, missing records relative to a signed count, unresolved calls, or similar incomplete evidence. `NOT_CHECKED` means a prerequisite prevented a dimension from running. The standalone CLI exits 0 only when `inspection_passed` is true; otherwise it exits 2. Inspection is repeatable and does not mean a fresh task-bound submission was accepted.

### A. Exact inputs

The five CLI inputs are M4's generated `evidence.json`, `expected.json`, `configuration.json`, `fixture-public.pem`, and the code-defined key ID `chainguard-m4-fixture-key`.

### B. What each input represents

The runner supplies `-B -m chainguard.verifier --package <run>/m4/evidence.json --expected <run>/m4/expected.json --config <run>/m4/configuration.json --public-key <run>/m4/fixture-public.pem --key-id chainguard-m4-fixture-key`. `evidence.json` is M4's generated signed claim. `expected.json` is the independently written run/challenge/session inventory; `configuration.json` is M4's pre-execution code/policy/tool identity; the public PEM is the key counterpart generated by M4; the fixed key ID is defined in `chainguard/m4.py:KEY_ID`. The verifier gets **no private key** and reads no M5 acceptance registry. These files are separate CLI inputs so package-supplied expectations or keys cannot substitute for assessor-held ones.

### C. Exact source file

The verifier entry point is `chainguard/verifier.py`; the structural, chain and signature helpers are in `chainguard/evidence.py`. The five inputs are generated artifacts or a code-defined key ID, not a stored verifier fixture.

### D. Processing path

`chainguard/verifier.py:main` reads each named file and calls `inspect_package`. `chainguard/evidence.py` validates schema/lifecycle, reconstructs the manifest genesis and event chain, checks commitment fields and verifies the signature with the supplied public key. `chainguard/verifier.py:reproduce_findings` reruns the installed B0/B1/B2 evaluators from eligible recorded facts; expected binding compares the run challenge, inventory association and configuration with installed approved artifacts. This is a new process after the M4 monitor exits. It executes no MCP tool and makes no acceptance write.

### E. Output and location

The standalone JSON is `<run>/logs/M4-standalone-verifier.stdout.log`; errors go to its stderr log. `run-manifest.json` holds the command, input package path, exit code and six per-dimension statuses. The successful run has `mode=INSPECT`, `fresh_submission=NOT_CHECKED`, `inspection_passed=true`, all six dimensions `PASS`, and process exit 0. `FAIL` or `INCOMPLETE` makes the CLI exit 2; `NOT_CHECKED` indicates a missing prerequisite, not success. The verifier does not create a new signed artifact or consume an expected run.

### F. Input → processing → decision/state change → output

M4 `evidence.json` + separately supplied expected inventory/configuration/public key/key ID → structural/chain/signature/binding/completeness/reproduction checks → no registry state change → `inspection_passed=true` only if every dimension passes. **Say:** “I gave a fresh process the package and four independent trust inputs. It checked what was signed and whether the recorded findings reproduce; this is inspection, not acceptance.”

## 9. M5 — expected-run acceptance

M5 creates a fresh `acceptance.sqlite` registry and registers a run inventory/configuration/public key **before** its embedded M4 execution. It then submits the signed package, closes/reopens through a new process, and submits the same run again. The stdout order is `milestone`, `live_M4`, `fresh_acceptance`, `duplicate_after_process_restart`, `synthetic_campaign`, `operational_campaign`, `false_acceptances`, `false_rejections`, `elapsed_seconds`, `passed`. The first result must have `status: ACCEPTED`. The duplicate has `status: REJECTED` and `reason: ALREADY_ACCEPTED`. This is a successful security outcome: it prevents counting the same evidence as a second fresh submission, though it does **not** prevent replay of a tool execution.

The synthetic campaign compares expected and actual statuses for defined mutation cases. `operational_campaign` lists selected engineering tests, number run, pass flag, and test output. These are engineering checks, not held-out research measurements. The runner requires the embedded M4 offline inspection, first acceptance, durable duplicate refusal, all synthetic cases, and operational tests to pass. It retains `m5/live/` artifacts, `m5/synthetic/`, and the registry. The expected-run registry is separate because a valid signed package can be authentic yet stale, for the wrong task, incomplete for the independently expected run, or already submitted.

### A. Exact inputs

The runner calls `-B -m chainguard.m5 campaign --directory <run>/m5`. `chainguard/m5.py:campaign` creates a new `acceptance.sqlite` and calls `chainguard/m4.py:execute_demo` **inside** `m5/live/`, supplying `registry.register` as a pre-execution callback. M4 generates the new `live/expected.json` inventory, `live/configuration.json`, `live/fixture-public.pem`, private fixture key and `live/evidence.json` package. M5 later reads `live/expected.json` to obtain its `run_id` and submits the bytes of `live/evidence.json` twice using separate `m5 accept` processes. `tests/m5_fixtures.py` constructs synthetic mutation cases and expected statuses for the campaign; selected tests named in `chainguard/m5.py` provide additional engineering checks. No standalone M4 artifact from the previous step is an M5 input.

### B. What each input represents

The pre-registered inventory fixes the fresh run challenge and expected session association. Configuration and public key fix the approved verifier context and signer. `run_id` links the submitted package to the registered expectation; challenge and expected-inventory digest bind its content. The **same** package and `run_id` are used for the second submission so the registry's accepted state can be tested after process restart. Synthetic mutation fixtures are test cases, not live attack observations.

### C. Exact source file

`chainguard/m5.py` constructs the campaign and test list; `chainguard/m4.py` creates its live package; `chainguard/acceptance.py` defines registry behavior. `tests/m5_fixtures.py` constructs synthetic attack cases.

### D. Processing path

`chainguard/m5.py:campaign` creates `AcceptanceRegistry` (`chainguard/acceptance.py`) and calls M4. During `chainguard/m4.py:execute_demo`, `register_expected` receives inventory, configuration and the public key **before bootstrap/tool input**. `AcceptanceRegistry.register` validates and commits an `ACTIVE` expectation. After M4 exits with its signed package, `m5.submit_process` launches `m5 accept`; `m5.main` reads package bytes once and `AcceptanceRegistry.submit` checks the registered run, invokes whole-run inspection, and atomically stores accepted commitments. A second `submit_process` opens the same durable registry in another process; its already-`ACCEPTED` state produces `ALREADY_ACCEPTED` without accepting again. `tests/m5_fixtures.py:attacks` and the selected `tests/test_m4.py`/`tests/test_m5.py` tests run as part of the engineering campaign.

### E. Output and location

`<run>/m5/acceptance.sqlite` has `expected_runs` (run ID, challenge, canonical inventory/configuration, public pins and state) and `accepted_sessions` (session ID and accepted commitment bytes/digest), defined in `chainguard/acceptance.py:SCHEMA`. `m5/live/` has its separate M4 DB/package/expected/config/key artifacts; `m5/synthetic/` holds mutation fixtures and per-case registries. The JSON in `<run>/logs/M5-campaign.stdout.log` has `live_M4`, `fresh_acceptance`, `duplicate_after_process_restart`, `synthetic_campaign`, `operational_campaign` and summary fields. The successful run shows first `status=ACCEPTED`, `reason=FRESH_COMPLETE_RUN`, `registry_durability=COMMITTED`; second `status=REJECTED`, `reason=ALREADY_ACCEPTED`; 32 passing synthetic cases, 16 engineering tests, zero reported false acceptances/rejections **within that campaign**, and `passed=true`. The manifest summarizes both security outcomes and names the artifact paths.

### F. Input → processing → decision/state change → output

Pre-execution inventory/configuration/public pin → `register` → durable `ACTIVE` expectation. Matching new signed M4 package + same `run_id` → whole-run checks → durable `ACCEPTED` and accepted commitment. Same bytes + same `run_id` after a new process opens the registry → state check → `REJECTED/ALREADY_ACCEPTED`; this rejection is the expected successful security result, not an execution failure.

**Say:** “I registered the run before M4 generated evidence. The first matching package was accepted and stored; the identical submission after restart was refused because that run was already accepted. The two statuses and the registry path are in the M5 log and manifest.”

## 10. M6Q — retained trusted-host evidence

M6's trusted host issues scoped grant/revoke controls, reserves one-use permission before forwarding, and records host, child and synthetic local-sink witnesses. Normal observation does not bypass authorization. The historical `case_results.json` records M6Q-01 source read, M6Q-02 ungranted send refusal, M6Q-03 grant and successful one-use send, M6Q-04 reuse refusal, M6Q-05 revoke refusal, M6Q-06 regrant and send, M6Q-07 duplicate request ID, and a **separate** M6Q-08 fault path. The retained report shows all eight `status: PASSED`; each case has named `checks`, `handler_count`, and `sink_count`. M6Q-08 tests a pre-dispatch persistence fault and no signed export, not a cleanly signed ordinary run.

`controls.json` lists the granted/revoked scopes and times. `witness_primary/host.jsonl` records host decisions, control/commit stages and process frames; `child.jsonl` records handler arrivals; `sink.jsonl` records actual local-sink arrivals with payload byte counts and digests. The witness streams have distinct roles: a host decision is not a child arrival, and neither alone proves bytes reached the sink. The retained `offline_verification.json` and `fresh_process_reinspection.json` both report `mode: INSPECT`, `fresh_submission: NOT_CHECKED`, `inspection_passed: true` and seven M6-specific PASS dimensions: `package_schema`, `commitment_integrity`, `trusted_signature`, `expected_binding`, `inventory_completeness`, `lifecycle_semantics`, `finding_reproduction`. `fresh_submission_readback.json` reports `post_restart_state: ACCEPTED` and a duplicate `REJECTED`/`ALREADY_ACCEPTED` after restart. These are retained historical results, not checks re-executed by the professor runner. A hash alone does not authenticate a witness; the assessor's independent capture boundary matters.

The runner reads these JSON files and confirms their status fields and file presence. It does not modify the historical directory, acceptance registry, or witnesses. **Do not rerun the historical M6Q qualification, reinspection, or submission harness.** This is bounded engineering qualification, not the final research validation or a claim of universal MCP protection.

### A. Exact inputs

The professor runner makes **no M6Q child-process call**. It reads the retained files under `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/live_m6_current/`. The historical qualification input is defined by `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/qualify_live_current.py`, not by the professor runner. That harness loaded the earlier `results/completion_sprint_2026-11-02/H2-H6/qualification_plan.json`, saved a `frozen_plan.json` copy, checked `CHAINGUARD_ASSESSOR_REVISION_PIN` against `CHAINGUARD_TRUSTED_CODE_REVISION`, generated a fresh run/challenge/task/session/monitor context and ephemeral P-256 key, and pre-registered the primary run. The saved `frozen_plan.json` retains its pre-execution `BLOCKED_UNEXECUTED` planning status; **`case_results.json` records the later executed qualification outcome**.

The primary task is one sequential `M6Q-01-07` trusted-host context with a synthetic local sink. `qualify_live_current.py:raw_call` constructs each JSON-RPC `tools/call` frame with protocol metadata and writes exact request bytes to `M6Q-XX/request.bin`. `chainguard/m6_live_profile.py:POLICY` fixes `secret-a` as `SYNTHETIC_CANARY_A`, the `sink` destination, and `TOOL_CONTRACTS` for `read_secret_a`, `send_sink` and `read_public`. Host controls, never MCP client arguments, grant or revoke `Scope(task_id, "secret-a", "sink", "release")`. The primary registration uses generated `assessor_inventory.json`, configuration in `assessor_context.json`, public key in `assessor_public_key.pem`, key ID `five-hour-ephemeral-assessor` and `acceptance_registry.sqlite`. The historical private key was generated in memory by the harness; it is not a professor display input.

### B. What each input represents

`M6Q-01` reads the synthetic sensitive source; `M6Q-02` tries to send that canary before any grant. `M6Q-03` uses trusted-host grant `g1` for the exact task/resource/destination release scope; its reservation selects and consumes that one-use grant before dispatch. `M6Q-04` repeats the send without a new grant. `M6Q-05` grants `g2`, then revokes the scope before sending. `M6Q-06` grants new `g3` and sends. `M6Q-07` tries `send_sink` using the already-used request ID `q1-read`, a duplicate admission attempt. `M6Q-08` is a **separate task and fault inventory**, using `read_public` while the audit commit is deliberately made to fail before dispatch. The canary and sink payload are synthetic; their exact bytes matter to the assessor's covered disclosure check.

### C. Exact source file

Historical requests and expected checks are in `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/qualify_live_current.py`; the earlier case plan is in `results/completion_sprint_2026-11-02/H2-H6/qualification_plan.json`. `chainguard/m6_live_profile.py` defines the policy and tool contract; the retained evidence is in `live_m6_current/`.

### D. Processing path

`qualify_live_current.py:main` calls `chainguard/m6_live_runtime.py:M6Host.open_task` with a fresh database path, trusted inventory, identities, witness directory and local assessor sink endpoint. `HostTask._submit_client_frame` validates the raw frame, metadata, tool and arguments; `chainguard/m6_live_profile.py:validate_tool_arguments` prevents client fields from defining source/destination security meaning. The host queues proposals and controls in admission order. `chainguard/m6_live_authorization.py` normalizes calls, computes required scopes from current sensitive content plus prior sensitive exposure, checks active grants, commits proposal/findings/decision/intent or denied outcome, and consumes selected one-use grants after confirmed intent. Only a permitted call is forwarded to `chainguard/m6_controlled_server.py`; its handler records receipt and sends payload bytes to the separate local assessor sink for allowed sends. `chainguard/m6_live_witness.py` and the harness retain host and child witness streams; `qualify_live_current.py:AssessorSink` independently records sink arrivals and payload digest/bytes. The primary audit database was created in a temporary directory by the historical harness and is **not retained** in `live_m6_current/`.

After clean primary shutdown, `HostTask.export_live_evidence` freezes the audit snapshot; `chainguard/m6_live_seal.py` signs its closure and writes `signed_package.json`. Like M4, this package contains a manifest, ordered event/hash records, commitment and signature. `chainguard/m6_live_verifier.py:inspect_live_package` checks it against the independently supplied inventory, configuration, pinned public key, accepted versions and suite; `offline_verification.json` is the first report. `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/reinspect_current.py` later supplied those inputs again in a fresh process and wrote `fresh_process_reinspection.json`. `submit_current.py` supplied the package bytes and registered `run_id` to `chainguard/acceptance.py:AcceptanceRegistry`, wrote `fresh_submission.json`, reopened the registry, and wrote `fresh_submission_readback.json`. Neither reinspection nor acceptance executes the MCP calls again. The fault task M6Q-08 halts and produces **no** `fault_signed_package.json`.

### E. Output and location

For each case, `M6Q-XX/request.bin`, `response.bin` and `call.json` preserve raw proposal/response bytes, IDs, status and digests; `controls.json` preserves grant/revoke actions. `witness_primary/host.jsonl` records admissions, commit confirmations, forwarding/closure and child frame observations; `child.jsonl` records handler arrivals; `sink.jsonl` records `sink_received` with request ID, tool, destination, byte count, base64 payload and SHA-256. `witness_fault/` contains the separate M6Q-08 streams. `case_results.json` supplies named checks and handler/sink counts. The retained offline and fresh-process reports both have `inspection_passed=true` and seven PASS dimensions. `fresh_submission.json` shows initial `ACCEPTED`/`FRESH_COMPLETE_RUN`; `fresh_submission_readback.json` shows `post_restart_state=ACCEPTED` and duplicate `REJECTED`/`ALREADY_ACCEPTED`. The professor runner's manifest lists the retained files and inspection status, but has **no M6Q stdout/stderr child logs** because it only reads them.

| Case | Actual input → processing → decision/state change → retained output |
| --- | --- |
| M6Q-01 | `q1-read`, `read_secret_a`, `{}` → source handler → synthetic canary returned; `case_results` says one handler, zero sink arrivals. |
| M6Q-02 | `q2-deny`, `send_sink`, canary payload before grant → permission unavailable → JSON-RPC refusal code `-32003`; zero handler and sink arrivals. |
| M6Q-03 | Host `GRANT g1` for `secret-a → sink`, then `q3-send` → committed selected one-use intent, child send and sink receipt → one handler, one sink; exact `SYNTHETIC_CANARY_A` bytes/digest and `captured by local sink` acknowledgement checked. |
| M6Q-04 | `q4-reuse` repeats the send after `g1` use → no active grant → `-32003`; zero new handler/sink arrivals. |
| M6Q-05 | Host `GRANT g2` then `REVOKE_SCOPE`, followed by `q5-revoked` → committed revoke removes the active scope → `-32003`; zero handler/sink arrivals. |
| M6Q-06 | Host `GRANT g3`, then `q6-send` → confirmed reservation and forwarding → one handler and one sink receipt with exact canary bytes and acknowledgement. |
| M6Q-07 | `send_sink` reuses ID `q1-read` → `HostTask._submit_client_frame` raises `Duplicate request ID` before a new admission; no new sink arrival. `case_results.handler_count=1` refers to the **earlier M6Q-01 read** bearing the same ID, not a newly forwarded duplicate send. |
| M6Q-08 | Separate `q8-fault`, `read_public`, `{}` with injected SQLite commit error → task halts before dispatch; no handler/sink arrival and no signed fault export. `M6Q-08/call.json` records a `LiveAuditError` exception. |

### F. Input → processing → decision/state change → output

Trusted context and host grant → scoped authorization and one-use reservation → signed record of the permitted action plus independently retained child/sink witnesses. Ungranted, consumed or revoked scope → refusal and no matching sink arrival. Separate persistence fault → halt and no signed export. Primary signed package + assessor-held context/key → offline PASS; same registered run/package → first accepted submission, then durable duplicate rejection. These are historical engineering checks: witness independence from SQLite does not make host observations cryptographic truth, and evidence replay rejection does not prevent tool-execution replay.

**Say:** “The trusted host received a synthetic read, sends, and host-only grants or revocation. It forwarded only calls with a confirmed one-use permission; separate child and sink logs show what reached the handler and local sink. I can show the retained case results and signed inspection, but I will not rerun the fixed historical harness.”

## 11. Likely professor questions

| Question | Short answer |
| --- | --- |
| Why more than a normal MCP proxy? | The controlled proxy connects calls to scoped authorization, sequence analysis and evidence with explicit verification contracts. The current coverage is bounded to the controlled surface. |
| What is the research contribution? | The proposed contribution is a controlled representation comparison and an evidence-linked, task-bound assessment method. Empirical contribution claims depend on the unfinished final study. |
| Why B0/B1/B2? | They isolate what current event, unordered history and ordered state can express on the same staged facts. B1 uses a named conservative operating point. |
| What does the signature prove? | Under the pinned-key assumption, it authenticates the signed closure commitment and detects changes to committed evidence. It is not a novel cryptographic primitive. |
| Can it prove an event happened? | No. Validly signed false or omitted observations remain possible; independent host/child/sink witnesses and oracle checks address bounded observational claims. |
| Why a separate registry? | Authenticity is separate from expected task/run binding, full inventory and durable submission eligibility. |
| Why reject duplicates? | To prevent one package from being counted as multiple fresh accepted submissions. This does not prevent replay of tool calls. |
| What does M6 add? | Trusted-host scoped grant/revoke, one-use reservation, enforcement and independent synthetic sink observations. |
| Current limitations? | Local controlled stdio surface, synthetic fixtures, no general provenance tracking or trusted timestamp service, and bounded witness assumptions. |
| What remains to evaluate? | Independently labeled held-out families, B0/B1/B2 errors and completion costs, audit mutation/freshness ablations, overhead, and uncertainty under the frozen evaluation protocol. |

### Consolidated input/output reference

`<run>` means the fresh professor-run directory selected in Section 3. `live_m6_current/` below means `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/live_m6_current/`. A source marked “constructed” contains code that creates runtime data; it is not a stored fixture file.

| Milestone | Input | Meaning | Input source file | Processing component | Output | Output location |
| --- | --- | --- | --- | --- | --- | --- |
| M1 | `-B -m chainguard.client`, existing Python | Launch controlled client | `scripts/demo/Run-ProfessorDemo.ps1` | `chainguard/client.py:main` | Process exit and checked JSON | `<run>/logs/M1-client.*.log`; manifest |
| M1 | Discovery/list requests and pinned protocol | Establish server/tool contract; requests constructed in code | `chainguard/client.py`; `chainguard/__init__.py` | `chainguard/proxy.py:run`; `chainguard/controlled_server.py:list_tools` | `protocol_version`, `server`, `tools` | `M1-client.stdout.log` |
| M1 | Three synthetic token calls | Success, controlled failure, recovery; constructed in code | `chainguard/client.py:exercise` | `chainguard/controlled_server.py:call_tool`; client `verify_result` | `success`, `controlled_error`, `success_after_error` | `M1-client.stdout.log` |
| M2 | `FIXTURES` staged journals | 23 synthetic replay scenarios in observed run; constructed fixture data | `tests/m2_fixtures.py` | `chainguard/m2.py:ReplayLedger` | `fixtures[].proposals[]` | `<run>/logs/M2-replay.stdout.log` |
| M2 | Order-pair read/grant/revoke/send journals | Same unordered facts, different permission order | `tests/m2_fixtures.py:research_fixtures` | `chainguard/semantics.py`; `chainguard/detectors.py` | Four `detectors[]` per proposal | `M2-replay.stdout.log` |
| M2 | Prewritten `Expected` labels and staged witnesses | Independent expected authorization/effects, not detector output | `tests/m2_fixtures.py`; `chainguard/oracle.py` | `chainguard/oracle.py:assess`; `chainguard/m2.py:verify_expectations` | Proposal `oracle`, `b2_equivalence` | `M2-replay.stdout.log`; manifest |
| M3 | Fresh `--db` path | New durable session, no prior authority | `scripts/demo/Run-ProfessorDemo.ps1` | `chainguard/audit.py:AuditSession` | SQLite database | `<run>/m3/audit.sqlite`; manifest |
| M3 | Discovery/list and IDs 3–5 echo/failure/echo frames | Code-constructed live MCP requests | `chainguard/m3.py:execute_demo` | `chainguard/proxy.py:run`; `chainguard/audit.py:LiveAudit` | `CALL_PROPOSAL`, findings, decision, intent, outcome | `<run>/m3/audit.sqlite:audit_records` |
| M3 | Runtime UUID context and fixed non-release profile | Bind one session and allowed public tool surface | `chainguard/m3.py:execute_demo` (generated); `chainguard/audit.py:PROFILE` | `AuditSession.append_batch` | `expected_context`, `monitor_instance_id`, receipts | `M3-durable.stdout.log`; `audit_records` |
| M3 | Handler responses/arrivals | Observe success/error/success after dispatch | `chainguard/controlled_server.py:call_tool` (runtime) | `LiveAudit.after`; `read_records`; `reconstruct_history` | `tool_outcomes`, `handler_request_ids`, `commit_witnesses` | `M3-durable.stdout.log`; `<run>/m3/audit.sqlite` |
| M4 | `demo --directory` and fresh MCP frames | New non-release signed-session workflow; frames constructed in code | `scripts/demo/Run-ProfessorDemo.ps1`; `chainguard/m4.py:execute_demo` | `chainguard/proxy.py`; `LiveAudit`; `ChainedAuditSession` | Recorded/chained events | `<run>/m4/audit.sqlite:audit_records` |
| M4 | Generated expected inventory and runtime monitor ID | Run/challenge/session association fixed before calls | `chainguard/m4.py:execute_demo` (generated) | `chainguard/evidence.py:make_manifest` | `manifest`, inventory digest | `<run>/m4/expected.json`; `evidence.json`; `audit_manifests` |
| M4 | Generated configuration from installed source | Approved policy, tools, normalizer, detector/code identities | `chainguard/evidence.py:configuration`; `chainguard/audit.py:PROFILE`; `chainguard/controlled_server.py:INPUT_SCHEMA` | `ChainedAuditSession`; verifier | Configuration binding | `<run>/m4/configuration.json`; `evidence.json:manifest` |
| M4 | New P-256 fixture keypair | Sign closure; independently pin public verifier key | `chainguard/m4.py:provision_key` (generated) | `chainguard/evidence.py:sign_commitment` | Signature and public-key check | `<run>/m4/evidence.json`; `fixture-public.pem`; **private** `fixture-private.pem` |
| M4 | Reconciled canonical records | Exact committed event count and chain head | `chainguard/evidence.py:ChainedAuditSession` (runtime) | `seal`; `make_commitment` | `records`, `commitment.final_head`, `record_count` | `<run>/m4/evidence.json`; `M4-signed.stdout.log` |
| M4 verifier | Package from standalone M4 | Submitted signed evidence | `<run>/m4/evidence.json` (generated by `chainguard/m4.py`) | `chainguard/verifier.py:inspect_package` | Schema/chain/signature/reproduction dimensions | `<run>/logs/M4-standalone-verifier.stdout.log` |
| M4 verifier | External inventory, configuration, public key, key ID | Independent expected context and signer pin | `<run>/m4/expected.json`, `configuration.json`, `fixture-public.pem` (M4-generated); `chainguard/m4.py:KEY_ID` | `chainguard/verifier.py:main` | `expected_binding`, `trusted_signature`, `inspection_passed` | `M4-standalone-verifier.stdout.log`; manifest |
| M5 | Fresh campaign directory and registry | Separate acceptance workflow | `scripts/demo/Run-ProfessorDemo.ps1`; `chainguard/m5.py:campaign` | `chainguard/acceptance.py:AcceptanceRegistry` | `ACTIVE` expectation, accepted commitments | `<run>/m5/acceptance.sqlite` |
| M5 | M5-created M4 inventory/configuration/public key | Pre-execution registered expected run; generated inside campaign | `chainguard/m5.py:campaign`; `chainguard/m4.py:execute_demo` | `AcceptanceRegistry.register` | `expected_runs` row | `<run>/m5/live/expected.json`, `configuration.json`, `fixture-public.pem`; registry |
| M5 | M5-created `live/evidence.json` plus same `run_id` twice | First fresh submission then durable duplicate check | `<run>/m5/live/evidence.json` and `expected.json` (generated by embedded M4) | `chainguard/m5.py:submit_process`; `AcceptanceRegistry.submit` | `ACCEPTED`, then `REJECTED/ALREADY_ACCEPTED` | `<run>/logs/M5-campaign.stdout.log`; `acceptance.sqlite` |
| M5 | Synthetic mutation cases and selected tests | Engineering acceptance/lifecycle checks | `tests/m5_fixtures.py`; `chainguard/m5.py` test-name list; `tests/test_m4.py`; `tests/test_m5.py` | `chainguard/m5.py:campaign` | `synthetic_campaign`, `operational_campaign` | `M5-campaign.stdout.log`; `<run>/m5/synthetic/` |
| M6Q | Frozen case plan and revision pins | Historical assessor plan and source-context gate | `results/completion_sprint_2026-11-02/H2-H6/qualification_plan.json`; `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/qualify_live_current.py` | Historical harness only | Copied plan, assessor context | `live_m6_current/frozen_plan.json`, `assessor_context.json` |
| M6Q | Generated primary inventory, signer public key, registered expectation | Trusted task/run/challenge and signature pin before execution | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/qualify_live_current.py:context/main` | `M6Host.open_task`; `AcceptanceRegistry.register` | Registered `ACTIVE` run | `live_m6_current/assessor_inventory.json`, `assessor_public_key.pem`, `pre_execution_registration.json`, `acceptance_registry.sqlite` |
| M6Q | Raw calls M6Q-01–07 | Read, ungranted send, authorized use, reuse, revoke, regrant, duplicate ID; constructed in code | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/qualify_live_current.py:raw_call/main` | `chainguard/m6_live_runtime.py:HostTask`; `chainguard/m6_live_authorization.py` | Refusals/forwarding, case status | `live_m6_current/M6Q-XX/request.bin`, `response.bin`, `call.json`, `case_results.json` |
| M6Q | Host grants `g1`, `g2`, `g3` and revoke for `secret-a → sink` | Scoped one-use authority; host-only controls | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/qualify_live_current.py:main`; `chainguard/m6_live_profile.py:POLICY` | `HostTask.grant/revoke`; live authority reservation | `GRANT`, `REVOKE_SCOPE`, `DISPATCH_INTENT` witnesses/records | `live_m6_current/controls.json`, `witness_primary/host.jsonl`, `signed_package.json` |
| M6Q | Controlled child responses and synthetic sink bytes | Independent handler and local receipt observations | `chainguard/m6_controlled_server.py`; historical `qualify_live_current.py:AssessorSink` | Child handler and assessor sink | Handler/sink counts, payload byte/digest witnesses | `live_m6_current/witness_primary/child.jsonl`, `sink.jsonl`, `case_results.json` |
| M6Q | Separate injected M6Q-08 commit fault | Pre-dispatch persistence failure, not signed ordinary run | `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/qualify_live_current.py:main` | M6 host/audit fail-closed path | Halt, no handler/sink, no fault signed export | `live_m6_current/M6Q-08/call.json`, `witness_fault/`, `case_results.json` |
| M6Q | Signed primary package plus assessor inventory/config/public key | Historical offline inspection in initial and fresh process | `live_m6_current/signed_package.json`, `assessor_inventory.json`, `assessor_context.json`, `assessor_public_key.pem`; `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/reinspect_current.py` | `chainguard/m6_live_verifier.py:inspect_live_package` | Seven verification dimensions | `live_m6_current/offline_verification.json`, `fresh_process_reinspection.json` |
| M6Q | Registered `run_id` and same signed package twice | Historical fresh acceptance/readback after restart | `live_m6_current/assessor_inventory.json`, `signed_package.json`; `results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/submit_current.py` | `chainguard/acceptance.py:AcceptanceRegistry` | `ACCEPTED`, then `ALREADY_ACCEPTED` | `live_m6_current/fresh_submission.json`, `fresh_submission_readback.json`, `acceptance_registry.sqlite` |

## 12. Concise talk track

“ChainGuard studies sequence-aware MCP security and evidence that can be checked independently, within a controlled local tool surface. I will show separate milestones, not one end-to-end conversation. M1 verifies the MCP path survives a controlled tool error. M2 replays prewritten histories through B0, B1 and B2 and checks streaming B2 against a reference. M3 writes a real non-release sequence to SQLite. M4 signs a clean closure and verifies six dimensions in another process. M5 pre-registers its own run, accepts it once, and rejects a duplicate after restart. Finally, I will inspect retained M6Q host, child and sink evidence for scoped one-use authorization, without rerunning the historical harness. These are implementation and engineering qualification demonstrations. The broader experimental comparisons and final research claims still require the frozen evaluation work.”
