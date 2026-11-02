# H22–H25 implementation and bounded M6 qualification

## Authority and scope

The owner confirmed that H16–H22 was skipped and produced no decision or design artifact. In this H22–H25 conversation the owner explicitly approved both H6–H9 proposals as written: a mandatory trusted host-provisioned 40-hex code revision with no Git fallback, and an assessor-held independent witness design. The owner subsequently supplied the independent revision pin `8b27b5a980a87887be66c409c5a6a31d415a3326`. The owner has **not** resolved the A1/A2 label or E08 pin conflicts. No dependency was installed, no Git command was run, and no E01–E13 population experiment or IEEE report work was performed.

The approved implementation scope in this phase was the no-Git entry, independent local witnesses, exact synthetic sink bytes/digest, bounded startup diagnostics and preservation of signed export/offline verification. Neither the earlier H6–H9 proposal nor the sprint priority list was treated as an A1/A2 or E08 decision. No new dependency set or version pins were approved here; any future external-baseline adapter/driver package remains blocked on separate dependency approval. The implemented changes use the existing standard library and already installed cryptography package.

The actual H22–H25 work-package began before nominal elapsed sprint H22. The first recorded local clock was 2026-11-02 19:37:20 +05:30; the exact work start before that is not exposed. Do not interpret this label as evidence that 22 elapsed hours had passed.

**Final source-state boundary:** after the `live_m6_sink_final/` package and 124-test suite, the child launch was tightened to strip inherited assessor sink/witness environment variables. Its focused test passed (see `env_guard.run.json`, exit 0). The owner then instructed no further reruns. Automatic approval review rejected the already requested `run_live.ps1 -Label live_release -OutputDirectory live_m6_release` action because that instruction revoked authorization for a redundant qualification run. No release run or package was created. Consequently, the eight M6Q passes and offline reinspection apply to the immediately preceding source state; **current source has not been live requalified**. H22–H25 is partially complete at handoff.

## Implementation

| Problem | Change | Files | Boundary |
| --- | --- | --- | --- |
| Live open, export and offline inspection invoked Git through `live_configuration` | Require `CHAINGUARD_TRUSTED_CODE_REVISION` as exactly 40 lowercase hex characters; preserve installed artifact digests and exact installed-configuration validation | `chainguard/m6_live_profile.py`; `tests/test_m6_live_profile.py` | Revision is a trusted host assertion, not proof of the working tree. Missing/malformed values fail closed. No Git fallback. |
| Audit-only reconstruction could not independently establish controls, reservation, dispatch, source/handler, sink or task effects | Add optional assessor-selected witness directory with exclusive `host.jsonl` and `child.jsonl`. Host records admitted controls, raw proposals, confirmed commit receipts with control/intent content, dispatch attempts/writes, client responses and child process closure. Child records startup/exit and handler receipt. A separate assessor-controlled loopback sink writes the exact bytes it receives, SHA-256, request ID, local receive sequence and collector closure to `sink.jsonl`. Ordinary child stderr keeps arrival metadata without payload bytes. | `chainguard/m6_live_witness.py`, `m6_live_authorization.py`, `m6_live_runtime.py`, `m6_controlled_server.py`; `tests/test_m6_live_runtime.py`; `qualify_live.py` | Witness files are outside SQLite and generated at the relevant boundaries, but assume a trusted host, child, assessor receiver and local filesystem. They are not signed, external timestamped, or proof against a dishonest monitor. Capture failure halts affected execution. |
| Earlier intermittent child handshake timeout lacked enough diagnostics | Include startup phase, child PID/exit state, recent child event phases and bounded stderr tail in the startup failure; retain the existing 15-second per-handshake timeout. | `chainguard/m6_live_runtime.py` | This helps diagnose a recurrence; it does not establish the earlier root cause or remove the intermittent full-discovery failure. |
| Signed evidence compatibility could be disturbed by instrumentation | Keep the M6 package format, P-256 signing, verifier dimensions, and expected-configuration checks; live run exports and offline-inspects a clean signed package. | Existing seal/verifier modules unchanged; last executed export and inspection results under `live_m6_sink_final/`. | Offline inspection checks normalized evidence and signature, not independent truth or fresh submission. |

The witness directory was provided by the assessor and is outside the simulated audit database. Raw content retained in this phase is synthetic only. No private key or `audit.sqlite` was placed in the deliverable directory; the generated signing key existed only in process memory. The public key pin, raw request/response bytes, control journal, host/child/sink records, signed package and verifier report are retained under `live_m6_sink_final/`. The earlier `live_m6/` and `live_m6_final/` runs remain preliminary captures before the separate receiver was added.

The trusted environment revision input was chosen because all existing open, export, inspect and acceptance paths call `live_configuration`; an explicit constructor parameter would expose provenance more clearly but require changes through each validator and offline API. The revision is an assessor assertion, so the installed artifact digests still bind the actual files. A viva answer must distinguish those two facts and explain why a missing pin fails closed. The child side stream and separate loopback receiver keep handler and actual sink observations outside SQLite and away from the host's parsed event list. They still trust the controlled child, assessor receiver and local filesystem; a dishonest host or receiver could forge unsigned observations. A viva answer must also distinguish a confirmed commit-boundary receipt from an issued grant and explain why missing witnesses produce `UNKNOWN`, not a positive authorization or non-arrival claim.

## Commands and outcomes

Each `*.run.json` records exact command, local start/end, elapsed seconds and exit code; raw stdout/stderr remain beside it. All launches used PowerShell and the repository CPython virtual environment. The first focused launch failed before Python started with Windows access denied (exit 101). The first live launch failed before a case started because the script's package import path was absent (exit 1). Both failures are retained, not overwritten.

| Attempt | Evidence | Outcome |
| --- | --- | --- |
| Focused initial | `focused.run.json`, `focused.stderr.log` | Windows access denied, exit 101; no test executed. |
| Focused retry 1 | `focused_retry_1.run.json`, `focused_retry_1.stderr.log` | 122 tests: 114 passed, 7 failed, 1 error; exit 1. Failures came from startup markers on stderr and an empty selected-grant list in the new test assertion. |
| Targeted retry | `targeted.run.json`, `targeted.stderr.log` | 5 focused tests passed; exit 0. |
| Live initial | `live.run.json`, `live.stderr.log` | Import failure before case execution; exit 1. |
| Live retry 1 | `live_retry_1.run.json`, `live_m6/` | All eight frozen M6Q cases executed; runner exit 0. |
| Focused retry 2 | `focused_retry_2.run.json`, `focused_retry_2.stderr.log` | 122/122 passed, exit 0, 2026-11-02 19:57:46–20:03:07 +05:30. |
| Startup diagnostic | `startup.run.json`, `startup.stderr.log` | 1/1 passed, exit 0, 2026-11-02 20:04:01–20:04:08 +05:30. |
| Final targeted privacy check | `targeted_final.run.json`, `targeted_final.stderr.log` | 5/5 passed, exit 0, 2026-11-02 20:08:54–20:09:40 +05:30. |
| Redacted-stderr live run | `live_final.run.json`, `live_m6_final/` | Eight checks passed, exit 0, 2026-11-02 20:09:51–20:10:05 +05:30; preliminary because the sink receiver was still the child. |
| Focused suite before separate receiver | `focused_final.run.json`, `focused_final.stderr.log` | See run metadata; superseded by final receiver qualification. |
| Separate-sink live run | `live_sink_final.run.json`, `live_m6_sink_final/` | Eight frozen cases passed with two assessor sink receipts and collector closure; exit 0, 2026-11-02 20:17:51–20:18:07 +05:30. |
| Sink unavailable failure test | `sink_failure.run.json`, `sink_failure.stderr.log` | 1/1 passed, exit 0. |
| Witness order check | `verify_witness_order.py`, `live_m6_sink_final/postrun_witness_order.json` | Seven checks passed, exit 0, 2026-11-02 20:23:35 +05:30. Confirmed grant/revoke/intent order, duplicate non-readmission, two sink receipts, and normal/fault collector closure. |
| Final focused suite | `focused_sink_final.run.json`, `focused_sink_final.stderr.log` | 124/124 passed, exit 0, 2026-11-02 20:19:43–20:25:22 +05:30. |
| Inherited environment guard | `env_guard.run.json`, `env_guard.stderr.log` | 1/1 passed, exit 0, after the final package and full suite. Current source has no subsequent full-suite/live run. |
| Requested release rerun | No `live_release.run.json` or `live_m6_release/` exists | **Rejected before execution by automatic approval review** after the owner's no-rerun instruction. No exit code or outcome exists. |
| Fresh-process offline reinspection | `reinspect.run.json`, `live_m6_sink_final/offline_reinspection.json` | All inspection dimensions passed with the saved assessor public key and expected context; exit 0, 2026-11-02 20:27:47–20:27:48 +05:30. Fresh submission remained `NOT_CHECKED`. |

## Frozen M6Q cases

The input case IDs and intended claims were copied from `../H2-H6/qualification_plan.json` to `live_m6_sink_final/frozen_plan.json` before execution. `live_m6_sink_final/case_results.json` gives per-check outcomes. `live_m6_sink_final/M6Q-XX/` retains raw request and response bytes and timestamps. The assessor-held `witness_primary/` covers M6Q-01 through M6Q-07 in one ordered task; `witness_fault/` covers M6Q-08. Each witness directory contains host, child and assessor sink streams. The clean task has `signed_package.json` and `offline_verification.json`; the faulted task intentionally has no signed package.

| Case | Intended bounded claim | Observed outcome |
| --- | --- | --- |
| M6Q-01 | Sensitive source read and handler arrival | PASSED: handler and client canary response observed. |
| M6Q-02 | Unauthorized pre-grant send denied without sink arrival | PASSED: refusal and no matching handler/sink record by clean closure. |
| M6Q-03 | Grant and first authorized use | PASSED: grant and selected intent receipts, handler, exact sink bytes/digest, client acknowledgement. |
| M6Q-04 | One-use reuse denied | PASSED: refusal and no matching handler/sink record. |
| M6Q-05 | Active unconsumed grant revoked | PASSED: revoke commit witness, refusal, no matching sink record. |
| M6Q-06 | Fresh regrant permits one send | PASSED: fresh grant and intent receipts, handler, exact sink bytes/digest, acknowledgement. |
| M6Q-07 | Duplicate request ID rejected | PASSED: ingress duplicate rejection and no additional sink arrival. The original ID belonged to M6Q-01's read, so its one source handler record is not a new send handler. |
| M6Q-08 | Pre-dispatch audit persistence failure | PASSED within the declared injected-fault boundary: task halted, no handler/sink arrival, child process closure, no signed export. This is an injected engineering fault plus assessor observations, not a natural-fault frequency measurement. |

The clean package's offline verifier reported `inspection_passed=true` with PASS for package schema, commitment integrity, trusted signature, expected binding, inventory completeness, lifecycle semantics and finding reproduction. `fresh_submission=NOT_CHECKED`. A valid signature and reproduced finding do not establish correctness of raw observations or actual disclosure. Non-arrival claims are bounded by the child side-channel, process closure and assessor sink-collector closure; gaps would make them unknown.
The last executed run's separate sink stream contains exactly two `sink_received` records and a collector closure. The [post-run ordering check](live_m6_sink_final/postrun_witness_order.json) binds those receipts and the host control/intent sequence to the case IDs. These are local observations under the trusted assessor boundary, not a population study or a proof against observer compromise.
Read-only artifact validation parsed 64 JSON files under H22–H25, found no `.sqlite`, `.db` or `.key` deliverables, and found only assessor **public** PEM files. The last executed package also passed [fresh-process offline reinspection](live_m6_sink_final/offline_reinspection.json) after the live runner had exited.
The [file manifest](file_manifest.json) lists the exact source, documentation and H22–H25 artifact paths with byte counts and SHA-256 digests; it excludes its own digest.

## E01–E13 readiness after this phase

No E01–E13 experiment was executed or promoted to a result. E01 and E02 retain development-only fixtures. E03 and E04 gain a bounded local source/sink/commit witness mechanism but still need frozen eligible research cases and independent oracle labels. E05 still needs held-out parents. E06 gains the live lifecycle qualification above, but the full experiment contract, including multi-scope and broader failure/denominator design, remains to execute in H25–H28. E07 gains one qualified injected pre-dispatch failure boundary, but its complete declared fault matrix remains. E08 stays blocked on owner pin resolution and conformance. E09 stays blocked on A1/A2 owner resolution and variants. E10 gains witness capture but no authentic-wrong case. E11 gains a clean signed inspection, not fresh acceptance study. E12 still needs valid scaling instrumentation. E13 retains development-only renaming and lacks the other frozen pairs. All thirteen tracker statuses remain `NOT STARTED` for population experiments.

## Remaining limits and next phase

- H22–H25 is **partially complete**: approved mechanisms and focused tests are implemented; eight frozen bounded M6Q checks and a signed package were obtained for the immediately preceding source state. The last environment-guard fix is focused-test verified but has no live package for current source because the owner stopped reruns. Final M6 study qualification also lacks multi-scope, broader failure, fresh acceptance and research-denominator work.
- The earlier full-discovery startup failure root cause remains unverified. Improved diagnostics do not prove it is fixed.
- A1/A2 variant labels and the E08 baseline pin still need explicit owner decisions. No packages were installed for E08 or E09.
- This live run has one synthetic task sequence and one injected failure. It does not supply study denominators, held-out families, uncertainty estimates, external-baseline conformance, or fresh-submission acceptance results.
- H25–H28 may execute eligible frozen E01–E13 contracts only after their individual evidence prerequisites are met. Do not reuse this engineering qualification as a population experiment.
