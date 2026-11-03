# E06-focused engineering execution results

**New execution:** 15 selected existing unittest methods; **15 passed, 0 assertion failures, 0 retries, 0 timeouts, 0 exclusions**. `focused_tests.run.json` records the exact 13-method command, local start/end, elapsed time, owner-supplied revision pin and exit **0**; `restart_order_tests.run.json` records the exact two-method command and exit **0**. Their stdout/stderr logs are retained beside these documents. No original M6Q case was rerun or overwritten. See [readiness](E06_READINESS.md), [matrix](E06_REQUIREMENT_MATRIX.md), [audit](E06_EVIDENCE_AUDIT.md), and [status](E06_FINAL_STATUS.md).

The rows below identify the **existing test input construction and asserted output/state**, rather than claiming retention of random runtime bytes. `Auth` = `tests.test_m6_live_authorization.LiveAuthorizationTests`, `Runtime` = `tests.test_m6_live_runtime.RuntimeTests`, `Writer` = `tests.test_m6_live_audit.LiveWriterTests`. Actual `ok` is the raw unittest observation. Each test uses fresh temporary SQLite fixtures with names `live.sqlite` or `m6-live.sqlite`; exact generated run/task IDs and database bytes are not retained. This is engineering testing, not a frozen E06 research case ledger.

| Existing method | Input/condition from test source | Expected asserted output/state | Actual |
| --- | --- | --- | --- |
| Auth.`test_grant_one_use_and_consumed_retry_denial` | Grant `g-1`, source read, first send intent, dispatched failed outcome, second send | One permit/consumption; failed dispatched use does not refund; retry denied; close unsealed | ok |
| Auth.`test_active_unconsumed_revoke_denies_then_new_grant_restores` | Grant `old`, revoke before use, source read, denied send, grant `new`, send | Old ID unusable; first send denied; new grant permits exact scope | ok |
| Auth.`test_multi_scope_all_or_nothing_and_minimum_id` | Grants `z`/`a` for A; read A and B; missing B, then grant B | No partial selection; after B grant choose `a` and `b`; later missing B denied | ok |
| Auth.`test_missing_permission_names_disabled_override_without_consumption` | Only A grant, read A/B, attempt send under disabled override | DENY/UNAUTHORIZED; denied outcome; A grant retained; no intent | ok |
| Auth.`test_failed_and_ambiguous_pre_dispatch_batch_never_returns_permit` | Inject failed and ambiguous pre-dispatch write | No usable dispatch permit or unauthorized forwarding | ok |
| Auth.`test_failed_reservation_keeps_whole_grant_set_unconsumed` | Fail multi-grant reservation batch | Entire set unconsumed; no partial permit | ok |
| Auth.`test_unknown_outcome_halts_with_consumed_intent` | Grant/read/send, dispatch, record unknown outcome, retry | UNKNOWN_OUTCOME halt; consumed intent retained; retry blocked | ok |
| Auth.`test_failed_outcome_write_cannot_refund_intent` | Grant/read/send; fail outcome COMMIT; retry | Intent still records selected grant; rollback failure state; retry blocked | ok |
| Runtime.`test_assessor_stream_retains_commit_handler_and_exact_sink_bytes` | Grant/read/send synthetic payload `SYNTHETIC_CANARY_A-π` through live child | Separate host commit/dispatch/client response and child handler/sink bytes+digest; closure | ok |
| Runtime.`test_one_use_release_and_second_denial` | Live source, grant, first sink release, second release | First succeeds; second denied after one use | ok |
| Runtime.`test_exact_revoke_and_new_grant_restore_scope` | Live exact scope revoke then new grant | Revocation denies; new grant permits release | ok |
| Runtime.`test_partial_write_and_flush_failure_record_unknown_without_replay` | Partial/flush/ack-loss downstream write variants | Unknown outcome, consumed intent, halted task and no automatic retry | ok |
| Runtime.`test_outcome_write_failure_never_refunds_or_replays` | Fail outcome persistence after dispatch | Consumed intent remains; no refund/replay | ok |
| Runtime.`test_fifo_revocation_waits_for_pending_intent` | Queue revoke behind pending proposal turn | Revocation waits; committed intent ordering preserved | ok |
| Writer.`test_reopen_does_not_restore_task_or_grant_authority` | Persist grant, close writer, attempt reopen same context | Old task/grant authority not restored | ok |

**Historical qualification:** [M6Q-01–08 case results](../completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/live_m6_current/case_results.json) record eight bounded synthetic checks as PASSED, with raw requests/responses, assessor inventory, host/child/sink witnesses, signed package and verifier outputs in `live_m6_current/`. The historical [run log](../completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/current_qualification.run.json) records the original command, timestamps and exit code. These cases are neither the 15 new test methods nor an E06 research denominator.

**Research outcome:** zero newly qualified E06 research cases. Existing test assertions do not retain exact random inputs/outputs and independent S3–S6 labels; no valid population metric or uncertainty estimate follows. The [evidence audit](E06_EVIDENCE_AUDIT.md) records the remaining gates.
