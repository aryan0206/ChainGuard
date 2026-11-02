# H6–H9 evidence-aligned demo plan

Prepared 2 November 2026. No demo or live qualification was executed during this checkpoint.

## Existing engineering evidence that can be shown now

1. Display the retained H0–H2 environment, exact focused command, `focused_retry_1.run.json`, and raw `focused_retry_1.stderr.log`: 28 verifier/acceptance engineering tests passed, exit 0. Explain that these tests exercise bounded code paths and do not establish independent live source/sink truth.
2. Display H0–H2 `full.run.json` and `full.stderr.log`: 466 tests with one child-startup setup error, exit 1. Then show H2–H6 `targeted.run.json` and `targeted.stderr.log`: the predecessor pair passed, exit 0. State that the startup root cause remains unresolved.
3. Walk through the source-defined bounded path without executing it: trusted host grant/revoke, raw MCP proposal, confirmed audit append, permit take, child handler, local sink event, clean-close export, and offline verifier dimensions. Identify which observations are audit products and which would need assessor collection.

These are reproducible explanations of retained engineering evidence. No H6–H9 test command is recommended under the current no-Git boundary because the live configuration validator invokes Git internally.

## New live qualification demo after entry and witnesses are READY

Freeze and retain case/run/challenge/configuration/key pins, then execute M6Q-01 through M6Q-07 in a controlled synthetic task with direct assessor capture of raw proposals, control/commit receipts, child handler stream, sink bytes/digest, task outputs, and complete negative-capture closure. Cleanly close and retain the signed package. Run offline `inspect_live_package` with independently pinned inputs and save all dimension results. Execute M6Q-08 separately with a predeclared fault and preserve its non-arrival/failure evidence; do not expect a signed clean-close export from a halted run. Record exact commands, start/end, exit codes, and raw files at execution time. This sequence is **planned, not demonstrated**.

## Further planned demonstrations still blocked

- Valid-versus-tampered offline package and fresh/duplicate acceptance after restart need retained real packages and independently pinned assessor inputs. Historical M6.4 tests cover the mechanisms; no new package or report exists in H6–H9.
- Multi-scope all-or-nothing, dispatched failure/no-refund, and ambiguous outcome are not covered by the eight frozen case IDs and need their own prewritten qualification contracts and witnesses.
- B0/B1/B2 research comparison and E01–E13 population experiments remain outside this checkpoint.

Professor-facing claim boundary: the current artifact supports a bounded engineering explanation and retained test outcomes. It does not show a newly qualified live disclosure/prevention result, prove observation truth from a signature, or claim arbitrary MCP protection.
