# Results ledger

Snapshot: 8 October 2026. Strict separation of engineering checks, final research observations and unmeasured work. Sources: owner-supplied Phase 1 status and [the archived engineering README](SPIKE_LOG.md#historical-engineering-readme-at-checkpoint-5d00057), especially Actual M5 validation and M4 durability correction. These results were recorded previously; no code, regression, campaign or experiment was run in Phase 1. Raw artifacts were not independently rerun or revalidated here.

M6.4 bounded engineering addendum: 21 October 2026. The dated entry below supplements this historical snapshot. The earlier final read-only completion audit ran no tests. A subsequent local M6.4 readiness audit executed the focused and full-discovery commands recorded below; this documentation edit did not rerun tests.

## A. COMPLETED ENGINEERING RESULTS

### Updated runtime and guided frontend — 4 November 2026

Main was fast-forwarded by 12 commits from `3688081` to `65d0eb6`, preserving local frontend work. The adapter now meets upstream's trusted revision requirement and captures synthetic M6 host/child witness metadata separately from signed audit. The UI links actual request/control records to their inputs, removes predicted output fields and explains the site and M2–M6. **471 upstream tests passed in 168.064s**, **18 adapter tests passed**, **16 frontend data/rendering tests passed**, and the production build passed. One initial upstream test required localhost socket permission; the full rerun passed. A real HTTP-proxy M6 run produced 59 records, 28 findings, seven PASS inspection dimensions, ACCEPTED submission, ALREADY_ACCEPTED on resubmission, 53 host and 8 child observations. The registry/witness workspace remains temporary; no external assessor TCP sink or persistent UI acceptance service is claimed. Browser visual/interaction QA remains unperformed. These are bounded engineering observations, not new qualified research samples. Upstream runtime/test source, retained research evidence and dependency pins have no local edits.

### Current M6 frontend integration — 31 October 2026

Upstream pull confirmed local and remote main already at `3688081`; no new upstream commits were merged. The existing local frontend now exposes the fixed synthetic M6.4 live permission/evidence/acceptance interfaces. **466 original tests passed in 79.997s**, **17 adapter tests passed**, **10 frontend data/rendering tests passed**, and the production build passed. A real run through the local frontend proxy produced seven tool responses (including three actual controller denials and one controlled tool failure), two sink arrivals, 59 audit records, 28 findings, seven PASS inspection dimensions, ACCEPTED/COMMITTED complete-run submission and REJECTED/ALREADY_ACCEPTED after registry reopen. Registry/evidence cleanup is per-run; persistent frontend submission history is not implemented. Browser visual/interaction QA remains unperformed. These checks establish bounded engineering behavior, not new independent research observations. The runtime source and dependency pins are unchanged.

### Local frontend milestone — 22 October 2026

Original M1/M4 CLI demos passed on macOS with Python 3.14.3. Existing full discovery passed **466 tests in 122.230s**. The separate web environment passed **14 adapter tests**, including genuine demo execution, M1 CLI parity, M4 evidence/finding checks, malformed/unsupported requests, local request boundaries, concurrency rejection, isolated workspaces, exit-code preservation, timeout and shutdown cleanup. Node 25.2.1/npm 11.6.2 passed **4 frontend data-handling tests** and the Vite build. A real M4 run through the frontend HTTP proxy returned three responses, 26 records, 12 findings and PASS in all six offline inspection dimensions; complete-run acceptance was NOT_CHECKED. These counts are engineering checks, not independent workflow experiments. Browser visual/interaction QA remains unperformed. Vite 7.2.2 is retained by owner choice despite its reported advisories; the compatible fix was offered. Setup and remaining UI milestones are in the [README](../README.md#local-frontend--updated-4-november-2026).

| ID | Completed engineering check | Recorded result | Interpretation / limit |
| --- | --- | --- | --- |
| ENG-M1 | Real MCP stdio mediation | 12 tests passed | Controlled client -> proxy -> server; bounded transport surface |
| ENG-M2 | Replay-only B0/B1/B2 and independent oracle | 41 tests passed | Synthetic replay; assumed commits do not establish live durability or M6 |
| ENG-M3 | Durable SQLite / trusted non-cryptographic continuity | 40 tests passed in current regression | Commit confirmation precedes trusted update/forwarding; unsealed M3 is not M4 evidence |
| ENG-M4 | Signed chain/offline inspection and repaired persistence gate | 67 tests passed in current regression | SHA-256 domain separation, ECDSA P-256/SHA-256; bounded faults/mutations |
| ENG-M5 | Expected-run lifecycle / durable whole-run acceptance | 27 tests passed | Inventory, duplicate/restart/concurrency protection; student review distinct from completion |
| ENG-TOTAL | M1–M5 regression subtotal (historical discovery) | 187 = 12 + 41 + 40 + 67 + 27 | Engineering tests, **not 187 independent research observations**; campaign checks not added to this total |
| ENG-M4-FLOW | Real success/error/success | 26 records; 8 confirmed transactions | Public non-release controlled calls, not a live sensitive-release study |
| ENG-M4-VERIFY | Separate-process offline verification | PASS across six dimensions; 12 findings reproduced; B2-R/B2-S agreement at all 3 proposal prefixes | Consistency/authenticated evidence, not oracle truth or population accuracy |
| ENG-M4-REPAIR | Persistence-gate correction | The archived engineering README records 27 targeted regressions passed and 10 independent recheck cases BLOCKED | Exact persisted-batch/manifest readback before commit; see AF-001. These are engineering checks, not added research samples |
| ENG-M5-CAMPAIGN | Declared adversarial package campaign | 32/32 cases and 16/16 consolidated checks passed | Bounded package matrix; no general cryptographic failure-rate estimate |
| ENG-M5-FRESH | Separate-process fresh acceptance | ACCEPTED | Eligible whole-run evidence, not benign behavior certification |
| ENG-M5-DUPLICATE | New-process submission after acceptance | REJECTED / ALREADY_ACCEPTED | Durable duplicate-evidence rejection; not prevention of MCP tool replay |

Verifier dimensions: schema/lifecycle/sequence; commitment/link integrity; trusted signature; external context/configuration binding; signed/inventory completeness; finding reproduction. Repeated inspection is permitted and distinct from fresh acceptance.

The archived engineering README records Windows x64, CPython 3.14.3, SQLite 3.50.4, MCP 2.3.0 and cryptography 50.0.2 for the existing milestones. These versions were not checked or installed in this phase. The archived README's suite durations are test observations, not E12 benchmarks. Older 35/45/160-test counts are historical checkpoints superseded by the current regression; do not sum them.

### Phase 2 foundation qualification — 8 October 2026

**PHASE 2 FOUNDATION COMPLETE.** This is infrastructure/engineering qualification, not a completed E01-E13 experiment. Added [workflows.py](../chainguard/workflows.py), [workflow_fixtures.py](../tests/workflow_fixtures.py) and [test_workflows.py](../tests/test_workflows.py). Only this ledger, the protocol and spike log receive status updates; other research claims and experiment statuses remain valid.

| Executed check | Actual result | Boundary |
| --- | --- | --- |
| New focused tests, initial version | 25 tests in 0.420s, OK, exit 0 | Contract/oracle separation, explicit receipts and matched input qualification |
| New focused tests, final version | 29 tests in 0.989s, OK, exit 0 | Added destination binding, unreadable sink bytes, fake-live evidence rejection and malformed observation coverage |
| M1 unchanged regression, isolated rerun | 12 tests in 20.926s, OK, exit 0 | Original discovery/assertions/timeouts unchanged |
| M2 unchanged regression | 41 tests in 0.585s, OK, exit 0 | Replay-only semantics preserved |
| M3 unchanged regression | 40 tests in 65.113s, OK, exit 0 | Existing durable/unsealed slice preserved |
| M4 unchanged regression | 67 tests in 166.955s, OK, exit 0 | Existing signed evidence/verifier tests preserved |
| M5 unchanged regression | 27 tests in 127.805s, OK, exit 0 | Existing expected-run acceptance tests preserved |

Nine authored **development** contracts cover all six strata. One matched group, `revocation_boundary_01`, checks identical non-order facts and actual B1-input bytes with prewritten UNAUTHORIZED/AUTHORIZED labels. This is a qualification example, not a final E02 research result, held-out validation or a general ordering-effect estimate. All new observation examples are explicitly injected synthetic unittest inputs; no live collector, M6, external baseline or evidence variant was implemented.

Independence checks: fresh process with detector/normalizer/controller imports absent; AST import inspection; altered detector findings and rejected controller/finding annotations; poisoned B2 evaluators; handler/sink receipts contradicting the authored plan; independently supplied consumption observations; unknown and incomplete data retained. Expected labels are checked with unchanged M2 assessor semantics. Its staged witness classification is preserved; receipt inputs are not manufactured from detector or controller outputs. Detector-relative metrics remain NOT_CHECKED in the truth-only foundation.

The initial concurrent M1/M3/M4/M5 run produced an M1 discovery timeout in setUpClass: 3 tests ran, one setup error, exit 1. Diagnosis found unchanged existing sources and tests; all other suites passed. The isolated M1 rerun passed all 12 tests without modifying code, assertions or timeouts. This is consistent with concurrent subprocess load, but does not conclusively identify the timeout's root cause. These test durations are engineering observations, not cost/scaling benchmarks.

Final separately executed suite counts: M1/M2/M3/M4/M5 = 12/41/40/67/27 (187 existing tests), plus 29 new foundation tests = **216 passing tests across the executed suites**. This is an aggregate of suite results, not a new project-wide discovery run, research sample size or count that includes failed/repeated attempts.

### M6.4 bounded engineering gate addendum — 21 October 2026

| Gate | Completion-audit decision | Evidence and limit |
| --- | --- | --- |
| 1 — Contract | PASS | Committed `m6_live_profile.py`/`m6_live_evidence.py` define exact versions, canonical package/closure fields and domain-separated signing bytes; `test_m6_live_evidence.py` includes a fixed byte/digest vector. Structural checks alone neither authenticate a signature nor recompute the chain. |
| 2 — Seal | PASS | Committed host exporter requires clean shutdown, reconciles one read-only snapshot against retained writer count/head, signs and exports it. The 19 October [engineering record](SPIKE_LOG.md#m64-gate-2-live-clean-close-sealing--19-october-2026) supplies historical fault and test coverage. |
| 3 — Independent verification | PASS | The new M6.4 `m6_live_verifier.py` and `test_m6_live_verifier.py` check chain, pinned signature, assessor context, lifecycle, normalized finding reproduction and mutation/inventory cases. Assessor inventory, configuration, challenge and signer pin must be supplied independently of the package. |
| 4 — Acceptance and ordering | PASS | The new M6.4 `test_m6_live_acceptance.py` exercises confirmed registration and full reopened expectation readback before the real live open; a call is sealed, independently inspected, accepted with `COMMITTED` durability, then rejected as a duplicate after restart. Both lost-acknowledgement cases prevent execution; the post-commit case checks exact intended signer-pin bytes. The strict-string malformed-report and valid-report tests pass. Gate 4's final independent review returned APPROVED. |

| Provenance | Recorded result | Interpretation |
| --- | --- | --- |
| 19 October Gate 2 engineering record | Focused 78 tests in 291.271s and combined 279 in 450.325s passed; initial full discovery of 438 had one child startup-handshake timeout, followed by 438 passed in 541.125s | Historical tests at Gate 2, not rerun for this addendum |
| Earlier M4/M5/all-M6 combined run reported for Gate 4 | 344 tests, exit 1 from one M6 child startup-handshake timeout; isolated case passed | Failed run retained; root cause unknown |
| Subsequent in-chat combined rerun in the repository `.venv` | 344 tests passed in 531.264s, exit 0 | Includes Gate 3/4 tests; does not explain the prior timeout |
| Subsequent full discovery reported to the review | 466 passed | Reported result; exact command/output was not retained in the completion audit |
| Signer-pin remediation check and final independent Gate 4 review | Three lost-ack tests passed in 7.040s; acceptance module 15 passed in 33.951s. Later focused review 4 passed in 20.058s; acceptance module 15 passed in 33.321s | Separate runs, not additive samples; final review APPROVED after P2 signer-pin fix |
| Final read-only completion audit | No tests run; source, test, documentation and Git state inspected | Gate 1/3 PASS decisions are this audit's source-and-test assessment; standalone Gate 1/3 approval reports were not located. Gate 2 engineering record and Gate 4 APPROVED review are available |
| Subsequent local M6.4 readiness audit — focused | `.\.venv\Scripts\python.exe -B -m unittest -v tests.test_m6_live_verifier tests.test_m6_live_acceptance`: 28 tests in 58.395s, `OK` | Later local engineering run; not part of the earlier read-only audit or an independent research experiment |
| Subsequent local M6.4 readiness audit — full discovery | `.\.venv\Scripts\python.exe -B -m unittest discover -s tests`: 466 tests in 670.885s, `OK` | Later local engineering run; does not resolve the earlier child-startup timeout or establish detector superiority/observation truth |

All four gates are bounded engineering checks, not final M6 or E01–E13 results. Shared class setup is a residual P3 test-isolation follow-up, not a failing test. The ordering test does not establish a global runtime preregistration gate. Signatures authenticate commitments, not observation truth or downstream tool behavior; registry rollback and directory-entry crash durability are outside the established claims. At the historical pre-commit checkpoint `3990258`, `chainguard/m6_live_verifier.py`, `tests/test_m6_live_verifier.py`, and `tests/test_m6_live_acceptance.py` were untracked, while `chainguard/acceptance.py` was tracked and modified; this records that checkpoint's Git status, not current status.

## B. COMPLETED RESEARCH/EXPERIMENTAL RESULTS

No completed final E01-E13 research results are established by the supplied status. Existing fixture checks, mutation checks and package campaigns remain engineering evidence above. No final held-out sample count, effect size, uncertainty interval, comparative superiority or novelty result is recorded.

**Current classification addendum — 3 November 2026, after Step 1–2 evidence audits:** No E01–E13 experiment is fully contract-qualified as a research result. [E03's bounded pilot](../results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/e03_pilot/) is **PARTIALLY EXECUTED — CONTRACT INCOMPLETE**: five calls, two task parents, four detector-evaluable descriptive rows and one schema-rejected control excluded; the frozen plan's separate task-level client objective acknowledgment is absent. Retained [metrics](../results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/e03_pilot_metrics.json) and raw records are unchanged, and the generated `RESEARCH` field does not establish full qualification. [Current-source M6Q-01–08](../results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/live_m6_current/case_results.json) passed bounded live engineering qualification with fresh reinspection and durable acceptance. [E08](../results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/e08_conformance_results.json) passed ten narrow pinned R02 conformance cases over nineteen supplied-fact steps; no paired ChainGuard/reference research comparison exists. E09's A3 development expectations matched 3/5 dimensions and remain inconclusive; E10/E11 are engineering qualification only; E12 is instrumentation without a benchmark. Section C and D prerequisite lists below are the original 8 October planning snapshot and do not override this current addendum.

**Current Step 4 reconciliation — 3 November 2026:** **No E01–E13 experiment is currently fully contract-qualified as a research result.** The following focused assessments update current interpretation. Their test-method counts, M6Q cases and proposed calls are not research-case denominators; the preceding addendum and Sections C–D retain their historical context.

| Experiment | Current evidence and classification | Research gap |
| --- | --- | --- |
| E03 | **PARTIALLY EXECUTED — CONTRACT INCOMPLETE.** [Pilot raw cases](../results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/e03_pilot/case_results.json): five calls in two parents, four detector-evaluable descriptive rows, one schema-rejected control excluded, zero research-qualified cases. [Step 4B](../results/STEP4B_E03_RESEARCH_2026-11-03/STEP4B_SUMMARY.md) proposes **unapproved** 12 parents/48 calls; no prospective cohort was run. | Separate task-level client objective acknowledgment cannot be captured and verified with the [current collector](../results/STEP4B_E03_RESEARCH_2026-11-03/COLLECTION_GAP_ASSESSMENT.md). |
| E06 | **ENGINEERING QUALIFICATION ONLY.** Historical [M6Q-01–08](../results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/live_m6_current/case_results.json) retained; [15 existing engineering methods](../results/STEP4_E06_SCOPE_LIFECYCLE_2026-11-03/E06_EXECUTION_RESULTS.md) passed, zero failed/retried/excluded. | Independent S3–S6 research population, exact case-level oracle and denominator missing; zero newly qualified research cases. |
| E07 | **ENGINEERING QUALIFICATION ONLY.** Historical M6Q-08 pre-dispatch fault retained; [focused assessment](../results/STEP4_E07_FAULT_MATRIX_2026-11-03/E07_FINAL_STATUS.md) ran zero new checks and completed zero fault/no-fault pairs. | No valid matching no-fault control in existing inventory; ten mapped research requirement categories blocked. |
| E09 | **INCONCLUSIVE.** [Seven-variant assessment](../results/STEP4_E09_PARITY_2026-11-03/E09_FINAL_STATUS.md): A0, A1, A2, A3, A3T, A4, A4T. Only A3 has five E09 development cells: three expected-dimension matches, two preserved schema-first mismatches (`E09-DEV-A3-02`, `E09-DEV-A3-03`), zero exclusions; zero new checks. | Six variants lack frozen E09 case-level inputs/expected outputs; no research-qualified case. |
| E11 | **ENGINEERING QUALIFICATION ONLY.** Historical [durable acceptance/readback and duplicate rejection](../results/completion_sprint_2026-11-02/FIVE_HOUR_SPRINT/live_m6_current/fresh_submission_readback.json) preserved; [14 existing engineering methods](../results/STEP4_E11_LIFECYCLE_2026-11-03/E11_EXECUTION_RESULTS.md) passed with zero assertion failures/exclusions, including separate-process restart and concurrency. Initial launcher exit 101 before collection is retained. | A3T inspection and A4T fresh acceptance blocked; no newly qualified research case. |

## C. PLANNED

E01-E13 are specified in the [matrix](EXPERIMENT_MATRIX.md) and [protocol](EVALUATION_PROTOCOL.md). Execution is outside Phase 1. E06, E08 and E12 have NOT STARTED prerequisites; other experiments are PLANNED. Target corpus size is coverage planning only, not an observation.

## D. NOT YET MEASURED

| Quantity / capability | Missing evidence |
| --- | --- |
| Final authorization, coverage/abstention, unnecessary denial, unsafe recommendations | Qualified independently labeled workflow-level results |
| Unauthorized disclosure, legitimate completion and disruption | Independent live source/sink/task observations across study workflows |
| B1 mixed-label ambiguity and held-out B2 benefit | Matched B1-input groups and frozen independent parent holdouts |
| Final live M6 grant/revoke/consumption and failure semantics | Independent qualified source/sink/task observations across study workflows; M6.3/M6.4 controlled engineering tests do not complete E06/E07 |
| External comparison | Resolved pin, conformance, common supported domain, paired outcomes |
| A3/A3T and A4/A4T assurance/cost tradeoffs | Equivalent-format experiments; resolve conflicting A1/A2 labels |
| Authentic wrong facts / omissions versus independent truth | Qualified E10 cases; prior incorrect-finding checks do not complete E10 |
| Final acceptance/mutation campaign statistics | Predeclared research case inventory and raw dimension-specific outcomes |
| Incremental B2-S scaling, latency, memory and storage | Actual retained-state implementation measured under E12 boundaries |

## Future entry contract

Append only after execution: experiment/run ID, actual date, frozen revision/configuration, fixture/parent/split, oracle provenance, actual independent workflow count and eligible denominator, observed outputs, raw artifact location/digests, failures/exclusions, repetitions, uncertainty method and limitations. Unknown values stay unknown. Review claims through [Claims Register](CLAIMS_REGISTER.md); do not overwrite unexpected results with intended outcomes.
