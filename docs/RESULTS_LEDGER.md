# Results ledger

Snapshot: 8 October 2026. Strict separation of engineering checks, final research observations and unmeasured work. Sources: owner-supplied Phase 1 status and [README](../README.md), especially Actual M5 validation and M4 durability correction. These results were recorded previously; no code, regression, campaign or experiment was run in Phase 1. Raw artifacts were not independently rerun or revalidated here.

## A. COMPLETED ENGINEERING RESULTS

| ID | Completed engineering check | Recorded result | Interpretation / limit |
| --- | --- | --- | --- |
| ENG-M1 | Real MCP stdio mediation | 12 tests passed | Controlled client -> proxy -> server; bounded transport surface |
| ENG-M2 | Replay-only B0/B1/B2 and independent oracle | 41 tests passed | Synthetic replay; assumed commits do not establish live durability or M6 |
| ENG-M3 | Durable SQLite / trusted non-cryptographic continuity | 40 tests passed in current regression | Commit confirmation precedes trusted update/forwarding; unsealed M3 is not M4 evidence |
| ENG-M4 | Signed chain/offline inspection and repaired persistence gate | 67 tests passed in current regression | SHA-256 domain separation, ECDSA P-256/SHA-256; bounded faults/mutations |
| ENG-M5 | Expected-run lifecycle / durable whole-run acceptance | 27 tests passed | Inventory, duplicate/restart/concurrency protection; student review distinct from completion |
| ENG-TOTAL | Current project regression | 187 = 12 + 41 + 40 + 67 + 27 | Engineering tests, **not 187 independent research observations**; campaign checks not added to this total |
| ENG-M4-FLOW | Real success/error/success | 26 records; 8 confirmed transactions | Public non-release controlled calls, not a live sensitive-release study |
| ENG-M4-VERIFY | Separate-process offline verification | PASS across six dimensions; 12 findings reproduced; B2-R/B2-S agreement at all 3 proposal prefixes | Consistency/authenticated evidence, not oracle truth or population accuracy |
| ENG-M4-REPAIR | Persistence-gate correction | README records 27 targeted regressions passed and 10 independent recheck cases BLOCKED | Exact persisted-batch/manifest readback before commit; see AF-001. These are engineering checks, not added research samples |
| ENG-M5-CAMPAIGN | Declared adversarial package campaign | 32/32 cases and 16/16 consolidated checks passed | Bounded package matrix; no general cryptographic failure-rate estimate |
| ENG-M5-FRESH | Separate-process fresh acceptance | ACCEPTED | Eligible whole-run evidence, not benign behavior certification |
| ENG-M5-DUPLICATE | New-process submission after acceptance | REJECTED / ALREADY_ACCEPTED | Durable duplicate-evidence rejection; not prevention of MCP tool replay |

Verifier dimensions: schema/lifecycle/sequence; commitment/link integrity; trusted signature; external context/configuration binding; signed/inventory completeness; finding reproduction. Repeated inspection is permitted and distinct from fresh acceptance.

README records Windows x64, CPython 3.14.3, SQLite 3.50.4, MCP 2.3.0 and cryptography 50.0.2 for the existing milestones. These versions were not checked or installed in this phase. README's suite durations are test observations, not E12 benchmarks. Older 35/45/160-test counts are historical checkpoints superseded by the current regression; do not sum them.

## B. COMPLETED RESEARCH/EXPERIMENTAL RESULTS

No completed final E01-E13 research results are established by the supplied status. Existing fixture checks, mutation checks and package campaigns remain engineering evidence above. No final held-out sample count, effect size, uncertainty interval, comparative superiority or novelty result is recorded.

## C. PLANNED

E01-E13 are specified in the [matrix](EXPERIMENT_MATRIX.md) and [protocol](EVALUATION_PROTOCOL.md). Execution is outside Phase 1. E06, E08 and E12 have NOT STARTED prerequisites; other experiments are PLANNED. Target corpus size is coverage planning only, not an observation.

## D. NOT YET MEASURED

| Quantity / capability | Missing evidence |
| --- | --- |
| Final authorization, coverage/abstention, unnecessary denial, unsafe recommendations | Qualified independently labeled workflow-level results |
| Unauthorized disclosure, legitimate completion and disruption | Independent live source/sink/task observations across study workflows |
| B1 mixed-label ambiguity and held-out B2 benefit | Matched B1-input groups and frozen independent parent holdouts |
| Live M6 grant/revoke/consumption and failure semantics | M6 implementation and independent live observations; replay checks insufficient |
| External comparison | Resolved pin, conformance, common supported domain, paired outcomes |
| A3/A3T and A4/A4T assurance/cost tradeoffs | Equivalent-format experiments; resolve conflicting A1/A2 labels |
| Authentic wrong facts / omissions versus independent truth | Qualified E10 cases; prior incorrect-finding checks do not complete E10 |
| Final acceptance/mutation campaign statistics | Predeclared research case inventory and raw dimension-specific outcomes |
| Incremental B2-S scaling, latency, memory and storage | Actual retained-state implementation measured under E12 boundaries |

## Future entry contract

Append only after execution: experiment/run ID, actual date, frozen revision/configuration, fixture/parent/split, oracle provenance, actual independent workflow count and eligible denominator, observed outputs, raw artifact location/digests, failures/exclusions, repetitions, uncertainty method and limitations. Unknown values stay unknown. Review claims through [Claims Register](CLAIMS_REGISTER.md); do not overwrite unexpected results with intended outcomes.
