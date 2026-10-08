# Research spike log

Documentation snapshot: 8 October 2026. [Architecture Lock](ARCHITECTURE_LOCK.md) controls architecture; [evaluation protocol](EVALUATION_PROTOCOL.md) controls this study's methodology. Entries below use dates explicitly recorded in [README](../README.md); no new execution occurred during Phase 1.

| Date / sequence | Decision or discovery | Evidence and consequence |
| --- | --- | --- |
| 7 October 2026 | Architecture v1.1 locked; ECDSA P-256 retained | Lock records approval and mandatory scope. Lock alone did not authorize implementation or dependencies. |
| 7 October 2026 | M1 local stdio mediation completed | Real MCP client -> proxy -> controlled server; 12 tests passed. Bounded transport evidence, not detection evidence. |
| 8 October 2026 | M2 replay-only B0/B1/B2 comparison completed | 41 tests; independent fixture oracle; B2-R/B2-S agreement checked at valid prefixes. Staged commit inputs are not durable commit witnesses. |
| 8 October 2026 | M3 durable unsealed persistence completed | Trusted non-cryptographic continuity; confirmed commit before forwarding. Initial 35-test suite later became 40 with the shared durability repair. Live release lifecycle remains M6 work. |
| 8 October 2026 | M4 signed-chain evidence and offline inspection completed | Separate streams; SHA-256 domain separation; ECDSA P-256/SHA-256 closure. Real success/error/success: 26 records, 8 confirmed transactions, six verifier dimensions PASS, 12 findings reproduced. |
| 8 October 2026, after initial M4 | Persistence-gate flaw discovered and repaired | SQL acknowledgments could hide missing/altered evidence while forwarding occurred; later seal rejection was too late. Transaction-local schema validation and exact persisted-batch/manifest readback before commit repair the gate. See [AF-001](ADVERSARIAL_FINDINGS.md). Repair baseline: `49aa07b31edc2d77f275ec15e7ae42af02d37065`. |
| 8 October 2026, after repair | M5 expected-run acceptance completed for review | Durable whole-run acceptance, complete external inventory, duplicate/restart/concurrency protection; 27 tests, 32 package cases and 16 consolidated checks. New-process duplicate rejected as ALREADY_ACCEPTED. README records student review pending; implementation completion does not imply milestone commit approval. |
| 8 October 2026, Phase 1 | Research-control pivot and approved Astra protocol recorded | Focus: representation sufficiency, useful authorization, independent outcomes, evidence/reproduction/acceptance separation and cost. No novelty or superiority conclusion. E01-E13 are planned, not completed research. |
| 8 October 2026, Phase 2 | PHASE 2 FOUNDATION COMPLETE: independent workflow/observation qualification | Added a separate workflow layer, nine explicit development contracts covering S1-S6 and focused tests. Reused unchanged M2 assessor for staged contract semantics; environment receipts remain separate and unknowns are preserved. `revocation_boundary_01` has identical B1-input bytes and prewritten opposite authorization labels. No final experiment or live M6 qualification. See protocol and ledger for tests/limits. |

## Evidence classes and open decisions

The current regression total is 187 engineering tests, not 187 independent research observations. Earlier suites are historical checkpoints, not extra samples. [Results ledger](RESULTS_LEDGER.md) separates those checks from the final workflow study.

The supplied protocol and existing documents disagree on A1/A2 labels, baseline revision and RQ numbering. [Protocol authority notes](EVALUATION_PROTOCOL.md#authority-and-open-ambiguities) preserve the exact alternatives and locked requirements. Existing stage-gate wording predates implementation; README records subsequent owner approvals. This task authorizes documentation only.

| Future decision | Required record before execution | Status |
| --- | --- | --- |
| Protocol freeze / ambiguity resolution | Owner resolution, versions/digests and affected experiment IDs; no silent lock amendment | PLANNED |
| Fixture and oracle qualification | Development foundation complete; live witness qualification, expanded corpus and grouped splits still required | FOUNDATION COMPLETE; FINAL QUALIFICATION PLANNED |
| Baseline conformance | Locked narrow subset, resolved pin and differential outputs | NOT STARTED |
| M6 live qualification | Separate implementation authorization; active-unconsumed revoke and one-use cases | NOT STARTED |
| Held-out freeze and analysis | Frozen rules, actual independent workflow count, raw artifacts and uncertainty method | PLANNED |
| Evidence variants and cost | Equivalent A3/A3T and A4/A4T boundaries; retained-state B2-S measurement | PLANNED |

Append future entries with actual date, question, alternatives, owner decision where required, artifact references, observation, limitations and affected claims. Do not backfill an execution date from this snapshot.
