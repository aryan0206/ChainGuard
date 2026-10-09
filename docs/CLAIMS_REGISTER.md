# Claims register

Snapshot: 8 October 2026. Evidence status comes from [Results Ledger](RESULTS_LEDGER.md); architecture/trust limits come from [Architecture Lock](ARCHITECTURE_LOCK.md) and [Threat Model](THREAT_MODEL.md). Engineering completion, methodology approval and empirical support are distinct. No final E01-E13 study, novelty assessment or cost benchmark was executed in Phase 1.

## Engineering claims

| Claim ID | Claim | Type | Evidence required | Current evidence | Status | Allowed wording | Forbidden wording |
| --- | --- | --- | --- | --- | --- | --- | --- |
| ENG-01 | Controlled stdio path operates | Engineering | Real mediated calls, correlation and errors | M1 12 tests; README | SUPPORTED WITHIN SLICE | M1 demonstrates the configured local client/proxy/server path | Full MCP compliance; arbitrary host protection |
| ENG-02 | Replay representations and independent oracle checks operate | Engineering | Frozen features, independent labels, valid-prefix equivalence | M2 41 tests, replay only | SUPPORTED WITHIN SLICE | Replay checks exercise B0/B1/B2 and B2-R/B2-S agreement | Live M6 validated; agreement establishes truth |
| ENG-03 | Durable gate repaired | Engineering | Exact materialization before commit; real no-forward fault checks | M3 40/M4 67; AF-001 and [archived README repair](SPIKE_LOG.md#historical-engineering-readme-at-checkpoint-5d00057) | SUPPORTED WITHIN TESTED BOUNDARY | Recorded repair checks block the declared admission manipulations | Every storage failure is prevented; tool effects are atomic with SQLite |
| ENG-04 | Signed evidence can be inspected and findings reproduced | Engineering | Pinned-key separate verifier and dimensions | 26 records/8 transactions; six PASS dimensions; 12 reproduced findings | SUPPORTED WITHIN SLICE | Separate-process verification/reproduction succeeded for the recorded demonstration | Signatures prove detector correctness or raw facts |
| ENG-05 | Durable expected-run acceptance operates | Engineering | Inventory, durable commit, restart/duplicate/concurrency checks | M5 27 tests; 32-case/16-check campaign; ALREADY_ACCEPTED after restart | SUPPORTED WITHIN CAMPAIGN | M5 recorded fresh acceptance and new-process duplicate rejection | Replay prevention for MCP executions; benign run certified |
| ENG-06 | M1–M5 regression subtotal passed | Engineering | Reported suite totals with provenance | 12/41/40/67/27 = 187 | RECORDED; NOT RERUN IN PHASE 1 | The historical engineering record reports 187 M1–M5 engineering/regression tests passed; the ledger records 29 additional foundation tests, giving 216 across separately executed suites | 187 or 216 independent research observations |

## Methodological claims

| Claim ID | Claim | Type | Evidence required | Current evidence | Status | Allowed wording | Forbidden wording |
| --- | --- | --- | --- | --- | --- | --- | --- |
| MET-01 | Bounded representation and evidence study | Methodological | Locked contracts, approved protocol, independent oracle design | Lock/charter plus supplied Astra protocol; authority conflicts documented | DOCUMENTED; FREEZE RESOLUTION PENDING | ChainGuard is a controlled MCP testbed for studying how retained historical information affects deterministic security decisions, and for evaluating the separate guarantees of authenticated evidence, decision reproduction and expected-run acceptance. | Established superiority or final novelty |
| MET-02 | Independent workflow-level evaluation | Methodological | Prewritten contracts, external witnesses, grouped holdouts | Protocol specified; M2 oracle engineering evidence | PLANNED FINAL QUALIFICATION | The protocol requires independent labels and workflow-level reporting | Detector outputs are ground truth; prefixes are independent samples |
| MET-03 | Coverage target is planning | Methodological | Actual independent parent inventory and split evidence | Target 60 parents, 10 per stratum; actual final count unknown | TARGET ONLY | The target covers six strata; actual feasible count will be reported | Power calculated; 60 workflows already evaluated |

## Empirical claims

| Claim ID | Claim | Type | Evidence required | Current evidence | Status | Allowed wording | Forbidden wording |
| --- | --- | --- | --- | --- | --- | --- | --- |
| EMP-01 | Ordering changes bounded authorization decisions | Empirical | E02 valid equal-B1-input mixed-label groups, independent labels | Replay engineering checks; no final study | NOT YET SUPPORTED | E02 will test where order changes decisions | B1 is wrong because it abstains; all history needs order |
| EMP-02 | Useful held-out B2 improvement | Empirical | E05 paired workflows, coverage/denial/disclosure/completion and uncertainty | No held-out study | NOT YET SUPPORTED | Improvement is a hypothesis | B2 is always better; general zero FAR/FRR |
| EMP-03 | Fair external comparison | Empirical | Resolved pin, E08 conformance and common-domain outcomes | No adapter/conformance/comparison | NOT YET SUPPORTED | A narrow conformance-first comparison is planned | Full Wang reproduction; baseline superiority established |
| EMP-04 | Representation/evidence cost tradeoffs | Empirical | E12 actual retained B2-S and equal A3/A3T/A4/A4T measurements | Test-run durations only | NOT YET SUPPORTED | Cost/scaling remains unmeasured | Constant-memory; constant-time; live replay demonstrates incremental performance |
| EMP-05 | Final integrated empirical contribution | Empirical | E01-E13 raw workflow results, independent oracles, limitations and review | Methodology and engineering evidence only | NOT YET SUPPORTED | The final study is planned; contribution wording below is conditional | Final experiments completed or novel contribution established |

Conditional later wording for EMP-05, only if final evidence supports every clause:

> We present a controlled study of current-event, unordered-prefix and ordered-state representations for bounded MCP exposure and revocable-authorization policies. Using independently specified workflow contracts and independently retained execution observations, we characterize where ordering changes authorization decisions and legitimate-task completion. We separately evaluate signed-chain and signed-transcript evidence, deterministic finding reproduction and expected-run acceptance, including authentic-but-incorrect observations and execution/persistence failures.

## Security claims

| Claim ID | Claim | Type | Evidence required | Current evidence | Status | Allowed wording | Forbidden wording |
| --- | --- | --- | --- | --- | --- | --- | --- |
| SEC-01 | Authenticated commitment is distinct from truth | Security | Trusted key/configuration and separate reproduction/oracle outcomes | Locked semantics; M4 verification; E10 planned | DESIGN BOUNDARY; ENGINEERING CHECKS ONLY | Signatures authenticate committed evidence under stated trust assumptions | Signatures prove truth; signatures prevent lies |
| SEC-02 | Tampering detected within declared cases | Security | Retained originals, mutation inventory and dimension outcomes | M4/M5 bounded engineering campaign | BOUNDED ENGINEERING SUPPORT | The declared campaign passed; final evidence study pending | Universal tamper resistance; zero failures give cryptographic failure probability |
| SEC-03 | Expected-run acceptance is evidence eligibility | Security | Independent complete inventory, durable registry transaction | M5 recorded acceptance/restart results | BOUNDED ENGINEERING SUPPORT | Complete expected evidence can be accepted, including evidence of violations | Acceptance proves benign behavior or actual execution truth |
| SEC-04 | Live one-use/revoke/failure semantics | Security | E06/E07 independent live consumption/source/sink witnesses | M6 unimplemented; replay only | NOT YET SUPPORTED | M6 remains mandatory final-project work | Live revocable release protection completed |
| SEC-05 | Scope/time/replay limits | Security | Explicit trust/observation boundary | Lock/threat model and README | DOCUMENTED LIMIT | Local timestamps are display context; evidence duplicates are distinct from tool replay | Trusted timestamping; universal protection; MCP command anti-replay |

## Novelty claims

| Claim ID | Claim | Type | Evidence required | Current evidence | Status | Allowed wording | Forbidden wording |
| --- | --- | --- | --- | --- | --- | --- | --- |
| NOV-01 | Final research novelty | Novelty | Updated primary literature review and supported final empirical contribution | Charter overlap review dated 7 October 2026; final study absent | NOT YET SUPPORTED | Publication feasibility and final novelty remain unresolved | First sequence-aware MCP defense; first verifiable agent trace; novel cryptographic primitive |

Before paper/PPT/viva use, attach exact ledger/artifact references, actual eligible counts, uncertainty and limitations to each empirical claim. A passed engineering check supports its bounded behavior only. Do not promote planned hypotheses, target counts or authentic-but-wrong examples into achieved research results.
