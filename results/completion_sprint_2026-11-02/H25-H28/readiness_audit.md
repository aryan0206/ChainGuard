# H25–H28 E01–E13 research readiness audit

Prepared 2 November 2026 from the Architecture Lock, Evaluation Protocol, Experiment Matrix, H9–H12 contract/case inventory, H12–H16 development capture, H22–H25 raw witness/package records, and current source/tests. This is a **readiness audit, not an experiment result**. No E01–E13 population experiment was executed here. Protocol RQ IDs and H IDs below are local to the Evaluation Protocol.

## Common eligibility rules and current source

An independent security sample is a workflow **parent**, not a call, prefix, variant, timing repetition, or M6Q engineering check. The protocol's 3 development / 2 validation / 5 held-out parents per S1–S6 is a coverage target, not a power calculation. At least one fully eligible parent/pair can support a bounded descriptive observation; uncertainty or broader comparison needs enough independent parents, with actual counts disclosed. Every run needs a prewritten fixture/effect oracle, frozen version/configuration, parent and split assignment, denominators and exclusions, raw proposals and outcomes, and the experiment-specific witnesses below. Unknown labels/effects are reported as unknown and excluded from binary metrics with counts. Paired variants remain in one parent split.

The H9 inventory has **nine development cases in eight parent groups**, no validation parents and no held-out parents. H12–H16 retained one 724-byte byte-identical E02 B1 pair and one E13 ID-renaming development check; their labels are authored/staged rather than independently observed live outcomes. H22–H25 recorded eight bounded M6Q checks, two assessor sink receipts, one injected fault, a signed package and offline inspection, all before the final child-environment guard. The saved package binds `m6_live_runtime.py` SHA-256 `ed1574f4599d61714c0d3db670d0a64dd82c74acb314433f2966334fdb96325e`; current source SHA-256 is `c136f3c68306a3fb2b377da9002738bcf3fab6276e84fef57c2047f47c0dd15d`. The guard had one focused passing test, but **current-source live M6 qualification is absent**. Prior package verification cannot supply it. No new dependency or current-source test was run in this audit.

`BLOCKED` below means the protocol defines the intended comparison but a required decision/input/oracle is absent. `CONTRACT INCOMPLETE` means the exact run-specific case, fault, benchmark or denominator contract remains unfrozen. Neither status permits research execution. No row is `READY` or `READY WITH EXPLICIT LIMITATIONS`.

## Individual readiness

### E01 order-insensitive controls — **BLOCKED**

- **RQ/H; variables and unit:** RQ1/RQ2, H1/H5. Vary B0/B1/B2-R/B2-S and valid benign order in S1/S2; measure authorization correctness, abstention, unnecessary denial, completion and B2 agreement. Unit: paired parent with equal current call, policy and scoped non-order facts; eligible parent/pair counts and exclusions must be frozen. Prefixes are diagnostics.
- **Oracle, controls, witnesses:** Prewritten independent authorization/effect labels and source/sink/task observations; one shared controller history for shadows, separately matched enforcement if used. Retain raw proposals, B1 bytes/projections, order journals, outcomes and task objective. Compare against the same static envelope.
- **Analysis and completion:** Paired per-parent error/coverage/completion counts, actual denominators and unknown exclusions; parent-level uncertainty only if enough parents. Completion requires valid benign pairs with equal allowed inputs, independent labels/effects, all representation outputs and B2-R/S prefix agreement. Existing S1/S2 cases are unpaired development foundations; no eligible benign-reordering pair or final observations exist.

### E02 matched order-sensitive groups — **BLOCKED**

- **RQ/H; variables and unit:** RQ1/RQ2, H2/H5. Vary valid lifecycle order at byte-identical B1 input; measure mixed-label ambiguity, B1/B2 authorization, coverage, denial and completion. Unit: independent matched parent group in S4–S6; freeze group membership and eligible labels.
- **Oracle, controls, witnesses:** Independently ordered grant/revoke/use and confirmed control/reservation commits before each proposal; same current call, scope/outcome categories, exact B1 bytes, static policy and B0 control. Retain raw proposal/order journals, detector outputs, controller/effect witnesses and task result. A use after revoke must have valid authority or be a denied proposal.
- **Analysis and completion:** Compute observed group bound `sum(min(authorized_count, unauthorized_count))`, separately B1 abstention/definite error and B2-R/S agreement; report parent-group denominator, not prefix significance. H12 has one exact 724-byte development pair with opposite **authored** labels; no independent live commit/effect labels, final mixed-label inventory or frozen denominator.

### E03 historical recognition — **BLOCKED**

- **RQ/H; variables and unit:** RQ1/RQ2, H1/H3/H4. Vary independently confirmed prior exposure outside frozen direct B0 recognition coverage; measure useful warning/authorization, covered disclosure, unsafe recommendations and disruption. Unit: S2/S3 parent, with actual eligible case and exclusion counts.
- **Oracle, controls, witnesses:** Freeze direct-coverage code/digest before case selection. Pair with unrelated-public-send and failed/denied-read controls under the same policy. Retain raw reads/sends, independent source success/canary, assessor sink bytes/decoding, pre-decision permission and task output; do not infer leakage from exposure alone.
- **Analysis and completion:** Per-parent eligible authorization/coverage and covered disclosure/disruption with denominators and unknowns; uncertainty only across independent parents. No frozen outside-coverage case/coverage digest or qualified paired controls exist. H22 source/sink checks used directly recognized canary payloads and cannot establish history benefit.

### E04 detector/controller attribution — **CONTRACT INCOMPLETE**

- **RQ/H; variables and unit:** RQ4/RQ6, H4/H6. Vary shadow and active representation/mode under a fixed controller envelope; measure detector recommendation error separately from controller refusal, dispatch, consumption, disclosure and completion. Unit: equivalent S1–S6 parent across separately executed configurations.
- **Oracle, controls, witnesses:** Independent pre-decision permission, raw proposals, commit/reservation, attempted forwarding, child handler, assessor sink and task output. Shadows share one controller history; enforcement needs separate runs and may diverge. Common-gate prevention is never detector credit; observation mode does not bypass authorization.
- **Analysis and completion:** Paired parent/configuration attribution ledger, definite-label denominators, coverage, gate prevention and completion/disclosure; parent-level uncertainty if feasible. Exact enforcement profiles, equivalent case mapping, comparison denominator and effect criteria are not frozen. Existing M6 profile is bounded observation and preceding-source M6Q checks cannot fill the matrix.

### E05 held-out workflows — **BLOCKED**

- **RQ/H; variables and unit:** RQ1/RQ2/RQ3, H1–H5. Vary representation/system on held-out S1–S6 parents; measure useful authorization, completion, abstention, denial and disclosure. Unit: independent parent template; target 3/2/5 development/validation/held-out per stratum is not achieved or a minimum power claim.
- **Oracle, controls, witnesses:** Freeze parent split, rules, extraction, thresholds, policy, mappings and digests before outcomes. Keep clones/variants in one split; use independent workflow oracle, raw paired outputs, source/sink/task witnesses and fixed static envelope. External subset requires E08 conformance.
- **Analysis and completion:** Actual parent and eligible-proposal denominators, unknown/exclusions, paired differences and parent-level uncertainty if sample supports it; no held-out tuning. Current inventory has eight development parents, zero validation/held-out. No final split or held-out oracle observations exist.

### E06 live M6 lifecycle — **BLOCKED**

- **RQ/H; variables and unit:** RQ4/RQ6, H5/H6. Vary grant/use/reuse, active-unconsumed revoke, new grant, multi-scope, dispatched failure/no refund and denial; measure authorization/consumption correctness and completion. Unit: independently witnessed live task/parent, with all required lifecycle branches and case denominators predeclared.
- **Oracle, controls, witnesses:** Prewritten controls and objective; raw proposals, assessor-held ordered control/reservation COMMIT, source, forwarding, child handler, separate sink bytes/non-arrival and task output. Keep authorization, dispatch, consumption and disclosure distinct; audit rows alone are ineligible.
- **Analysis and completion:** Per-case and per-parent correctness/unknown matrices, no-refund/denial and task-completion rates with actual denominators; completion requires the entire frozen lifecycle set including all-or-nothing multi-scope and failed dispatched call. H22 M6Q covers some branches only on the preceding source; current-source live qualification and remaining branches are absent.

### E07 execution/failure boundaries — **CONTRACT INCOMPLETE**

- **RQ/H; variables and unit:** RQ4/RQ6, H6/H7. Vary declared fault at control, intent, COMMIT, forward, result and close, with known versus ambiguous outcome; measure forwarding safety, unknown/consumption handling, no replay/refund and incomplete evidence. Unit: paired S5/S6 faulted parent and equivalent no-fault control.
- **Oracle, controls, witnesses:** Frozen fault ledger and timing, independent transaction-boundary receipt, downstream write, handler/sink, raw response and closure observations. Ambiguous possible arrival stays UNKNOWN, never assumed absent.
- **Analysis and completion:** Boundary-by-boundary eligible fault matrix, unknown/incomplete counts and paired effects; timing repetitions are not security samples. H22 has one injected pre-dispatch COMMIT refusal on preceding source. Exact remaining fault/counterfactual case IDs, expected statuses and current-source qualified hooks are not frozen.

### E08 external baseline — **BLOCKED**

- **RQ/H; variables and unit:** RQ1/RQ3/RQ7, H4/H9. Compare ChainGuard with pinned Wang-style R02 subset on common supported facts; measure authorization correctness, coverage, completion, disclosure and cost. Unit: paired common-domain parent after conformance.
- **Oracle, controls, witnesses:** Same extraction, facts, outcomes, mapping, history and static envelope; independent oracle. First retain pinned reference/adapter outputs for decision, R02 rule, effective and accumulated sensitivity on required differential conformance cases; exclude unsupported domain with denominator.
- **Analysis and completion:** Paired parent-level errors/coverage and uncertainty if feasible, plus separately measured cost. Owner must resolve supplied short revision versus Lock §17 full pin; no adapter/driver, dependency approval, conformance or paired input exists. No substitute revision is permitted.

### E09 evidence integrity — **BLOCKED**

- **RQ/H; variables and unit:** RQ5/RQ6/RQ8, H7/H8. Vary repository A0/A1/A2/A3/A3T/A4/A4T and declared mutation; measure verifier-dimension detection, false acceptance/rejection, incomplete handling and cost. Unit: assessor original–mutant–variant cell; freeze full eligible cell ledger and equal semantic content/durability/signing frequency.
- **Oracle, controls, witnesses:** Assessor original bytes/digest, exact mutation script/ledger, independent expected inventory/challenge/key/config and expected verifier dimension; actual mutant bytes/digest and outputs. Keep pre/post-seal and whole-session removal limits distinct; A3T/A4T need parity with A3/A4.
- **Analysis and completion:** Dimension-specific eligible cell denominator, false acceptance/rejection/incomplete counts and paired cost; zero misses is only bounded-campaign evidence. Owner has not resolved A1/A2 label conflict. A3T/A4T and frozen mutation matrix are absent; engineering mutation tests are not the study.

### E10 authentic-but-wrong facts/findings — **CONTRACT INCOMPLETE**

- **RQ/H; variables and unit:** RQ4/RQ5, H7. Vary legitimately signed wrong observation, wrong finding and witnessed omission; measure authenticity/reproduction/oracle disagreement. Unit: selected qualified original–mutant workflow/package pair, with case denominator predeclared.
- **Oracle, controls, witnesses:** Fixed legitimate test signer/key and rules; independent raw source/sink/dispatch truth and omission journal; signed original/mutant, verifier dimensions and task effects. Missing truth makes the case unevaluable, not correct.
- **Analysis and completion:** Per-class authentic, reproduced and oracle-agreement counts with unknown exclusions; no generality from one mutant. Exact signed case set, expected dimensions, legitimate test signer provision and current-source independently observed truth are not frozen.

### E11 acceptance — **CONTRACT INCOMPLETE**

- **RQ/H; variables and unit:** RQ5/RQ6, H7/H8. Vary context/inventory, stale/duplicate, restart/concurrency and registry commit fault across A4/A4T with A3/A3T inspect controls; measure whole-run acceptance correctness and expectation preservation. Unit: complete expected run submission, singleton or multi-session.
- **Oracle, controls, witnesses:** Independently registered challenge/inventory and pinned key, original package set, registry transaction/readback, restart/process boundary and per-dimension inspection; acceptance never certifies benign behavior.
- **Analysis and completion:** Predeclared submission denominator, false acceptance/rejection, stale/duplicate and incomplete/ambiguous counts by case. M5/M6.4 engineering tests exist; A4T and frozen case/registry-observation ledger do not. H22 package had inspection only, `fresh_submission=NOT_CHECKED`, and predates current source.

### E12 cost/scaling — **CONTRACT INCOMPLETE**

- **RQ/H; variables and unit:** RQ8, H5/H8/H10. Vary session length/scopes, B2-R versus **retained** B2-S, pipeline stage and A3/A3T/A4/A4T; measure latency, storage, memory, throughput and correctness. Unit: common workload/length/scope cell with repeated timing trials; repetitions are not independent security parents.
- **Oracle, controls, witnesses:** Same hardware/OS/packages, semantic records, signing frequency and boundaries; independent timing/resource capture and correctness agreement. Retain capture/detect/SQLite/seal/verify/accept timings, disk bytes, detector state/tombstones/references, queue, total process and export buffers.
- **Analysis and completion:** Frozen warmup/repetition counts and workload cells; median/IQR, p95 only with enough repetitions, bytes/event/session and all memory components, with failed correctness cells retained. Test durations and live B2-R prefix replay are ineligible. Retained-state measurement, equivalent variants and benchmark contract remain absent.

### E13 invariance/explanation — **BLOCKED**

- **RQ/H; variables and unit:** RQ1/RQ2/RQ4, H1/H5. Vary harmless gaps, bijective opaque-ID renaming and valid scope interleaving; measure verdict/rule/reference consistency, explanation fidelity, B1 leakage and B2 agreement. Unit: before/after pair within an independent parent; freeze eligible transformation counts.
- **Oracle, controls, witnesses:** Independent invariant/authorization labels, valid before/after raw journals, same relevant semantics, exact B0/B1/B2 projections, declared reference bijection and explanation outputs. An interleaving that changes permission belongs to E02, not invariance.
- **Analysis and completion:** Pair-level agreement/disagreement by transformation, reference validity and B2-R/S prefix agreement with parent-level aggregation; report exclusions. H12 has one authored ID-renaming development pair only. Qualified harmless-gap and scope-interleaving pairs and independent final observation/label records are missing.

## Decisions and H28–H31 preparation

1. **Owner decision:** explicitly reconcile A1/A2 naming before E09. The supplied shorthand says A1 chain/A2 signed closure; repository charter/protocol uses A1 independent hashes/A2 unkeyed chain. This audit changes neither.
2. **Owner decision:** confirm exact E08 source pin. Supplied `3dd9690b5b6f9c4ef385289714b314d13f6ad1` conflicts with Lock §17 `3dd9690b5b6f9c4ef385289714b314d13f6ad9a1`. The 40-hex H22 live runtime revision is unrelated to this baseline decision.
3. **Separate approvals:** any new dependency set/pins, missing evidence-variant implementation, material architecture change or final held-out split requires the applicable owner gate. No such decision was inferred here.
4. **H28–H31 analysis preparation:** retain the current zero-execution denominator; prepare only schemas/scripts for per-parent eligibility, unknown/exclusion counts, paired differences, B1 identical-input grouping, dimension-specific verifier outcomes and timing median/IQR after contracts and data freeze. No figure or IEEE result table is justified now. Do not use H22 test totals or M6Q case count as research sample size.
