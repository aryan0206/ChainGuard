# E01–E13 contract audit — H9–H12

Prepared 2 November 2026 from `docs/EXPERIMENT_MATRIX.md`, `docs/EVALUATION_PROTOCOL.md`, Architecture Lock v1.1, the charter, and existing fixture code. All RQ IDs below are **protocol-local**; Lock/charter RQ numbering is separate. No experiment was executed. Hypotheses are predictions, not findings. The matrix provides experiment variables and primary/secondary outcomes; the protocol and lock provide oracle, controls, validity, and measurement rules.

## Common execution and denominator rules

Prewrite contracts and expected effects before results. A parent template/workflow is the independent security unit; per-call/prefix rows are diagnostics, not independent samples. Keep reordered variants and near duplicates in one parent split. Freeze rules, policy, extraction, direct recognition coverage, labels, expected inventory, configuration digests, seeds and denominators before held-out runs. Independently reconstruct pre-decision AUTHORIZED/UNAUTHORIZED/INDETERMINATE for **every** proposal, including denied ones. Exclude unknown labels from binary authorization denominators and disclose counts; do not turn an absent receipt into non-arrival. Separate detector recommendations, controller refusals, dispatch, consumption, covered disclosure and task completion. Report per-family and overall matrices/precision/recall/F1/FPR/FNR only with actual eligible denominators and undefined handling. Paired uncertainty uses independent parent groups where sample size supports it; timing repetitions are not new security samples. Exact aggregation/weighting, binary treatment and final sample inventory are **not frozen in the authority documents** and must be frozen before execution.

## E01 — order-insensitive controls

- **RQ/H; IV → DV:** RQ1/RQ2, H1/H5. Vary B0/B1/B2-R/B2-S and benign order in S1/S2 while keeping current facts, policy and scoped non-order facts equal → independent authorization correctness; secondary abstention, denial, completion, B2 agreement.
- **Unit/eligibility:** paired parent workflow; only valid benign reorderings with equal eligible facts and prewritten labels. Development `public-current` and `monotone-public-transfer` are candidate foundations, not a frozen paired study. Exclude unequal-current or unsupported paths and disclose them.
- **Controls/oracle/raw:** common history for shadows, separately run enforcement if used; independent staged or live oracle labels, raw proposals, projections/B1 bytes, source/sink/task receipts, all detector and controller outcomes.
- **Metrics/stat/completion:** eligible labeled proposal/workflow errors and coverage, legitimate completion/disruption, B2-R/S prefix agreement; paired parent summaries and uncertainty if enough parents. Complete only after paired cases, denominators, raw observations and exclusions are retained. Gap: no frozen valid reorderings or independent final observations.

## E02 — matched order-sensitive groups

- **RQ/H; IV → DV:** RQ1/RQ2, H2/H5. Vary valid lifecycle order at byte-identical B1 input; compare conservative B1 and B2-R/S (B0 control) → mixed-label ambiguity and authorization correctness; secondary coverage, unnecessary denial, enforcement consequence.
- **Unit/eligibility:** matched identical-input parent group in S4–S6. Equal counts alone fail eligibility; current call, scoped categories/outcomes and serialized B1 bytes must match. Use after revoke requires a valid new/other grant or explicit committed synthetic override. Keep paired variants in one split.
- **Controls/oracle/raw:** independent ordered controls/commit witnesses and pre-decision labels; exact B1 bytes, order journals, current proposal, grant/use/revoke scopes, detector assessments, separate controller effects. `revocation_boundary_01` is one development qualification example with opposite authored labels and asserted exact B1-byte equality in `tests/test_workflows.py`; no final observed sample.
- **Metrics/stat/completion:** within identical-input mixed-label groups, report `sum(min(authorized_count, unauthorized_count))` as the observed minimum binary error bound; separately report B1 abstention, definite error, denial/completion and B2 agreement. Parent-group analysis, not prefix-level significance. Gap: broader mixed-label inventory and independent final commit/effect witnesses.

## E03 — historical recognition

- **RQ/H; IV → DV:** RQ1/RQ2, H1/H3/H4. Vary eligible prior exposure outside frozen direct-recognition coverage; compare B0/B1/B2 → authorization correctness and useful historical warning; secondary covered disclosure, unsafe recommendations, disruption.
- **Unit/eligibility:** S2/S3 parent workflows with independently witnessed successful sensitive source exposure; direct content coverage fixed in advance. Include unrelated public send and failed/denied-read controls. Exclude cases where the current payload already falls inside direct coverage from a history-benefit claim.
- **Controls/oracle/raw:** frozen coverage digest, raw read/send proposals, independent source status/canary, destination-tagged exact/decoded sink bytes, task output, labels and detector/controller paths.
- **Metrics/stat/completion:** eligible labeled workflow errors/coverage plus independently covered sink disclosure and false disruption with denominators/exclusions; paired parent/family uncertainty if feasible. Gap: no frozen direct-coverage inventory or qualified live sink/source observations.

## E04 — detector/controller attribution

- **RQ/H; IV → DV:** RQ4/RQ6, H4/H6. Vary shadow/active representation and execution mode under a common static envelope → attributed authorization decisions; secondary refusal, dispatch, consumption, disclosure and completion.
- **Unit/eligibility:** equivalent S1–S6 parent fixtures; shadows share one controller-generated history and cannot dispatch/consume; enforcement configurations need separate runs, whose histories may diverge. Normal observation never bypasses authorization.
- **Controls/oracle/raw:** fixed profile and explicit default-disabled synthetic override; independent pre-decision permission, raw proposal, forwarding attempt, handler, commit/consumption, sink bytes and task outcome; retain each detector recommendation and controller refusal separately.
- **Metrics/stat/completion:** eligible labeled recommendation error and coverage, gate prevention attribution, unauthorized disclosure and legitimate completion by parent/configuration. No detector credit for common-gate prevention. Gap: independent live boundary and equivalent enforcement observations missing.

## E05 — held-out workflows

- **RQ/H; IV → DV:** RQ1/RQ2/RQ3, H1–H5. Vary representation/system on frozen S1–S6 held-out parents → useful authorization and completion; secondary abstention, denial, disclosure, disruption.
- **Unit/eligibility:** parent template; protocol targets 3 development, 2 validation, 5 held-out parents per stratum (coverage target only). Reorders/clones/near duplicates cannot cross splits. No held-out evaluation until labels, oracle, rules, extraction, thresholds, mappings, splits, and digests freeze; no test tuning.
- **Controls/oracle/raw:** same static envelope and independently qualified workflow oracle, paired raw outcomes, source/sink/task receipts, parent/split inventory. External subset may enter only after E08 conformance.
- **Metrics/stat/completion:** report actual parent/workflow denominators, excluded/unknowns, paired differences and parent-level uncertainty (e.g. paired bootstrap if enough parents). Gap: only nine development contracts; zero verified validation/held-out parents and no frozen parent split.

## E06 — live M6 lifecycle

- **RQ/H; IV → DV:** RQ4/RQ6, H5/H6. Vary grant/use/reuse/revoke/regrant and scope lifecycle in S3–S6 → authorization and consumption correctness; secondary denial/completion/no refund.
- **Unit/eligibility:** independently witnessed live task/workflow. Must include active **unconsumed** revoke, first release then denial without new grant, fresh regrant, all-or-nothing multi-scope, failed dispatched call without refund, denial consuming nothing, and ambiguous halt/no replay.
- **Controls/oracle/raw:** prewritten task/controls; raw proposals, independent control and reservation COMMIT witnesses, source bytes, handler arrival, sink bytes/non-arrival and task outputs. Audit-only reconstruction is ineligible.
- **Metrics/stat/completion:** per eligible proposal/task contract correctness, consumption, unauthorized disclosure and completion with unknowns. Gap: H6–H9 no-Git live entry and witness blockers; no final live case observed.

## E07 — execution/failure boundaries

- **RQ/H; IV → DV:** RQ4/RQ6, H6/H7. Vary declared fault point at control, intent, commit, forward, result, close → no unauthorized forwarding and correct unknown/consumption handling; secondary halt, evidence completeness and completion.
- **Unit/eligibility:** S5/S6 faulted workflow paired with equivalent no-fault control; distinguish confirmed failure from ambiguous acknowledgement. Do not treat a possible tool arrival as non-arrival.
- **Controls/oracle/raw:** frozen fault ledger/timing, commit-boundary witness, forward attempt, handler/sink observations, raw result and closure status outside audit storage.
- **Metrics/stat/completion:** eligible fault-case outcome matrix, no-replay/no-refund and UNKNOWN counts by boundary; paired cases, not timing repetitions as security samples. Gap: qualified fault hooks and independent live effects/commit witnesses missing; historical tests are engineering support only.

## E08 — external baseline

- **RQ/H; IV → DV:** RQ1/RQ3/RQ7, H4/H9. Vary ChainGuard versus pinned Wang-style R02 sensitivity subset on the common supported domain → authorization correctness; secondary coverage, denial, disclosure, completion, cost.
- **Unit/eligibility:** shared-fact workflow parent, after exact revision pin resolution and differential conformance. Exclude unsupported tools/rules/facts and report common-domain denominator; no full-system reproduction claim.
- **Controls/oracle/raw:** same extraction/facts, outcomes, mappings, histories and static envelope; independent oracle. First retain reference driver/adaptation outputs for decision, R02 rule, effective sensitivity and accumulated sensitivity on all lock-required conformance cases; only then paired workflows.
- **Metrics/stat/completion:** eligible paired workflow errors/coverage/completion and cost with parent-level uncertainty if feasible. Gap: conflicting supplied pin, no adapter/driver/conformance or comparison result.

## E09 — evidence integrity

- **RQ/H; IV → DV:** RQ5/RQ6/RQ8, H7/H8. Vary A0/A1/A2/A3/A3T/A4/A4T (repository labels) and predeclared mutation class → dimension-specific detection, false acceptance/rejection/incomplete status and cost.
- **Unit/eligibility:** original assessor-held package plus exact mutant pair and expected verifier dimension; same semantic records, durability and signing frequency, with matching P-256/SHA-256 trust for signed variants. Include edit, insert/delete, reorder/duplicate/splice/truncate/whole-session removal, recomputation, signer/config substitution, stale/duplicate, pre-/post-seal cases.
- **Controls/oracle/raw:** original bytes/digest, mutation script/ledger and target field, independent inventory/challenge/key pin, actual mutated bytes/digest, per-dimension verifier outputs. Authentic wrong facts belong additionally to E10.
- **Metrics/stat/completion:** eligible mutant-by-variant denominator and per-dimension false acceptance/rejection/incomplete; paired cost with measured boundaries. Do not infer a cryptographic failure probability from zero observed misses. Gap: A1/A2 authority conflict and missing A3T/A4T/other variants; no frozen campaign.

## E10 — authentic-but-wrong facts/findings

- **RQ/H; IV → DV:** RQ4/RQ5, H7. Vary correctly signed wrong observation, wrong finding, and independently witnessed omission → separation of authenticity, reproduction and oracle truth.
- **Unit/eligibility:** selected qualified S1–S6 workflow/package with legitimate test signer and independent truth journal. Missing oracle observation makes completeness unevaluable, not correct.
- **Controls/oracle/raw:** fixed signer/key, rules, semantic inputs, signed original/mutant, source/sink/dispatch witness and exact expected verifier dimensions.
- **Metrics/stat/completion:** case inventory and dimension-specific authentic/reproduced/oracle-agreement counts with unknown exclusions; no generality from one mutant. Gap: qualified independent truth/omission witnesses and predeclared signed case set.

## E11 — acceptance

- **RQ/H; IV → DV:** RQ5/RQ6, H7/H8. Vary expected context/inventory, stale/duplicate submission, restart/concurrency and registry commit fault across A4/A4T versus inspect-only A3/A3T → whole-run acceptance correctness and expectation preservation.
- **Unit/eligibility:** complete expected run submission, singleton or multi-session; independently registered challenge/inventory and signer pin. Include missing/extra/wrong-context, duplicate after restart and lost-ack cases.
- **Controls/oracle/raw:** original package(s), frozen assessor registration, actual registry transaction/readback and process boundary, per-dimension inspection plus acceptance status. Acceptance never certifies benign behavior.
- **Metrics/stat/completion:** eligible submission denominator, false acceptance/rejection, duplicate/stale rejection and INCOMPLETE/ambiguous counts by case. Gap: A4T study support and frozen campaign/registry observations; M5/M6.4 tests are engineering only.

## E12 — cost/scaling

- **RQ/H; IV → DV:** RQ8, H5/H8/H10. Vary session length/scopes, B2-R versus actually retained B2-S, proxy/evidence stage and A3/A3T/A4/A4T → latency, storage and memory; secondary throughput, correctness/agreement, completion.
- **Unit/eligibility:** common workload/length/scope configuration with repeated timing runs; correctness checked first. Repetitions estimate timing reliability, not independent security sample size. B2-R prefix replay is not B2-S retained-state measurement.
- **Controls/oracle/raw:** same hardware/OS/packages, semantic records, signing frequency and measurement boundaries; record capture/detection/SQLite/sealing/verification/acceptance timings, bytes per event/session, audit disk, detector state, lifecycle tombstones/references, queued work, total process and export buffers.
- **Metrics/stat/completion:** median/IQR and p95 only with sufficient repetitions, throughput and staged overhead with actual repetition denominator; no constant-memory claim. Gap: retained B2-S benchmark path, instrumentation and equivalent evidence variants absent.

## E13 — invariance/explanation

- **RQ/H; IV → DV:** RQ1/RQ2/RQ4, H1/H5. Vary harmless gaps, opaque-ID renaming and valid scope interleaving → verdict/rule/reference consistency; secondary explanation fidelity, B1 order leakage and B2 agreement.
- **Unit/eligibility:** before/after metamorphic pair within one parent, preserving the independently specified invariant and valid lifecycle. Exclude an interleaving that changes authorization from an invariance claim; analyze it as order-sensitive instead.
- **Controls/oracle/raw:** frozen raw before/after journals, B0/B1/B2 inputs/projections, independent labels, deterministic reference mapping and explanation outputs.
- **Metrics/stat/completion:** eligible pair agreement/disagreement counts by transformation, explanation reference validity and B2-R/S prefix agreement; paired parent summaries, not per-prefix samples. Gap: only development identifier-renaming checks; no frozen qualified metamorphic corpus or output ledger.
